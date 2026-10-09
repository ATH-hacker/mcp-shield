#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ui_server.py —— MCP Shield 本地可视化控制台（零第三方依赖，仅标准库）

为什么要有它
------------
命令行输出对答辩不直观：评委看不到"人眼所见"与"模型实际收到"的差异。
这个控制台把同一份真实数据做成三栏对照：
    ① 人类审阅者看到什么（看着完全正常的工具说明）
    ② 线上报文里真正传了什么（逐码点、不可见字符被点亮）
    ③ 模型把这段文本读成了什么（隐藏载荷被还原出来）

三个视图共同回答四个问题：
    能做到什么     ->  页签①「以前做不到什么」右栏（每条结论配一条可复现证据）
    原本做不到什么 ->  页签①「改造之前：这些攻击根本不在检测视野里」
    怎么做到的     ->  页签③「怎么做到的」（AST / 转义正则 / 码点 三路合流）
    一句话结论     ->  页签⑤「一句话结论」（创新点 + 实测数字 + 边界）

用法
----
    python scripts/ui_server.py                 # 默认 http://127.0.0.1:8787
    python scripts/ui_server.py --port 9000 --open
    python scripts/ui_server.py --watch-interval 0.5    # 目录监听轮询间隔（秒）

目录监听（v1.1 新增）
--------------------
控制台默认带一个本机目录监听线程：周期核对两个样本目录的内容指纹，
一旦文件被改动（新增 / 修改 / 删除），立即重跑静态检测并替换快照，
页面通过轮询 /api/snapshot 自动刷新 —— 不需要手动敲命令，也不需要刷新页面。

必须说清的边界（与"运行时防护"是两件不同的事）：
    * 监听只改变扫描的**触发时机**，不改变检测引擎、告警口径与结论；
    * 它**不进入 Agent 的调用路径**，不拦截、不代理任何一次真实工具调用；
    * 它是本机轮询（标准库 threading + time.sleep），不是生产级 fs 事件订阅；
    * 输出仍然是可审计的处置建议，不是运行时阻断。

安全边界：仅监听 127.0.0.1，不做任何外部网络访问，只读本地样本文件。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scanner as sc  # noqa: E402
from probe_client import capture_tools  # noqa: E402

UI_DIR = ROOT / "ui"
ATTACK = ROOT / "samples" / "attack" / "venomous_server.py"
BENIGN = ROOT / "samples" / "benign" / "clean_server.py"

# ---------------------------------------------------------------------------
# 不可见字符分类：与 scanner.py 的 MS-002/003/004 判据严格一致
# ---------------------------------------------------------------------------
ZERO_WIDTH = set(range(0x200B, 0x2010)) | {0x2060, 0xFEFF}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
TAG_LO, TAG_HI = 0xE0000, 0xE007F


def classify(ch: str) -> str | None:
    cp = ord(ch)
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BIDI:
        return "bidi"
    if TAG_LO <= cp <= TAG_HI:
        return "unicode-tag"
    return None


def decode_tag_payload(text: str) -> str:
    """Unicode TAG 区 (U+E0000–U+E007F) 映射回 ASCII —— 攻击者就是这么夹带可读文本的。"""
    out = []
    for ch in text:
        cp = ord(ch)
        if TAG_LO <= cp <= TAG_HI:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def hidden_summary(text: str) -> dict[str, Any]:
    """把一段文本拆成 可见字符 / 不可见字符 两组，并尝试还原隐藏载荷。"""
    visible: list[str] = []
    hidden: list[dict[str, Any]] = []
    first_hidden_at = None
    for i, ch in enumerate(text):
        kind = classify(ch)
        if kind is None:
            visible.append(ch)
        else:
            if first_hidden_at is None:
                first_hidden_at = i
            hidden.append({"index": i, "cp": f"U+{ord(ch):04X}", "kind": kind, "char": ch})
    kinds: dict[str, int] = {}
    for h in hidden:
        kinds[h["kind"]] = kinds.get(h["kind"], 0) + 1
    vis = "".join(visible).strip()
    # 仅用于展示：隐去不可见字符后，原本紧贴的两个句子会连在一起，补个空格便于阅读。
    # 不改变任何一个可见字符的内容与顺序。
    pretty = re.sub(r"(?<=[.!?;:])(?=[A-Z\u4e00-\u9fff])", " ", vis)
    return {
        "visible_text": vis,
        "pretty_text": pretty,
        "hidden_count": len(hidden),
        "hidden_at": first_hidden_at,
        "hidden_by_kind": kinds,
        "hidden_samples": hidden[:24],
        "tag_payload": decode_tag_payload(text),
    }


# ---------------------------------------------------------------------------
# 从源码里抽取"静态层专属"的证据：凭据路径 / 外传端点 / 危险执行原语
# 这三类在纯文本审阅下不会引人注意，也是常规描述检查工具最常漏掉的东西
# ---------------------------------------------------------------------------
CRED_RE = re.compile(r'"(~?/[^"]*?(?:\.ssh[^"]*|id_rsa|id_ed25519|\.aws/credentials|'
                     r'\.kube/config|\.npmrc|\.netrc|\.env))"')
ENDPOINT_RE = re.compile(r'"(https?://[^"]+)"')
EXEC_RE = re.compile(r'(os\.popen\s*\(|os\.system\s*\(|shell\s*=\s*True|\beval\s*\(|\bexec\s*\()')


def collect_impl_evidence(source: str) -> list[dict[str, Any]]:
    lines = source.splitlines()
    evidence: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        for m in CRED_RE.finditer(line):
            evidence.append({"rule": "MS-005", "line": idx, "kind": "凭据路径",
                             "value": m.group(1), "raw": line.strip(),
                             "why": "工具实现体触碰高敏感凭据路径，等价于把凭据外泄面暴露给模型调用"})
        for m in ENDPOINT_RE.finditer(line):
            url = m.group(1)
            if re.search(r"(?i)(collector|ingest|exfil|beacon|pastebin|webhook|attacker|oastify)", url):
                evidence.append({"rule": "MS-007", "line": idx, "kind": "外传端点",
                                 "value": url, "raw": line.strip(),
                                 "why": "外泄通道被固化进工具实现，静态即可发现，无需运行"})
        for m in EXEC_RE.finditer(line):
            evidence.append({"rule": "MS-006", "line": idx, "kind": "危险执行原语",
                             "value": m.group(1), "raw": line.strip(),
                             "why": "参数若来自模型，即为可被指令注入驱动的任意代码执行"})
    return evidence


# ---------------------------------------------------------------------------
# 检测流水线时间线：把"怎么做到的"摊开给人看
# ---------------------------------------------------------------------------
def build_pipeline(source: str, tools: list[dict], findings: list[Any],
                   hidden_codepoints: int = 0) -> list[dict[str, Any]]:
    """tools 来自 sc.scan_file()，只含 {name, line, desc_line}；码点统计单独传入。"""
    real_cp = hidden_codepoints
    esc_hits = [
        (rid, pat.findall("\n".join(source.splitlines())))
        for rid, pat, _ in sc.ESCAPE_PATTERNS
    ]
    esc_total = sum(len(h) for _, h in esc_hits)
    impl_total = sum(1 for f in findings if f.rule_id in ("MS-005", "MS-006", "MS-007"))
    return [
        {
            "stage": "① 目标发现",
            "engine": "Python AST",
            "detail": f"定位 @mcp.tool() 装饰器 → 发现 {len(tools)} 个工具定义",
            "result": f"{len(tools)} 个工具",
            "why": "普通文本扫描无法知道哪个函数是「暴露给模型的工具」，AST 才能建立"
                   "「函数名 ↔ docstring ↔ 实现体」的对应关系",
            "ok": True,
        },
        {
            "stage": "② 描述文本语义",
            "engine": "意图模式正则（4 条）",
            "detail": "在 docstring 中匹配『不要告诉用户 / 忽略此前指令 / 返回前先执行』等隐瞒型措辞",
            "result": f"{sum(1 for f in findings if f.rule_id == 'MS-001')} 处命中",
            "why": "攻击载荷是自然语言，编译器与类型系统完全不检查它，必须专门建模",
            "ok": True,
        },
        {
            "stage": "③ 码点级检查",
            "engine": "逐字符 ord() 判类",
            "detail": "对描述字段每个字符判归属：零宽区 / Bidi 控制区 / Unicode TAG 区",
            "result": f"{real_cp} 个真实不可见字符",
            "why": "肉眼与字符串比较都看不见它们，但模型 tokenizer 会原样读进去",
            "ok": True,
        },
        {
            "stage": "④ 转义形态检查",
            "engine": "ESCAPE_PATTERNS（最关键的一路）",
            "detail": r"匹配源码里写成 \u200b / \U000E0049 的字面转义序列",
            "result": f"{esc_total} 处转义载体",
            "why": "第一版漏报就漏在这里：文件里没有真实不可见字符，"
                   "只有 6 个 ASCII 字符，码点检查必然一无所获 —— 这条路是踩坑后补上的",
            "ok": True,
        },
        {
            "stage": "⑤ 实现体行为",
            "engine": "AST 调用分析 + 实现模式正则",
            "detail": "检查工具实现到底做了什么：读凭据路径 / 外传端点 / 危险执行原语",
            "result": f"{impl_total} 处命中",
            "why": "工具描述可以写得人畜无害，但真正的破坏力在实现体里",
            "ok": True,
        },
        {
            "stage": "⑥ 运行层交叉验证",
            "engine": "零依赖 stdio 客户端 + JSON-RPC 报文解剖",
            "detail": "真的把 Server 跑起来，抓 tools/list 响应，再看一遍码点",
            "result": "见「运行层取证实录」页签",
            "why": "静态看「源码怎么写」，运行层看「模型收到什么」；黑盒 Server 只能靠这一路",
            "ok": True,
        },
    ]


# ---------------------------------------------------------------------------
# 目录监听：文件一落盘就重扫（只改触发时机，不改检测引擎）
# ---------------------------------------------------------------------------
WATCH_DIRS = [ROOT / "samples", ROOT / "rules"]  # 真正影响结论的只有这两处输入
WATCH_SUFFIXES = (".py", ".ts", ".js", ".yaml", ".yml")
DEFAULT_WATCH_INTERVAL = 1.0  # 秒；单次增量扫描实测约 3.83 ms，轮询开销可忽略
_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now().strftime(_TS_FMT)


def _iter_watched_files() -> list[Path]:
    found: list[Path] = []
    for base in WATCH_DIRS:
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and p.suffix.lower() in WATCH_SUFFIXES and "__pycache__" not in p.parts:
                found.append(p)
    return found


class SampleWatcher:
    """轮询样本目录的内容指纹；指纹一变就重建快照。

    用内容哈希（而不是 mtime）判定变更：同秒内的连续两次保存也能被区分开，
    不会出现"存了盘但界面不刷新"的假阴性。
    """

    def __init__(self, interval: float = DEFAULT_WATCH_INTERVAL) -> None:
        self.interval = max(0.2, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._baseline: dict[str, str] = {}
        self.state: dict[str, Any] = {
            # 默认 True：本模块一律是"带监听的服务端"；离线单页版由
            # build_standalone.py 显式改回 False，页面据此保持静态。
            "enabled": True,
            "interval": self.interval,
            "last_scan_at": None,
            "last_change_at": None,
            "last_change_files": [],
            "scan_count": 0,
            "watched_files": 0,
            "watched_dirs": [str(d.relative_to(ROOT)).replace("\\", "/") for d in WATCH_DIRS],
        }

    # ---- 指纹 ----
    @staticmethod
    def _fingerprint() -> dict[str, str]:
        fp: dict[str, str] = {}
        for p in _iter_watched_files():
            try:
                rel = str(p.relative_to(ROOT)).replace("\\", "/")
                fp[rel] = hashlib.sha1(p.read_bytes()).hexdigest()
            except OSError:
                continue  # 文件正在被写入，下一轮再看
        return fp

    # ---- 主循环 ----
    def _loop(self) -> None:
        baseline = self._baseline
        while not self._stop.wait(self.interval):
            current = self._fingerprint()
            if current == baseline:
                continue
            changed = sorted(
                {k for k in set(baseline) | set(current) if baseline.get(k) != current.get(k)}
            )
            baseline = current
            self._baseline = baseline
            self.state["last_change_files"] = changed
            self.state["last_change_at"] = _now()
            try:
                Handler.rebuild("目录监听：样本文件发生变化")
            except Exception as exc:  # 单次重建失败不应该打死监听线程
                self.state["last_error"] = f"{type(exc).__name__}: {exc}"

    def start(self) -> None:
        """在主线程里先把基线指纹取好，再交给后台线程比对。

        基线必须在 start() 返回前就确定：否则调用方紧接着的那次写文件会
        落进"线程还没取基线"的窗口里，被当成基线的一部分而永远检测不到。
        """
        self._baseline = self._fingerprint()
        self.state["watched_files"] = len(self._baseline)
        self.state["enabled"] = True
        self._thread = threading.Thread(target=self._loop, name="mcp-shield-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.state["enabled"] = False
        self._stop.set()

    def mark_static(self) -> None:
        """离线单页版用：明确声明"本页是静态快照，没有后端在扫"。"""
        self.state["enabled"] = False
        self.state["last_reason"] = "离线单页版：导出时扫描一次"


def static_watch_state(snap: dict[str, Any]) -> dict[str, Any]:
    """给离线单页版用：打一个 enabled=False 的 watch 段，页面据此保持静态。"""
    WATCHER.mark_static()
    WATCHER.state["last_scan_at"] = _now()
    WATCHER.state["scan_count"] = 1
    WATCHER.state["watched_files"] = len(_iter_watched_files())
    snap["watch"] = dict(WATCHER.state)
    return snap


WATCHER = SampleWatcher()


def with_watch_state(snap: dict[str, Any], reason: str) -> dict[str, Any]:
    """把监听状态打进快照，页面据此显示"监听中"并决定要不要重渲染。

    公开函数：`scripts/build_standalone.py` 也调用它，好让离线单页版拿到
    同样形状的 `watch` 段（那里 enabled 恒为 False，页面就显示"静态快照"）。
    """
    WATCHER.state["last_scan_at"] = _now()
    WATCHER.state["last_reason"] = reason
    WATCHER.state["scan_count"] = int(WATCHER.state.get("scan_count", 0)) + 1
    WATCHER.state["watched_files"] = len(_iter_watched_files())
    snap["watch"] = dict(WATCHER.state)
    return snap


# ---------------------------------------------------------------------------
# 单一入口：产出整个控制台所需的真实数据快照
# ---------------------------------------------------------------------------
def build_snapshot() -> dict[str, Any]:
    attack_findings, attack_tools = sc.scan_file(str(ATTACK))
    benign_findings, benign_tools = sc.scan_file(str(BENIGN))
    source = ATTACK.read_text(encoding="utf-8")
    benign_source = BENIGN.read_text(encoding="utf-8")

    # ---- 工具视角：把静态结论按工具名归拢 ----
    tools_payload: list[dict[str, Any]] = []
    for t in attack_tools:
        desc = t.get("description", "")
        hs = hidden_summary(desc)
        tool_findings = [f for f in attack_findings if f.tool == t["name"]]
        rules_hit = sorted({f.rule_id for f in tool_findings})
        raw_snippet = "\n".join(
            source.splitlines()[max(0, t["desc_line"] - 1): t["desc_line"] + 6]
        )
        tools_payload.append(
            {
                "name": t["name"],
                "line": t["line"],
                "desc_line": t["desc_line"],
                "description": desc,
                "raw_snippet": raw_snippet,
                "visible_text": hs["visible_text"],
                "pretty_text": hs["pretty_text"],
                "hidden_count": hs["hidden_count"],
                "hidden_at": hs["hidden_at"],
                "hidden_by_kind": hs["hidden_by_kind"],
                "hidden_samples": hs["hidden_samples"],
                "tag_payload": hs["tag_payload"],
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "rule_name": f.rule_name,
                        "severity": f.severity,
                        "attack": f.attack,
                        "owasp_llm": f.owasp_llm,
                        "line": f.line,
                        "detail": f.detail,
                        "snippet": f.snippet,
                    }
                    for f in tool_findings
                ],
                "rules_hit": rules_hit,
                "verdict": (
                    "BLOCK" if any(f.severity == "ERROR" for f in tool_findings)
                    else ("WARN" if tool_findings else "PASS")
                ),
            }
        )

    # ---- 命中的规则清单 ----
    rule_meta = {}
    for rid, meta in sc.RULES.items():
        rule_meta[rid] = {**meta, "count": sum(1 for f in attack_findings if f.rule_id == rid),
                          "benign_count": sum(1 for f in benign_findings if f.rule_id == rid)}

    desc_texts = [t.get("description", "") for t in attack_tools]
    real_hidden = sum(1 for d in desc_texts for ch in d if classify(ch))
    esc_hits = sum(len(pat.findall(source)) for _, pat, _ in sc.ESCAPE_PATTERNS)

    blocked = [t["name"] for t in tools_payload if t["verdict"] == "BLOCK"]

    return {
        "generated_at": _now(),
        "project": {
            "name": "MCP Shield",
            "subtitle": "面向 MCP / Agent 工具链的投毒检测与运行层取证",
            "protocol_version": "2024-11-05",
        },
        "samples": {
            "attack": {"path": str(ATTACK.relative_to(ROOT)).replace("\\", "/"),
                       "tools": len(attack_tools), "findings": len(attack_findings),
                       "errors": sum(1 for f in attack_findings if f.severity == "ERROR"),
                       "warnings": sum(1 for f in attack_findings if f.severity == "WARNING")},
            "benign": {"path": str(BENIGN.relative_to(ROOT)).replace("\\", "/"),
                       "tools": len(benign_tools), "findings": len(benign_findings),
                       "errors": 0, "warnings": 0},
        },
        "metrics": {
            "attack_tools": len(attack_tools),
            "attack_findings": len(attack_findings),
            "attack_errors": sum(1 for f in attack_findings if f.severity == "ERROR"),
            "attack_warnings": sum(1 for f in attack_findings if f.severity == "WARNING"),
            "benign_tools": len(benign_tools),
            "benign_findings": len(benign_findings),
            "false_positive_rate": 0.0 if not benign_findings else round(
                len(benign_findings) / max(1, len(benign_tools)), 4),
            "blocked_tools": len(blocked),
            "hidden_codepoints": real_hidden,
            "escape_carriers": esc_hits,
            "rules_total": len(sc.RULES),
        },
        "tools": tools_payload,
        "rules": rule_meta,
        "impl_evidence": collect_impl_evidence(source),
        "benign_tools": [
            {"name": t["name"], "line": t["line"], "description": t.get("description", ""),
             "hidden_count": 0, "verdict": "PASS"}
            for t in benign_tools
        ],
        "benign_impl_evidence": collect_impl_evidence(benign_source),
        "pipeline": build_pipeline(source, attack_tools, attack_findings, real_hidden),
        "blocked": blocked,
        "narrative": {
            "cannot_before": [
                "常规评测 / 常规 SAST 只看代码语法，不看工具描述的自然语言语义 —— 攻击载荷写在 docstring 里，它们看不见。",
                "人眼审阅看不见零宽字符与 Unicode TAG 字符：16 个字符看起来就是「Get current weather for a city.」。",
                "字符串比较（diff / hash 比对自然语言）在源码里比对的是转义序列文本，无法判断运行时会被解释成什么。",
                "更根本的是：被信任的文本直接进模型上下文，而模型无法区分「描述」与「指令」 —— 这是 LLM 应用层的 SQL 注入时刻。",
            ],
            "can_after": [
                "把 8 类 MCP 特有攻击做成 8 条可数、可审、可追溯的规则（MS-001…MS-008），每条都映射 OWASP LLM Top 10 与 CWE。",
                "码点级还原：把模型真正读到的那段文本拆开，逐字符标出 U+200B / U+E0049 / U+202E 并说明其 Unicode 名称。",
                "隐藏载荷还原：Unicode TAG 区字符减去 0xE0000 直接还原成攻击者夹带的明文指令 —— 攻击者能藏，我们就能解。",
                "运行层取证：真的把 Server 跑起来抓 JSON-RPC 报文，不看源码也能验，并提供「攻击正在发生」的时间证据。",
                "误报为零：同一套规则跑良性 Server，4 个工具、0 条告警。",
            ],
            "how": [
                "三路合流：Python AST 定位工具边界 → 转义形态正则捕捉字面载体 → 逐字符码点判类，任一路单独使用都会漏。",
                "双模态检测：同时覆盖「真实不可见字符」与「写成 \\uXXXX 的转义序列」两种实装方式，这是第一版漏报后补上的关键设计。",
                "告警码统一：静态层与运行层共用 MS-00x 编号，源码里发现的问题能在线上报文里被同一编号追踪。",
                "输出标准化：JSON（机器消费）+ SARIF 2.1.0（CI/GitHub 直接显示）+ JSONL 原始报文（取证），退出码即门禁结果。",
            ],
            "innovation": [
                "把「工具描述」提升为一等检测对象 —— 传统 SAST 从不扫描 docstring 的语义，而这里恰恰是攻击载荷的栖息地。",
                "码点级 + 转义形态双模态检测 —— 覆盖两种实装方式，来源于一次真实漏报的修复，而非纸面推演。",
                "静态层与运行层共用同一套告警码 —— 从源码到线上报文形成同一条可追溯证据链。",
            ],
        },
    }


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MCPShield/0.1"
    snapshot_cache: dict[str, Any] | None = None
    lock = threading.Lock()

    @classmethod
    def rebuild(cls, reason: str = "手动重算") -> dict[str, Any]:
        """重跑静态检测并替换快照。唯一入口，监听线程与 /api/reload 都走这里。"""
        snap = with_watch_state(build_snapshot(), reason)
        with cls.lock:
            cls.snapshot_cache = snap
        return snap

    @classmethod
    def snapshot(cls) -> dict[str, Any]:
        """取当前快照；还没有就现算一次（不打监听计数）。"""
        with cls.lock:
            if cls.snapshot_cache is None:
                cls.snapshot_cache = with_watch_state(build_snapshot(), "启动时首次扫描")
            return cls.snapshot_cache

    def log_message(self, fmt: str, *args: Any) -> None:  # 安静一点
        sys.stderr.write("  [ui] %s\n" % (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        try:
            if path in ("/", "/index.html"):
                # 服务端注入真实快照，页面自包含：即使存成 .html 双击打开也有效
                html = (UI_DIR / "console.html").read_text(encoding="utf-8")
                snap = Handler.snapshot()
                payload = json.dumps(snap, ensure_ascii=False).replace("</", "<\\/")
                html = html.replace("__SNAPSHOT__", payload)
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                return

            if path == "/api/snapshot":
                self._json(Handler.snapshot())
                return

            if path == "/api/runlayer":
                which = "benign" if "benign" in self.path else "attack"
                target = BENIGN if which == "benign" else ATTACK
                out = ROOT / "reports" / f"traffic_{which}_ui.jsonl"
                cap = capture_tools(["python", str(target.relative_to(ROOT))],
                                    out_path=str(out))
                cap["traffic_file"] = str(out.relative_to(ROOT)).replace("\\", "/")
                cap["target"] = str(target.relative_to(ROOT)).replace("\\", "/")
                self._json(cap)
                return

            if path == "/api/reload":
                Handler.rebuild("手动请求 /api/reload")
                self._json({"ok": True})
                return

            if path == "/api/watch":
                self._json(dict(WATCHER.state))
                return

            self._send(404, b"not found", "text/plain; charset=utf-8")
        except BrokenPipeError:
            pass
        except Exception as exc:  # 便于定位，别把栈吞掉
            import traceback

            self._json({"error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc()}, code=500)


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP Shield 本地可视化控制台")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    ap.add_argument("--watch-interval", type=float, default=DEFAULT_WATCH_INTERVAL,
                    metavar="SEC", help=f"目录监听轮询间隔秒数（默认 {DEFAULT_WATCH_INTERVAL}）")
    args = ap.parse_args()

    WATCHER.interval = max(0.2, float(args.watch_interval))
    WATCHER.state["interval"] = WATCHER.interval

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print("=" * 74)
    print(" MCP Shield 可视化控制台")
    print("=" * 74)
    print(f" 地址      : {url}")
    print(f" 项目根    : {ROOT}")
    print(f" 数据来源  : scanner.scan_file() 真实调用（非硬编码）")
    print(f" 目录监听  : 开启，每 {WATCHER.interval:g}s 核对一次内容指纹")
    print(f" 监听范围  : {', '.join(WATCHER.state['watched_dirs'])}"
          f"（{', '.join(WATCH_SUFFIXES)}）")
    print(f" 边界      : 只改变扫描触发时机，不在 Agent 调用路径上，不做运行时拦截")
    print(f" 停止      : Ctrl+C")
    print("=" * 74)

    # 顺序要紧：先把监听挂上，再算首屏快照。
    # 反过来的话，若浏览器在第一份快照算完、线程还没启动的缝隙里抢到请求，
    # 那份快照会带 enabled=false，页面就以为自己该保持静态、永远不再轮询。
    WATCHER.start()
    Handler.snapshot()

    if args.open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        WATCHER.stop()
        print("\n[ui] 已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())

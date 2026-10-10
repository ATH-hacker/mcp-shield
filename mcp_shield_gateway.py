#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
mcp_shield_gateway.py —— 零依赖 MCP stdio 网关：站在 `tools/list` 这一跳做在线裁决

为什么会有这个模块
------------------
MCP Shield 默认的三个形态（`scan` 静态扫描 / `probe` 运行层取证 / 可视化控制台）
都**不在 Agent 的调用路径上**：它们产出的是可审计的处置建议。这是一个刻意的定位，
不是能力缺口 —— 但在真实部署里，集成方常常希望再多一种选择：**不要让这个工具
进到模型上下文里**。

本模块提供这第四种形态：一个透明的 stdio 反向代理，夹在 MCP Client 与 MCP Server
之间。它之所以能"真的不让进去"，是因为 MCP 协议本身给了一个天然的关卡 ——
任何 MCP 工具都必须先经过 `initialize → notifications/initialized → tools/list`
才会出现在模型的上下文里。**网关就站在 `tools/list` 这一跳上。**

它做什么
--------
  1. 原样转发 Client ↔ Server 之间的全部 JSON-RPC 报文，不解释、不重写协议
  2. 只拦下 `tools/list` 的**响应**，对每个工具的 `name` / `description`
     跑与 `scanner.py` **完全相同的规则表**：
       MS-001 描述夹带隐瞒/绕过指令      （scanner.DESC_PATTERNS）
       MS-002 零宽/不可见字符            （scanner.CHAR_CHECKS + ESCAPE_PATTERNS）
       MS-003 Unicode TAG 字符走私       （scanner.CHAR_CHECKS + ESCAPE_PATTERNS）
       MS-004 双向文本覆盖字符           （scanner.CHAR_CHECKS + ESCAPE_PATTERNS）
       MS-008 高危工具未声明 annotations （scanner.DANGEROUS_NAME）
  3. 按同一套 BLOCK / WARN / PASS 策略裁决（复用 `scanner.policy_verdicts`），
     把判为 BLOCK 的工具**从响应里移除**，其余原样透传
  4. 双向报文按与 `probe_client.py` 相同的格式落 JSONL，作为不可伪造的取证

命中 MS-003 时，网关还会把 TAG 载荷按 `chr(cp - 0xE0000)` **当场还原成明文**
写进日志 —— 拦下的同时把"它想让你做什么"留在证据里。

它不做什么（诚实边界，必须一起说）
----------------------------------
  * **只覆盖 stdio 传输**。HTTP / SSE 形态的 MCP Server 不在本模块范围内。
  * 只覆盖 **MS-001 / 002 / 003 / 004 / 008** 这五条能在**报文体**上判定的规则。
    MS-005 / 006 / 007 需要看工具的实现体（源码），网关看不到 —— 交给 `scan`。
  * 拦截动作严格定义为「**从 `tools/list` 的结果里移除该工具**」，
    不篡改任何字段内容，不伪造错误，不改变协议语义。
  * 不覆盖 `tools/list` 之后的动态改写：Server 在 `tools/call` 里返回的文本
    不经过本网关的工具准入判定（那属于指纹 ΔS / 后续路线）。
  * 因此，**默认形态（scan / probe / 控制台）"不在调用路径上"这一表述依然成立**；
    网关是额外提供的可选部署形态，不是默认行为。

stdout 是协议通道
-----------------
本模块把 stdout **完整让给 JSON-RPC**，所有人类可读输出一律走 stderr。
这是它能被任何标准 MCP Client 直接使用的前提。

用法
----
  # 作为 Server 直接被 MCP Client 加载（把它当成一个 Server 命令）
  python mcp_shield_gateway.py python samples/attack/venomous_server.py

  # 用 MCP Shield 自己的取证客户端观测它（同一条 probe 命令，多一层网关）
  python mcp_shield.py probe mcp_shield_gateway.py python samples/attack/venomous_server.py

  # 观察模式：只报不拦（先看清楚它抓到了什么，再决定要不要拦）
  python mcp_shield_gateway.py --report-only python samples/attack/venomous_server.py

  # 把 TAG 走私单列为硬拦截项
  python mcp_shield_gateway.py --block-on ERROR,MS-003 python samples/attack/venomous_server.py
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from typing import Any

from version import __version__

# ---------------------------------------------------------------------------
# 网关能覆盖的规则：只包含「报文里就能判定」的那五条。
# 剩下的 MS-005 / MS-006 / MS-007 需要读工具实现体，属于 scan 形态的地盘。
# ---------------------------------------------------------------------------
WIRE_RULES: tuple[str, ...] = ("MS-001", "MS-002", "MS-003", "MS-004", "MS-008")

TAG_LO, TAG_HI = 0xE0000, 0xE007F  # Unicode TAG 区块，MS-003 的判据


def decode_tag_payload(text: str) -> str:
    r"""把 TAG 区码点还原成 ASCII：chr(cp - 0xE0000)。

    与 scanner.py 的可逆还原、控制台的 TAG 解码用的是同一套映射。
    E0020 还原成空格、E0041 还原成 'A'，所以整段走私文本可以直接读出来。
    """
    return "".join(chr(ord(c) - TAG_LO) for c in text
                   if TAG_LO <= ord(c) <= TAG_HI)


def strip_invisibles(text: str) -> str:
    r"""去掉零宽字符与双向控制字符，用于 MS-001 的关键词匹配。

    为什么需要这一步：攻击者把 `Ig<U+200B><U+200B>nore` 插进描述里，
    正则 `ignore` 就匹配不上了 —— 但模型读到的语义仍然是 `Ignore`。
    所以判定"这句话是不是在教模型隐瞒"时，必须先看**去掉不可见字符之后的文本**。
    这是网关相对静态扫描多做的一件小事，也是它必须做的事。
    """
    from scanner import CHAR_CHECKS

    ranges: list[tuple[int, int]] = []
    for rule_id, rs, _label in CHAR_CHECKS:
        if rule_id in ("MS-002", "MS-004"):
            ranges.extend(rs)
    return "".join(c for c in text
                   if not any(lo <= ord(c) <= hi for lo, hi in ranges))


# ---------------------------------------------------------------------------
# 报文体检测：对 tools/list 里的单个工具跑规则表
# ---------------------------------------------------------------------------
def scan_wire_tool(tool: dict[str, Any]) -> list:
    """把一个线上工具定义过一遍规则表，返回 scanner.Finding 列表。

    刻意复用 scanner.py 的规则**数据**（RULES / DESC_PATTERNS / CHAR_CHECKS /
    ESCAPE_PATTERNS / DANGEROUS_NAME），保证"同一套规则、第三个位置"是真的，
    而不是另起一套写法。
    """
    from scanner import (CHAR_CHECKS, DANGEROUS_NAME, DESC_PATTERNS, ESCAPE_PATTERNS,
                         RULES, Finding)

    name = tool.get("name") or ""
    desc = tool.get("description") or ""
    # 线上报文里 name 与 description 都属于"工具描述面"，一起送检
    text = f"{name}\n{desc}" if name else desc
    out: list = []

    def add(rule_id: str, detail: str, codepoints: list | None = None,
            snippet: str = "") -> None:
        meta = RULES[rule_id]
        out.append(Finding(
            rule_id=rule_id,
            rule_name=meta["name"],
            severity=meta["severity"],
            attack=meta["attack"],
            owasp_llm=meta["owasp_llm"],
            file="<tools/list>",
            line=0,
            tool=name,
            detail=detail,
            snippet=(snippet or "").strip()[:160],
            concealed_codepoints=codepoints or [],
        ))

    # -- MS-001：描述文本里的隐瞒 / 绕过指令 --------------------------------
    # 先看原文；原文一条都没命中时，再看"剔除不可见字符之后"的文本。
    # 后者专门抓拆词规避：攻击者把 `Ig<U+200B>nore all rules` 插开写，
    # 正则 `ignore` 就匹配不上，但模型读到的语义仍然是 Ignore。
    def _ms001_hits(probe_text: str, label: str) -> int:
        n = 0
        for pat, why in DESC_PATTERNS:
            for i, m in enumerate(pat.finditer(probe_text)):
                tag = "" if i == 0 else f" (第 {i + 1} 处)"
                add("MS-001", f"{why}{tag}{label}；命中片段: {m.group(0)!r}",
                    snippet=probe_text[max(0, m.start() - 20):m.end() + 40])
                n += 1
        return n

    if _ms001_hits(text, "") == 0:
        norm = strip_invisibles(text)
        if norm != text:
            _ms001_hits(norm, "（已剔除不可见字符后）")

    # -- MS-002 / MS-003 / MS-004：真实不可见码点 --------------------------
    for rule_id, ranges, label in CHAR_CHECKS:
        found = [c for c in text if any(lo <= ord(c) <= hi for lo, hi in ranges)]
        if not found:
            continue
        detail = (f"{label} 共 {len(found)} 个（真实字符），"
                  f"位于线上 tools/list 报文的描述字段内")
        if rule_id == "MS-003":
            payload = decode_tag_payload(text).strip()
            if payload:
                detail += f"；TAG 载荷当场还原: {payload!r}"
        add(rule_id, detail, codepoints=_describe_cp(found), snippet=text)

    # -- MS-002 / MS-003 / MS-004：字面转义载体 ----------------------------
    # 例：描述里写的是 "\u200b" 这六个字符，运行时才被解释成真字符。
    for rule_id, pat, kind in ESCAPE_PATTERNS:
        ms = list(pat.finditer(text))
        if not ms:
            continue
        forms = sorted({m.group(0) for m in ms})
        add(rule_id,
            f"检测到转义形态的不可见字符 {len(ms)} 处（{kind}），"
            f"共 {len(forms)} 种：{', '.join(forms[:6])}",
            codepoints=[{"codepoint": f, "name": kind, "char_repr": "escaped"}
                        for f in forms],
            snippet=text)

    # -- MS-008：高危语义工具名 + 未声明 annotations ------------------------
    if DANGEROUS_NAME.search(name) and not tool.get("annotations"):
        add("MS-008", f"高危语义工具 '{name}' 未通过 annotations 声明安全提示")

    return out


def _describe_cp(chars: list[str]) -> list[dict]:
    """与 scanner._describe_codepoints 同构：码点 / Unicode 名 / repr。"""
    import unicodedata

    out = []
    for ch in chars:
        cp = ord(ch)
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "UNNAMED"
        out.append({"codepoint": f"U+{cp:04X}", "name": name, "char_repr": repr(ch)})
    return out


# ---------------------------------------------------------------------------
# 网关本体
# ---------------------------------------------------------------------------
class MCPGateway:
    r"""双向 stdio 反向代理：只对 `tools/list` 的响应动手，其余原样透传。"""

    def __init__(self, upstream: list[str], *, block_on: tuple[str, ...],
                 warn_on: tuple[str, ...], out_path: str | None,
                 report_only: bool = False, quiet: bool = False,
                 source: str | None = None) -> None:
        self.upstream = upstream
        self.block_on = block_on
        self.warn_on = warn_on
        self.out_path = out_path
        self.report_only = report_only
        self.quiet = quiet
        self.source = source
        # 可选的源码层证据：MS-005/006/007 只能从实现体里看出来，
        # 报文里没有。给了 --source 就把这一层叠上来，按工具名对齐。
        self.static_by_tool: dict[str, list] = {}
        self.static_scanned = 0

        self.proc: subprocess.Popen[str] | None = None
        self.seq = 0
        self.records: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.pending: dict[Any, str] = {}          # 请求 id -> method
        self.stderr_buf: list[str] = []
        self.stats = {"tools_seen": 0, "blocked": 0, "warned": 0, "passed": 0,
                      "tools_list_calls": 0}
        self._stop = threading.Event()

    # -- 人类可读输出：一律走 stderr，绝不碰 stdout -------------------------
    def log(self, msg: str = "") -> None:
        if not self.quiet:
            print(msg, file=sys.stderr, flush=True)

    # -- 取证日志 -----------------------------------------------------------
    def _record(self, direction: str, msg: Any) -> None:
        with self.lock:
            self.seq += 1
            self.records.append({"dir": direction, "seq": self.seq,
                                 "ts": time.time(), "msg": msg})

    def _dump(self) -> None:
        if not self.out_path:
            return
        d = os.path.dirname(os.path.abspath(self.out_path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as f:
            for rec in self.records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- 上游进程 -----------------------------------------------------------
    def _start_upstream(self) -> None:
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen(
            self.upstream,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            creationflags=flags,
        )
        threading.Thread(target=self._drain_upstream_stderr, daemon=True).start()

    def _drain_upstream_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            line = line.rstrip("\n")
            self.stderr_buf.append(line)
            # 上游 Server 的 stderr 透传给 Client 的 stderr（协议外通道）；
            # 加 [server] 前缀，把上游日志与网关自己的裁决表分开，录屏时读得清。
            print(f"[server] {line}", file=sys.stderr, flush=True)

    # -- 协议通道 -----------------------------------------------------------
    @staticmethod
    def _write(stream, payload: Any) -> None:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        stream.flush()

    def _to_upstream(self, payload: Any) -> None:
        assert self.proc and self.proc.stdin
        self._write(self.proc.stdin, payload)

    def _to_client(self, payload: Any) -> None:
        self._write(sys.stdout, payload)

    # -- 可选的源码层证据 ---------------------------------------------------
    def load_source(self) -> None:
        """把 --source 指向的源码扫一遍，按工具名归档 MS-005/006/007 的证据。

        这不是必须的：不给 --source，网关就只看报文（覆盖 5 条规则）；
        给了 --source，就叠上源码层的 3 条规则，覆盖率变成 8 条。
        两种覆盖率都在控制台和证据文件里如实标注，不混为一谈。
        """
        if not self.source:
            return
        import scanner

        errors: list[str] = []
        findings: list = []
        targets = scanner.iter_targets(self.source)
        for p in targets:
            f, _t = scanner.scan_file(p, errors)
            findings.extend(f)
        for f in findings:
            self.static_by_tool.setdefault(f.tool, []).append(f)
        self.static_scanned = len(targets)
        covered = sorted({f.rule_id for f in findings})
        self.log(f" 源码层     : {self.source}（{len(targets)} 个文件，"
                 f"额外覆盖 {' '.join(covered) or '无'}）")

    # -- tools/list 响应处理 ------------------------------------------------
    def _handle_tools_list(self, msg: dict[str, Any]) -> dict[str, Any]:
        """对一个 tools/list 响应做在线裁决；返回（可能被裁剪过的）响应。"""
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg

        tools = result["tools"]
        self.stats["tools_list_calls"] += 1
        self.stats["tools_seen"] += len(tools)

        from scanner import policy_verdicts

        findings: list = []
        synth: list[dict] = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            tname = t.get("name") or ""
            synth.append({"file": "<tools/list>", "name": tname, "line": 0})
            findings.extend(scan_wire_tool(t))
            if self.static_by_tool:
                # 源码层证据：只有给了 --source 才有，按工具名对齐
                findings.extend(self.static_by_tool.get(tname, []))

        verdicts = policy_verdicts(synth, findings, block_on=self.block_on,
                                   warn_on=self.warn_on)
        # policy_verdicts 按 (file, tool) 分桶：源码层证据的 file 是源码路径，
        # 会和报文层分成两条。这里按工具名合并成一条，裁决取更强的那个。
        rank = {"PASS": 0, "WARN": 1, "BLOCK": 2}
        by_tool: dict[str, dict] = {}
        for v in verdicts:
            cur = by_tool.setdefault(v["tool"], {"tool": v["tool"], "verdict": "PASS",
                                                 "rules_hit": [], "from_source": False})
            for r in v["rules_hit"]:
                if r not in cur["rules_hit"]:
                    cur["rules_hit"].append(r)
            if v.get("file") != "<tools/list>":
                cur["from_source"] = True
            if rank.get(v["verdict"], 0) > rank.get(cur["verdict"], 0):
                cur["verdict"] = v["verdict"]
        for cur in by_tool.values():
            cur["rules_hit"].sort()

        kept: list[dict] = []
        removed: list[str] = []
        rows: list[tuple[str, str, list[str], str]] = []
        for t in tools:
            name = t.get("name") if isinstance(t, dict) else None
            v = by_tool.get(name or "") or {"verdict": "PASS", "rules_hit": []}
            verdict = v["verdict"]
            origin = " · 含源码层证据" if v.get("from_source") else ""
            if verdict == "BLOCK":
                self.stats["blocked"] += 1
                if self.report_only:
                    kept.append(t)
                    rows.append((name or "", "BLOCK", v["rules_hit"], "观察模式：保留" + origin))
                else:
                    removed.append(name or "")
                    rows.append((name or "", "BLOCK", v["rules_hit"], "已从响应中移除" + origin))
            elif verdict == "WARN":
                self.stats["warned"] += 1
                kept.append(t)
                rows.append((name or "", "WARN", v["rules_hit"], "保留（附裁决标记）" + origin))
            else:
                self.stats["passed"] += 1
                kept.append(t)
                rows.append((name or "", "PASS", v["rules_hit"], "保留"))

        # 表格输出：工具名 / 裁决 / 命中规则 / 处置
        width = max([len(r[0]) for r in rows] + [8])
        self.log("-" * 78)
        self.log(f" [tools/list] 收到 {len(tools)} 个工具，"
                 f"{'观察模式（不裁剪）' if self.report_only else '拦截模式'}：")
        for name, verdict, rules, action in rows:
            mark = {"BLOCK": "✗✗", "WARN": "!!", "PASS": "  "}[verdict]
            hit = " ".join(rules) if rules else "-"
            self.log(f"  {mark} {verdict:<5} {name:<{width}}  {hit:<22} {action}")
        if removed:
            self.log(f"  >> 本次从响应中移除 {len(removed)} 个工具：{', '.join(removed)}")
            self.log("  >> 效果：这些工具不会出现在模型的上下文里。")
        else:
            self.log("  >> 本次没有工具被移除。")

        # MS-003 的还原载荷单独打一条，作为"拦下它、并说清它想干什么"的证据
        for f in findings:
            if f.rule_id == "MS-003" and "TAG 载荷当场还原" in f.detail:
                self.log(f"  !! TAG 载荷还原（工具 {f.tool}）：{f.detail.split('TAG 载荷当场还原: ', 1)[1]}")

        # 摘要按"工具"口径统计，不用 policy_summary(verdicts) ——
        # verdicts 是按 (file, tool) 分桶的，源码层证据会把同一个工具算两次。
        summary = {"BLOCK": 0, "WARN": 0, "PASS": 0, "total": len(by_tool)}
        for cur in by_tool.values():
            summary[cur["verdict"]] = summary.get(cur["verdict"], 0) + 1
        self.log(f"  >> 累计：{summary}")

        new_result = dict(result)
        new_result["tools"] = kept
        # 把裁决结果挂在响应上：不改变 MCP 语义（未知字段，客户端会忽略），
        # 但让任何抓包工具都能看到"这一跳发生了什么"。
        new_result["_mcpShield"] = {
            "version": __version__,
            "mode": "report-only" if self.report_only else "enforce",
            "block_on": list(self.block_on),
            "warn_on": list(self.warn_on),
            "tools_in": len(tools),
            "tools_out": len(kept),
            "removed": removed,
            "summary": summary,
            "verdicts": list(by_tool.values()),
            "wire_rules": list(WIRE_RULES),
            "source_layer": bool(self.static_by_tool),
        }
        out = dict(msg)
        out["result"] = new_result
        return out

    # -- 主循环 -------------------------------------------------------------
    def run(self) -> int:
        self.log("=" * 78)
        self.log(" MCP Shield · stdio 网关（可选形态：站在 tools/list 这一跳）")
        self.log("=" * 78)
        self.log(f" 上游命令 : {self.upstream}")
        self.log(f" 策略     : BLOCK={list(self.block_on)}  WARN={list(self.warn_on)}")
        self.log(f" 模式     : {'观察（只报不拦）' if self.report_only else '拦截（命中即移出响应）'}")
        self.log(f" 报文落盘 : {self.out_path or '(不落盘)'}")
        self.log(f" 覆盖规则 : {' '.join(WIRE_RULES)}"
                 + ("（报文体可判定的全部 5 条）" if not self.source else ""))
        if not self.source:
            self.log("            MS-005/006/007 需要读工具实现体，网关看不到；"
                     "要么用 scan 形态，要么加 --source")
        self.log("=" * 78)

        self.load_source()
        self._start_upstream()
        self._reader = threading.Thread(target=self._upstream_loop, daemon=True)
        self._reader.start()

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    # 解析不了就原样转发，网关不替 Client 做协议判断
                    assert self.proc and self.proc.stdin
                    self.proc.stdin.write(line + "\n")
                    self.proc.stdin.flush()
                    continue
                self._record("client->server", msg)
                if isinstance(msg, dict) and "id" in msg and "method" in msg:
                    self.pending[msg["id"]] = msg.get("method") or ""
                self._to_upstream(msg)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            self._shutdown()
        return self._exit_code()

    def _exit_code(self) -> int:
        """退出码契约（与 scan 同一条原则：**「连不上」不等于「没风险」**）。

        网关最危险的失败模式不是误拦，而是**静默地什么都没拦**：上游起不来、
        或是 Client 还没拿到 tools/list 就断了，此时若返回一个空/原样的结果并
        以 0 退出，调用方会把「没审过」当成「审过且干净」。所以这里刻意用 2
        表示「网关没能完成这一跳」，与 scan 的「扫不动 = 2」保持同一语义。
        """
        upstream_rc = self.proc.returncode if self.proc else None
        if upstream_rc in (0, None):
            return 0
        if self.stats["tools_list_calls"] > 0:
            # 至少完整做完了一次裁决，客户端拿到过真实数据；上游随后的非零退出
            # 记在 stderr 里就够了，不必污染调用方看到的结论。
            return 0
        return 2

    def _upstream_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self._to_client_raw(line)
                    continue
                self._record("server->client", msg)
                method = None
                if isinstance(msg, dict) and "id" in msg and msg["id"] in self.pending:
                    method = self.pending.pop(msg["id"])
                if method == "tools/list":
                    msg = self._handle_tools_list(msg)
                    self._record("gateway", {"action": "tools/list 裁决",
                                             "result": (msg.get("result") or {})
                                             .get("_mcpShield")})
                self._to_client(msg)
        except (ValueError, OSError):
            pass
        finally:
            self._stop.set()

    def _to_client_raw(self, line: str) -> None:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    def _shutdown(self) -> None:
        # 先把可能还在路上的最后一条响应放完（Client 关闭 stdin 与
        # Server 回完 tools/list 之间存在极小的竞态窗口），再收上游进程。
        reader = getattr(self, "_reader", None)
        if reader is not None:
            reader.join(timeout=1.0)
        if self.proc:
            try:
                if self.proc.stdin:
                    self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._dump()
        self.log("-" * 78)
        self.log(f" 网关退出：工具 {self.stats['tools_seen']} 个 · "
                 f"BLOCK {self.stats['blocked']} · WARN {self.stats['warned']} · "
                 f"PASS {self.stats['passed']} · 报文 {len(self.records)} 条")
        if self.out_path:
            self.log(f" 取证已写入：{self.out_path}")
        rc = self._exit_code()
        if rc != 0:
            upstream_rc = self.proc.returncode if self.proc else None
            self.log(f" [!] 网关没能完成这一跳：上游退出码 {upstream_rc}，"
                     f"且有 {len(self.pending)} 个请求没有拿到响应。")
            self.log("     「连不上」不等于「没有风险」—— 这里不能用空结果冒充干净。")
            self.log("     退出码 2 = 这次没有产生可信结论，调用方不要当成通过。")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mcp_shield_gateway",
        description="MCP Shield stdio 网关：在 tools/list 这一跳做在线裁决",
    )
    ap.add_argument("--version", action="version", version=f"MCP-Shield {__version__}")
    ap.add_argument("--report-only", action="store_true",
                    help="观察模式：只报告裁决结果，不裁剪 tools/list 响应")
    ap.add_argument("--block-on", default=None, metavar="LIST",
                    help="触发 BLOCK 的严重度或规则号，逗号分隔（默认 ERROR）")
    ap.add_argument("--warn-on", default=None, metavar="LIST",
                    help="触发 WARN 的严重度或规则号，逗号分隔（默认 WARNING）")
    ap.add_argument("--out", default="reports/gateway.jsonl",
                    help="双向报文落盘路径（默认 reports/gateway.jsonl，给 none 则不落盘）")
    ap.add_argument("--source", default=None, metavar="PATH",
                    help="可选：上游 Server 的源码路径（文件或目录）。给了就把 "
                         "MS-005/006/007 的源码层证据叠上来，覆盖率从 5 条变 8 条")
    ap.add_argument("--quiet", action="store_true", help="不打控制台裁决表")
    ap.add_argument("server", help="上游 MCP Server 启动命令")
    ap.add_argument("server_arg", nargs="*", help="传给上游 Server 的参数")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    import scanner
    from mcp_shield import _selector  # 复用 CLI 的逗号列表解析，保持两处语义一致

    block_on = _selector(args.block_on, scanner.DEFAULT_BLOCK_ON)
    warn_on = _selector(args.warn_on, scanner.DEFAULT_WARN_ON)

    from probe_client import _pin_interpreter
    upstream = _pin_interpreter([args.server] + (args.server_arg or []))

    out = None if (args.out or "").lower() in ("none", "") else args.out
    gw = MCPGateway(upstream, block_on=block_on, warn_on=warn_on, out_path=out,
                    report_only=args.report_only, quiet=args.quiet,
                    source=args.source)
    return gw.run()


if __name__ == "__main__":
    sys.exit(main())

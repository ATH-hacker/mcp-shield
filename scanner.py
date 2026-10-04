#!/usr/bin/env python3
"""
scanner.py —— MCP Shield 无依赖兜底扫描器

为什么需要它：
  1. 比赛演示环境可能没有网络，无法安装 semgrep
  2. semgrep 的规则语法对 MCP 的 AST 结构支持存在版本差异
  3. 本扫描器可作为"语义层"补充，做 semgrep 做不到的跨行/上下文判断

它与 semgrep 共用同一套告警码(MS-00x)，便于运行时拦截层统一引用。

用法:
  python scanner.py <目标路径> [--json 输出文件.json] [--sarif 输出文件.sarif]
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Iterable

from version import __version__

# ---------------------------------------------------------------------------
# 告警码定义（与 rules/*.yaml 中的 [MS-xxx] 一一对应）
# ---------------------------------------------------------------------------
RULES: dict[str, dict] = {
    "MS-001": {
        "name": "工具描述夹带隐瞒/绕过指令",
        "attack": "tool-poisoning",
        "severity": "ERROR",
        "owasp_llm": "LLM01: Prompt Injection",
    },
    "MS-002": {
        "name": "零宽/不可见字符",
        "attack": "hidden-instruction",
        "severity": "WARNING",
        "owasp_llm": "LLM01: Prompt Injection",
    },
    "MS-003": {
        "name": "Unicode TAG 字符走私",
        "attack": "hidden-instruction",
        "severity": "ERROR",
        "owasp_llm": "LLM01: Prompt Injection",
    },
    "MS-004": {
        "name": "双向文本覆盖字符(Bidi Override)",
        "attack": "hidden-instruction",
        "severity": "ERROR",
        "owasp_llm": "LLM01: Prompt Injection",
    },
    "MS-005": {
        "name": "工具实现触碰敏感凭据路径",
        "attack": "credential-exfiltration",
        "severity": "ERROR",
        "owasp_llm": "LLM02: Sensitive Information Disclosure",
    },
    "MS-006": {
        "name": "工具实现使用危险执行原语",
        "attack": "excessive-agency",
        "severity": "ERROR",
        "owasp_llm": "LLM06: Excessive Agency",
    },
    "MS-007": {
        "name": "硬编码可疑外传端点",
        "attack": "data-exfiltration",
        "severity": "ERROR",
        "owasp_llm": "LLM02: Sensitive Information Disclosure",
    },
    "MS-008": {
        "name": "高危工具未声明 annotations",
        "attack": "excessive-agency",
        "severity": "WARNING",
        "owasp_llm": "LLM06: Excessive Agency",
    },
}

# ---------------------------------------------------------------------------
# 字符级别检测表
# ---------------------------------------------------------------------------
CHAR_CHECKS = [
    ("MS-002", [(0x200B, 0x200F), (0x2060, 0x2060), (0xFEFF, 0xFEFF)], "零宽/不可见字符"),
    ("MS-003", [(0xE0000, 0xE007F)], "Unicode TAG 字符"),
    ("MS-004", [(0x202A, 0x202E), (0x2066, 0x2069)], "双向文本控制字符"),
]

# 转义形态检测：源码里写的是 \u200b / \U000E0049 这种字面转义，而非真实字符。
# 这是最容易被漏掉的一种载体——文件里看不到不可见字符，但运行时会被解释成真实字符。
ESCAPE_PATTERNS = [
    ("MS-002", re.compile(r"\\u(?:200[0-9A-Fa-f]|202[89A-Fa-f]|2060|FEFF)"), "zero-width"),
    ("MS-003", re.compile(r"\\U000E00[0-7][0-9A-Fa-f]"), "unicode-tag"),
    ("MS-004", re.compile(r"\\u(?:202[0-9A-Ea-e]|206[6-9])"), "bidi"),
]


# ---------------------------------------------------------------------------
# 文本级别检测表（工具描述）
# ---------------------------------------------------------------------------
DESC_PATTERNS = [
    (re.compile(r"(?i)(do not tell|don't tell|never tell|without telling|hide this from|"
                r"do not\s+(mention|reveal|inform|disclose)|never\s+(mention|reveal|disclose))"),
     "描述中出现'不要告知用户'类措辞"),
    (re.compile(r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|"
                r"disregard\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)|"
                r"override\s+(the\s+)?(system|safety)\s+(prompt|rules?))"),
     "描述中出现'忽略此前指令'类措辞（直接提示注入）"),
    (re.compile(r"(?i)(before\s+(returning|responding)|as\s+a\s+first\s+step).{0,80}"
                r"(read|send|upload|exfiltrat|post)"),
     "描述中出现'返回前先执行某动作'型隐蔽指令"),
    (re.compile(r"不(要|得)(告诉|告知|提及|透露)用户|对用户隐瞒"),
     "描述中出现中文'隐瞒用户'类措辞"),
]

# ---------------------------------------------------------------------------
# 代码级别检测表（工具实现体）
# ---------------------------------------------------------------------------
IMPL_PATTERNS = [
    (re.compile(r"(?i)(\.ssh\b|id_rsa|id_ed25519|\.aws/credentials|\.kube/config|"
                r"\.npmrc|\.netrc|(?<![\w.])\.env\b|credentials\.json)"),
     "MS-005", "实现体中引用高敏感凭据路径"),
    (re.compile(r"(?i)https?://[^\"'\s]*(collector|ingest|exfil|beacon|pastebin|"
                r"webhook\.site|requestbin|attacker|oastify|interact\.sh)"),
     "MS-007", "实现体中硬编码可疑外传端点"),
    (re.compile(r"(?i)\b(eval|exec)\s*\(|os\.popen\s*\(|os\.system\s*\(|shell\s*=\s*True"),
     "MS-006", "实现体使用危险执行原语"),
]

# 高危工具名（用于 MS-008）
DANGEROUS_NAME = re.compile(
    r"(?i)(delete|drop|remove|exec|shell|run|eval|upload|download|send|write|"
    r"transfer|deploy|install|grant|chmod|sudo)"
)


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    attack: str
    owasp_llm: str
    file: str
    line: int
    tool: str
    detail: str
    snippet: str = ""
    concealed_codepoints: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}:{os.path.basename(self.file)}:{self.line}"


def _describe_codepoints(chars: Iterable[str]) -> list[dict]:
    out = []
    for ch in chars:
        cp = ord(ch)
        try:
            import unicodedata
            name = unicodedata.name(ch)
        except ValueError:
            name = "UNNAMED"
        out.append({"codepoint": f"U+{cp:04X}", "name": name, "char_repr": repr(ch)})
    return out


def _match_char_checks(line: str) -> list[tuple[str, str, list[str]]]:
    hits = []
    for rule_id, ranges, label in CHAR_CHECKS:
        found = [c for c in line if any(lo <= ord(c) <= hi for lo, hi in ranges)]
        if found:
            hits.append((rule_id, label, found))
    return hits


def _narrow(line: str, col: int, width: int = 46) -> str:
    """以列位置 col 为中心截取源码片段，让报告能直接看到命中的指令原文。"""
    s = max(0, col - width // 2)
    e = min(len(line), col + width)
    prefix = "..." if s > 0 else ""
    suffix = "..." if e < len(line) else ""
    return f"{prefix}{line[s:e]}{suffix}".strip()


class MCPServerScanner(ast.NodeVisitor):
    """基于 AST 的扫描：精确关联工具名 -> 描述 -> 实现体。"""

    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.tools: list[dict] = []

    # -- 工具发现 ---------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorator_names = [self._decorator_name(d) for d in node.decorator_list]
        is_tool = any(n and "tool" in n for n in decorator_names)
        if not is_tool:
            self.generic_visit(node)
            return

        doc = ast.get_docstring(node, clean=False) or ""
        desc_line = (node.body[0].lineno if node.body else node.lineno)
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
            desc_line = node.body[0].lineno

        self.tools.append({"name": node.name, "line": node.lineno, "file": self.path,
                           "desc_line": desc_line, "description": doc})

        # MS-001 描述文本检测
        for pat, why in DESC_PATTERNS:
            hits = list(pat.finditer(doc))
            if not hits:
                continue
            for i, m in enumerate(hits):
                ln = desc_line + doc[:m.start()].count("\n")
                raw = self.lines[ln - 1] if ln - 1 < len(self.lines) else ""
                col = max(0, raw.find(m.group(0)))
                tag = "" if i == 0 else f" (第 {i + 1} 处)"
                self._add("MS-001", node.name, ln,
                          f"{why}{tag}；命中片段: {m.group(0)!r}",
                          snippet=_narrow(raw, col))

        # MS-002/003/004 描述中的隐藏字符（含多行 docstring）
        seg_end = (node.body[0].end_lineno or desc_line) if node.body and isinstance(node.body[0], ast.Expr) else desc_line
        for ln in range(desc_line, min(seg_end, len(self.lines)) + 1):
            raw = self.lines[ln - 1]
            # (a) 真实不可见字符
            for rule_id, label, found in _match_char_checks(raw):
                self._add(rule_id, node.name, ln,
                          f"{label} 共 {len(found)} 个（真实字符），位于工具描述内",
                          snippet=raw,
                          codepoints=_describe_codepoints(found))
            # (b) 转义形态 \\uXXXX / \\UXXXXXXXX —— 运行时才还原成不可见字符
            for rule_id, pat, kind in ESCAPE_PATTERNS:
                ms = list(pat.finditer(raw))
                if ms:
                    forms = sorted({m.group(0) for m in ms})
                    self._add(rule_id, node.name, ln,
                              f"检测到转义形态的不可见字符 {len(ms)} 处（{kind}），"
                              f"共 {len(forms)} 种：{', '.join(forms[:6])}",
                              snippet=_narrow(raw, ms[0].start()),
                              codepoints=[{"codepoint": f, "name": kind, "char_repr": "escaped"}
                                          for f in forms])

        # 实现体检测：MS-005 / MS-006 / MS-007
        body_start = (node.body[0].end_lineno or desc_line) if node.body else node.lineno
        body_text = "\n".join(self.lines[body_start:node.end_lineno])
        body_offset = body_start
        for pat, rule_id, why in IMPL_PATTERNS:
            hits = list(pat.finditer(body_text))
            if not hits:
                continue
            first = hits[0]
            ln = body_offset + body_text[:first.start()].count("\n") + 1
            raw_line = self.lines[ln - 1] if ln - 1 < len(self.lines) else ""
            col = first.start() - (body_text.rfind("\n", 0, first.start()) + 1)
            seen = []
            for m in hits:
                if m.group(0) not in seen:
                    seen.append(m.group(0))
            self._add(rule_id, node.name, ln,
                      f"{why}；命中 {len(hits)} 处，片段: {', '.join(repr(s) for s in seen[:4])}",
                      snippet=_narrow(raw_line, col))

        # MS-008 高危名 + 无 annotations 声明
        dec_src = "".join(self.lines[d.lineno - 1] for d in node.decorator_list
                          if d.lineno - 1 < len(self.lines))
        if DANGEROUS_NAME.search(node.name) and "annotations" not in dec_src:
            self._add("MS-008", node.name, node.lineno,
                      f"高危语义工具 '{node.name}' 未通过 annotations 声明安全提示")

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    # -- 工具函数 ---------------------------------------------------------
    @staticmethod
    def _decorator_name(d: ast.AST) -> str:
        if isinstance(d, ast.Call):
            d = d.func
        parts = []
        while isinstance(d, ast.Attribute):
            parts.append(d.attr)
            d = d.value
        if isinstance(d, ast.Name):
            parts.append(d.id)
        return ".".join(reversed(parts))

    def _add(self, rule_id: str, tool: str, line: int, detail: str,
             snippet: str = "", codepoints: list | None = None) -> None:
        meta = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id,
            rule_name=meta["name"],
            severity=meta["severity"],
            attack=meta["attack"],
            owasp_llm=meta["owasp_llm"],
            file=self.path,
            line=line,
            tool=tool,
            detail=detail,
            snippet=(snippet or "").strip()[:160],
            concealed_codepoints=codepoints or [],
        ))


def scan_file(path: str, errors: list[str] | None = None) -> tuple[list[Finding], list[dict]]:
    """扫描单个 Python 文件。

    errors: 可选的收集列表。传入时，任何「扫不了」的原因都会记进去。
    为什么需要它：一个扫不动的文件**绝不能被当成干净文件**——否则攻击者只要
    交一个语法坏掉的文件，CI 就会绿着放过它。调用方据此把退出码区分开。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError) as e:
        msg = f"无法读取 {path}: {e}"
        print(f"[!] {msg}", file=sys.stderr)
        if errors is not None:
            errors.append(msg)
        return [], []
    scanner = MCPServerScanner(path, source)
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        msg = f"语法解析失败 {path}: {e}"
        print(f"[!] {msg}", file=sys.stderr)
        if errors is not None:
            errors.append(msg)
        return [], []
    scanner.visit(tree)
    return scanner.findings, scanner.tools


def iter_targets(root: str) -> list[str]:
    if os.path.isfile(root):
        return [root]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
        for fn in filenames:
            if fn.endswith((".py", ".ts", ".js", ".mjs", ".cjs")):
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


# 策略层默认值：命中 ERROR 级规则 → BLOCK；只命中 WARNING → WARN；都没有 → PASS。
# 可用 mcp_shield.py scan --block-on / --warn-on 覆盖（可给严重度，也可给规则号）。
DEFAULT_BLOCK_ON: tuple[str, ...] = ("ERROR",)
DEFAULT_WARN_ON: tuple[str, ...] = ("WARNING",)


def policy_verdicts(tools: list[dict], findings: list[Finding],
                    block_on: tuple[str, ...] = DEFAULT_BLOCK_ON,
                    warn_on: tuple[str, ...] = DEFAULT_WARN_ON) -> list[dict]:
    """把告警按「工具」聚合成 BLOCK / WARN / PASS 三级裁决。

    **这是静态分析给出的处置建议，不是运行时拦截。** MCP Shield 不在 Agent 的
    调用路径上，它回答的是「这个工具该不该被信任、该以什么级别上报」，由集成方
    决定接到 CI 门禁、MCP 客户端加载前的准入检查，还是 SIEM 工单流。

    block_on / warn_on 里的元素既可以是严重度（ERROR / WARNING），也可以是
    规则号（MS-003），方便使用者把「描述走私 TAG」单列为硬阻断项。

    兜底规则：**只要命中过任何一条规则，最低也是 WARN**。PASS 的含义是
    「这个工具完全没有命中任何规则」，绝不用来表示「我们没看懂」。

    返回按发现顺序排列的列表，每项形如：
      {"tool", "file", "line", "verdict", "rules_hit", "max_severity"}
    """
    seen: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []

    def _entry(file: str, tool: str, line: int) -> dict:
        key = (file, tool)
        if key not in seen:
            seen[key] = {"tool": tool, "file": file, "line": line,
                         "rules_hit": [], "block": False, "warn": False,
                         "max_severity": None}
            order.append(key)
        return seen[key]

    for t in tools:
        _entry(t.get("file") or "", t.get("name") or "", t.get("line") or 0)

    for f in findings:
        e = _entry(f.file, f.tool, f.line)
        if f.rule_id not in e["rules_hit"]:
            e["rules_hit"].append(f.rule_id)
        if f.severity == "ERROR":
            e["max_severity"] = "ERROR"
        elif e["max_severity"] is None:
            e["max_severity"] = "WARNING"
        hit = f.severity in block_on or f.rule_id in block_on
        if hit:
            e["block"] = True
        elif f.severity in warn_on or f.rule_id in warn_on:
            e["warn"] = True

    out: list[dict] = []
    for key in order:
        e = seen[key]
        blocked = e.pop("block")
        warned = e.pop("warn")
        # 底线：只要命中过任何规则，最低也是 WARN。
        # 这样即便使用者用 --block-on 只挑某几条硬阻断，其余有告警的工具也不会
        # 显示成 PASS —— 一个「有 6 条 ERROR 却写着 PASS」的工具是危险的误导。
        if blocked:
            verdict = "BLOCK"
        elif warned or e["rules_hit"]:
            verdict = "WARN"
        else:
            verdict = "PASS"
        out.append({"tool": e["tool"], "file": e["file"], "line": e["line"],
                    "verdict": verdict, "rules_hit": sorted(e["rules_hit"]),
                    "max_severity": e["max_severity"]})
    return out


def policy_summary(verdicts: list[dict]) -> dict:
    """三级裁决的计数汇总。"""
    out = {"BLOCK": 0, "WARN": 0, "PASS": 0, "total": len(verdicts)}
    for v in verdicts:
        if v["verdict"] in out:
            out[v["verdict"]] += 1
    return out


def render_console(findings: list[Finding], tools: list[dict], scanned: int,
                   failed: int = 0, verdicts: list[dict] | None = None) -> None:
    icons = {"ERROR": "\033[91mERROR\033[0m", "WARNING": "\033[93mWARN \033[0m"}
    print("=" * 78)
    print(" MCP Shield · 静态扫描报告 (无依赖兜底扫描器)")
    print("=" * 78)
    print(f" 扫描文件: {scanned}    发现工具: {len(tools)}    告警总数: {len(findings)}")
    if failed:
        print(f"\033[91m 解析失败: {failed} 个文件 —— 这些文件的内容【未被检查】，不计入以上结论\033[0m")
    if findings:
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        print(" 告警分布: " + "  ".join(f"{k}×{v}" for k, v in sorted(by_rule.items())))
    print("-" * 78)
    current = None
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.rule_id)):
        if f.file != current:
            current = f.file
            file_findings = [x for x in findings if x.file == current]
            hit_rules = sorted({x.rule_id for x in file_findings})
            print(f"\n\033[96m{current}\033[0m")
            print(f"  命中规则: {', '.join(hit_rules)}  （共 {len(file_findings)} 条告警）")
        print(f"\n  {f.line:>4} │ {icons.get(f.severity, f.severity)} "
              f"[{f.rule_id}] {f.rule_name}")
        print(f"       │ tool={f.tool}  attack={f.attack}  {f.owasp_llm}")
        print(f"       │ {f.detail}")
        if f.snippet:
            print(f"       │ 源码: {f.snippet}")
        for cp in f.concealed_codepoints[:6]:
            print(f"       │   隐藏字符 {cp['codepoint']} ({cp['name']}) {cp['char_repr']}")
        if len(f.concealed_codepoints) > 6:
            print(f"       │   ... 另有 {len(f.concealed_codepoints) - 6} 个隐藏字符")
    if verdicts:
        by = policy_summary(verdicts)
        print("\n" + "-" * 78)
        print(" 策略裁决（静态分析给出的处置建议，非运行时拦截）")
        print(f"   BLOCK {by['BLOCK']}    WARN {by['WARN']}    PASS {by['PASS']}    共 {by['total']} 个工具")
        for v in verdicts:
            mark = {"BLOCK": "\033[91mBLOCK\033[0m", "WARN": "\033[93mWARN \033[0m",
                    "PASS": "\033[92mPASS \033[0m"}[v["verdict"]]
            rules = ",".join(v["rules_hit"]) if v["rules_hit"] else "-"
            print(f"   {mark}  {v['tool']:<18} {rules}")
    print("\n" + "=" * 78)


def render_sarif(findings: list[Finding], target: str,
                 verdicts: list[dict] | None = None) -> dict:
    vmap = {(v["file"], v["tool"]): v["verdict"] for v in (verdicts or [])}
    rules_def = []
    seen = set()
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rules_def.append({
            "id": f.rule_id,
            "name": f.rule_name,
            "shortDescription": {"text": f.rule_name},
            "defaultConfiguration": {"level": "error" if f.severity == "ERROR" else "warning"},
            "properties": {"attack": f.attack, "owasp-llm": f.owasp_llm, "tags": ["mcp", "agent-security"]},
        })
    results = [{
        "ruleId": f.rule_id,
        "level": "error" if f.severity == "ERROR" else "warning",
        "message": {"text": f"[{f.rule_id}] {f.rule_name} | tool={f.tool} | {f.detail}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file.replace("\\", "/")},
                "region": {"startLine": f.line},
            }
        }],
        "partialFingerprints": {"mcpShield/v1": f.fingerprint},
        "properties": {"mcpShieldVerdict": vmap.get((f.file, f.tool), "PASS")},
    } for f in findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "MCP-Shield",
                "informationUri": "https://github.com/ATH-hacker/mcp-shield",
                "version": __version__,
                "rules": rules_def,
            }},
            "artifacts": [{"location": {"uri": target.replace("\\", "/")}}],
            "results": results,
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP Shield 静态扫描器")
    ap.add_argument("target", help="待扫描文件或目录")
    ap.add_argument("--json", dest="json_out", help="输出 JSON 报告")
    ap.add_argument("--sarif", dest="sarif_out", help="输出 SARIF 报告")
    ap.add_argument("--quiet", action="store_true", help="仅输出 JSON/SARIF，不打印控制台报告")
    ap.add_argument("--block-on", default=None, metavar="LIST",
                    help="触发 BLOCK 的严重度或规则号，逗号分隔（默认 ERROR）")
    ap.add_argument("--warn-on", default=None, metavar="LIST",
                    help="触发 WARN 的严重度或规则号，逗号分隔（默认 WARNING）")
    ap.add_argument("--version", action="version", version=f"MCP-Shield {__version__}")
    args = ap.parse_args()

    targets = iter_targets(args.target)
    if not targets:
        print(f"[!] 目标下没有可扫描的文件: {args.target}", file=sys.stderr)
        return 2
    all_findings: list[Finding] = []
    all_tools: list[dict] = []
    errors: list[str] = []
    for t in targets:
        fs, ts = scan_file(t, errors)
        all_findings.extend(fs)
        all_tools.extend(ts)

    def _sel(raw, default):
        if not raw:
            return default
        parts = tuple(p.strip() for p in raw.split(",") if p.strip())
        return parts or default

    block_on = _sel(args.block_on, DEFAULT_BLOCK_ON)
    warn_on = _sel(args.warn_on, DEFAULT_WARN_ON)
    verdicts = policy_verdicts(all_tools, all_findings, block_on=block_on, warn_on=warn_on)

    if not args.quiet:
        render_console(all_findings, all_tools, len(targets), failed=len(errors),
                       verdicts=verdicts)
        if errors:
            print("\n 以下文件未能解析，其内容未被检查：")
            for e in errors:
                print(f"   ! {e}")

    if args.json_out:
        payload = {
            "scanner": "MCP-Shield",
            "version": __version__,
            "target": args.target,
            "files_scanned": len(targets),
            "tools_discovered": all_tools,
            "summary": {
                "total": len(all_findings),
                "by_rule": {r: sum(1 for f in all_findings if f.rule_id == r)
                            for r in sorted({f.rule_id for f in all_findings})},
                "by_severity": {s: sum(1 for f in all_findings if f.severity == s)
                                for s in ("ERROR", "WARNING")},
            },
            "policy": {
                "block_on": list(block_on),
                "warn_on": list(warn_on),
                "summary": policy_summary(verdicts),
                "verdicts": verdicts,
            },
            "findings": [asdict(f) for f in all_findings],
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        if not args.quiet:
            print(f"[+] JSON 报告已写入: {args.json_out}")

    if args.sarif_out:
        with open(args.sarif_out, "w", encoding="utf-8") as f:
            json.dump(render_sarif(all_findings, args.target, verdicts=verdicts),
                      f, ensure_ascii=False, indent=2)
        if not args.quiet:
            print(f"[+] SARIF 报告已写入: {args.sarif_out}")

    # 退出码契约（README 与 tests 都依赖它）：
    #   0 = 扫描完成，无 ERROR 级告警
    #   1 = 扫描完成，存在 ERROR 级告警
    #   2 = 扫描未能完成（文件读不了 / 解析不了）—— 绝不能被当成「干净」
    if errors:
        return 2
    return 1 if any(f.severity == "ERROR" for f in all_findings) else 0


if __name__ == "__main__":
    sys.exit(main())

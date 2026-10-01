#!/usr/bin/env python3
r"""
tsjs_scanner.py —— MCP Shield 的 TypeScript / JavaScript 静态扫描器

为什么单独写一层：
  scanner.py 用 Python 的 ast 模块做精确的「工具名 → 描述 → 实现体」关联。
  现实中的 MCP Server 有相当一部分是 TypeScript/JavaScript 写的，而 Python
  标准库里没有 TS/JS 解析器。本模块用**状态机 + 正则**在源码文本层完成同一件事，
  同样零第三方依赖。

与 Python 侧的对应关系（告警码统一，便于两套实现共用规则语义）：
  MS-001 ← MS-101 描述夹带隐瞒/绕过指令     MS-005 ← MS-105 敏感凭据路径
  MS-002 ← MS-102 零宽/不可见字符           MS-006 ← MS-106 危险执行原语
  MS-003 ← MS-103 Unicode TAG 走私          MS-007 ← MS-107 硬编码外传端点
  MS-004 ← MS-104 Bidi 覆盖字符             MS-008 ← MS-108 高危工具未声明 annotations

覆盖三种主流注册形态（与 rules/mcp-typescript.yaml 一致）：
  ① server.registerTool("name", { description: "...", inputSchema }, handler)
  ② server.tool("name", "description", schema, handler)
  ③ server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools:
       [{ name: "name", description: "...", inputSchema: {...} }] }))

已知边界（诚实声明，写进 README）：
  - 非工具函数体内的字符串不参与「实现体」判定；
  - 模板字符串中的表达式 ${...} 不做求值；
  - 本层是文本层近似，不是完整的 TS/JS 语法分析；需要更强分析时请配合 semgrep。

用法：
  python tsjs_scanner.py <文件或目录> [--json 报告.json] [--sarif 报告.sarif]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from scanner import (  # 复用同一套告警码、Finding 结构与渲染器，保证两套实现口径一致
    CHAR_CHECKS,
    DANGEROUS_NAME,
    DESC_PATTERNS,
    IMPL_PATTERNS,
    RULES,
    Finding,
    _describe_codepoints,
    _match_char_checks,
    _narrow,
    iter_targets,
    render_console,
    render_sarif,
)
from version import __version__

TS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

# 转义形态检测（与 scanner.py 的 ESCAPE_PATTERNS 同源，这里补上 \xNN 形态）
ESCAPE_PATTERNS = [
    (re.compile(r"\\u(?:200[0-9A-Fa-f]|202[89A-Fa-f]|2060|FEFF)", re.I), "MS-002", "zero-width"),
    (re.compile(r"\\x(?:0?0?0?[bBcCdD]|0?0?0?[eEfF])", re.I), "MS-002", "zero-width"),
    (re.compile(r"\\u\{E00[0-7][0-9A-Fa-f]\}", re.I), "MS-003", "unicode-tag"),
    (re.compile(r"\\U000E00[0-7][0-9A-Fa-f]"), "MS-003", "unicode-tag"),
    (re.compile(r"\\u(?:202[0-9A-Ea-e]|206[6-9])", re.I), "MS-004", "bidi"),
]

# ---------------------------------------------------------------------------
# 工具注册形态识别
# ---------------------------------------------------------------------------
RE_REGISTER_CALL = re.compile(r"\.(?:registerTool|tool|addTool)\s*\(")
# 注意：不能写成 ["']?name["']?\s*: —— 那样只能匹配 "name": 或 name:，而常见的
# 写法是裸键 name:，可选引号组后面直接跟冒号会让整个正则失配（首版真实踩坑）。
RE_TOOL_NAME_KEYS = re.compile(r"""["']?name["']?\s*:\s*["'`]([^"'`]+)["'`]""")
RE_JSON_TOOL_OBJ = re.compile(r"""["']?(?:inputSchema|schema)["']?\s*:\s*\{""")
RE_STR = re.compile(r"""["'`]""")

# 位置形态：{ name: "...", description: "..." }
RE_DESC_AFTER_NAME = re.compile(
    r"""name\s*:\s*["'`][^"'`]+["'`]\s*,\s*description\s*:\s*(["'`])""", re.S)
# 位置形态：registerTool("name", {...}) / server.tool("name", "desc", ...)
# 只负责取第一个位置参数（工具名）；描述单独定位，因为第二个参数可能是对象
# （{ description: ... }）也可能是字符串（经典 server.tool 形态）。
RE_POSITIONAL_NAME = re.compile(r"""\s*(["'`])([^"'`]+)\1""")
# 对象里的 description 键
RE_DESC_KEY = re.compile(r"""description\s*:\s*(["'`])""")
# 经典形态的第二个位置参数（描述）
RE_SECOND_ARG = re.compile(r"""\s*(["'`])[^"'`]*\1\s*,\s*(["'`])""")


def _read_balanced(text: str, start: int, quote: str,
                   single_line: bool = False) -> tuple[str, int, int]:
    """从 text[start]（引号字符）起读取到配对的收尾引号。

    返回 (内容, 内容起始下标, 收尾引号下标)。处理反斜杠转义，并跳过 \\uXXXX
    这类字面转义序列（它们要留到运行层才还原，本层按字面保留以便识别）。

    single_line=True 时遇到裸换行即停止：`"` 与 `'` 字符串本来不允许跨行，
    这种写法一旦出现就说明源码有语法错误（例如样本里被编辑器折行破坏的
    多行字符串），此时若继续向后吞会一路吃到文件末尾，必须止损。
    未闭合时返回到行尾/文末的截断结果。
    """
    i = start + 1
    n = len(text)
    out: list[str] = []
    while i < n:
        ch = text[i]
        if single_line and ch == "\n" and quote != "`":
            break
        if ch == "\\":
            # 原样保留转义序列（含 \u200b / \U000E0049 / \xE0049）
            out.append(ch)
            if i + 1 < n:
                out.append(text[i + 1])
            i += 2
            continue
        if ch == quote:
            return "".join(out), start + 1, i
        out.append(ch)
        i += 1
    return "".join(out), start + 1, i


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _line_text(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    if end == -1:
        end = len(text)
    return text[start:end]


def _brace_end(text: str, open_idx: int, limit: int = 40000) -> int:
    """从 '{' / '(' / '[' 位置出发，返回与之配对的下标（跳过字符串字面量）。

    必须用**栈**而不是计数器：MCP 的工具注册调用里同时出现 `(`、`{`、`[`，
    只统计深度而不区分括号种类，会在 `}` `]` 上漏减、在 `)` 上多减，
    深度永远回不到 0 —— 这正是首版把整份文件当成一次调用的原因。
    """
    pairs = {"{": "}", "(": ")", "[": "]"}
    closers = set(pairs.values())
    if text[open_idx] not in pairs:
        return open_idx
    stack: list[str] = []
    i = open_idx
    n = min(len(text), open_idx + limit)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            _, _, endq = _read_balanced(text, i, ch, single_line=True)
            i = endq + 1
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in closers:
            if stack and ch == stack[-1]:
                stack.pop()
                if not stack:
                    return i
        i += 1
    return n


class TSJSScanner:
    """文本层状态机：定位工具注册点，再在其描述/实现体范围内做规则匹配。"""

    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.tools: list[dict] = []

    # -- 工具发现 ---------------------------------------------------------
    def _register(self, name: str, name_idx: int, desc: str, desc_idx: int,
                  body: str, body_idx: int, obj_src: str = "") -> None:
        """登记一个工具：定位行号、扫描述、扫实现体。

        body_idx 是 body 在源文件中的起始下标，实现体行号由它换算得出，
        避免调用方各自传递行号导致口径不一致。
        obj_src 是该工具的完整注册对象文本，用于 MS-008 判断 annotations
        是否声明 —— 只看 description 字符串会把「描述里没提 annotations」
        误判成「整个工具没声明 annotations」。
        """
        desc_line = _line_of(self.source, desc_idx)
        self.tools.append({"name": name, "line": _line_of(self.source, name_idx),
                           "desc_line": desc_line, "description": desc})
        self._scan_description(name, desc, desc_line, obj_src or desc)
        self._scan_impl(name, body, _line_of(self.source, body_idx))

    def _scan_description(self, tool: str, desc: str, desc_line: int,
                          obj_src: str = "") -> None:
        # MS-001 语义词
        for pat, why in DESC_PATTERNS:
            hits = list(pat.finditer(desc))
            for i, m in enumerate(hits):
                ln = desc_line + desc.count("\n", 0, m.start())
                tag = "" if i == 0 else f" (第 {i + 1} 处)"
                self._add("MS-001", tool, ln,
                          f"{why}{tag}；命中片段: {m.group(0)!r}",
                          snippet=_narrow(desc[max(0, m.start() - 20):m.end() + 20], 0))
        # MS-002/003/004 不可见字符（真实码点 + 转义载体）
        start_line = desc_line
        for off, seg in enumerate(desc.split("\n")):
            ln = start_line + off
            for rule_id, label, found in _match_char_checks(seg):
                self._add(rule_id, tool, ln,
                          f"{label} 共 {len(found)} 个（真实字符），位于工具描述内",
                          snippet=seg[:160], codepoints=_describe_codepoints(found))
            for pat, rule_id, kind in ESCAPE_PATTERNS:
                ms = list(pat.finditer(seg))
                if ms:
                    forms = sorted({m.group(0) for m in ms})
                    self._add(rule_id, tool, ln,
                              f"检测到转义形态的不可见字符 {len(ms)} 处（{kind}），"
                              f"共 {len(forms)} 种：{', '.join(forms[:6])}",
                              snippet=_narrow(seg, ms[0].start()),
                              codepoints=[{"codepoint": f, "name": kind, "char_repr": "escaped"}
                                          for f in forms])
        # MS-008 高危工具名 + 未声明 annotations
        # 判断范围必须是**整个注册对象**（obj_src），而不是 description 字符串：
        # 否则 `{description: "delete a file", annotations: {destructiveHint: true}}`
        # 这种已声明的工具会被误报。仅当对象里确实找不到 annotations 才告警。
        if DANGEROUS_NAME.search(tool) and "annotations" not in (obj_src or desc):
            ln = desc_line if desc else _line_of(self.source, 0)
            self._add("MS-008", tool, ln,
                      f"高危语义工具 '{tool}' 未通过 annotations 声明安全提示")

    def _scan_impl(self, tool: str, body: str, body_line: int) -> None:
        for pat, rule_id, why in IMPL_PATTERNS:
            hits = list(pat.finditer(body))
            if not hits:
                continue
            first = hits[0]
            ln = body_line + body.count("\n", 0, first.start())
            seen: list[str] = []
            for m in hits:
                if m.group(0) not in seen:
                    seen.append(m.group(0))
            self._add(rule_id, tool, ln,
                      f"{why}；命中 {len(hits)} 处，片段: {', '.join(repr(s) for s in seen[:4])}",
                      snippet=_narrow(_line_text(body, first.start()), 0))

    # -- 注册点扫描 -------------------------------------------------------
    def run(self) -> None:
        src = self.source
        # 形态 ③：setRequestHandler(ListTools...) 里的 { name: "...", description: "..." }
        for m in RE_DESC_AFTER_NAME.finditer(src):
            name_m = RE_TOOL_NAME_KEYS.search(src, max(0, m.start() - 120), m.end())
            name = name_m.group(1) if name_m else "?"
            q = m.group(1)
            desc, dstart, _ = _read_balanced(src, m.end(1) - 1, q, single_line=True)
            obj_open = src.rfind("{", 0, m.start())
            obj_close = _brace_end(src, obj_open) if obj_open != -1 else m.end()
            # 实现体取该工具对象闭合之后的一段（handler 通常紧跟其后）
            body_start = obj_close
            obj_src = src[obj_open:obj_close + 1] if obj_open != -1 else src[m.start():m.end()]
            self._register(name, name_m.start(1) if name_m else m.start(),
                           desc, dstart, src[body_start:body_start + 2000], body_start,
                           obj_src)

        # 形态 ①/②：.registerTool(...) / .tool(...)
        for m in RE_REGISTER_CALL.finditer(src):
            open_idx = m.end() - 1                     # 指向 '('
            close_idx = _brace_end(src, open_idx)
            if close_idx <= open_idx:
                continue
            # 工具名 = 第一个位置参数（紧跟在 '(' 之后）
            pos = RE_POSITIONAL_NAME.match(src, open_idx + 1)
            if not pos:
                continue
            name = pos.group(2)
            name_idx = pos.start(2)
            # 描述优先取对象里的 description: 键，否则取第二个位置参数
            dk = RE_DESC_KEY.search(src, open_idx, close_idx)
            if dk:
                desc_off, desc_q = dk.end(1) - 1, dk.group(1)
            else:
                second = RE_SECOND_ARG.search(src, open_idx, close_idx)
                if not second:
                    continue
                desc_off, desc_q = second.end(2) - 1, second.group(2)
            desc, dstart, _ = _read_balanced(src, desc_off, desc_q, single_line=True)
            # 整个注册调用文本作为 obj_src，供 MS-008 判断 annotations 是否声明
            self._register(name, name_idx, desc, dstart,
                           src[open_idx:close_idx + 1], open_idx,
                           src[open_idx:close_idx + 1])

    # -- 告警构造 ---------------------------------------------------------
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


def is_tsjs(path: str) -> bool:
    return path.lower().endswith(TS_EXT)


def scan_tsjs_file(path: str, errors: list[str] | None = None) -> tuple[list[Finding], list[dict]]:
    """扫描单个 TS/JS 文件。

    errors 传入时，读不了的文件会被记进去——「扫不动」不等于「干净」。
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError as e:
        msg = f"无法读取 {path}: {e}"
        print(f"[!] {msg}", file=sys.stderr)
        if errors is not None:
            errors.append(msg)
        return [], []
    sc = TSJSScanner(path, source)
    sc.run()
    return sc.findings, sc.tools


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP Shield TypeScript/JavaScript 扫描器")
    ap.add_argument("target", help="待扫描文件或目录")
    ap.add_argument("--json", dest="json_out", help="输出 JSON 报告")
    ap.add_argument("--sarif", dest="sarif_out", help="输出 SARIF 报告")
    ap.add_argument("--quiet", action="store_true", help="仅输出 JSON/SARIF，不打印控制台报告")
    ap.add_argument("--version", action="version", version=f"MCP-Shield {__version__}")
    args = ap.parse_args()

    targets = [t for t in iter_targets(args.target) if is_tsjs(t)]
    if not targets:
        print(f"[!] 目标下没有 TS/JS 文件: {args.target}", file=sys.stderr)
        return 2
    findings: list[Finding] = []
    tools: list[dict] = []
    errors: list[str] = []
    for t in targets:
        f, tl = scan_tsjs_file(t, errors)
        findings.extend(f)
        tools.extend(tl)

    if not args.quiet:
        render_console(findings, tools, len(targets), failed=len(errors))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({
                "scanner": "MCP-Shield/tsjs",
                "target": args.target,
                "files_scanned": len(targets),
                "tools_discovered": tools,
                "summary": {"total": len(findings),
                            "by_severity": {s: sum(1 for x in findings if x.severity == s)
                                            for s in ("ERROR", "WARNING")}},
                "findings": [x.__dict__ for x in findings],
            }, f, ensure_ascii=False, indent=2)
    if args.sarif_out:
        with open(args.sarif_out, "w", encoding="utf-8") as f:
            json.dump(render_sarif(findings, args.target), f, ensure_ascii=False, indent=2)
    return 1 if any(x.severity == "ERROR" for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())

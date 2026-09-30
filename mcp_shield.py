#!/usr/bin/env python3
r"""
mcp_shield.py —— MCP Shield 统一入口。

把三件事收敛到一条命令，避免使用者记三个脚本名：

  scan    静态扫描（Python 用 AST，TS/JS 用文本层状态机）
  probe   运行层取证：真的把 Server 跑起来，抓 tools/list 报文并逐码点解剖
  config  打印内建规则清单（8 条告警码 + 映射关系）

设计取舍：默认**不合并** scan 与 probe 的结果。两条证据链各自独立输出，
交叉验证才有意义；把运行层结论直接并进静态告警会污染"独立证据"这一定位
（详见 README「创新点 ③」）。

用法示例：
  python mcp_shield.py scan samples/attack/venomous_server.py
  python mcp_shield.py scan . --json reports/scan.json --sarif reports/scan.sarif
  python mcp_shield.py probe samples/attack/venomous_server.py
  python mcp_shield.py config
"""
from __future__ import annotations

import argparse
import json
import sys

from version import __version__


def _cmd_scan(args) -> int:
    """静态扫描：按扩展名分派到 Python 或 TS/JS 扫描器，汇总后统一输出。"""
    import scanner
    import tsjs_scanner

    from scanner import Finding, RULES, iter_targets, render_console, render_sarif

    targets = iter_targets(args.target)
    if args.lang == "python":
        targets = [t for t in targets if t.endswith(".py")]
    elif args.lang in ("ts", "js"):
        targets = [t for t in targets if tsjs_scanner.is_tsjs(t)]

    findings: list[Finding] = []
    tools: list[dict] = []
    for t in targets:
        if tsjs_scanner.is_tsjs(t):
            f, tl = tsjs_scanner.scan_tsjs_file(t)
        else:
            f, tl = scanner.scan_file(t)
        findings.extend(f)
        tools.extend(tl)

    if not args.quiet:
        render_console(findings, tools, len(targets))
        by_engine = {"python-ast": 0, "tsjs-text": 0}
        for t in targets:
            by_engine["tsjs-text" if tsjs_scanner.is_tsjs(t) else "python-ast"] += 1
        print(f" 扫描引擎分布: " + "  ".join(f"{k}×{v} 文件" for k, v in by_engine.items() if v))

    if args.json:
        payload = {
            "scanner": "MCP-Shield",
            "version": __version__,
            "target": args.target,
            "files_scanned": len(targets),
            "tools_discovered": tools,
            "summary": {
                "total": len(findings),
                "by_rule": {r: sum(1 for f in findings if f.rule_id == r)
                            for r in sorted({f.rule_id for f in findings})},
                "by_severity": {s: sum(1 for f in findings if f.severity == s)
                                for s in ("ERROR", "WARNING")},
            },
            "findings": [f.__dict__ for f in findings],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        if not args.quiet:
            print(f"[+] JSON 报告已写入: {args.json}")

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(render_sarif(findings, args.target), fh, ensure_ascii=False, indent=2)
        if not args.quiet:
            print(f"[+] SARIF 报告已写入: {args.sarif}")

    return 1 if any(f.severity == "ERROR" for f in findings) else 0


def _cmd_probe(args) -> int:
    """运行层取证：拉起 Server 进程，抓 tools/list 并逐码点解剖。"""
    import probe_client

    argv = [args.server] + (args.server_arg or [])
    return probe_client.run_forensics(argv, args.out) if args.out else _probe_stdout(argv)


def _probe_stdout(argv: list[str]) -> int:
    """不带 --out 时不写文件，直接把取证摘要打到屏幕。"""
    import probe_client

    snap = probe_client.capture_tools(argv)
    if not snap.get("ok"):
        print(f"[!] 取证失败: {snap.get('error')}", file=sys.stderr)
        return 2
    info = snap.get("server_info") or {}
    print("=" * 78)
    print(" MCP Shield · 运行层取证（不看源码，只看线上 JSON-RPC 报文）")
    print("=" * 78)
    print(f" serverInfo : {info}")
    print(f" 协议版本   : {snap.get('protocol_version')}")
    print(f" 工具总数   : {len(snap.get('tools') or [])}")
    print(f" 携带不可见字符的工具: {len(snap.get('poisoned_tools') or [])}")
    for t in snap.get("poisoned_tools") or []:
        kinds = ", ".join(f"{k}×{v}" for k, v in (t.get("by_kind") or {}).items())
        print(f"   - {t.get('name'):<18} {t.get('suspicious_total')} 处  {kinds}")
    print("=" * 78)
    return 0


def _cmd_config(args) -> int:
    """打印内建规则表，方便现场说明「我们到底检查什么」。"""
    from scanner import RULES

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(RULES, fh, ensure_ascii=False, indent=2)
        print(f"[+] 规则清单已写入: {args.json}")
        return 0
    print(f"MCP Shield {__version__} · 内建规则 {len(RULES)} 条")
    print("-" * 78)
    for rid, meta in RULES.items():
        print(f" {rid}  {meta['severity']:<7} {meta['name']}")
        print(f"        attack={meta['attack']}  owasp={meta['owasp_llm']}")
    print("-" * 78)
    print(" 规则语义与 rules/mcp-python.yaml、rules/mcp-typescript.yaml 一一对应。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="mcp_shield",
        description="MCP Shield · 面向 MCP / Agent 工具链的投毒检测与运行时防护网关",
    )
    ap.add_argument("--version", action="version", version=f"MCP-Shield {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="静态扫描（Python AST + TS/JS 文本层）")
    p_scan.add_argument("target", help="待扫描文件或目录")
    p_scan.add_argument("--json", help="输出 JSON 报告路径")
    p_scan.add_argument("--sarif", help="输出 SARIF 报告路径")
    p_scan.add_argument("--lang", choices=["auto", "python", "ts", "js"], default="auto",
                        help="只扫指定语言（默认 auto：按扩展名分派）")
    p_scan.add_argument("--quiet", action="store_true", help="不打印控制台报告")
    p_scan.set_defaults(func=_cmd_scan)

    p_probe = sub.add_parser("probe", help="运行层取证（跑起 Server 抓 tools/list）")
    p_probe.add_argument("server", help="Server 启动命令（如 samples/attack/venomous_server.py）")
    p_probe.add_argument("server_arg", nargs="*", help="传给 Server 的参数")
    p_probe.add_argument("--out", help="报文落盘路径（.jsonl）")
    p_probe.set_defaults(func=_cmd_probe)

    p_conf = sub.add_parser("config", help="打印内建规则清单")
    p_conf.add_argument("--json", help="把规则清单写入 JSON 文件")
    p_conf.set_defaults(func=_cmd_config)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

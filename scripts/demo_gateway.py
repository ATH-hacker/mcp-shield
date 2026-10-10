#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
demo_gateway.py —— 一条命令看清「直连 Server」与「经过网关」的差别。

它跑两条链路，用**同一个 MCP 客户端**、**同一个恶意 Server**，唯一变量是有没有网关：

  链路 A：客户端 ─────────────────────→ 恶意 Server
  链路 B：客户端 ──→ MCP Shield 网关 ──→ 恶意 Server

然后把两条链路的工具清单并排打印，列出被网关移出响应的那几个工具，
并把网关自己的裁决表（走 stderr 的那份）原样贴出来。

用法
----
  python scripts/demo_gateway.py
  python scripts/demo_gateway.py --server samples/attack/venomous_server.py
  python scripts/demo_gateway.py --report-only      # 观察模式：只报不拦

为什么要有这个脚本
------------------
答辩时最容易被追问的一句是「你这个到底拦没拦住」。这个脚本的作用是让这个问题
变成一个可以当场敲的命令：左边 8 个工具，右边 4 个工具，少掉的三四个名字和
它们命中的规则一条条列在下面 —— 而且是同一个客户端跑出来的，没有剪辑空间。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from probe_client import MCPStdioClient, _pin_interpreter  # noqa: E402
from version import __version__  # noqa: E402


def talk(argv: list[str], out_path: str, timeout: float = 25.0) -> dict:
    """跑一次完整的 initialize → tools/list，返回工具清单与网关 stderr。"""
    cli = MCPStdioClient(_pin_interpreter(argv), out_path, timeout=timeout)
    result: dict = {"ok": False, "tools": [], "verdict": None,
                    "stderr": [], "error": None, "protocol_version": cli.PROTOCOL_VERSION,
                    "argv": _pin_interpreter(argv)}
    cli.start()
    try:
        init = cli.request("initialize", {
            "protocolVersion": cli.PROTOCOL_VERSION,
            "capabilities": {"roots": {"listChanged": False}},
            "clientInfo": {"name": "mcp-shield-demo", "version": __version__},
        })
        if init is None:
            result["error"] = "initialize 无响应"
            result["stderr"] = list(cli.stderr_buf)
            return result
        result["server_info"] = (init.get("result") or {}).get("serverInfo")
        cli.send("notifications/initialized", {}, notification=True)
        listing = cli.request("tools/list", {}) or {}
        res = listing.get("result") or {}
        result["tools"] = [t.get("name") for t in (res.get("tools") or [])]
        result["verdict"] = res.get("_mcpShield")
        result["ok"] = True
    finally:
        cli.close()
        result["stderr"] = list(cli.stderr_buf)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(prog="demo_gateway",
                                 description="直连 Server vs 经过 MCP Shield 网关")
    ap.add_argument("--server", default=os.path.join("samples", "attack", "venomous_server.py"),
                    help="被测的 MCP Server（默认恶意样本）")
    ap.add_argument("--report-only", action="store_true", help="网关观察模式：只报不拦")
    ap.add_argument("--source", default=None, metavar="PATH",
                    help="可选：把 Server 的源码交给网关，叠上 MS-005/006/007 源码层证据")
    ap.add_argument("--lang", choices=["python", "python3"], default="python",
                    help="启动 Server 用的解释器占位符（默认 python）")
    args = ap.parse_args()

    server = args.server if os.path.isabs(args.server) else os.path.join(ROOT, args.server)
    if not os.path.isfile(server):
        print(f"[!] 找不到 Server: {server}", file=sys.stderr)
        return 2

    gw_flags = ["--report-only"] if args.report_only else []
    if args.source:
        src = args.source if os.path.isabs(args.source) else os.path.join(ROOT, args.source)
        gw_flags += ["--source", src]
    base_out = os.path.join(ROOT, "reports", "demo_direct.jsonl")
    gw_out = os.path.join(ROOT, "reports", "demo_gateway.jsonl")

    print("=" * 78)
    print(" MCP Shield · 网关演示：同一个客户端，同一个 Server，只差一层网关")
    print("=" * 78)
    print(f" Server   : {os.path.relpath(server, ROOT)}")
    print(f" 网关模式 : {'观察（只报不拦）' if args.report_only else '拦截（命中即移出响应）'}")
    print()

    print(" 链路 A：客户端 ─────────────────────→ Server")
    a = talk([args.lang, server], base_out)
    if not a["ok"]:
        print(f"   [!] 失败：{a['error']}")
        for l in a["stderr"][-12:]:
            print("   | " + l)
        return 2
    print(f"   协议 {a['protocol_version']} · serverInfo {a['server_info']}")
    print(f"   客户端看到 {len(a['tools'])} 个工具：{', '.join(a['tools'])}")
    print()

    print(" 链路 B：客户端 ──→ MCP Shield 网关 ──→ Server")
    b = talk([args.lang, "mcp_shield_gateway.py", *gw_flags, args.lang, server], gw_out)
    if not b["ok"]:
        print(f"   [!] 失败：{b['error']}")
        for l in b["stderr"][-12:]:
            print("   | " + l)
        return 2
    print(f"   协议 {b['protocol_version']} · serverInfo {b['server_info']}")
    print(f"   客户端看到 {len(b['tools'])} 个工具：{', '.join(b['tools']) or '(空)'}")
    print()

    # -- 网关自己怎么说 -----------------------------------------------------
    if b["stderr"]:
        print(" 网关侧输出（stderr，协议通道不受影响）：")
        for line in b["stderr"]:
            print("   | " + line)
        print()

    removed = [t for t in a["tools"] if t not in b["tools"]]
    print("=" * 78)
    print(" 结果")
    print("=" * 78)
    print(f"   直连 Server   : {len(a['tools'])} 个工具")
    print(f"   经过网关      : {len(b['tools'])} 个工具")
    if removed:
        print(f"   被移出响应    : {len(removed)} 个 → {', '.join(removed)}")
        print("   含义          : 这些工具根本不会出现在模型的上下文里。")
    elif args.report_only:
        print("   被移出响应    : 0 个（观察模式，只报告不裁剪）")
    else:
        print("   被移出响应    : 0 个（本样本没有被判为 BLOCK 的工具）")

    v = b["verdict"] or {}
    if v:
        print()
        print(f"   网关裁决摘要  : {json.dumps(v.get('summary'), ensure_ascii=False)}")
        print(f"   工具进出      : {v.get('tools_in')} → {v.get('tools_out')}")

    payload = {
        "tool": "demo_gateway",
        "version": __version__,
        "server": os.path.relpath(server, ROOT),
        "mode": "report-only" if args.report_only else "enforce",
        "direct": {"tools": a["tools"], "count": len(a["tools"])},
        "gateway": {"tools": b["tools"], "count": len(b["tools"]),
                    "verdict": b["verdict"]},
        "removed": removed,
    }
    ev = os.path.join(ROOT, "reports", "gateway_evidence.json")
    os.makedirs(os.path.dirname(ev), exist_ok=True)
    with open(ev, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print()
    print(f"[+] 证据已写入: {os.path.relpath(ev, ROOT)}")
    print(f"[+] 两条链路的原始报文: {os.path.relpath(base_out, ROOT)} / "
          f"{os.path.relpath(gw_out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

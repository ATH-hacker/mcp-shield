#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
probe_client.py —— 零依赖 MCP stdio 客户端 + 双向 JSON-RPC 流量捕获（用于录屏取证）

设计目标
--------
不依赖官方 mcp SDK，直接用 行分隔 JSON-RPC over stdio 与任意 MCP Server 通信。
把"线上真实发生的"请求与响应原样落盘，作为 PPT/答辩的不可伪造证据。

与静态扫描的分工
----------------
  scanner.py  : 源码层 → 发现工具描述里的投毒/隐藏字符
  probe_client: 运行层 → 抓取 tools/list 的真实响应报文（含不可见字符的原始码点）

用法
----
  python probe_client.py -- python samples/attack/venomous_server.py --out reports/traffic_attack.jsonl
  python probe_client.py -- python samples/benign/clean_server.py  --out reports/traffic_benign.jsonl

输出
----
  *.jsonl    每行一条 {"dir": "send"|"recv", "seq": n, "msg": {...}}
  控制台      人类可读的双向报文流 + 不可见字符码点解剖表
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

# ---------------------------------------------------------------------------
# 不可见 / 危险码点分类表：与 scanner.py 的 MS-002/003/004 判据保持一致
# ---------------------------------------------------------------------------
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
BIDI_CTRL = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def classify_cp(cp: int) -> str | None:
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BIDI_CTRL:
        return "bidi"
    if 0xE0000 <= cp <= 0xE007F:
        return "unicode-tag"
    if 0xE000 <= cp <= 0xF8FF:
        return "private-use"
    return None


def dissect(text: str) -> list[dict[str, Any]]:
    """逐个码点扫描，返回所有可疑码点的位置/种类/字符名。"""
    import unicodedata

    out: list[dict[str, Any]] = []
    for i, ch in enumerate(text):
        kind = classify_cp(ord(ch))
        if kind is None:
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "<unnamed>"
        out.append(
            {
                "index": i,
                "cp": f"U+{ord(ch):04X}",
                "kind": kind,
                "name": name,
                "repr": repr(ch),
            }
        )
    return out


def summarize_codepoints(text: str) -> dict[str, Any]:
    ds = dissect(text)
    kinds: dict[str, int] = {}
    for d in ds:
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    return {
        "total_suspicious": len(ds),
        "by_kind": kinds,
        "samples": ds[:8],
        "distinct_codepoints": sorted({d["cp"] for d in ds}),
    }


# ---------------------------------------------------------------------------
# 极简 MCP stdio 客户端
# ---------------------------------------------------------------------------
class MCPStdioClient:
    """行分隔 JSON-RPC 2.0 over stdio。刻意不复用官方 SDK —— 为了看清线上报文。"""

    PROTOCOL_VERSION = "2024-11-05"  # 锁定协议版本，避免规范漂移导致复现失败

    def __init__(self, argv: list[str], out_path: str, timeout: float = 20.0) -> None:
        self.argv = argv
        self.out_path = out_path
        self.timeout = timeout
        self.seq = 0
        self.next_id = 1
        self.records: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.stderr_buf: list[str] = []
        self.proc: subprocess.Popen[str] | None = None

    # -- 日志 ---------------------------------------------------------------
    def _log(self, direction: str, msg: Any) -> None:
        with self.lock:
            self.seq += 1
            self.records.append({"dir": direction, "seq": self.seq, "ts": time.time(), "msg": msg})

    def _dump(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.out_path)), exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as f:
            for rec in self.records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- 进程与 IO ----------------------------------------------------------
    def _stderr_reader(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            self.stderr_buf.append(line.rstrip("\n"))

    def start(self) -> None:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )
        threading.Thread(target=self._stderr_reader, daemon=True).start()

    def send(self, method: str, params: dict | None = None, *, notification: bool = False) -> Any:
        assert self.proc and self.proc.stdin
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if not notification:
            payload["id"] = self.next_id
            self.next_id += 1
        self._log("send", payload)
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        return payload.get("id")

    def recv(self) -> dict[str, Any] | None:
        """读取一条报文，跳过通知；超时返回 None。"""
        assert self.proc and self.proc.stdout
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = {"_unparsed": line}
            self._log("recv", msg)
            if isinstance(msg, dict) and "id" in msg:
                return msg
        return None

    def request(self, method: str, params: dict | None = None) -> dict[str, Any] | None:
        self.send(method, params)
        return self.recv()

    def close(self) -> None:
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


# ---------------------------------------------------------------------------
# 取证流程
# ---------------------------------------------------------------------------
def _pin_interpreter(server_argv: list[str]) -> list[str]:
    """规范化 Server 启动命令。

    两种情况都要处理：
      1. argv[0] 是 'python' / 'python3' / 'py' 占位符 —— 换成当前解释器绝对路径，
         避免子进程落到 PATH 上另一个解释器（曾因此报 `No module named 'mcp'`）。
      2. argv[0] 直接是个 .py 脚本 —— 补上当前解释器。否则 Windows 会拿脚本文件
         去 CreateProcess，报 `OSError: [WinError 193] %1 不是有效的 Win32 应用程序`。
    调用方因此既可以写 ["python", "server.py"]，也可以直接写 ["server.py"]。
    """
    argv = list(server_argv)
    if not argv:
        return argv
    base = os.path.basename(argv[0]).lower()
    if base in ("python", "python3", "py"):
        argv[0] = sys.executable
    elif base.endswith(".py"):
        argv.insert(0, sys.executable)
    return argv


def capture_tools(server_argv: list[str], out_path: str | None = None,
                  timeout: float = 20.0) -> dict[str, Any]:
    """
    运行层取证核心：启动 MCP Server → initialize → tools/list → 逐码点解剖。

    返回可直接序列化为 JSON 的结构，供 CLI 与 Web 控制台共用。
    不打印任何东西，失败时在返回值的 error 字段里说明原因。
    """
    argv = _pin_interpreter(server_argv)
    cli = MCPStdioClient(argv, out_path or os.devnull, timeout=timeout)
    cli.start()
    result: dict[str, Any] = {
        "ok": False,
        "interpreter": argv[0],
        "argv": argv,
        "protocol_version": cli.PROTOCOL_VERSION,
        "server_info": None,
        "tools": [],
        "poisoned_tools": 0,
        "messages": 0,
        "stderr_tail": [],
        "error": None,
    }
    try:
        init = cli.request(
            "initialize",
            {
                "protocolVersion": cli.PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": {"name": "mcp-shield-probe", "version": "0.1.0"},
            },
        )
        if init is None:
            result["error"] = "initialize 无响应：Server 可能启动失败或缺少依赖（pip install 'mcp<2'）"
            result["stderr_tail"] = cli.stderr_buf[-15:]
            return result
        result["server_info"] = (init.get("result") or {}).get("serverInfo", {})

        cli.send("notifications/initialized", {}, notification=True)
        listing = cli.request("tools/list", {})
        tools = ((listing or {}).get("result") or {}).get("tools") or []

        for t in tools:
            desc = t.get("description") or ""
            summary = summarize_codepoints(desc)
            if summary["total_suspicious"]:
                result["poisoned_tools"] += 1
            result["tools"].append(
                {
                    "name": t.get("name"),
                    "description": desc,
                    "description_len": len(desc),
                    "annotations": t.get("annotations") or None,
                    "input_schema_keys": sorted((t.get("inputSchema") or {}).get("properties", {}).keys()),
                    "codepoints": summary,
                }
            )
        result["ok"] = True
    finally:
        cli.close()
        result["messages"] = len(cli.records)
        if out_path:
            result["traffic_file"] = out_path
    return result


def run_forensics(server_argv: list[str], out_path: str) -> int:
    sep = "=" * 78
    print(sep)
    print(" MCP Shield -- 运行层取证：tools/list 真实报文捕获")
    print(sep)
    print(f" 目标 Server : {' '.join(server_argv)}")
    print(f" 协议版本    : {MCPStdioClient.PROTOCOL_VERSION} (锁定)")
    print(f" 流量落盘    : {out_path}")
    print("-" * 78)

    # 关键：这里必须走 _pin_interpreter，不能自己重写一遍判断。
    # 曾经在这里保留了一份「只替换 python/python3/py」的旧逻辑，而 _pin_interpreter
    # 后来补上了「裸 .py 脚本自动补解释器」的分支 —— 于是 `probe server.py --out x.jsonl`
    # 会拿 .py 文件直接去 CreateProcess，崩在 cli.start()：
    #   OSError: [WinError 193] %1 不是有效的 Win32 应用程序
    # 教训：同一件事只能有一处实现。
    argv = _pin_interpreter(server_argv)

    exe = argv[0]
    if os.path.isabs(exe):
        if not os.path.exists(exe):
            print(f"[!] 解释器不存在: {exe}")
            return 2
    elif shutil.which(exe) is None:
        print(f"[!] 找不到可执行文件 {exe!r}，请检查 PATH")
        return 2
    if len(argv) >= 2 and os.path.isabs(argv[1]) and not os.path.exists(argv[1]):
        print(f"[!] Server 脚本不存在: {argv[1]}")
        return 2

    print(f" 解释器      : {argv[0]}")

    cli = MCPStdioClient(argv, out_path)
    cli.start()
    rc = 0
    try:
        init = cli.request(
            "initialize",
            {
                "protocolVersion": cli.PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": False}},
                "clientInfo": {"name": "mcp-shield-probe", "version": "0.1.0"},
            },
        )
        if init is None:
            print("[!] initialize 无响应；Server 可能未安装 (pip install mcp)。")
            print("[i] Server stderr 末尾：")
            for line in cli.stderr_buf[-15:]:
                print("    " + line)
            return 3
        server_info = (init.get("result") or {}).get("serverInfo", {})
        print(f"[+] initialize 成功  serverInfo={server_info}")

        cli.send("notifications/initialized", {}, notification=True)

        listing = cli.request("tools/list", {})
        tools = ((listing or {}).get("result") or {}).get("tools") or []
        print(f"[+] tools/list 返回 {len(tools)} 个工具\n")

        poison_hits = 0
        for t in tools:
            name = t.get("name", "?")
            desc = t.get("description") or ""
            print("-" * 78)
            print(f" tool: {name}")
            print(f"   description 字段长度 = {len(desc)} 字符")
            s = summarize_codepoints(desc)
            ann = (t.get("annotations") or {})
            print(f"   annotations = {ann if ann else '(缺失 —— 见 MS-008)'}")
            if s["total_suspicious"]:
                poison_hits += 1
                print(f"   [!] 线上报文含可疑码点 {s['total_suspicious']} 处: {s['by_kind']}")
                for d in s["samples"]:
                    print(f"        idx={d['index']:<4} {d['cp']} {d['kind']:<12} {d['name']}")
            else:
                print("   [ok] 线上报文未发现不可见字符")
            shown = desc.replace("\u200b", "").replace("\u200d", "").strip()
            if len(shown) > 150:
                shown = shown[:150] + " ..."
            if shown:
                print(f"   可见文本: {shown!r}")

        print(sep)
        print(f" 结论: {len(tools)} 个工具，其中 {poison_hits} 个的工具描述在线上报文中携带不可见字符")
        print(f" 报文总数: {len(cli.records)} 条（已写入 {out_path}）")
        print(sep)
    finally:
        cli.close()
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(
        description="MCP stdio 客户端与流量取证",
        epilog="注意：因为 server 用了 REMAINDER，--out 必须写在 Server 命令【之前】。"
               "写成 `--out x.jsonl -- python server.py`，或让末位参数以 .jsonl 结尾。",
    )
    ap.add_argument("--out", default=None,
                    help="流量 JSONL 输出路径（不写则默认 reports/traffic.jsonl）")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("server", nargs=argparse.REMAINDER, help="-- 之后的 MCP Server 启动命令")
    args = ap.parse_args()

    argv = [a for a in args.server if a != "--"]

    out = args.out
    # 兜底：REMAINDER 会把写在 Server 后面的 --out 也吞进 server 列表，
    # 用户于是看到「明明指定了路径却没落盘」。这里把末位的 .jsonl 参数捡回来。
    if out is None and len(argv) >= 2 and argv[-1].lower().endswith(".jsonl"):
        out = argv.pop()
    if out is None:
        out = os.path.join("reports", "traffic.jsonl")
        print(f"[i] 未指定 --out，默认写入 {out}（--out 要写在 Server 命令之前）")

    if not argv:
        print("用法: python probe_client.py --out reports/traffic.jsonl -- python server.py")
        return 2
    return run_forensics(argv, out)


if __name__ == "__main__":
    sys.exit(main())

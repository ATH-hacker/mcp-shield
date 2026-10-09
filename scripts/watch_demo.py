#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP Shield -- 演示辅助：安全地"改一下文件"，用来现场展示控制台的目录监听。

背景
----
控制台（`scripts/ui_server.py`）默认带一个本机目录监听：它每 1 秒核对
`samples/` 与 `rules/` 下样本文件的内容指纹，一旦发现变化就重跑静态检测、
替换内存快照，页面自己刷新（右上角角标显示"已重扫 第 N 次：文件名"）。

演示时需要一个"看得见"的文件改动。直接手改正式样本有三处风险：
  1. 记事本另存为可能改变编码或加上 BOM，破坏源码；
  2. 改动很容易忘记还原；
  3. 正式样本一旦残留，后续所有统计口径（行号、告警数）都会与报告对不上。

所以这里提供一个**幂等且可自检**的开关：只在样本末尾追加/删除一行注释，
并在每一步后校验文件状态。它**不修改任何检测逻辑**，也只动它自己的那一行。

用法
----
    python scripts/watch_demo.py on     # 追加一行注释（触发重扫，看角标变）
    python scripts/watch_demo.py off    # 删掉那一行（还原到原始内容）
    python scripts/watch_demo.py check  # 只检查现在是什么状态（不写文件）

退出码：0 = 操作成功且状态符合预期；1 = 状态异常（或参数错误）。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "samples" / "attack" / "venomous_server.py"
MARK = "# watch-demo"
LAST_LINE = "    mcp.run()"


def read_lines() -> list[str]:
    """按 utf-8 读取，保留原有的换行约定（splitlines 会去掉行尾）。"""
    text = TARGET.read_text(encoding="utf-8")
    return text.splitlines()


def write_lines(lines: list[str]) -> None:
    TARGET.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def state(lines: list[str]) -> str:
    """返回 'on' / 'off' / 'bad'。"""
    if lines and lines[-1] == LAST_LINE:
        return "off"
    if len(lines) >= 2 and lines[-1] == MARK and lines[-2] == LAST_LINE:
        return "on"
    return "bad"


def show(tag: str, lines: list[str]) -> None:
    st = state(lines)
    print(f"  文件      : {TARGET}")
    print(f"  行数      : {len(lines)}")
    print(f"  最后一行  : {lines[-1] if lines else '(空文件)'}")
    print(f"  状态      : {st}  (on = 演示行在位, off = 原始内容)")
    if st == "bad":
        print()
        print(f"  [!] 文件末尾既不是 {LAST_LINE!r} 也不是 {MARK!r} -- 请手动检查！")
    print()


def main(argv: list[str]) -> int:
    print("=" * 62)
    print("MCP Shield -- 目录监听演示开关")
    print("=" * 62)

    if not TARGET.is_file():
        print(f"[x] 找不到样本文件：{TARGET}")
        return 1

    if len(argv) != 2 or argv[1] not in ("on", "off", "check"):
        print("用法: python scripts/watch_demo.py on|off|check")
        return 1

    action = argv[1]
    lines = read_lines()
    before = state(lines)

    if before == "bad":
        print("[x] 样本文件末尾不是预期内容，先手动修好再跑本脚本。")
        show("before", lines)
        return 1

    if action == "check":
        show("check", lines)
        print(f"提示: 期望状态 = off（原始内容）。当前 = {before}。")
        return 0 if before == "off" else 1

    if action == "on":
        if before == "on":
            print("[=] 演示行已经在位，无需重复追加。")
        else:
            lines.append(MARK)
            write_lines(lines)
            print("[+] 已在样本末尾追加演示行，目录监听应在本轮轮询内发现变化。")
        lines = read_lines()
        show("after", lines)
        if state(lines) != "on":
            print("[x] 追加后状态不对，请手动检查！")
            return 1
        print("下一步: 切到浏览器，盯右上角角标 ->「已重扫 第 N 次：venomous_server.py」")
        print("演示完务必执行:  python scripts/watch_demo.py off")
        return 0

    # action == "off"
    if before == "off":
        print("[=] 文件本来就是原始内容，无需还原。")
    else:
        del lines[-1]
        write_lines(lines)
        print("[-] 已删除演示行，样本还原为原始内容。")
    lines = read_lines()
    show("after", lines)
    if state(lines) != "off":
        print("[x] 还原后状态不对，请手动检查！")
        return 1
    print("[ok] 样本已还原。交付前请再跑一次本脚本的 check 子命令确认。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

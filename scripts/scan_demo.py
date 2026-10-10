# -*- coding: utf-8 -*-
"""扫描并显式打印退出码 —— 录像演示专用。

为什么需要它：
  `mcp_shield.py scan` 的退出码（0/见 ERROR 则为 1）是真实存在的，但它只是
  进程退出状态，**PowerShell 不会自动显示**。录像时需要在画面上看到这一行，
  所以包一层：跑完扫描后把 `$LASTEXITCODE` 打印出来。

用法：
    python "scripts\\scan_demo.py" "samples\\_demo\\clean_server.py"
    python "scripts\\scan_demo.py" "samples\\_demo\\poisoned_server.py"
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python scripts\\scan_demo.py <要扫描的文件或目录>", file=sys.stderr)
        return 2

    target = sys.argv[1]
    cmd = [sys.executable, str(ROOT / "mcp_shield.py"), "scan", target]

    proc = subprocess.run(cmd, cwd=str(ROOT))

    # 关键：把退出码显式画在屏幕上
    bar = "=" * 62
    print()
    print(bar)
    if proc.returncode == 0:
        print(f"  退出码 = {proc.returncode}   →  无 ERROR，CI 门禁放行")
    else:
        print(f"  退出码 = {proc.returncode}   →  存在 ERROR，CI 门禁拦截")
    print(bar)

    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())

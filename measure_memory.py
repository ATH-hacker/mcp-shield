#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内存占用实测 —— 为 PPT「性能开销（实测）」页提供可复现数字。

为什么不用轮询：扫描一次只要 3.8 ms，外部按毫秒轮询 `WorkingSet64` 永远
抓不到真实峰值，量到的永远是进程刚创建时的常驻集（结果会和 `python -c pass`
一模一样）。这里直接向操作系统要 **PeakWorkingSetSize**（自进程启动以来的
峰值），由内核记账，不依赖采样时机。

用法（在代码目录下执行）：
    python docs/measure_memory.py            # 从项目根运行
    python measure_memory.py                 # 从 docs/ 运行
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import statistics
import sys
import time
from pathlib import Path

def _find_root() -> Path:
    """向上找到含 scanner.py 的那一层。

    不能写死 `parent.parent` —— 本脚本既能放在项目根的 docs/ 下，也能直接
    放在项目根（发布包为了少一层目录就是放在根的），写死就会指到项目外面，
    于是所有样本路径失效、扫描秒退，量出来的耗时与内存全是假的。
    """
    here = Path(__file__).resolve().parent
    for cand in (here, *here.parents):
        if (cand / "scanner.py").is_file():
            return cand
    return here


ROOT = _find_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_PROBE = None          # 延迟初始化：只在真正要用时才去找导出函数


def _load_probe():
    """定位并配置 GetProcessMemoryInfo。
    两个必须做对的细节（否则必然报「调用失败」）：
    1. `GetCurrentProcess()` 返回的伪句柄是 -1，必须声明 restype 为 HANDLE。
       不声明时 ctypes 按 C int 传参，64 位下会变成 0x00000000FFFFFFFF，
       内核认不出这个句柄，直接失败。
    2. 现代 Windows 上该函数由 kernel32 以 K32GetProcessMemoryInfo 导出，
       psapi.dll 里的同名函数是给老程序的转发层，优先用前者。
    """
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.GetCurrentProcess.argtypes = []

    candidates = []
    if hasattr(k32, "K32GetProcessMemoryInfo"):
        candidates.append(k32.K32GetProcessMemoryInfo)
    try:
        psapi = ctypes.windll.psapi
        candidates.append(psapi.GetProcessMemoryInfo)
    except OSError:
        pass
    if not candidates:
        raise OSError("系统中找不到 GetProcessMemoryInfo")

    for fn in candidates:
        fn.restype = wt.BOOL
        fn.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wt.DWORD]
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if fn(k32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
            return fn
    raise OSError("GetProcessMemoryInfo 调用失败（两种实现都不可用）")


def peak_bytes() -> int:
    """本进程自启动以来的峰值常驻内存（字节）。仅 Windows 可用。"""
    global _PROBE
    if _PROBE is None:
        _PROBE = _load_probe()
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    _PROBE(ctypes.windll.kernel32.GetCurrentProcess(),
           ctypes.byref(counters), counters.cb)
    return int(counters.PeakWorkingSetSize)


def mb(n: int) -> float:
    return round(n / (1024 * 1024), 1)


def bench(label: str, fn, rounds: int = 7) -> dict:
    """跑 rounds 次，报告耗时中位与峰值内存。"""
    baseline = peak_bytes()          # import 完成后的基线峰值
    times: list[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    peak = peak_bytes()
    med = statistics.median(times)
    row = {
        "label": label,
        "rounds": rounds,
        "ms_median": round(med, 2),
        "ms_min": round(min(times), 2),
        "ms_max": round(max(times), 2),
        "peak_mb_process": mb(peak),
        "peak_mb_delta_over_import": mb(peak - baseline),
    }
    print(f"{label:<30} {row['ms_median']:>8.2f} ms (中位)   "
          f"进程峰值 {row['peak_mb_process']:>5.1f} MB   "
          f"较 import 后新增 {row['peak_mb_delta_over_import']:>5.1f} MB")
    return row


def main() -> int:
    if not sys.platform.startswith("win"):
        print("本脚本依赖 Windows 的 GetProcessMemoryInfo；其他平台请改用 resource.getrusage。")
        return 2

    import scanner
    import tsjs_scanner

    attack_py = ROOT / "samples" / "attack" / "venomous_server.py"
    benign_py = ROOT / "samples" / "benign" / "clean_server.py"
    attack_ts = ROOT / "samples" / "attack" / "venomous_server.ts"
    benign_ts = ROOT / "samples" / "benign" / "clean_server.ts"

    # 先确认样本真的在。否则 scan_file 会「失败得很快」，量出来的 0.02 ms
    # 和「扫描不涨内存」全是假象 —— 这类静默失败比报错更危险。
    missing = [str(p) for p in (attack_py, benign_py, attack_ts, benign_ts) if not p.is_file()]
    if missing:
        print("样本文件缺失，拒绝输出任何数字：", file=sys.stderr)
        for m in missing:
            print(f"  缺 {m}", file=sys.stderr)
        return 3

    print(f"解释器: {sys.executable}")
    print(f"Python : {sys.version.split()[0]}")
    print(f"基线   : import scanner/tsjs_scanner 之后，进程峰值 {mb(peak_bytes())} MB\n")

    rows = []
    rows.append(bench("扫描恶意样本 8 工具", lambda: scanner.scan_file(str(attack_py))))
    rows.append(bench("扫描良性样本 4 工具", lambda: scanner.scan_file(str(benign_py))))
    rows.append(bench("扫描恶意 TS 样本 8 工具", lambda: tsjs_scanner.scan_tsjs_file(str(attack_ts))))
    rows.append(bench("扫描良性 TS 样本 4 工具", lambda: tsjs_scanner.scan_tsjs_file(str(benign_ts))))

    # 目录级扫描：一次扫完全部样本，这才是内存上界
    def scan_all() -> None:
        for p in ("samples/attack", "samples/benign"):
            for f in scanner.iter_targets(ROOT / p):
                if f.endswith(".py"):
                    scanner.scan_file(str(f))
                else:
                    tsjs_scanner.scan_tsjs_file(str(f))
    rows.append(bench("一次扫完全部 4 个样本", scan_all))

    print(f"\n最终进程峰值 = {mb(peak_bytes())} MB"
          f"（这就是「内存占用」一栏应填的数字上界）")

    out = ROOT / "reports" / "memory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "interpreter": sys.executable,
        "python": sys.version.split()[0],
        "rows": rows,
        "final_peak_mb": mb(peak_bytes()),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

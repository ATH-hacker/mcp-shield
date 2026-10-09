#!/usr/bin/env python
# -*- coding: utf-8 -*-
r"""
build_standalone.py —— 把可视化控制台导出成一个**自包含单页 HTML**。

为什么需要：
    答辩现场可能没有 Python 环境、没有网络、甚至不允许起服务。
    导出的 HTML 把真实数据快照内嵌在页面里（`__SNAPSHOT__` 占位符被替换掉），
    双击即可用浏览器打开，页签、表格、码点高亮全部照常工作。
    —— 唯一失效的是「运行层取证」页签上的两个按钮：它们需要后端真的去拉起
       MCP Server 进程，离线单页版本没有后端，点击会提示这一点（不会假装成功）。

用法: python scripts/build_standalone.py
输出: docs/console_standalone.html

维护提醒：改完 ui/console.html 后要重新跑一次本脚本，
         否则单页版会停留在旧界面。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import ui_server as uis  # noqa: E402

TEMPLATE = uis.UI_DIR / "console.html"
OUT = ROOT / "docs" / "console_standalone.html"

# 离线版需要明确告诉使用者「按钮为什么点不动」，否则会被当成 bug。
OFFLINE_BANNER = """
<div id="offline-banner" style="margin:0 0 14px;padding:10px 15px;border-radius:9px;
     background:#2a2113;border:1px solid #fbbf24;color:#fde68a;font-size:12.5px;line-height:1.65">
  <b>离线单页版</b> · 本页数据为真实快照（生成时间见右上角），已内嵌进 HTML，断网可用。<br>
  唯一例外：<b>「运行层取证实录」页签里的两个按钮不可用</b> —— 它们需要本地后端真的去拉起
  MCP Server 进程。要看现场取证，请用
  <code style="color:#22d3ee">python scripts/ui_server.py --port 8787 --open</code> 启动控制台。
</div>
"""

# 没有后端时，fetch 必然失败；把按钮替换为明确的说明而不是静默报错。
OFFLINE_PATCH = """
/* ---- 离线单页版补丁：运行层按钮降级为明确提示 ---- */
(function(){
  const banner = document.getElementById('offline-banner');
  if (banner) document.querySelector('main').insertBefore(banner, document.querySelector('main .view'));
  async function explain(which){
    const st = document.getElementById('run-status');
    const rs = document.getElementById('run-result');
    if (st) st.textContent = '离线单页版无后端，无法现场取证';
    if (rs) {
      rs.innerHTML = '<div class="verdict WARN">⚠ 离线单页版没有后端'
        + '<span class="why">运行层取证需要真的拉起 MCP Server 子进程并读取其 stdio 报文，'
        + '这一步无法在静态 HTML 里完成 —— 也正因如此它才是一份「不可伪造」的证据。'
        + '请运行 <code>python scripts/ui_server.py --port 8787 --open</code> 后重试。</span></div>';
    }
  }
  const a = document.getElementById('btn-run-attack');
  const b = document.getElementById('btn-run-benign');
  if (a) a.onclick = () => explain('attack');
  if (b) b.onclick = () => explain('benign');
})();
"""


def build() -> Path:
    if not TEMPLATE.exists():
        raise SystemExit(f"[!] 模板不存在: {TEMPLATE}")

    print("[*] 正在执行真实扫描（调用 scanner.scan_file，非硬编码）…")
    snap = uis.static_watch_state(uis.build_snapshot())
    print(f"    - 恶意样本: {len(snap['tools'])} 个工具 / {snap['metrics']['attack_findings']} 条告警")
    print(f"    - 良性样本: {len(snap['benign_tools'])} 个工具 / {snap['metrics']['benign_findings']} 条告警")
    print(f"    - 真实不可见码点: {snap['metrics']['hidden_codepoints']} 个")

    html = TEMPLATE.read_text(encoding="utf-8")
    if "__SNAPSHOT__" not in html:
        raise SystemExit("[!] 模板里找不到 __SNAPSHOT__ 占位符")

    payload = json.dumps(snap, ensure_ascii=False).replace("</", "<\\/")
    html = html.replace("__SNAPSHOT__", payload)
    html = html.replace("</main>", OFFLINE_BANNER + "</main>", 1)
    html = html.replace("</script>\n</body>", OFFLINE_PATCH + "\n</script>\n</body>", 1)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n"：交付副本要求与 GitHub 逐字节一致，绝不能让 Windows 文本模式
    # 把 LF 变成 CRLF（否则本地比远程多出「行数」个字节）
    OUT.write_text(html, encoding="utf-8", newline="\n")
    return OUT


if __name__ == "__main__":
    path = build()
    size = path.stat().st_size
    print(f"[+] 已生成: {path}")
    print(f"[+] 大小: {size} B ({size/1024:.1f} KB) —— 双击即可离线打开，无需 Python 与网络")

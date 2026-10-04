#!/usr/bin/env python3
r"""
build_release.py —— 生成「可直接上传 GitHub」的发布包

为什么要这个脚本：项目根目录里混着答辩材料、截图、PPT、node_modules 这类
**不该进公共仓库**的东西。手工挑选容易漏（漏了要么泄露内部材料，要么让仓库
体积爆炸）。这个脚本用**白名单**方式复制，并做三道检查后才落盘。

产出：~/Desktop/mcp-shield-release/    ← 直接 git init 上传这个目录
（答辩材料、PPT、截图、docs/ 一律不进发布包 —— 白名单里根本没有它们）

用法：
  python build_release.py                                  # 生成到桌面
  python build_release.py --user zhangsan                  # 顺便替换 README/SARIF 里的用户名占位符
  python build_release.py --out D:\some\path               # 自定义输出目录
  python build_release.py --zip                            # 额外打一个 zip，便于备份
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.path.expanduser("~"), "Desktop", "mcp-shield-release")
PLACEHOLDER = "REPLACE-WITH-YOUR-USERNAME"

# ── 白名单：只有这些会被复制 ────────────────────────────────────────────
FILES = [
    "scanner.py",
    "tsjs_scanner.py",
    "probe_client.py",
    "mcp_shield.py",
    "version.py",
    "verify_release.py",
    "build_release.py",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    ".gitignore",
    "mcp-shield.toml.example",
]
DIRS = [
    "rules",
    "samples",
    "tests",
    "scripts",
    "ui",
    ".github",
]

# ── 黑名单：即使落在白名单目录里也剔除 ──────────────────────────────────
EXCLUDE_NAMES = {
    "__pycache__", "node_modules", ".git", ".pytest_cache", ".mypy_cache",
    "shots",                      # 截图（体积大，且可由脚本重生成）
}
EXCLUDE_SUFFIX = {
    ".pyc", ".pyo", ".pptx", ".zip", ".log",
    ".png", ".jpg", ".jpeg",           # 演示图片不入库
}
# docs/ 里只保留这几类文件（大纲与脚本），剔除中间产物
DOCS_KEEP_SUFFIX = {".md", ".py", ".json"}

# 本项目自己的调试垃圾
JUNK_RE = re.compile(r"^_dbg\d*\.(py|txt|json)$")


def _should_skip(rel: str, name: str) -> bool:
    if name in EXCLUDE_NAMES:
        return True
    if JUNK_RE.match(name):
        return True
    suffix = os.path.splitext(name)[1].lower()
    if suffix in EXCLUDE_SUFFIX:
        return True
    # docs/ 目录额外收窄
    norm = rel.replace("\\", "/")
    if norm.startswith("docs/") and suffix and suffix not in DOCS_KEEP_SUFFIX:
        return True
    return False


def _copy_tree(src: str, dst: str, rel: str = "") -> list[str]:
    """递归复制，返回实际落盘的文件相对路径列表。"""
    written: list[str] = []
    for entry in sorted(os.listdir(src)):
        s = os.path.join(src, entry)
        d = os.path.join(dst, entry)
        r = f"{rel}/{entry}" if rel else entry
        if os.path.isdir(s):
            if _should_skip(r, entry):
                continue
            os.makedirs(d, exist_ok=True)
            written += _copy_tree(s, d, r)
        else:
            if _should_skip(r, entry):
                continue
            shutil.copy2(s, d)
            written.append(r)
    return written


def _replace_placeholder(root: str, user: str) -> int:
    """把用户名占位符替换成真实用户名。返回改动的文件数。"""
    changed = 0
    self_name = os.path.basename(__file__)
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            # 不要改写本工具自身：本文件第 29 行的 PLACEHOLDER 常量是「定义」，
            # 把它替换掉会让 --user 的语义退化成「替换上一个用户名」，
            # 并且会把用户名写死在发给别人的构建脚本里。
            if fn == self_name:
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if PLACEHOLDER not in text:
                continue
            text = text.replace(PLACEHOLDER, user)
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            changed += 1
    return changed


def _audit(root: str) -> list[str]:
    """发布前审计：泄露、可路由域名、残留占位符、意外大文件。"""
    problems: list[str] = []

    # 1) 不该出现的文件
    forbidden = ["__pycache__", "node_modules", ".pptx", "_dbg"]
    for dirpath, dirs, files in os.walk(root):
        for name in list(dirs) + files:
            if any(f in name for f in forbidden):
                problems.append(f"发现不该发布的条目: {os.path.relpath(os.path.join(dirpath, name), root)}")

    # 2) 样本里的可路由真实域名
    allow = ("example", "invalid", "localhost", "127.0.0.1", "schema.org",
             "modelcontextprotocol", "json-schema.org", "w3.org", "github.com",
             "apache.org", "unicode.org", "owasp.org", "mitre.org", "semver.org",
             "keepachangelog.com", "python.org", "docs.oasis-open.org", "img.shields.io")
    pat = re.compile(r"https?://([A-Za-z0-9.-]+)")
    samples_dir = os.path.join(root, "samples")
    if os.path.isdir(samples_dir):
        for dirpath, _dirs, files in os.walk(samples_dir):
            for fn in files:
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for host in pat.findall(text):
                    if not any(a in host for a in allow):
                        problems.append(f"样本含非保留域名: {os.path.relpath(p, root)} -> {host}")

    # 3) 残留占位符（只在「文件名会出现在公网」的地方检查）
    for fn in ("README.md", "scanner.py", "CHANGELOG.md", "CONTRIBUTING.md",
               "SECURITY.md", ".github/workflows/tests.yml"):
        p = os.path.join(root, fn)
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                if PLACEHOLDER in fh.read():
                    problems.append(f"{fn} 仍有用户名占位符（可用 --user <你的GitHub用户名> 替换）")

    # 4) 意外的大文件（> 1 MB 提示一下）
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            size = os.path.getsize(p)
            if size > 1024 * 1024:
                problems.append(f"大文件 {os.path.relpath(p, root)}: {size / 1048576:.1f} MB")

    return problems


def _force_rmtree(path: str) -> None:
    """删除目录，能处理 Windows 上 Git 对象文件的只读属性。

    背景：如果发布目录里已经 `git init` 过，`.git/objects/**` 下的文件带只读位，
    直接 shutil.rmtree 会抛
    `PermissionError: [WinError 5] 拒绝访问。: '...\\.git\\objects\\..'`。
    这里的 onerror 回调先把只读位摘掉再重试。
    """
    import stat as _stat

    def onerror(func, target, _exc):
        try:
            os.chmod(target, _stat.S_IWRITE)
            func(target)
        except OSError as e:
            raise OSError(f"无法删除 {target}: {e}") from e

    shutil.rmtree(path, onerror=onerror)


def main() -> int:
    ap = argparse.ArgumentParser(description="生成可上传 GitHub 的发布包")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"输出目录（默认 {DEFAULT_OUT}）")
    ap.add_argument("--user", help="GitHub 用户名，用于替换 README/SARIF 里的占位符")
    ap.add_argument("--zip", action="store_true", help="额外生成 zip 备份")
    ap.add_argument("--force", action="store_true", help="输出目录已存在时直接覆盖")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    if os.path.exists(out):
        if not args.force:
            print(f"[!] 输出目录已存在: {out}")
            print("    加 --force 覆盖，或换一个 --out 路径。")
            return 2
        _force_rmtree(out)
    os.makedirs(out, exist_ok=True)

    written: list[str] = []
    for fn in FILES:
        s = os.path.join(ROOT, fn)
        if not os.path.exists(s):
            print(f"[!] 白名单文件不存在，跳过: {fn}")
            continue
        shutil.copy2(s, os.path.join(out, fn))
        written.append(fn)
    for d in DIRS:
        s = os.path.join(ROOT, d)
        if not os.path.isdir(s):
            print(f"[!] 白名单目录不存在，跳过: {d}/")
            continue
        os.makedirs(os.path.join(out, d), exist_ok=True)
        written += _copy_tree(s, os.path.join(out, d), d)

    # reports/ 只放一个说明，不放具体产物（可随手重跑）
    rep = os.path.join(out, "reports")
    os.makedirs(rep, exist_ok=True)
    with open(os.path.join(rep, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(
            "# reports/\n\n"
            "扫描产物目录。这里**刻意不提交**具体报告文件 —— 它们随时可重新生成，\n"
            "且内容会随规则演进变化。生成方式：\n\n"
            "```bash\n"
            "python scanner.py samples/attack/venomous_server.py \\\n"
            "    --json reports/scan_attack.json --sarif reports/scan_attack.sarif\n"
            "python mcp_shield.py probe samples/attack/venomous_server.py \\\n"
            "    --out reports/traffic_attack.jsonl\n"
            "```\n"
        )
    written.append("reports/README.md")
    open(os.path.join(rep, ".gitkeep"), "w").close()

    changed = 0
    if args.user:
        changed = _replace_placeholder(out, args.user.lstrip("@"))

    problems = _audit(out)

    print("=" * 74)
    print(f" 发布包已生成: {out}")
    print(f" 文件数: {len(written)}" + (f"（其中 {changed} 个文件替换了用户名占位符）" if args.user else ""))
    print("=" * 74)
    for f in sorted(written):
        print(f"   {f}")
    print("=" * 74)
    if problems:
        print(" 审计提示:")
        for p in problems:
            print(f"   ! {p}")
    else:
        print(" 审计通过：无泄露、无违规域名、无异常大文件。")

    if args.zip:
        zp = out + ".zip"
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
            for dirpath, _dirs, files in os.walk(out):
                for fn in files:
                    p = os.path.join(dirpath, fn)
                    zf.write(p, os.path.relpath(p, out))
        print(f"\n zip 备份: {zp}  ({os.path.getsize(zp) / 1024:.1f} KB)")

    print("\n 下一步：")
    print(f'   cd "{out}"')
    print("   git init && git add -A && git commit -m \"MCP Shield v0.1.0\"")
    print("   然后按桌面《GitHub上传步骤.md》操作。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

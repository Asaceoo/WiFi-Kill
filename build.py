#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build.py — 一键构建：自动递增版本号 → 同步文档版本 → 打包 exe → 出 zip

版本策略（每次执行都会递增，无需手工维护）：
  versions.json 里的 app / user_manual / tech_manual 各自 +1 个 patch，
  build 计数 +1，并把新版本号回写到两份手册的版本标记行。

用法：
  python build.py              递增版本并打包
  python build.py --no-bump    用当前版本号重新打包（调试用）
  python build.py --zip-only   只重新打 zip，不编译
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VERSIONS = ROOT / "versions.json"
DOCS = ROOT / "docs"
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "WiFiKill.spec"

DOC_FILES = {
    "user_manual": DOCS / "USER_MANUAL.md",
    "tech_manual": DOCS / "TECH_MANUAL.md",
}

DOCVER_RE = re.compile(r"(文档版本：\*\*v)(\d+\.\d+\.\d+)(\*\*)")
APPVER_RE = re.compile(r"(对应程序：\*\*v)(\d+\.\d+\.\d+)(\*\*)")
README_VER_RE = re.compile(r"(\| 程序 \| \*\*v)(\d+\.\d+\.\d+)(\*\*)")
README_BADGE_RE = re.compile(r"(badge/version-v)(\d+\.\d+\.\d+)")
README_MANUAL_RE = re.compile(
    r"(\| \[(用户手册|技术手册)\]\(docs/[A-Z_]+\.md\) \| v)(\d+\.\d+\.\d+)( \|)")


def bump(v: str, level: str = "patch") -> str:
    """语义化递增：patch 修 bug，minor 加功能，major 破坏性变更。

    手册版本跟着程序走：minor 及以上时手册也升 minor，否则只升 patch。
    """
    major, minor, patch = (int(x) for x in v.split("."))
    if level == "major":
        major, minor, patch = major + 1, 0, 0
    elif level == "minor":
        major, minor, patch = major, minor + 1, 0
    else:
        patch += 1
    return f"{major}.{minor}.{patch}"


def bump_docs(v: dict, level: str) -> None:
    for key in ("user_manual", "tech_manual"):
        v[key] = bump(v[key], "minor" if level in ("minor", "major") else "patch")


def load_versions() -> dict:
    return json.loads(VERSIONS.read_text(encoding="utf-8"))


def save_versions(v: dict):
    VERSIONS.write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")


def sync_docs(v: dict):
    """把新版本号写进两份手册的标记行。"""
    changed = []
    for key, path in DOC_FILES.items():
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        new = DOCVER_RE.sub(lambda m: f"{m.group(1)}{v[key]}{m.group(3)}", text)
        new = APPVER_RE.sub(lambda m: f"{m.group(1)}{v['app']}{m.group(3)}", new)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed.append(path.name)

    core_py = ROOT / "core.py"
    if core_py.exists():
        t = core_py.read_text(encoding="utf-8")
        n = re.sub(r'APP_VERSION = "[\d.]+"', f'APP_VERSION = "{v["app"]}"', t)
        if n != t:
            core_py.write_text(n, encoding="utf-8")
            changed.append("core.py")

    readme = ROOT / "README.md"
    if readme.exists():
        t = readme.read_text(encoding="utf-8")
        n = README_VER_RE.sub(lambda m: f"{m.group(1)}{v['app']}{m.group(3)}", t)
        n = README_BADGE_RE.sub(lambda m: f"{m.group(1)}{v['app']}", n)
        # 手册版本行（v1.2.0 形式，非 **加粗**）也要同步
        n = README_MANUAL_RE.sub(
            lambda m: f"{m.group(1)}{v['user_manual' if m.group(2) == '用户手册' else 'tech_manual']}{m.group(4)}",
            n)
        if n != t:
            readme.write_text(n, encoding="utf-8")
            changed.append("README.md")
    return changed


def version_tuple(v: str) -> tuple[int, int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c, 0


def write_version_resource(v: dict) -> Path:
    """生成 Windows 文件版本资源，让 exe 属性里能看到版本号。"""
    BUILD.mkdir(exist_ok=True)
    out = BUILD / "version_info.txt"
    t = version_tuple(v["app"])
    out.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={t}, prodvers={t},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('080404B0', [
        StringStruct('CompanyName', 'WiFiKill Project'),
        StringStruct('FileDescription', 'WiFiKill - 局域网设备发现与 ARP 阻断工具'),
        StringStruct('FileVersion', '{v["app"]}'),
        StringStruct('InternalName', 'WiFiKill'),
        StringStruct('LegalCopyright', '仅供自有或已授权网络安全测试使用'),
        StringStruct('OriginalFilename', 'WiFiKill.exe'),
        StringStruct('ProductName', 'WiFiKill'),
        StringStruct('ProductVersion', '{v["app"]}')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
""", encoding="utf-8")
    return out


def python_exe() -> str:
    venv = ROOT / ".buildenv" / "Scripts" / "python.exe"
    if venv.exists():
        return str(venv)
    return sys.executable


def run(cmd: list[str], desc: str) -> None:
    print(f"[*] {desc}")
    p = subprocess.run(cmd, cwd=ROOT)
    if p.returncode != 0:
        raise SystemExit(f"[-] 失败：{desc}（退出码 {p.returncode}）")


def ensure_env():
    py = python_exe()
    try:
        subprocess.run([py, "-c", "import PyInstaller, scapy, tkinter"],
                       check=True, capture_output=True)
    except Exception:
        raise SystemExit(
            "[-] 构建环境不完整：需要 PyInstaller + scapy + tkinter\n"
            f"   当前解释器：{py}\n"
            "   建议：python -m venv .buildenv && "
            ".buildenv\\Scripts\\pip install scapy pyinstaller")
    return py


def build_exe(v: dict) -> Path:
    py = ensure_env()
    vi = write_version_resource(v)
    run([py, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--onefile", "--windowed",
         "--name", "WiFiKill",
         "--icon", "wifikill.ico",
         "--version-file", str(vi),
         "--add-data", "wifikill.ico;.",
         "--hidden-import", "tray",
         "--hidden-import", "ui",
         "--hidden-import", "ipv6",
         "--collect-submodules", "scapy",
         "--collect-data", "scapy",
         "--exclude-module", "numpy",
         "--exclude-module", "matplotlib",
         "--exclude-module", "pandas",
         "--exclude-module", "PIL",
         "--exclude-module", "setuptools",
         "--exclude-module", "test",
         "gui.py"], "PyInstaller 打包")
    exe = DIST / "WiFiKill.exe"
    if not exe.exists():
        raise SystemExit("[-] 未生成 WiFiKill.exe")
    return exe


ARTIFACTS: list[Path] = []


def make_zip(v: dict, exe: Path) -> Path:
    """打包版：exe + 文档 + 许可，解压即用。"""
    out = DIST / f"WiFiKill-v{v['app']}-portable.zip"
    payload = [
        (exe, "WiFiKill.exe"),
        (ROOT / "README.md", "README.md"),
        (DOCS / "USER_MANUAL.md", "docs/USER_MANUAL.md"),
        (DOCS / "TECH_MANUAL.md", "docs/TECH_MANUAL.md"),
        (ROOT / "LICENSE.txt", "LICENSE.txt"),
    ]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in payload:
            if src.exists():
                z.write(src, arc)
            else:
                print(f"[!] 跳过缺失文件：{src}")
    return out


def make_single(v: dict, exe: Path) -> Path:
    """单文件版：只有 exe，改名带版本号。"""
    out = DIST / f"WiFiKill-v{v['app']}.exe"
    shutil.copy2(exe, out)
    return out


def find_iscc() -> str | None:
    cands = [
        r"C://Program Files (x86)//Inno Setup 6//ISCC.exe",
        r"C://Program Files//Inno Setup 6//ISCC.exe",
    ]
    for c in cands:
        if Path(c).exists():
            return c
    return None


def make_setup(v: dict) -> Path | None:
    """安装版：Inno Setup 编译，产物在 dist/。"""
    iscc = find_iscc()
    iss = ROOT / "installer" / "WiFiKill.iss"
    if not iscc:
        print("[!] 未找到 Inno Setup，跳过安装版")
        return None
    if not iss.exists():
        print("[!] 缺少 installer/WiFiKill.iss，跳过安装版")
        return None
    run([iscc, f"/DAppVersion={v['app']}", str(iss)], "编译安装程序")
    out = DIST / f"WiFiKill-v{v['app']}-setup.exe"
    return out if out.exists() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-bump", action="store_true")
    ap.add_argument("--bump", choices=("patch", "minor", "major"),
                    default="patch", help="版本递增档位，默认 patch")
    ap.add_argument("--zip-only", action="store_true")
    args = ap.parse_args()

    v = load_versions()
    if not args.no_bump:
        v["app"] = bump(v["app"], args.bump)
        bump_docs(v, args.bump)
        v["build"] = int(v.get("build", 0)) + 1
    v["released"] = dt.date.today().isoformat()
    save_versions(v)

    print(f"[*] 版本：程序 v{v['app']} | 用户手册 v{v['user_manual']} "
          f"| 技术手册 v{v['tech_manual']} | build {v['build']}")

    changed = sync_docs(v)
    if changed:
        print(f"[*] 已同步文档版本：{', '.join(changed)}")

    exe = DIST / "WiFiKill.exe"
    if not args.zip_only:
        exe = build_exe(v)
        print(f"[+] exe 生成：{exe}  ({exe.stat().st_size / 1048576:.1f} MB)")

    if exe.exists():
        single = make_single(v, exe)
        print(f"[+] 单文件版：{single.name}  ({single.stat().st_size / 1048576:.1f} MB)")
        setup = make_setup(v)
        if setup:
            print(f"[+] 安装版  ：{setup.name}  ({setup.stat().st_size / 1048576:.1f} MB)")
        zp = make_zip(v, exe)
        print(f"[+] 打包版  ：{zp.name}  ({zp.stat().st_size / 1048576:.1f} MB)")
    print(f"\n[=] 完成：v{v['app']}")


if __name__ == "__main__":
    main()

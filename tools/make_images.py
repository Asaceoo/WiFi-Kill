#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/make_images.py — 生成 README / 手册用的概念图（纯 Pillow 绘制）"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
OUT.mkdir(parents=True, exist_ok=True)

FONT_R = "C:/Windows/Fonts/msyh.ttc"
FONT_B = "C:/Windows/Fonts/msyhbd.ttc"
FONT_M = "C:/Windows/Fonts/consola.ttf"

BG = "#F2F0EC"
CARD = "#FBFAF7"
BORDER = "#E4E0D9"
TEXT = "#3A3733"
MUTED = "#87817A"
ACCENT = "#8C9E93"
ACCENT_BG = "#E7EDE8"
DANGER = "#BC8C82"
DANGER_BG = "#F2E6E3"
OK = "#8FA98B"
OK_BG = "#E8EFE6"
WARN = "#C4A785"
WARN_BG = "#F4EDE4"
DARK = "#2E2C29"


def font(size: int, bold: bool = False, mono: bool = False):
    return ImageFont.truetype(FONT_M if mono else (FONT_B if bold else FONT_R), size)


def rbox(d, xy, r, fill, outline=None, w=2):
    d.rounded_rectangle(xy, radius=r, fill=fill, outline=outline, width=w)


def center(d, box, text, f, fill):
    x0, y0, x1, y1 = box
    b = d.textbbox((0, 0), text, font=f)
    d.text(((x0 + x1 - (b[2] - b[0])) / 2, (y0 + y1 - (b[3] - b[1])) / 2 - b[1]),
           text, font=f, fill=fill)


def arrow(d, x1, y1, x2, y2, color=MUTED, w=3):
    d.line([(x1, y1), (x2, y2)], fill=color, width=w)
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    L, A = 14, 0.42
    d.polygon([(x2, y2),
               (x2 - L * math.cos(ang - A), y2 - L * math.sin(ang - A)),
               (x2 - L * math.cos(ang + A), y2 - L * math.sin(ang + A))], fill=color)


# ------------------------------------------------------------------ hero

def make_hero():
    W, H = 1280, 380
    im = Image.new("RGB", (W, H), DARK)
    d = ImageDraw.Draw(im)

    for i in range(0, W, 40):
        d.line([(i, 0), (i, H)], fill="#3A3733", width=1)
    for j in range(0, H, 40):
        d.line([(0, j), (W, j)], fill="#3A3733", width=1)

    icon = Image.open(ROOT / "wifikill.png").convert("RGBA").resize((132, 132), Image.LANCZOS)
    im.paste(icon, (84, 124), icon)

    d.text((250, 112), "WiFiKill", font=font(74, bold=True), fill="#FFFFFF")
    d.text((254, 200), "局域网设备发现与 ARP 阻断工具", font=font(30), fill="#C9C3BA")
    d.text((254, 248), "Windows GUI  ·  单文件免安装  ·  ARP 层阻断，不受 WPA3 / PMF 影响",
           font=font(20), fill="#9A948B")

    badge_f = font(19, bold=True)
    x = 254
    for txt, fg, bgc in (("设备发现", "#7DD3FC", "#1B2A3A"),
                         ("双向阻断", "#FCA5A5", "#2E1E22"),
                         ("白名单", "#C4B5FD", "#241F33"),
                         ("崩溃自恢复", "#86EFAC", "#1B2E24")):
        b = d.textbbox((0, 0), txt, font=badge_f)
        w = b[2] - b[0] + 28
        rbox(d, (x, 300, x + w, 340), 8, bgc)
        center(d, (x, 300, x + w, 340), txt, badge_f, fg)
        x += w + 12

    im.save(OUT / "hero.png")


# ------------------------------------------------------------------ 架构

def make_arch():
    W, H = 1280, 620
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    d.text((60, 40), "三层架构", font=font(34, bold=True), fill=TEXT)
    d.text((60, 88), "界面只负责渲染，所有网络动作都在工作线程里执行", font=font(20), fill=MUTED)

    layers = [
        ("表现层  gui.py", ACCENT_BG, ACCENT, [
            ("主窗口 Tkinter", "设备表 / 状态灯 / 日志"),
            ("交互入口", "按钮 · 右键 · 双击"),
            ("线程编排", "after 队列回主线程"),
        ]),
        ("逻辑层  core.py", OK_BG, OK, [
            ("发现", "ARP 扫描 + 缓存合并"),
            ("投毒", "双向伪造 + 定时重发"),
            ("状态", "原子写 + 单实例锁"),
        ]),
        ("系统层", WARN_BG, WARN, [
            ("Npcap / wpcap.dll", "二层帧收发"),
            ("无线网卡", "Intel / MediaTek / ..."),
            ("系统 ARP 表", "arp -a 只读兜底"),
        ]),
    ]

    y = 150
    for name, bg, fg, items in layers:
        rbox(d, (60, y, 1220, y + 128), 14, CARD, BORDER, 2)
        rbox(d, (60, y, 300, y + 128), 14, bg)
        center(d, (60, y, 300, y + 128), name, font(23, bold=True), fg)
        for i, (t1, t2) in enumerate(items):
            bx = 330 + i * 300
            d.text((bx, y + 34), t1, font=font(21, bold=True), fill=TEXT)
            d.text((bx, y + 72), t2, font=font(18), fill=MUTED)
        y += 160

    for yy in (278, 438):
        arrow(d, 640, yy - 14, 640, yy + 16, ACCENT, 3)

    im.save(OUT / "arch.png")


# ------------------------------------------------------------------ 流程

def make_flow():
    W, H = 1280, 400
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    d.text((60, 36), "一次阻断的完整生命周期", font=font(34, bold=True), fill=TEXT)
    d.text((60, 84), "任何出口都会回到「恢复」，不会把人永久断网", font=font(20), fill=MUTED)

    steps = [("1  扫描", "ARP 请求 + 缓存", ACCENT_BG, ACCENT),
             ("2  选择目标", "单选 / 多选 / 全选", ACCENT_BG, ACCENT),
             ("3  构造报文", "双向 ARP 应答", WARN_BG, WARN),
             ("4  周期投毒", "默认 1.5s 重发", DANGER_BG, DANGER),
             ("5  恢复", "回填真实 MAC", OK_BG, OK)]

    bw, gap = 208, 46
    x = 60
    for i, (t1, t2, bg, fg) in enumerate(steps):
        rbox(d, (x, 160, x + bw, 250), 12, bg)
        center(d, (x, 168, x + bw, 208), t1, font(21, bold=True), fg)
        center(d, (x, 208, x + bw, 242), t2, font(17), MUTED)
        if i < len(steps) - 1:
            arrow(d, x + bw + 6, 205, x + bw + gap - 10, 205, "#9AA6B8", 3)
        x += bw + gap

    bx0, bx1 = 736, 1116
    rbox(d, (bx0, 292, bx1, 356), 12, CARD, BORDER, 2)
    center(d, (bx0, 292, bx1, 356), "Ctrl+C / 关闭窗口 / 异常退出", font(19), TEXT)
    arrow(d, 926, 292, 926, 262, "#9AA6B8", 3)
    d.text((bx0, 366), "任何中断都会先执行「恢复」再退出", font=font(17), fill=MUTED)

    im.save(OUT / "flow.png")


# ------------------------------------------------------------------ 安全

def make_safety():
    W, H = 1280, 340
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    d.text((60, 36), "四道安全护栏", font=font(34, bold=True), fill=TEXT)
    d.text((60, 84), "宁可少断一个，也不误断一片", font=font(20), fill=MUTED)

    items = [("网关保护", "阻断网关会切断全网，默认拒绝", DANGER_BG, DANGER),
             ("本机保护", "自己永远不在候选列表里", ACCENT_BG, ACCENT),
             ("白名单", "IP 与 MAC 双键匹配，改 IP 也认", OK_BG, OK),
             ("崩溃恢复", "状态落盘，下次启动提示恢复", WARN_BG, WARN)]

    bw, gap = 282, 24
    x = 60
    for t1, t2, bg, fg in items:
        rbox(d, (x, 150, x + bw, 296), 14, CARD, BORDER, 2)
        rbox(d, (x, 150, x + bw, 196), 14, bg)
        center(d, (x, 150, x + bw, 196), t1, font(22, bold=True), fg)
        for k, line in enumerate(_wrap(t2, 15)):
            d.text((x + 22, 216 + k * 30), line, font=font(18), fill=MUTED)
        x += bw + gap

    im.save(OUT / "safety.png")


def _wrap(s: str, n: int) -> list[str]:
    return [s[i:i + n] for i in range(0, len(s), n)] or [""]


# ------------------------------------------------------------------ 界面标注

def make_ui():
    src = ROOT / "screenshot.png"
    if not src.exists():
        return
    shot = Image.open(src).convert("RGB")
    scale = 1180 / shot.width
    shot = shot.resize((1180, int(shot.height * scale)), Image.LANCZOS)

    W = 1180
    H = shot.height + 340
    im = Image.new("RGB", (W, H), BG)
    im.paste(shot, (0, 120))
    d = ImageDraw.Draw(im)
    d.text((40, 34), "界面说明", font=font(32, bold=True), fill=TEXT)
    d.text((40, 78), "所有操作都能在不看文档的情况下完成", font=font(19), fill=MUTED)

    legend = [
        ("环境状态徽章", "绿点=就绪，黄点=缺依赖或 IPv6 未覆盖", ACCENT),
        ("网络信息条", "网卡 / 本机 / 网关 / 网段", ACCENT),
        ("功能按钮组", "扫描、阻断选中、全阻断、全部放行", DANGER),
        ("设备表", "状态列实时反映：网关 / 本机 / 白名单 / 阻断中", OK),
        ("运行日志", "每次扫描与阻断都有时间戳记录", WARN),
        ("状态汇总", "设备总数与当前阻断数", MUTED),
    ]
    y = shot.height + 150
    for i, (t1, t2, c) in enumerate(legend):
        col, row = i % 3, i // 3
        x = 40 + col * 380
        yy = y + row * 78
        d.ellipse([x, yy + 8, x + 14, yy + 22], fill=c)
        d.text((x + 26, yy), t1, font=font(20, bold=True), fill=TEXT)
        d.text((x + 26, yy + 30), t2, font=font(16), fill=MUTED)

    im.save(OUT / "ui.png")


def make_guard():
    W, H = 1280, 372
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)

    d.text((60, 36), "本机守护（主动防御）", font=font(34, bold=True), fill=TEXT)
    d.text((60, 84), "不攻击任何人，只保证「网关 IP/LLA → 真实网关 MAC」不被篡改",
           font=font(20), fill=MUTED)

    steps = [("① 建立基准", "扫描缓存 + 实时询问双源一致才采纳，分歧即 fail closed", ACCENT_BG, ACCENT),
             ("② 周期监测", "每 2 秒核对本机 ARP / NDP 缓存里的网关映射", WARN_BG, WARN),
             ("③ 去抖判定", "连续 2 次漂移才判定投毒，瞬时抖动不误报", OK_BG, OK),
             ("④ 双路纠正", "广播真实映射护他人；arp -d 删脏缓存护本机", DANGER_BG, DANGER)]
    bw, gap = 282, 24
    x = 60
    for t1, t2, bg, fg in steps:
        rbox(d, (x, 140, x + bw, 306), 14, CARD, BORDER, 2)
        rbox(d, (x, 140, x + bw, 190), 14, bg)
        center(d, (x, 140, x + bw, 190), t1, font(22, bold=True), fg)
        yy = 210
        for line in _wrap(t2, 13):
            d.text((x + 20, yy), line, font=font(18), fill=MUTED)
            yy += 30
        if x + bw + gap < W - 80:
            arrow(d, x + bw + 3, 224, x + bw + gap - 3, 224)
        x += bw + gap

    d.text((60, 326), "网络切换自动重估基准  ·  广播帧不回环本机协议栈，故本机自愈靠「删除 → 重新解析」",
           font=font(18), fill=DANGER)
    im.save(OUT / "guard.png")


if __name__ == "__main__":
    make_hero()
    make_arch()
    make_flow()
    make_safety()
    make_guard()
    make_ui()
    for p in sorted(OUT.glob("*.png")):
        print(f"  {p.name:12s} {p.stat().st_size // 1024} KB")
    print("images ok")

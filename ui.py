#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ui.py — 视觉层组件：莫兰迪配色、圆角绘制、Canvas 按钮、动画缓动

Tkinter 没有圆角和阴影，这里全部用 Canvas 自绘：
  - 圆角矩形：smooth 多边形的经典解法
  - 按钮：整块画在 Canvas 上，逐帧插值颜色做 hover / press 动画
  - 卡片：在背景 Canvas 上画，内容控件用 place() 摆进去
"""

from __future__ import annotations

import math
import tkinter as tk

# ---------------------------------------------------------------- 莫兰迪色板

BG        = "#F2F0EC"   # 页面底：暖白
CARD      = "#FBFAF7"   # 卡片面
CARD_ALT  = "#F6F4F0"   # 次级面
LINE      = "#E4E0D9"   # 分隔线
LINE_SOFT = "#EDEAE4"   # 更浅的分隔
SHADOW    = "#E7E3DB"   # 伪阴影

TEXT      = "#3A3733"   # 主文字
TEXT2     = "#87817A"   # 次文字
TEXT3     = "#ADA79F"   # 提示文字

SAGE      = "#8C9E93"   # 主色：灰绿
SAGE_DK   = "#77897E"
SAGE_BG   = "#E7EDE8"

ROSE      = "#BC8C82"   # 危险：灰玫瑰
ROSE_DK   = "#A8796F"
ROSE_BG   = "#F2E6E3"

OLIVE     = "#8FA98B"   # 成功：灰橄榄
OLIVE_BG  = "#E8EFE6"

SAND      = "#C4A785"   # 提示：灰驼
SAND_BG   = "#F4EDE4"
SAND_DK   = "#8A7255"   # 提示文字：驼色加深，保证在 SAND_BG 上可读

STONE     = "#9A958E"   # 中性
STONE_BG  = "#ECEAE5"

BLUSH     = "#B9A5A0"   # 白名单：灰藕
BLUSH_BG  = "#EFE8E6"


def mix(c1: str, c2: str, t: float) -> str:
    """颜色线性插值，t=0 取 c1，t=1 取 c2。"""
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{int(a[i] + (b[i] - a[i]) * t):02x}" for i in range(3))


def ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


# ---------------------------------------------------------------- 绘图基元

def rrect(cv: tk.Canvas, x0, y0, x1, y1, r=12, **kw):
    """圆角矩形：把四角拆成重复点交给 smooth 样条。"""
    r = min(r, abs(x1 - x0) / 2, abs(y1 - y0) / 2)
    pts = [
        x0 + r, y0, x1 - r, y0, x1, y0,
        x1, y0 + r, x1, y1 - r, x1, y1,
        x1 - r, y1, x0 + r, y1, x0, y1,
        x0, y1 - r, x0, y0 + r, x0, y0,
    ]
    return cv.create_polygon(pts, smooth=True, splinesteps=24, **kw)


def card(cv: tk.Canvas, x0, y0, x1, y1, r=16, lift=2, lit=True, **kw):
    """画一张带极淡底影的卡片，返回 (阴影ids, 面ids)。

    lit=True 时在卡片上沿画一条比底色更亮的细线 —— Canvas 没有模糊，
    这条「受光边」是最省成本的高光表现。
    """
    sh = rrect(cv, x0, y0 + lift, x1, y1 + lift, r,
               fill=SHADOW, outline="", **kw)
    face = rrect(cv, x0, y0, x1, y1, r, fill=CARD, outline=LINE, width=1, **kw)
    if lit:
        cv.create_line(x0 + r, y0 + 1, x1 - r, y0 + 1,
                       fill=mix(CARD, "#FFFFFF", 0.85), width=1, **kw)
    return sh, face


def halo_ring(cv: tk.Canvas, color: str, width: int = 1):
    """创建一条光晕环（不可见），由调用方驱动位置与颜色。"""
    return cv.create_oval(0, 0, 0, 0, outline=color, width=width, fill="")


def shine_edge(cv: tk.Canvas, x0: float, x1: float, y: float,
               color: str = "#FFFFFF", span: float = 90, ms: int = 2600):
    """沿一条水平边扫过的高光，用来表示「正在刷新」。

    返回 job id；调用方可在需要时 cv.delete(item) 或让它自然结束。
    """
    try:
        oid = cv.create_line(x0, y, x0 + span, y, fill=color, width=2,
                             capstyle="round")
    except tk.TclError:
        return None
    total = max(1, int(ms / 24))
    state = {"i": 0}

    def tick():
        try:
            state["i"] += 1
            t = state["i"] / total
            if t >= 1:
                cv.delete(oid)
                return
            x = x0 + (x1 - x0 - span) * ease_out(t)
            cv.coords(oid, x, y, x + span, y)
            cv.itemconfig(oid, fill=mix(color, LINE_SOFT, min(1.0, t * 0.9)))
            cv.after(24, tick)
        except tk.TclError:
            pass

    tick()
    return oid


def hline(cv, x0, x1, y, color=LINE_SOFT):
    return cv.create_line(x0, y, x1, y, fill=color)


# ---------------------------------------------------------------- Canvas 按钮

class CanvasButton:
    """画在 Canvas 上的按钮：圆角、hover 过渡、按下反馈、禁用态。"""

    _registry: list["CanvasButton"] = []

    def __init__(self, cv: tk.Canvas, text: str, x: int, y: int, w: int, h: int,
                 command=None, kind: str = "primary", radius: int = 10,
                 font=("Microsoft YaHei UI", 10), pad: int = 18):
        self.cv = cv
        self.text = text
        self.command = command
        self.kind = kind
        self.x, self.y, self.w, self.h = x, y, w, h
        self.r = radius
        self.font = font
        self.enabled = True
        self._hover = 0.0          # 0..1
        self._press = 0.0
        self._anim = None

        base, hover, fg, bd = self._palette(kind)
        self._c_base, self._c_hover, self._c_fg, self._c_bd = base, hover, fg, bd

        self.bg = rrect(cv, x, y, x + w, y + h, radius, fill=base,
                        outline=bd or "", width=1 if bd else 0)
        self.label = cv.create_text(x + w / 2, y + h / 2, text=text,
                                    font=font, fill=fg)
        self._glow: list[int] = []
        self._tag = f"btn{id(self)}"
        cv.itemconfig(self.bg, tags=(self._tag,))
        cv.itemconfig(self.label, tags=(self._tag,))
        cv.tag_bind(self._tag, "<Enter>", lambda e: self._to(1.0))
        cv.tag_bind(self._tag, "<Leave>", lambda e: self._to(0.0))
        cv.tag_bind(self._tag, "<ButtonPress-1>", self._down)
        cv.tag_bind(self._tag, "<ButtonRelease-1>", self._up)
        CanvasButton._registry.append(self)

    @staticmethod
    def _palette(kind):
        return {
            "primary": (SAGE, SAGE_DK, "#FFFFFF", ""),
            "danger":  (ROSE, ROSE_DK, "#FFFFFF", ""),
            "ok":      (OLIVE_BG, "#DCE7DA", "#4E6B4A", ""),
            "ghost":   (CARD_ALT, "#EEEAE3", TEXT2, LINE),
            "quiet":   (BG, "#EAE7E1", TEXT2, ""),
        }.get(kind, (CARD_ALT, "#EEEAE3", TEXT, LINE))

    # --- 状态 ---

    def set_enabled(self, on: bool):
        self.enabled = bool(on)
        if not on:
            self._hover = 0.0
            self.cv.itemconfig(self.bg, fill=mix(CARD_ALT, BG, 0.5))
            self.cv.itemconfig(self.label, fill=TEXT3)
        else:
            self.cv.itemconfig(self.bg, fill=self._c_base)
            self.cv.itemconfig(self.label, fill=self._c_fg)

    def set_text(self, t: str):
        self.text = t
        self.cv.itemconfig(self.label, text=t)

    # --- 动画 ---

    def _to(self, target: float):
        if not self.enabled:
            return
        self._animate(self._hover, target, "_hover", 120)

    def _animate(self, start, end, attr, ms):
        if self._anim:
            try:
                self.cv.after_cancel(self._anim)
            except Exception:
                pass
        steps = max(1, ms // 16)
        state = {"i": 0}

        def tick():
            state["i"] += 1
            t = state["i"] / steps
            val = start + (end - start) * ease_out(t)
            setattr(self, attr, val)
            self._render()
            if state["i"] < steps:
                self._anim = self.cv.after(16, tick)
            else:
                self._anim = None
        tick()

    def _render(self):
        if not self.enabled:
            return
        # hover 时在按钮外围叠两层极淡的光环（Canvas 无模糊，用叠色模拟辉光）
        if self._hover > 0.02:
            if not self._glow:
                try:
                    for k in range(2):
                        pad = 3 + k * 3
                        oid = rrect(self.cv, self.x - pad, self.y - pad,
                                    self.x + self.w + pad, self.y + self.h + pad,
                                    self.r + pad, fill="",
                                    outline=self._c_base, width=2)
                        self.cv.tag_lower(oid, self.bg)
                        self._glow.append(oid)
                except tk.TclError:
                    self._glow = []
            for k, oid in enumerate(self._glow):
                t = self._hover * (0.42 - k * 0.16)
                self.cv.itemconfig(oid, outline=mix(CARD, self._c_hover, t))
        elif self._glow:
            for oid in self._glow:
                try:
                    self.cv.delete(oid)
                except tk.TclError:
                    pass
            self._glow = []

        base = mix(self._c_base, self._c_hover, self._hover)
        if self._press > 0:
            base = mix(base, "#000000", 0.06 * self._press)
        self.cv.itemconfig(self.bg, fill=base)
        self.cv.coords(self.label,
                       self.x + self.w / 2, self.y + self.h / 2 + self._press)

    def _down(self, _e):
        if not self.enabled:
            return
        self._press = 1
        self._render()

    def _up(self, e):
        if not self.enabled:
            return
        self._press = 0
        self._render()
        try:
            ripple(self.cv, e.x, e.y, self._c_hover, self._c_base,
                   r0=6, r1=max(self.w, self.h) * 0.62, ms=420)
        except Exception:
            pass
        if self.command:
            self.command()


# ---------------------------------------------------------------- 状态点

class StatusDot:
    """带呼吸动画的状态圆点。"""

    def __init__(self, cv, x, y, r=5, color=OLIVE):
        self.cv = cv
        self.x, self.y, self.r = x, y, r
        self.color = color
        self.id = cv.create_oval(x - r, y - r, x + r, y + r,
                                 fill=color, outline="")
        self._pulse = None
        self._halo = None
        self._on = False

    def set(self, color: str, pulse: bool = False):
        self.color = color
        self.cv.itemconfig(self.id, fill=color)
        if pulse and not self._on:
            self._start_pulse()
        elif not pulse:
            self._stop_pulse()

    def move(self, x, y):
        self.x, self.y = x, y
        self.cv.coords(self.id, x - self.r, y - self.r, x + self.r, y + self.r)

    def _start_pulse(self):
        self._on = True
        state = {"t": 0.0}
        try:
            self._halo = halo_ring(self.cv, self.color, width=1)
        except tk.TclError:
            self._halo = None

        def tick():
            if not self._on:
                return
            state["t"] = (state["t"] + 0.045) % (math.pi * 2)
            k = 0.5 + 0.5 * math.sin(state["t"])
            r = self.r * (1 + 0.32 * k)
            self.cv.coords(self.id, self.x - r, self.y - r,
                           self.x + r, self.y + r)
            # 光晕：一圈随时间向外扩散并淡到底色
            if self._halo:
                ph = state["t"] / (math.pi * 2)
                hr = self.r * (1.4 + 3.0 * ph)
                self.cv.coords(self._halo, self.x - hr, self.y - hr,
                               self.x + hr, self.y + hr)
                self.cv.itemconfig(self._halo,
                                   outline=mix(self.color, BG, min(1.0, ph * 1.05)))
            self._pulse = self.cv.after(40, tick)
        tick()

    def _stop_pulse(self):
        self._on = False
        if self._pulse:
            try:
                self.cv.after_cancel(self._pulse)
            except Exception:
                pass
            self._pulse = None
        self.cv.coords(self.id, self.x - self.r, self.y - self.r,
                       self.x + self.r, self.y + self.r)
        if self._halo:
            try:
                self.cv.delete(self._halo)
            except tk.TclError:
                pass
            self._halo = None


# ---------------------------------------------------------------- 进度条

class Shimmer:
    """扫描时的细长流动进度条，不占布局空间，直接画在 Canvas 上。"""

    def __init__(self, cv, y, x0, x1, color=SAGE):
        self.cv, self.y, self.x0, self.x1 = cv, y, x0, x1
        self.color = color
        self.track = cv.create_line(x0, y, x1, y, fill=LINE_SOFT, width=3,
                                    capstyle="round", state="hidden")
        self.bar = cv.create_line(x0, y, x0 + 60, y, fill=color, width=3,
                                  capstyle="round", state="hidden")
        self._job = None
        self._t = 0.0

    def start(self):
        self.cv.itemconfig(self.track, state="normal")
        self.cv.itemconfig(self.bar, state="normal")
        self._t = 0.0

        def tick():
            w = self.x1 - self.x0
            span = max(80, w * 0.32)
            self._t += 0.028
            p = (math.sin(self._t) + 1) / 2
            x = self.x0 + p * (w - span)
            self.cv.coords(self.bar, x, self.y, x + span, self.y)
            self._job = self.cv.after(24, tick)
        tick()

    def stop(self):
        if self._job:
            try:
                self.cv.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        self.cv.itemconfig(self.track, state="hidden")
        self.cv.itemconfig(self.bar, state="hidden")


# ---------------------------------------------------------------- 动画调度

class Anim:
    """极小的动画调度器。

    集中登记 after id，窗口销毁时一把取消 —— 否则 after 回调会在控件销毁后
    继续触发，抛 "invalid command name" 的 TclError（这是 Tk 动画最常见的坑）。
    """

    def __init__(self, widget):
        self.w = widget
        self._ids: list[str] = []
        self._dead = False

    def after(self, ms: int, fn, *args):
        if self._dead:
            return None
        try:
            jid = self.w.after(ms, fn, *args)
        except tk.TclError:
            return None
        self._ids.append(jid)
        if len(self._ids) > 300:                 # 剪掉已经触发过的，避免无限增长
            self._ids = self._ids[-120:]
        return jid

    def cancel_all(self):
        self._dead = True
        for jid in self._ids:
            try:
                self.w.after_cancel(jid)
            except Exception:
                pass
        self._ids.clear()


# ---------------------------------------------------------------- 点击波纹

def ripple(cv: tk.Canvas, x: float, y: float, color: str, bg: str,
           r0: float = 8, r1: float = 52, ms: int = 420, steps: int = 14):
    """点击位置扩散一圈涟漪，颜色由 color 渐隐到 bg，结束后自行删除。

    Canvas 没有 alpha，所以用「颜色向背景混合」模拟淡出。
    """
    try:
        oid = cv.create_oval(x - r0, y - r0, x + r0, y + r0,
                             outline=color, width=2, fill="")
    except tk.TclError:
        return

    def tick(i: int = 0):
        try:
            if i > steps:
                cv.delete(oid)
                return
            t = i / steps
            r = r0 + (r1 - r0) * ease_out(t)
            cv.coords(oid, x - r, y - r, x + r, y + r)
            cv.itemconfig(oid, outline=mix(color, bg, min(1.0, t * 1.15)))
            cv.after(int(ms / steps), tick, i + 1)
        except tk.TclError:
            pass

    tick()


def slide_in(cv: tk.Canvas, ids, dy: float = -12, ms: int = 200, steps: int = 12):
    """把一批已画好的元素从上方滑入原位。ids 是 canvas item id 列表。"""
    ids = [i for i in ids if i]
    if not ids:
        return
    dx = 0.0
    step = dy / steps

    def tick(i: int = 0):
        try:
            if i >= steps:
                return
            for oid in ids:
                cv.move(oid, dx, -step)     # step 的符号与 dy 一致，取负即为「回到原位」
            cv.after(int(ms / steps), tick, i + 1)
        except tk.TclError:
            pass

    for oid in ids:
        try:
            cv.move(oid, 0, dy)
        except tk.TclError:
            return
    tick()

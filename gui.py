#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui.py — WiFiKill 图形界面（Canvas 自绘 · 莫兰迪风格）

设计要点：
  · 整窗只有一个 Canvas 作为画布，卡片/按钮/文字全部自绘，才能做出圆角与动效
  · 真正需要原生控件的只有三处：设备表(Treeview)、日志(Text)、滚动条
  · 所有网络操作仍在工作线程，结果经队列回主线程，界面不卡
"""

from __future__ import annotations

import math
import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from tkinter import messagebox, simpledialog, ttk

import core
import ui

NPCAP_URL = "https://npcap.com/#download"


def pick_family():
    fams = set(tkfont.families())
    for name in ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "SimHei"):
        if name in fams:
            return name
    return "TkDefaultFont"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"WiFiKill {core.APP_VERSION}")
        self.geometry("1320x980")
        self.minsize(1180, 860)
        self.configure(bg=ui.BG)
        ico = core.resource_path("wifikill.ico")
        if ico:
            try:
                self.iconbitmap(default=ico)
            except Exception:
                pass

        fam = pick_family()
        # 字号按用户反馈第二轮放大：正文 14，辅助 13，最小 12
        self.F = {
            "h1": (fam, 32), "sub": (fam, 14), "body": (fam, 14),
            "small": (fam, 13), "tiny": (fam, 12),
            "k": (fam, 13), "v": (fam, 16), "mono": ("Consolas", 13),
        }

        self._q: queue.Queue = queue.Queue()
        self._busy = False
        self._devices: list[core.Device] = []
        self._net = core.NetInfo()
        self._killer: core.Killer | None = None
        self._whitelist: set[str] = core.load_whitelist()
        self._aliases: dict[str, str] = core.load_aliases()
        self._closing = False
        self._destroyed = False
        self._main_thread = threading.current_thread()  # log/set_status 必须回主线程
        self._opts = (1.5, False)
        self._ndp_on = False              # IPv6 阻断开关，默认关（两道门之一）
        self._v6env = None                # ipv6.V6Env，扫描后探测
        import ipv6 as _v6mod
        self._ndp_mgr = _v6mod.NdpManager()   # 多目标 IPv6 阻断管理器
        self._guard = core.Guard(self._net, interval=2.0, dry_run=self._opts[1])
        self._guard_on = core.guard_enabled()   # 本机守护（主动防御）开关，持久化
        self._sentinel = core.Sentinel(notify=self._sentinel_notify)  # 全网哨兵（v2.5.0）
        self._guard.event_sink = self._sentinel.feed_event
        self._tray = None
        self._tray_hinted = False
        self._quitting = False
        self._banner_state: tuple[str, str] | None = None
        self._ui = ui.Anim(self)
        self._row_gen = 0
        self._foot_item = None
        self._foot_shown = 0
        self._breath_job = None
        self._status_text = "就绪"
        self._wl_hidden = False
        self._geo = {"w": 1300, "h": 940, "P": 36}

        self._lock_holder = core.SingleInstance()
        if not self._lock_holder.acquire():
            self.withdraw()
            messagebox.showwarning("已在运行", "检测到另一个 WiFiKill 实例。\n"
                                               "多开会导致状态文件互相覆盖，请先关闭它。")
            self._destroyed = True
            self.destroy()
            raise SystemExit(0)

        self._build()
        core.LOG.subscribe(self._log_sink)
        self.after(70, self._drain)
        self.after(130, self._init_tray)
        self.after(180, self._bootstrap)
        self.after(40, self._fade_in)

    # ------------------------------------------------------------ 构建

    def _build(self):
        self.canvas = tk.Canvas(self, bg=ui.BG, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self._relayout(e.width, e.height))
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._init_style()
        self._make_tree()
        self._make_log()
        self._make_menu()
        self._make_buttons()

    def _init_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("M.Treeview", background=ui.CARD, fieldbackground=ui.CARD,
                     foreground=ui.TEXT, rowheight=44, borderwidth=0,
                     font=self.F["body"])
        st.configure("M.Treeview.Heading", background=ui.CARD,
                     foreground=ui.TEXT3, font=self.F["tiny"], relief="flat",
                     padding=(10, 12))
        st.map("M.Treeview", background=[("selected", ui.SAGE_BG)],
               foreground=[("selected", ui.TEXT)])
        st.map("M.Treeview.Heading", background=[("active", ui.CARD)])
        st.layout("M.Treeview", [("M.Treeview.treearea", {"sticky": "nswe"})])
        st.configure("M.Vertical.TScrollbar", background=ui.CARD_ALT,
                     troughcolor=ui.CARD, borderwidth=0, arrowsize=0, width=8)
        st.map("M.Vertical.TScrollbar", background=[("active", ui.LINE)])

    def _make_tree(self):
        self.tree = ttk.Treeview(self.canvas, style="M.Treeview",
                                 columns=("no", "ip", "mac", "vendor",
                                          "dtype", "mark", "state", "_sp"),
                                 show="headings", selectmode="extended")
        heads = {"no": "#", "ip": "IP 地址", "mac": "MAC 地址",
                 "vendor": "厂商", "dtype": "类型", "mark": "标识",
                 "state": "状态", "_sp": ""}
        widths = {"no": 50, "ip": 142, "mac": 168, "vendor": 172,
                  "dtype": 94, "mark": 120, "state": 106, "_sp": 36}
        for c in heads:
            self.tree.heading(c, text=heads[c], anchor="w")
            self.tree.column(c, width=widths[c], minwidth=widths[c] - 24,
                             anchor="w", stretch=(c == "_sp"))
        self.tree.tag_configure("blocked", foreground=ui.ROSE_DK)
        self.tree.tag_configure("gw", foreground=ui.TEXT3)
        self.tree.tag_configure("me", foreground=ui.SAGE_DK)
        self.tree.tag_configure("wl", foreground=ui.BLUSH)
        self.tree.tag_configure("flash", background=ui.SAGE_BG)
        self.tree.tag_configure("v4only", foreground=getattr(ui, "SAND_DK", ui.SAND))

        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>", self._on_right)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_buttons())

        self.vsb = ttk.Scrollbar(self.canvas, orient="vertical",
                                 command=self.tree.yview,
                                 style="M.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=self.vsb.set)

    def _make_log(self):
        self._logwrap = tk.Frame(self.canvas, bg=ui.CARD, bd=0, highlightthickness=0)
        self.logtext = tk.Text(self._logwrap, height=5, bg=ui.CARD, fg=ui.TEXT2,
                               font=self.F["mono"], relief="flat", bd=0,
                               wrap="none", state="disabled", padx=0, pady=0,
                               insertbackground=ui.TEXT, spacing1=2, spacing3=2)
        self.logtext.pack(fill="both", expand=True)
        for lv, c in (("info", ui.TEXT2), ("ok", ui.OLIVE), ("warn", ui.SAND),
                      ("err", ui.ROSE_DK), ("debug", ui.TEXT3)):
            self.logtext.tag_configure(lv, foreground=c)
        self.logtext.tag_configure("fresh", background=ui.SAGE_BG)

    def _make_menu(self):
        self.menu = tk.Menu(self, tearoff=0, font=self.F["body"], bg=ui.CARD,
                            fg=ui.TEXT, activebackground=ui.SAGE_BG,
                            activeforeground=ui.TEXT, bd=0, relief="flat")

    def _make_buttons(self):
        cv = self.canvas
        b = self.F["small"]
        f = self.F["body"]
        self.btn_env = ui.CanvasButton(cv, "环境自检", 0, 0, 92, 34,
                                       command=self._show_env, kind="ghost", font=b)
        self.btn_set = ui.CanvasButton(cv, "设置", 0, 0, 68, 34,
                                       command=self._open_settings, kind="ghost", font=b)
        self.btn_scan = ui.CanvasButton(cv, "扫描设备", 0, 0, 118, 38,
                                        command=self.do_scan, kind="primary", font=f)
        self.btn_block = ui.CanvasButton(cv, "阻断选中", 0, 0, 112, 38,
                                         command=lambda: self.do_block(False),
                                         kind="danger", font=f)
        self.btn_all = ui.CanvasButton(cv, "全阻断", 0, 0, 96, 38,
                                       command=lambda: self.do_block(True),
                                       kind="danger", font=f)
        self.btn_free = ui.CanvasButton(cv, "全部放行", 0, 0, 112, 38,
                                        command=self.do_unblock_all, kind="ok", font=f)
        self.btn_sel_all = ui.CanvasButton(cv, "全选", 0, 0, 56, 34,
                                           command=self._select_all, kind="ghost", font=b)
        self.btn_sel_inv = ui.CanvasButton(cv, "反选", 0, 0, 56, 34,
                                           command=self._select_invert, kind="ghost", font=b)
        self.btn_verify = ui.CanvasButton(cv, "验证断网", 0, 0, 96, 34,
                                          command=self.do_verify, kind="ghost", font=b)
        self.btn_guard = ui.CanvasButton(cv, "守护本机", 0, 0, 92, 34,
                                         command=self._toggle_guard, kind="ghost", font=b)
        for x in (self.btn_scan, self.btn_block, self.btn_all, self.btn_free,
                  self.btn_verify):
            x.set_enabled(False)

        self._badge_dot = None
        self._shimmer = ui.Shimmer(cv, 0, 0, 0)

    # ------------------------------------------------------------ 布局

    def _relayout(self, w: int, h: int):
        if w < 300 or h < 300 or not hasattr(self, "btn_scan"):
            return
        P = 32
        self._geo = {"w": w, "h": h, "P": P}
        cv = self.canvas
        cv.delete("static")

        cv.create_text(P, 40, text="WiFiKill", anchor="w",
                       font=self.F["h1"], fill=ui.TEXT, tags="static")
        cv.create_text(P + 1, 66, text="局域网设备与阻断控制", anchor="w",
                       font=self.F["sub"], fill=ui.TEXT2, tags="static")
        # 标题下的一道强调线：首次渲染从 0 生长到全宽（只播一次，重排不再重放）
        acc_w = 118
        acc = cv.create_line(P, 58, P + acc_w, 58, fill=ui.SAGE,
                             width=3, capstyle="round", tags="static")
        if not getattr(self, "_title_grown", False):
            self._title_grown = True

            def _grow(i: int = 0):
                if self._destroyed:
                    return
                t = i / 10
                try:
                    cv.coords(acc, P, 58, P + acc_w * ui.ease_out(t), 58)
                except tk.TclError:
                    return
                if i < 10:
                    self._ui.after(22, _grow, i + 1)
            _grow()

        self.btn_set.x = w - P - 68
        self.btn_env.x = self.btn_set.x - 8 - 92
        for btn in (self.btn_env, self.btn_set):
            btn.y = 30
            self._place_btn(btn)

        sx = self.btn_env.x - 22
        if self._badge_dot is None:
            self._badge_dot = ui.StatusDot(cv, sx, 47, 5, ui.OLIVE)
        else:
            self._badge_dot.move(sx, 47)
        cv.create_text(sx - 10, 47, text=self._status_text, anchor="e",
                       font=self.F["small"], fill=ui.TEXT2,
                       tags=("static", "badgetext"))

        by = 96
        if self._banner_state:
            kind, text = self._banner_state
            bgc = ui.SAND_BG if kind != "info" else ui.SAGE_BG
            fgc = getattr(ui, "SAND_DK", ui.SAND) if kind != "info" else ui.SAGE_DK
            # 只有内容变了才播滑入，否则每次窗口重排都要重放一遍，很吵
            sig = (kind, text)
            fresh = sig != getattr(self, "_banner_sig", None)
            self._banner_sig = sig
            dy = -10 if fresh else 0
            ids = [
                ui.rrect(cv, P, by + dy, w - P, by + 34 + dy, 12, fill=bgc,
                         outline="", tags="static"),
                cv.create_text(P + 16, by + 17 + dy, text=text, anchor="w",
                               font=self.F["small"], fill=fgc, tags="static"),
            ]
            if kind == "npcap":
                ids.append(cv.create_text(
                    w - P - 16, by + 17 + dy, text="打开下载页 →",
                    anchor="e", font=self.F["small"], fill=fgc,
                    tags=("static", "bannerlink")))
                cv.tag_bind("bannerlink", "<Button-1>",
                            lambda e: webbrowser.open(NPCAP_URL))
            if dy:
                self._ui.after(8, lambda i=list(ids), d=dy: ui.slide_in(cv, i, d, ms=180))
            ny = by + 48
        else:
            self._banner_sig = None
            ny = 92

        card_h = 134
        ui.card(cv, P, ny, w - P, ny + card_h, 16, tags="static")
        cols = [("iface", "网卡"), ("ip", "本机"), ("gw", "网关"), ("cidr", "网段")]
        inner_w = (w - P * 2 - 44) / 4
        self._net_items = {}
        for i, (key, cap) in enumerate(cols):
            cx = P + 22 + i * inner_w
            cv.create_text(cx, ny + 30, text=cap, anchor="w",
                           font=self.F["k"], fill=ui.TEXT3, tags="static")
            main = cv.create_text(cx, ny + 68, text="—", anchor="w",
                                  width=inner_w - 14, font=self.F["v"],
                                  fill=ui.TEXT, tags="static")
            sub = cv.create_text(cx, ny + 102, text="", anchor="w",
                                 width=inner_w - 14, font=self.F["small"],
                                 fill=ui.TEXT3, tags="static")
            self._net_items[key] = (main, sub)
        self._render_net()

        ty = ny + card_h + 20
        bx = P
        for btn in (self.btn_scan, self.btn_block, self.btn_all, self.btn_free,
                    self.btn_verify, self.btn_sel_all, self.btn_sel_inv,
                    self.btn_guard):
            btn.x, btn.y = bx, ty
            self._place_btn(btn)
            bx += btn.w + 10

        # 隐藏白名单开关
        tx1, tx0 = w - P, w - P - 104
        y0, y1 = ty + 9, ty + 29
        on = self._wl_hidden
        ui.rrect(cv, tx0, y0, tx1, y1, 10, fill=ui.SAGE if on else ui.LINE_SOFT,
                 outline="", tags=("static", "wlt"))
        knob = tx1 - 12 if on else tx0 + 12
        cv.create_oval(knob - 8, y0 + 2, knob + 8, y1 - 2, fill="#FFFFFF",
                       outline="", tags=("static", "wlt"))
        cv.create_text(tx0 - 12, (y0 + y1) / 2, text="隐藏白名单", anchor="e",
                       font=self.F["small"], fill=ui.TEXT3, tags=("static", "wlt"))
        cv.tag_bind("wlt", "<Button-1>", lambda e: self._toggle_wl())
        cv.tag_bind("wlt", "<Enter>", lambda e: cv.configure(cursor="hand2"))
        cv.tag_bind("wlt", "<Leave>", lambda e: cv.configure(cursor=""))

        self._shimmer.y, self._shimmer.x0, self._shimmer.x1 = ty + 52, P, w - P
        if self._busy:
            self._shimmer.stop()
            self._shimmer.start()

        tbl_y = ty + 72
        # 剩余空间优先给表格，日志卡 104~140 自适应
        avail = max(320, h - tbl_y - 88)
        log_h = int(min(170, max(126, avail * 0.25)))
        tbl_h = max(170, avail - log_h - 14)
        ui.card(cv, P, tbl_y, w - P, tbl_y + tbl_h, 16, tags="static")
        self.tree.place(x=P + 14, y=tbl_y + 12, width=w - P * 2 - 40,
                        height=tbl_h - 24)
        self.vsb.place(x=w - P - 20, y=tbl_y + 18, width=8, height=tbl_h - 36)

        ly = tbl_y + tbl_h + 14
        ui.card(cv, P, ly, w - P, ly + log_h, 16, tags="static")
        self._logwrap.place(x=P + 20, y=ly + 16, width=w - P * 2 - 40,
                            height=log_h - 32)

        self._draw_footer()

    def _draw_footer(self):
        cv = self.canvas
        cv.delete("footer")
        g = self._geo
        self._foot_item = cv.create_text(
            g["P"], g["h"] - 26, text=self._footer_text(), anchor="w",
            font=self.F["small"], fill=ui.TEXT3, tags=("static", "footer"))
        self._draw_chips()
        vx = getattr(self, "_chips_left", g["w"] - g["P"]) - 18
        cv.create_text(vx, g["h"] - 26, text=f"v{core.APP_VERSION}",
                       anchor="e", font=self.F["small"], fill=ui.TEXT3,
                       tags=("static", "footer"))

    @staticmethod
    def _rr_pts(x0, y0, x1, y1, r):
        r = min(r, (x1 - x0) / 2, (y1 - y0) / 2)
        return [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r,
                x1, y1, x1 - r, y1, x0 + r, y1, x0, y1, x0, y1 - r,
                x0, y0 + r, x0, y0]

    def _place_btn(self, b):
        self.canvas.coords(b.bg, *self._rr_pts(b.x, b.y, b.x + b.w,
                                               b.y + b.h, b.r))
        self.canvas.coords(b.label, b.x + b.w / 2, b.y + b.h / 2)

    def _draw_chips(self):
        """页脚右侧的状态徽章排：在线 / 阻断 / IPv6。

        数值变化时向上弹一下再落回 —— 比干巴巴的数字更容易注意到变化。
        """
        cv = self.canvas
        cv.delete("chips")
        g = self._geo
        y = g["h"] - 26

        n_online = len(self._devices)
        n_block = len(self._killer.targets()) if self._killer else 0
        n_block += len(self._ndp_mgr.active_ips())
        env = self._v6env
        chips = [(f"在线 {n_online}", ui.SAGE_BG, ui.SAGE_DK)]
        if n_block:
            chips.append((f"阻断 {n_block}", ui.ROSE_BG, ui.ROSE_DK))
        if env is not None and env.dual_stack:
            on = self._ndp_on
            chips.append(("IPv6 已接管" if on else "IPv6 未覆盖",
                          ui.SAGE_BG if on else ui.SAND_BG,
                          ui.SAGE_DK if on else getattr(ui, "SAND_DK", ui.SAND)))
        if self._guard.is_active():
            ac = self._guard.anomaly_count
            chips.append(("守护中" + (f"·纠正{ac}" if ac else ""),
                          ui.OLIVE_BG, ui.OLIVE_DK))

        font = tkfont.Font(font=self.F["small"])
        x = g["w"] - g["P"]
        ids: list[int] = []
        for text, bg, fg in reversed(chips):
            tw = font.measure(text) + 26
            x -= tw
            ids.append(ui.rrect(cv, x, y - 12, x + tw, y + 12, 12,
                                fill=bg, outline="", tags=("chips",)))
            ids.append(cv.create_text(x + tw / 2, y, text=text,
                                      font=self.F["small"], fill=fg,
                                      tags=("chips",)))
            x -= 10

        self._chips_left = x
        vals = (n_online, n_block, self._ndp_on, self._guard.is_active(),
                self._guard.anomaly_count)
        if getattr(self, "_chip_vals", None) not in (None, vals) and ids:
            self._ui.after(10, lambda i=list(ids): self._chip_pop(i))
        self._chip_vals = vals

    def _chip_pop(self, ids):
        """徽章弹一下：先整体上移 3px，再分两步落回。"""
        try:
            for oid in ids:
                self.canvas.move(oid, 0, -3)
        except tk.TclError:
            return

        def back(step=0):
            if self._destroyed:
                return
            try:
                for oid in ids:
                    self.canvas.move(oid, 0, 1 if step < 2 else 2)
            except tk.TclError:
                return
            if step < 2:
                self._ui.after(60, back, step + 1)

        self._ui.after(90, back)

    def _footer_text(self, shown: int | None = None) -> str:
        blocked = len(self._killer.targets()) if self._killer else 0
        blocked += len(self._ndp_mgr.active_ips())
        total = len(self._devices) if shown is None else shown
        return f"共 {total} 台设备 · 阻断中 {blocked} 台 · 关闭窗口将驻留托盘"

    # ------------------------------------------------------------ 动画

    def _animate_footer(self):
        """设备总数变化时滚一下数字，比直接跳变更容易注意到。"""
        target = len(self._devices)
        start = self._foot_shown
        if target == start:
            return
        self._foot_shown = target
        steps = 12

        def tick(i: int = 1):
            if self._destroyed or self._foot_item is None:
                return
            t = i / steps
            val = start + (target - start) * ui.ease_out(t)
            try:
                self.canvas.itemconfig(self._foot_item,
                                       text=self._footer_text(round(val)))
            except tk.TclError:
                return
            if i < steps:
                self._ui.after(24, tick, i + 1)
            else:
                try:
                    self.canvas.itemconfig(self._foot_item,
                                           text=self._footer_text())
                except tk.TclError:
                    pass

        tick()

    def _fade_in(self):
        try:
            self.attributes("-alpha", 0.0)
        except Exception:
            return
        state = {"a": 0.0}

        def tick():
            state["a"] = min(1.0, state["a"] + 0.10)
            try:
                self.attributes("-alpha", state["a"])
            except Exception:
                return
            if state["a"] < 1.0:
                self._ui.after(16, tick)
        tick()

    def _flash(self, ip: str):
        try:
            if self.tree.exists(ip):
                tags = [t for t in self.tree.item(ip, "tags") if t != "flash"]
                self.tree.item(ip, tags=tuple(tags + ["flash"]))
                self._ui.after(520, lambda: self._unflash(ip))
        except Exception:
            pass

    def _unflash(self, ip: str):
        try:
            if self.tree.exists(ip):
                tags = [t for t in self.tree.item(ip, "tags") if t != "flash"]
                self.tree.item(ip, tags=tuple(tags))
        except Exception:
            pass

    # ------------------------------------------------------------ 日志

    def _log_sink(self, level: str, msg: str):
        self._q.put(("log", level, msg))

    def log(self, msg: str, level: str = "info"):
        # 线程安全：网络线程（do_block/do_unblock/do_quit 的 work() 等）也会调 log，
        # 必须经过主线程投递，否则并发触碰 Tk Text 会崩溃或产生 "invalid command name"。
        if threading.current_thread() is not self._main_thread:
            try:
                self.after_idle(lambda: self.log(msg, level))
            except Exception:
                pass
            return
        if self._destroyed:
            return
        self.logtext.configure(state="normal")
        self.logtext.tag_remove("fresh", "1.0", "end")
        self.logtext.insert("end", f"{time.strftime('%H:%M:%S')}   {msg}\n", level)
        # 最新一条短暂高亮，模拟「滚动到位」的提示
        self.logtext.tag_add("fresh", "end-1c linestart", "end-1c lineend")
        self.logtext.see("end")
        lines = int(self.logtext.index("end-1c").split(".")[0])
        if lines > 400:
            self.logtext.delete("1.0", f"{lines - 400}.0")
        self.logtext.configure(state="disabled")
        if not getattr(self, "_log_fade", False):
            self._log_fade = True
            self.after(620, self._clear_log_fresh)

    def _clear_log_fresh(self):
        self._log_fade = False
        try:
            self.logtext.tag_remove("fresh", "1.0", "end")
        except tk.TclError:
            pass

    def _drain(self):
        try:
            while True:
                item = self._q.get_nowait()
                if item[0] == "log":
                    self.log(item[2], item[1])
                else:
                    try:
                        item[1]()
                    except Exception:
                        import traceback
                        self.log("界面回调异常：" + traceback.format_exc(limit=2).splitlines()[-2].strip(), "err")
        except queue.Empty:
            pass
        if not self._destroyed:
            try:
                self.after(70, self._drain)
            except tk.TclError:
                pass

    def _post(self, fn):
        self._q.put(("call", fn))

    # ------------------------------------------------------------ 状态

    def set_status(self, text: str):
        # Tk 控件不是线程安全的：worker 线程直接改 canvas 会偶发 TclError / 损坏。
        # 非主线程一律投递回主线程执行（after_idle 在控件销毁时会抛错，已吞掉）。
        if threading.current_thread() is not self._main_thread:
            try:
                self.after_idle(lambda: self.set_status(text))
            except Exception:
                pass
            return
        self._status_text = text
        try:
            self.canvas.itemconfig("badgetext", text=text)
        except tk.TclError:
            pass

    def _update_buttons(self):
        idle = not self._busy
        has = bool(self.tree.selection())
        # IPv6 阻断也算「有阻断」：只看 v4 队列会让「全部放行」在只剩 v6 目标时
        # 变成不可点的死按钮，用户除了退出程序没别的办法停它（对抗性审查第 5 轮）。
        blocked = bool(self._killer and self._killer.targets()) \
            or bool(self._ndp_mgr.active_ips())
        self.btn_scan.set_enabled(idle)
        self.btn_block.set_enabled(idle and has)
        self.btn_all.set_enabled(idle and bool(self._devices))
        self.btn_free.set_enabled(idle and blocked)
        self.btn_verify.set_enabled(idle and blocked)
        self._draw_footer()

    def _set_busy(self, busy: bool, text: str | None = None):
        self._busy = busy
        if text:
            self.set_status(text)
        if busy:
            self._shimmer.stop()
            self._shimmer.start()
        else:
            self._shimmer.stop()
        self._update_buttons()

    def _toggle_wl(self):
        self._wl_hidden = not self._wl_hidden
        self._render_rows()
        self._relayout(self._geo["w"], self._geo["h"])

    # ------------------------------------------------------------ 启动

    def _bootstrap(self):
        def work():
            self._net = core.get_netinfo()
            self._post(self._render_net)
            code, msg = core.l2_check()
            self._post(lambda: self._render_banner(code, msg))
            self._post(self._maybe_recover)
            self._post(lambda: self.log("已就绪，正在扫描局域网…", "info"))
            self._post(self.do_scan)
        threading.Thread(target=work, daemon=True).start()

    def _render_net(self):
        n = self._net
        vals = {
            "iface": (n.iface_name or n.iface or "—", ""),
            "ip": (n.my_ip or "—", n.my_mac or ""),
            "gw": (n.gateway_ip or "—", n.gateway_mac or ""),
            "cidr": (n.cidr or "—", ""),
        }
        for k, (main, sub) in vals.items():
            pair = getattr(self, "_net_items", {}).get(k)
            if not pair:
                continue
            try:
                self.canvas.itemconfig(pair[0], text=main)
                self.canvas.itemconfig(pair[1], text=sub)
            except tk.TclError:
                pass

    def _render_banner(self, code: str | None = None, msg: str | None = None):
        if code is None:
            code, msg = core.l2_check()
        admin = core.is_admin()
        if code == "no_npcap":
            self._banner_state = ("npcap", "未安装 Npcap —— 只能扫描，无法阻断")
            self._badge_dot.set(ui.SAND)
            self._status_text = "缺少 Npcap"
        elif code == "no_scapy":
            self._banner_state = ("warn", f"依赖缺失：{msg}")
            self._badge_dot.set(ui.SAND)
            self._status_text = "依赖缺失"
        elif self._v6env is not None and self._v6env.dual_stack and not self._ndp_on:
            # 比「未提权」更重要：不说清楚，用户会以为阻断已经生效
            self._banner_state = ("warn",
                                  "本网已启用 IPv6 —— 当前阻断只对 IPv4 生效，"
                                  "可在「设置」开启 IPv6 阻断（实验）")
            self._badge_dot.set(ui.SAND)
            self._status_text = "IPv6 未覆盖"
        elif self._ndp_on and self._v6env is not None and self._v6env.dual_stack:
            self._banner_state = ("info",
                                  "IPv6 阻断已启用（实验）：只断经网关的出站，"
                                  "支持多目标并发（每目标独立护栏）")
            self._badge_dot.set(ui.OLIVE)
            self._status_text = "IPv6 已启用"
        elif not admin:
            self._banner_state = ("info", "当前未以管理员运行；多数网卡仍可发送，失败时再提权")
            self._badge_dot.set(ui.OLIVE)
            self._status_text = "就绪"
        else:
            self._banner_state = None
            self._badge_dot.set(ui.OLIVE)
            self._status_text = "就绪"
        self._relayout(self._geo["w"], self._geo["h"])

    def _maybe_recover(self):
        st = core.load_state()
        # 对抗性审查第 5 轮：解析下沉到 core.state_targets（非法条目跳过），
        # 此前直接在 GUI 里 it["ip"]，状态文件缺字段会让整个恢复线程静默死掉。
        items = core.state_targets(st)
        if not items:
            if st.get("targets"):
                core.clear_state()
                self.log("残留阻断记录不合法（地址缺失或格式错误），已清除", "warn")
            return
        names = "、".join(t.ip for t in items[:4])
        more = f" 等 {len(items)} 台" if len(items) > 4 else ""
        if messagebox.askyesno(
                "发现残留阻断",
                f"上次退出时仍有 {len(items)} 台设备处于阻断状态：\n{names}{more}\n\n现在恢复它们吗？"):
            self._restore_from_state(items)
        else:
            self.log("已忽略残留记录；可稍后点「全部放行」清理", "warn")

    def _restore_from_state(self, items):
        def work():
            try:
                ni = core.NetInfo(**self._net.__dict__)
                st = core.load_state()
                # 对抗性审查 R1：状态里的网关信息可能来自旧网络 —— 换网后按旧网关
                # 构造恢复帧只会发向失效 MAC，救不回目标还可能误报成功。
                # 接口或网关 IP 不一致时放弃恢复并清除残留记录。
                if (st.get("iface") and st["iface"] != ni.iface) or \
                        (st.get("gateway_ip") and st["gateway_ip"] != ni.gateway_ip):
                    self._post(lambda: self.log("残留阻断记录来自其他网络，已忽略并清除", "warn"))
                    core.clear_state()
                    return
                k = core.Killer(ni, dry_run=False)
                for t in items:
                    # 队列来自 core.state_targets()：地址已校验，duty 已夹取
                    #（对抗性审查 F1：占空比必须随状态回来，否则崩溃重启后限速变全断）
                    k._targets[t.ip] = t
                n = k.restore_all()
                if n == len(items):
                    self._post(lambda: self.log(f"已恢复 {n} 台设备", "ok"))
                else:
                    self._post(lambda: self.log(
                        f"仅恢复 {n}/{len(items)} 台，其余恢复帧未能发出"
                        f"（可再点「全部放行」重试）", "warn"))
            except Exception as e:
                # 恢复线程异常必须让用户看见，不能只留 traceback。
                self._post(lambda: self.log(f"残留阻断恢复失败：{e}", "err"))
            finally:
                self._post(self.do_scan)
        threading.Thread(target=work, daemon=True).start()

    def _drop_old_network(self, old, old_gw, ni):
        """换网后清理旧阻断：停线程、丢队列、清状态（在后台线程里做，避免 join 卡 UI）。"""
        n = 0
        try:
            n = old.abandon()
        except Exception as e:
            self.log(f"清理旧阻断失败：{e}", "debug")
        try:
            self._stop_ndp()
        except Exception:
            pass
        self._post(lambda: self.log(
            f"网络已变更（旧网关 {old_gw} → 新网关 {ni.gateway_ip or '?'}），"
            f"已中止对旧网络的阻断（{n} 台），请重新扫描后重新阻断", "err"))
        self._post(self._render_rows)
        self._post(self._update_buttons)

    # ------------------------------------------------------------ 扫描

    def do_scan(self):
        if self._busy:
            return
        self._set_busy(True, "正在扫描…")
        cidr = self._net.cidr or None

        def work():
            try:
                ni = core.get_netinfo(cidr)
                if not ni.gateway_ip:
                    def _no_gw():
                        n = len(self._killer.targets()) if self._killer else 0
                        if n:
                            self.log(f"无法确定网关：本次扫描中断，仍有 {n} 台设备处于阻断状态，"
                                     f"其是否仍有效无法确认（请检查网络后重新扫描）", "err")
                        else:
                            self.log("无法确定网关，请检查是否已联网", "err")
                    self._post(_no_gw)
                    return
                devs, active = core.scan(ni, timeout=2.0, active=True)
                self._post(lambda: self._apply_scan(ni, devs, active))
            except Exception as e:
                self._post(lambda: self.log(f"扫描异常：{e}", "err"))
            finally:
                self._post(lambda: self._set_busy(False))
        threading.Thread(target=work, daemon=True).start()

    def _apply_scan(self, ni: core.NetInfo, devs: list[core.Device], active: bool):
        for d in devs:
            if d.ip == ni.gateway_ip and not ni.gateway_mac:
                ni.gateway_mac = d.mac
        # 对抗性审查第 5 轮：Killer 持有的是建它时的 NetInfo 快照。换网后若继续沿用，
        # 帧会一直发向旧网关 MAC —— 界面「阻断中」，目标照常上网（静默失效）。
        # 探测失败（拿不到网卡/网关）时无法判定上下文是否仍然有效：不误杀阻断，
        # 但必须说清楚——否则又是一次「界面阻断中、实际可能已失效」的静默状态。
        if self._killer and self._killer.targets() \
                and (not ni.gateway_ip or not ni.iface):
            self.log("本次扫描未拿到网关或网卡信息，无法确认当前阻断是否仍然有效；"
                     "请检查网络连接后重新扫描", "warn")
        if self._killer and self._killer.targets() \
                and ni.gateway_ip and ni.iface \
                and not self._killer.matches_network(ni):
            old, old_gw = self._killer, self._killer.ni.gateway_ip or "?"
            self._killer = None      # 立刻摘掉旧上下文：下次阻断必须用新 ni 重建
            threading.Thread(target=self._drop_old_network,
                             args=(old, old_gw, ni), daemon=True).start()
        self._net = ni
        self._devices = devs
        self._refresh_v6env(ni)
        # 守护本机：同步最新网络上下文；若已开启则确保运行（扫描自愈，断网重连也能恢复）
        self._guard.ni = ni
        self._guard.v6env = self._v6env
        if self._guard.is_active():
            self._guard.refresh_v6()   # 网络切换重估后恢复 IPv6 重宣告上下文
        if self._guard_on and not self._guard.is_active():
            self._guard.dry_run = self._opts[1]
            self._guard.start()
        try:
            self._sentinel.feed_scan(devs)   # 全网哨兵：基线比对 + 新设备告警
        except Exception as e:
            self.log(f"哨兵处理异常：{e}", "debug")
        self._sync_guard_btn()
        self._render_net()
        self._render_rows(animate=True)
        self._animate_footer()
        self._render_banner()      # IPv6 状态会影响横幅，扫描完必须重画
        if not active:
            self.log("二层不可用，改为读取系统 ARP 缓存（可能不完整）", "warn")
        self.log(f"{'主动扫描' if active else '缓存读取'}完成，发现 {len(devs)} 台设备", "ok")

    def _refresh_v6env(self, ni: core.NetInfo):
        """探测本网段的 IPv6 状况。只读系统路由表，不发包。"""
        try:
            import ipv6 as v6
            self._v6env = v6.probe_env(ni)
        except Exception as e:
            self._v6env = None
            self.log(f"IPv6 探测失败：{e}", "debug")
            return
        env = self._v6env
        if env and env.dual_stack and not self._ndp_on:
            self.log(f"本网已启用 IPv6（{env.prefixes[0]}），"
                     f"当前 ARP 阻断对 IPv6 流量无效", "warn")

    def _mark_of(self, d: core.Device) -> str:
        """标识列：这台设备「是什么」，与阻断状态无关。

        优先级：用户备注 > 角色（网关/本机/白名单）> 随机 MAC / 厂商。
        """
        alias = self._aliases.get(d.mac) or self._aliases.get(d.ip)
        if alias:
            return alias
        if d.note == "网关":
            return "网关"
        if d.note == "本机":
            return "本机"
        if d.ip in self._whitelist or d.mac in self._whitelist:
            return "白名单"
        if "随机" in d.vendor:
            return "随机 MAC"
        if d.vendor and d.vendor != "—":
            return d.vendor
        return "—"

    def _state_of(self, d: core.Device) -> tuple[str, str]:
        """状态列：这台设备「正被怎样对待」。"""
        duty = self._killer.duty_of(d.ip) if self._killer else None
        v4 = duty is not None
        v6 = self._ndp_mgr.state_of(d.ip) if self._ndp_on else ""
        if v4 and 0 < (duty or 100) < 100:
            state = f"限速 {duty}%"
            if v6 == "ok":
                state += "·v6全断"
            return state, "blocked"
        if v4 and v6 == "ok":
            return "阻断中·双栈", "blocked"
        if v4 and v6 == "miss":
            return "阻断中·仅v4", "v4only"
        if v4:
            return "阻断中", "blocked"
        if v6 == "ok":
            return "阻断中·IPv6", "blocked"
        if v6 == "miss":
            return "仅v4·未探明", "v4only"
        return "未阻断", ""

    def _set_duty(self, duty: int):
        """对选中的已阻断设备调整占空比（占空比限速）。"""
        if not self._killer:
            messagebox.showinfo("限速", "当前没有阻断中的目标。", parent=self)
            return
        picked = [ip for ip in self.tree.selection()]
        done = [self._killer.set_duty(ip, duty) for ip in picked]
        n = sum(1 for ok in done if ok)
        if n:
            self.log(f"已对 {n} 台设备设置占空比 {duty}%", "ok")
            self._render_rows()
            self._update_buttons()
        else:
            messagebox.showinfo("限速", "选中的设备不在阻断队列（先阻断再限速）。", parent=self)

    def _render_rows(self, animate: bool = False):
        """重画设备表。

        animate=True 仅用于「扫描结果落地」这一处：错峰逐行插入。
        其余场景必须同步插入 —— 调用方（右键菜单、自检脚本、阻断后刷新）
        默认渲染完就能立刻选中某行，异步会让这个约定失效。
        """
        # 每次重画都换一个世代号：上一轮还没插入完的行必须作废，
        # 否则连点两次扫描会插出重复行。
        self._row_gen += 1
        gen = self._row_gen
        sel = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())

        rows = []
        idx = 0
        for d in self._devices:
            state, tag = self._state_of(d)
            if self._wl_hidden and state == "白名单":
                continue
            idx += 1
            rows.append((d, idx, tag, state, self._mark_of(d)))

        # 行数多时不逐行动画，否则看起来像卡顿
        if not animate or len(rows) > 24:
            for d, i, tag, state, mark in rows:
                self._insert_row(None, d, i, tag, state, mark)
        else:
            for n, (d, i, tag, state, mark) in enumerate(rows):
                self._ui.after(n * 26, self._insert_row, gen, d, i, tag,
                               state, mark)

        for iid in sel:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)

        blocked = len(self._killer.targets()) if self._killer else 0
        blocked += len(self._ndp_mgr.active_ips())
        if self._badge_dot:
            self._badge_dot.set(ui.ROSE if blocked else ui.OLIVE, pulse=blocked > 0)
        if blocked:
            self._start_block_breath()
        else:
            self._stop_block_breath()
        if not self._destroyed:
            self._draw_chips()
        self._update_buttons()

    def _insert_row(self, gen, d, idx, tag, state, mark="—"):
        if self._destroyed or (gen is not None and gen != self._row_gen):
            return
        try:
            self.tree.insert("", "end", iid=d.ip,
                             tags=(tag,) if tag else (),
                             values=(idx, d.ip, d.mac, d.vendor, d.dtype,
                                     mark, state, ""))
        except tk.TclError:
            pass

    def _start_block_breath(self):
        """被阻断的行做一次缓慢的底色呼吸，提示「这里正在生效」。"""
        if self._breath_job or self._destroyed:
            return
        state = {"t": 0.0}

        def tick():
            if self._destroyed:
                return
            state["t"] += 0.085
            k = 0.5 + 0.5 * math.sin(state["t"])
            col = ui.mix(ui.CARD, ui.ROSE_BG, 0.30 + 0.70 * k)
            try:
                self.tree.tag_configure("blocked", background=col)
            except tk.TclError:
                return
            self._breath_job = self._ui.after(70, tick)

        tick()

    def _stop_block_breath(self):
        if self._breath_job:
            try:
                self.after_cancel(self._breath_job)
            except Exception:
                pass
            self._breath_job = None
        try:
            self.tree.tag_configure("blocked", background="")
        except tk.TclError:
            pass

    # ------------------------------------------------------------ 阻断

    def _build_killer(self) -> core.Killer:
        code, msg = core.l2_check()
        if code != "ok":
            raise core.BlockError(msg)
        if self._killer and not self._killer.matches_network(self._net):
            # 兜底：任何原因留下的旧上下文（换网早于扫描、外部改 ni）都在这里作废
            self._killer.stop()
            self._killer = None
        if not self._killer:
            ni = core.NetInfo(**self._net.__dict__)
            if not ni.gateway_mac:
                gw = core.resolve_mac(ni.gateway_ip, ni)
                if not gw:
                    raise core.BlockError("拿不到网关 MAC，无法建立双向阻断")
                ni.gateway_mac = gw
            self._killer = core.Killer(ni, interval=self._opts[0],
                                       dry_run=self._opts[1])
        return self._killer

    def do_block(self, all_devices: bool):
        if self._busy:
            return
        if all_devices:
            picks = [d for d in self._devices
                     if not core.is_protected(d)
                     and d.ip not in self._whitelist and d.mac not in self._whitelist]
            if not picks:
                messagebox.showinfo("无可阻断设备", "除网关/本机/白名单外没有目标。")
                return
            if self._v6env and self._v6env.dual_stack and not self._ndp_on:
                ans = messagebox.askyesnocancel(
                    "全阻断（含 IPv6）",
                    f"将阻断 {len(picks)} 台设备（网关与本机已自动排除）。\n\n"
                    f"本网检测到 IPv6：是否同时切断它们的 IPv6 出站？\n"
                    f"（实验功能，只断经网关的出站，每台独立护栏）")
                if ans is None:
                    return
                if ans:
                    self._ndp_on = True
                    self.log("全阻断：本次已自动启用 IPv6 定向阻断（实验）", "warn")
            elif not messagebox.askyesno(
                    "确认全阻断",
                    f"将阻断 {len(picks)} 台设备。\n网关与本机已自动排除。\n\n继续？"):
                return
        else:
            ips = list(self.tree.selection())
            if not ips:
                return
            by_ip = {d.ip: d for d in self._devices}
            # 安全阀 1：单目标路径同样必须剔除网关与本机（core.is_protected）。
            # 网关被断 = 全家断网；本机被断 = 自己失联。与「全阻断」的保护一致。
            picks = [by_ip[i] for i in ips
                     if i in by_ip and not core.is_protected(by_ip[i])]
            skipped_protected = [i for i in ips
                                 if i in by_ip and core.is_protected(by_ip[i])]
            if skipped_protected:
                self.log("已跳过受保护设备（网关/本机）：" + "、".join(skipped_protected), "warn")
            # 安全阀 2：白名单设备不可被阻断（与「全阻断」保持一致，避免单点绕过）。
            picks = [d for d in picks
                     if d.ip not in self._whitelist and d.mac not in self._whitelist]
            skipped_wl = [i for i in ips
                          if i in by_ip and not core.is_protected(by_ip[i])
                          and (i in self._whitelist or by_ip[i].mac in self._whitelist)]
            if skipped_wl:
                self.log("已跳过白名单设备：" + "、".join(skipped_wl), "warn")
            if not picks:
                if skipped_wl and not skipped_protected:
                    messagebox.showwarning(
                        "白名单保护",
                        "所选设备都在白名单中，已被自动跳过。\n"
                        "白名单用于保护重要设备不被误阻断。")
                else:
                    messagebox.showwarning(
                        "受保护设备",
                        "网关与本机不能被阻断。\n"
                        "阻断网关会切断整个网络，阻断本机会让自己失联。")
                return

        code, msg = core.l2_check()
        if code != "ok":
            self._render_banner(code, msg)
            messagebox.showwarning("无法阻断", f"{msg}\n\n请先处理顶部提示。")
            return

        # 第二道门已移除：IPv6 阻断现已支持多目标（NdpManager 逐目标独立护栏）。
        self._set_busy(True, "正在阻断…")

        def work():
            try:
                k = self._build_killer()
            except core.BlockError as e:
                def fail():
                    self._set_busy(False)
                    messagebox.showerror("无法阻断", str(e))
                self._post(fail)
                return
            added, skipped = 0, []
            for d in picks:
                try:
                    k.add(core.Target(d.ip, d.mac))
                    added += 1
                except Exception as e:
                    skipped.append(f"{d.ip}({e})")
            if added and not k.is_active():
                k.start()

            v6msgs = []
            if added and self._ndp_on and self._v6env:
                from concurrent.futures import ThreadPoolExecutor

                def _add_one(d):
                    return self._ndp_mgr.add(k.ni, self._v6env, d, self._opts[0])

                try:
                    with ThreadPoolExecutor(max_workers=min(len(picks), 4)) as ex:
                        futs = {d.ip: ex.submit(_add_one, d) for d in picks}
                    for d in picks:
                        _ok, _m = futs[d.ip].result()
                        v6msgs.append(_m)
                except Exception as e:
                    v6msgs.append(f"IPv6 阻断启动异常：{e}")
            v6msg = "；".join(v6msgs)

            def done():
                if added:
                    self.log(f"已阻断 {added} 台", "ok")
                if skipped:
                    self.log("跳过：" + "，".join(skipped), "warn")
                if v6msg:
                    ok_any = bool(self._ndp_mgr.active_ips())
                    self.log(v6msg, "ok" if ok_any else "warn")
                self._render_rows()
                self._render_banner()
                for d in picks:
                    self._flash(d.ip)
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _stop_ndp(self, ip: str | None = None, restore: bool = True):
        """停止 IPv6 阻断。ip=None 停止全部，否则只停指定目标。"""
        if ip is None:
            n = self._ndp_mgr.restore_all(restore=restore)
        else:
            n = self._ndp_mgr.remove(ip, restore=restore)
        if n:
            self.log(f"IPv6 阻断已停止，回填 {n} 次", "info")
        return n

    def do_verify(self):
        """逐个验证已阻断设备是否真的断网（被动嗅探，不发新包）。"""
        targets = self._killer.targets() if self._killer else []
        if not targets:
            messagebox.showinfo("验证断网", "当前没有处于阻断状态的设备。", parent=self)
            return
        self._set_busy(True, "正在验证…")
        ni = core.NetInfo(**self._killer.ni.__dict__)

        def work():
            result = core.verify_targets(ni, targets, seconds=4.0)

            def done():
                lines = []
                for t in targets:
                    r = result.get(t.ip) or {"status": "unknown", "text": "无结果",
                                             "hits": 0, "leaks": 0}
                    lines.append(f"{t.ip}  {r['text']}")
                    self.log(f"[验证] {t.ip}：{r['text']}"
                             f"（吸到本机 {r['hits']} 帧 / 直连网关 {r['leaks']} 帧）",
                             "ok" if r.get("status") == "ok" else "warn")
                self._set_busy(False)
                messagebox.showinfo("验证断网", "\n".join(lines), parent=self)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _ask_duty(self):
        """自定义占空比（10–100%）：对选中的已阻断设备生效。"""
        if not self._killer or not self._killer.targets():
            messagebox.showinfo("限速", "先阻断目标，再设置限速。", parent=self)
            return
        sel = [ip for ip in self.tree.selection()
               if self._killer.duty_of(ip) is not None]
        cur = self._killer.duty_of(sel[0]) if sel else 50
        win = tk.Toplevel(self)
        win.title("自定义限速")
        win.configure(bg=ui.CARD)
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        win.geometry(f"+{self.winfo_rootx() + 320}+{self.winfo_rooty() + 240}")

        body = tk.Frame(win, bg=ui.CARD, padx=22, pady=16)
        body.pack(fill="both", expand=True)
        var = tk.IntVar(value=int(cur or 50))
        tk.Label(body, text="在线占空比：目标有多少比例的时间可以上网",
                 bg=ui.CARD, fg=ui.TEXT, font=self.F["small"]).pack(anchor="w")
        val = tk.Label(body, text=f"{var.get()}%", bg=ui.CARD, fg=ui.SAGE_DK,
                       font=self.F["h1"])
        val.pack(anchor="w", pady=(6, 0))
        tk.Scale(body, from_=10, to=100, resolution=5, orient="horizontal",
                 variable=var, length=320, bg=ui.CARD, fg=ui.TEXT,
                 highlightthickness=0, troughcolor=ui.CARD_ALT, showvalue=False,
                 command=lambda v: val.config(text=f"{int(float(v))}%")).pack(
            anchor="w", pady=(4, 8))
        tk.Label(body, text="100% = 全断；50% = 一半时间能上网（体感一直卡）",
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"]).pack(anchor="w")

        def apply():
            duty = max(10, min(100, int(float(var.get()))))
            ips = sel or [t.ip for t in self._killer.targets()]
            n = sum(1 for ip in ips if self._killer.set_duty(ip, duty))
            self.log(f"已对 {n} 台设备设置占空比 {duty}%", "ok" if n else "warn")
            self._render_rows()
            win.destroy()

        row = tk.Frame(body, bg=ui.CARD)
        row.pack(fill="x", pady=(14, 0))
        tk.Button(row, text="应用", command=apply, relief="flat", bd=0,
                  bg=ui.SAGE, fg="#FFFFFF", font=self.F["small"], padx=18, pady=6,
                  cursor="hand2", activebackground=ui.SAGE_DK).pack(side="right")
        tk.Button(row, text="取消", command=win.destroy, relief="flat", bd=0,
                  bg=ui.CARD_ALT, fg=ui.TEXT2, font=self.F["small"], padx=16, pady=6,
                  cursor="hand2").pack(side="right", padx=8)

    def do_unblock_all(self):
        v4 = len(self._killer.targets()) if self._killer else 0
        v6 = len(self._ndp_mgr.active_ips())
        if not v4 and not v6:
            return
        if not messagebox.askyesno("确认放行",
                                   f"恢复全部 {v4 + v6} 台设备的网络？"
                                   + (f"\n（IPv4 {v4} 台 / IPv6 {v6} 台）"
                                      if v4 and v6 else "")):
            return
        self._set_busy(True, "正在恢复…")

        def work():
            n6 = self._stop_ndp()
            ok = self._killer.restore_all() if self._killer else 0

            def done():
                if ok or n6:
                    self.log(f"已放行 {ok} 台（IPv6 回填 {n6} 次），网络应已恢复", "ok")
                else:
                    self.log("放行失败：恢复帧未能发出，请检查网卡/管理员权限后重试", "err")
                self._render_rows()
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _unblock_selected(self):
        if not self._killer and not self._ndp_mgr.active_ips():
            return
        sel = list(self.tree.selection())

        def work():
            for ip in sel:
                if ip in self._ndp_mgr.active_ips():
                    self._ndp_mgr.remove(ip)
            fails = []
            if self._killer:
                for ip in sel:
                    if not self._killer.remove(ip):
                        fails.append(ip)
            if fails:
                # 恢复帧发不出去时不谎报成功：目标会留在队列里继续被投毒。
                self._post(lambda: self.log(
                    "放行失败（恢复帧未能发出，目标仍在阻断队列）：" + "、".join(fails),
                    "err"))
            self._post(self._render_rows)
        threading.Thread(target=work, daemon=True).start()

    def _select_all(self):
        """选中当前可见的全部设备行（不跨隐藏的白名单行）。"""
        try:
            self.tree.selection_set(*self.tree.get_children())
        except tk.TclError:
            pass

    def _select_invert(self):
        """反选：当前选中的取消，未选中的全选。"""
        try:
            cur = set(self.tree.selection())
            allc = set(self.tree.get_children())
            self.tree.selection_set(*(allc - cur))
        except tk.TclError:
            pass

    # ------------------------------------------------------------ 本机守护

    def _sentinel_notify(self, title: str, msg: str):
        """Sentinel → 托盘气泡。走主线程队列（notify 修改共享 NOTIFYICONDATAW）。"""
        def _fire():
            try:
                if self._tray:
                    self._tray.notify(title[:63], msg[:255])
            except Exception:
                pass
        self._post(_fire)

    def _sync_guard_btn(self):
        """按真实运行状态刷新「守护本机」按钮外观（ghost ↔ primary）。"""
        if not hasattr(self, "btn_guard"):
            return
        on = self._guard_on and self._guard.is_active()
        self.btn_guard.set_text("守护中" if on else "守护本机")
        self.btn_guard.set_kind("primary" if on else "ghost")

    def _start_guard(self) -> bool:
        """尝试启动守护；成功返回 True。失败（无网关等）返回 False。"""
        ni = self._net
        if not ni.gateway_ip:
            return False
        self._guard.ni = ni
        self._guard.v6env = self._v6env
        self._guard.dry_run = self._opts[1]
        return self._guard.start()

    def _toggle_guard(self):
        if self._guard_on:
            self._guard.stop()
            self._guard_on = False
            core.set_guard_enabled(False)
            self.log("本机守护已关闭", "info")
        else:
            ok = self._start_guard()
            if ok:
                self._guard_on = True
                core.set_guard_enabled(True)
                self.log("本机守护已开启（主动防御）", "ok")
            else:
                self.log("本机守护启动失败：请先扫描到网关与真实网关 MAC", "warn")
        self._sync_guard_btn()

    # ------------------------------------------------------------ 哨兵面板

    def _open_sentinel(self):
        """哨兵事件面板：待认领设备 + 事件历史（最近 200 条）。"""
        win = tk.Toplevel(self)
        win.title("哨兵 · 全网名册")
        win.configure(bg=ui.BG)
        win.transient(self)
        body = tk.Frame(win, bg=ui.CARD, padx=18, pady=14)
        body.pack(fill="both", expand=True)

        pend = self._sentinel.pending()
        tk.Label(body, text=f"待认领设备：{len(pend)} 台（新上线、尚未入册）",
                 bg=ui.CARD, fg=ui.TEXT, font=self.F["small"]).pack(anchor="w")

        def _refresh():
            win.destroy()
            self._open_sentinel()

        # 对抗性审查第 5 轮：此前只渲染 pend[:6]，第 7 台起既看不到也认领不了，
        # 面板反而成了「永远清不干净」的列表。改成可滚动的完整列表 + 选中操作 + 全部认领。
        pcols = ("ip", "mac", "first")
        pv = ttk.Treeview(body, columns=pcols, show="headings",
                          height=min(8, max(3, len(pend))),
                          selectmode="extended")
        for cid, txt, w in (("ip", "IP", 150), ("mac", "MAC", 200),
                            ("first", "首次出现", 150)):
            pv.heading(cid, text=txt)
            pv.column(cid, width=w, anchor="w", stretch=(cid == "mac"))
        pv.pack(fill="x", pady=(6, 6))
        for it in pend:
            pv.insert("", "end", values=(
                it.get("ip") or "?",
                it.get("mac") or "",
                time.strftime("%m-%d %H:%M", time.localtime(it.get("first", 0)))
                if it.get("first") else "—"))

        def _sel_macs() -> list[str]:
            return [pv.item(i, "values")[1] for i in pv.selection()]

        def _claim_sel():
            macs = _sel_macs()
            if not macs:
                messagebox.showinfo("哨兵", "先在上面的列表里选中要认领的设备。", parent=win)
                return
            for m in macs:
                self._sentinel.claim(m)
            self.log(f"[哨兵] 已认领 {len(macs)} 台设备入基线", "ok")
            _refresh()

        def _forget_sel():
            macs = _sel_macs()
            if not macs:
                messagebox.showinfo("哨兵", "先选中要移出的设备（下次出现会重新告警）。", parent=win)
                return
            for m in macs:
                self._sentinel.forget(m)
            self.log(f"[哨兵] 已将 {len(macs)} 台设备移出基线", "info")
            _refresh()

        def _claim_all():
            if not pend:
                return
            for it in pend:
                self._sentinel.claim(it["mac"])
            self.log(f"[哨兵] 已全部认领（{len(pend)} 台）", "ok")
            _refresh()

        brow = tk.Frame(body, bg=ui.CARD)
        brow.pack(fill="x")
        for txt, cmd, bg, fg in (("认领选中", _claim_sel, ui.OLIVE_BG, ui.OLIVE_DK),
                                 ("移出选中", _forget_sel, ui.ROSE_BG, ui.ROSE_DK),
                                 ("全部认领", _claim_all, ui.CARD_ALT, ui.TEXT)):
            tk.Button(brow, text=txt, command=cmd, relief="flat", bd=0,
                      bg=bg, fg=fg, font=self.F["tiny"], padx=12, pady=4,
                      cursor="hand2", activebackground=bg).pack(side="left", padx=(0, 8))

        tk.Label(body, text=f"事件历史（最近 {len(self._sentinel.events)} 条）",
                 bg=ui.CARD, fg=ui.TEXT, font=self.F["small"]).pack(
            anchor="w", pady=(12, 4))
        cols = ("t", "kind", "text")
        tv = ttk.Treeview(body, columns=cols, show="headings", height=12)
        for cid, w, h in (("t", 110, "时间"), ("kind", 70, "类型"), ("text", 380, "事件")):
            tv.heading(cid, text=h)
            tv.column(cid, width=w, anchor="w", stretch=(cid == "text"))
        tv.pack(fill="both", expand=True)
        for ev in reversed(self._sentinel.events):
            tv.insert("", "end", values=(
                time.strftime("%m-%d %H:%M:%S", time.localtime(ev.get("t", 0))),
                {"new": "新设备", "claim": "认领", "forget": "移出",
                 "poison": "投毒", "info": "信息"}.get(ev.get("kind", ""), ev.get("kind", "")),
                ev.get("text", "")))
        tk.Button(body, text="关闭", command=win.destroy, relief="flat",
                  bg=ui.CARD_ALT, fg=ui.TEXT, font=self.F["small"],
                  cursor="hand2", activebackground=ui.BG).pack(pady=(10, 0))
        self._draw_chips()

    def _on_double(self, _e):
        if not self._killer:
            self.do_block(False)
            return
        blocked = {t.ip for t in self._killer.targets()}
        sel = list(self.tree.selection())
        if any(ip not in blocked for ip in sel):
            self.do_block(False)
        else:
            self._unblock_selected()

    # ------------------------------------------------------------ 右键

    def _on_right(self, e):
        iid = self.tree.identify_row(e.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        if not self.tree.selection():
            return
        self.menu.delete(0, "end")
        self.menu.add_command(label="阻断选中", command=lambda: self.do_block(False))
        self.menu.add_command(label="放行选中", command=self._unblock_selected)
        self.menu.add_separator()
        self.menu.add_command(label="限速（自定义 %）…", command=self._ask_duty)
        self.menu.add_command(label="限速 80%（轻度）", command=lambda: self._set_duty(80))
        self.menu.add_command(label="限速 50%", command=lambda: self._set_duty(50))
        self.menu.add_command(label="限速 20%（重度）", command=lambda: self._set_duty(20))
        self.menu.add_command(label="取消限速（恢复全断）", command=lambda: self._set_duty(100))
        self.menu.add_separator()
        self.menu.add_command(label="验证是否已断网", command=self.do_verify)
        self.menu.add_separator()
        self.menu.add_command(label="加入白名单", command=lambda: self._wl(True))
        self.menu.add_command(label="移出白名单", command=lambda: self._wl(False))
        self.menu.add_separator()
        self.menu.add_command(label="复制 IP", command=lambda: self._copy("ip"))
        self.menu.add_command(label="复制 MAC", command=lambda: self._copy("mac"))
        sel = self.tree.selection()
        has_alias = any((self._aliases.get(i)) for i in sel)
        self.menu.add_command(label="设置备注…", command=self._set_alias)
        if has_alias:
            self.menu.add_command(label="清除备注", command=self._clear_alias)
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

    def _set_alias(self):
        sel = self.tree.selection()
        if not sel:
            return
        by_ip = {d.ip: d for d in self._devices}
        dev = by_ip.get(sel[0])
        old = (self._aliases.get(dev.mac) or self._aliases.get(dev.ip, "")) if dev else ""
        name = simpledialog.askstring("设置备注",
                                      f"给 {sel[0]} 起个名字（显示在「标识」列）：",
                                      initialvalue=old, parent=self)
        if name is None:
            return
        name = name.strip()
        if dev:
            self._aliases.pop(dev.mac, None)
            self._aliases.pop(dev.ip, None)
        if name:
            if dev and dev.mac:
                self._aliases[dev.mac] = name
            self._aliases[sel[0]] = name
        core.save_aliases(self._aliases)
        self.log(f"已设置备注：{sel[0]} → {name}" if name
                 else f"已清除备注：{sel[0]}", "ok")
        self._render_rows()

    def _clear_alias(self):
        for i in self.tree.selection():
            self._aliases.pop(i, None)
            by_ip = {d.ip: d for d in self._devices}
            if i in by_ip and by_ip[i].mac:
                self._aliases.pop(by_ip[i].mac, None)
        core.save_aliases(self._aliases)
        self._render_rows()

    def _wl(self, add: bool):
        by_ip = {d.ip: d for d in self._devices}
        changed = 0
        for ip in list(self.tree.selection()):
            d = by_ip.get(ip)
            if not d:
                continue
            if add:
                self._whitelist.add(ip)
                self._whitelist.add(d.mac)
            else:
                self._whitelist.discard(ip)
                self._whitelist.discard(d.mac)
            changed += 1
        if changed:
            core.save_whitelist(self._whitelist)
            self.log(f"白名单更新 {changed} 项", "info")
            self._render_rows()

    def _copy(self, field: str):
        vals = [d.ip if field == "ip" else d.mac
                for d in self._devices if d.ip in self.tree.selection()]
        if vals:
            self.clipboard_clear()
            self.clipboard_append("\n".join(vals))
            self.log(f"已复制 {len(vals)} 个{field.upper()}", "info")

    # ------------------------------------------------------------ 托盘

    def _init_tray(self):
        try:
            import tray as tray_mod
            self._tray = tray_mod.TrayIcon(
                tip=f"WiFiKill {core.APP_VERSION}",
                on_show=lambda: self._post(self._show_window),
                on_release=lambda: self._post(self._tray_release),
                on_quit=lambda: self._post(self._quit))
            if self._tray.start():
                self.log("已驻留系统托盘，关闭窗口不会退出", "info")
            else:
                self._tray = None
                self.log("托盘初始化失败，关闭窗口将直接退出", "warn")
        except Exception as e:
            self._tray = None
            self.log(f"托盘不可用：{e}", "warn")

    def _show_window(self):
        try:
            self.deiconify()
            self.state("normal")
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _hide_to_tray(self):
        self.withdraw()
        if not self._tray_hinted and self._tray:
            self._tray_hinted = True
            self._tray.notify("WiFiKill 仍在运行", "右键托盘图标可以显示主界面或退出")

    def _tray_release(self):
        v4 = len(self._killer.targets()) if self._killer else 0
        v6 = len(self._ndp_mgr.active_ips())
        if not v4 and not v6:
            self._show_window()
            self.log("当前没有阻断目标", "info")
            return
        self._set_busy(True, "正在放行…")

        def work():
            n6 = self._stop_ndp()
            n = self._killer.restore_all() if self._killer else 0

            def done():
                self.log(f"从托盘放行 {n} 台（IPv6 回填 {n6} 次）", "ok")
                if self._tray:
                    self._tray.notify("已全部放行", f"{n} 台设备网络已恢复")
                self._render_rows()
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _quit(self, ask: bool = True):
        if self._quitting:
            return
        self._quitting = True
        active = self._killer.targets() if self._killer else []
        restore = True
        if active and ask:
            try:
                restore = messagebox.askyesno(
                    "退出 WiFiKill",
                    f"仍有 {len(active)} 台设备处于阻断状态。\n\n退出前恢复它们吗？")
            except Exception:
                restore = True
        if self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
        self.set_status("正在退出…")

        def work():
            try:
                self._stop_ndp(restore=restore)
                if restore and self._killer:
                    self._killer.restore_all()
                self._guard.stop()   # 退出时一并停止本机守护
            except Exception:
                pass
            self._post(self._finish)
        threading.Thread(target=work, daemon=True).start()

    def _restart_as_admin(self):
        """以管理员身份重启（UAC 提权后由新实例接管，本实例退出）。

        为什么要有它：部分网卡默认拒绝普通用户发二层帧；顶部横幅只会提示，
        没有入口的话用户只能自己去「右键 → 以管理员身份运行」再开一遍。
        """
        if core.is_admin():
            messagebox.showinfo("以管理员身份重启", "当前已经是管理员权限。", parent=self)
            return
        n = len(self._killer.targets()) if self._killer else 0
        if n and not messagebox.askyesno(
                "以管理员身份重启",
                f"仍有 {n} 台设备处于阻断状态。\n重启会先恢复它们，然后以管理员身份重新启动。\n\n继续？",
                parent=self):
            return
        if not core.relaunch_elevated([]):
            messagebox.showwarning(
                "以管理员身份重启",
                "未能启动提权实例（可能取消了 UAC 弹窗，或当前平台不支持）。\n"
                "也可以手动右键 exe →「以管理员身份运行」。", parent=self)
            return
        self.log("正在以管理员身份重启…", "info")
        self._quit(ask=False)

    def _finish(self):
        self._destroyed = True
        self._stop_block_breath()
        try:
            self._ui.cancel_all()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def on_close(self):
        if self._closing or self._destroyed:
            return
        if self._tray is not None:
            self._hide_to_tray()
            return
        self._quit()

    # ------------------------------------------------------------ 弹窗

    def _show_env(self):
        ni = self._net
        code, msg = core.l2_check()
        lines = [
            f"WiFiKill {core.APP_VERSION}",
            f"Python      {sys.version.split()[0]}",
            f"scapy       {core.scapy_version()}",
            f"管理员权限  {'是' if core.is_admin() else '否'}",
            f"二层收发    {'可用' if code == 'ok' else '不可用（' + msg + '）'}",
            "",
            f"网卡        {ni.iface_name or ni.iface or '—'}",
            f"本机        {ni.my_ip or '—'}  {ni.my_mac or ''}",
            f"网关        {ni.gateway_ip or '—'}  {ni.gateway_mac or ''}",
            f"网段        {ni.cidr or '—'}",
            "",
            "⚠ 免责声明：本工具仅供你在自己拥有或已获授权的网络上进行",
            "学习研究。阻断他人设备可能违反法律法规与网络使用条款。",
        ]
        messagebox.showinfo("环境自检", "\n".join(lines))

    def _open_settings(self):
        # 首次扫描可能还没回来，此时 _v6env 是 None。
        # 不补探一次就会把「IPv6 阻断」误显示为不可用 —— 探测是只读的，几毫秒。
        if self._v6env is None:
            self._refresh_v6env(self._net)

        win = tk.Toplevel(self)
        win.title("设置")
        win.configure(bg=ui.CARD)
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        win.geometry(f"+{self.winfo_rootx() + 240}+{self.winfo_rooty() + 190}")

        body = tk.Frame(win, bg=ui.CARD)
        body.pack(padx=26, pady=22, fill="both")

        tk.Label(body, text="重发间隔", bg=ui.CARD, fg=ui.TEXT,
                 font=self.F["body"]).grid(row=0, column=0, sticky="w")
        iv = tk.StringVar(value=str(self._killer.interval if self._killer
                                    else self._opts[0]))
        tk.Spinbox(body, from_=0.5, to=10.0, increment=0.5, textvariable=iv,
                   width=6, font=self.F["body"], relief="flat", bg=ui.CARD_ALT,
                   fg=ui.TEXT, buttonbackground=ui.CARD_ALT).grid(
            row=0, column=1, sticky="w", padx=14)
        tk.Label(body, text="秒", bg=ui.CARD, fg=ui.TEXT3,
                 font=self.F["small"]).grid(row=0, column=2, sticky="w")

        dry = tk.BooleanVar(value=bool(self._killer.dry_run if self._killer
                                       else self._opts[1]))
        tk.Checkbutton(body, text="演练模式（只记录，不发送）", variable=dry,
                       bg=ui.CARD, fg=ui.TEXT, font=self.F["small"],
                       selectcolor=ui.BG, activebackground=ui.CARD,
                       highlightthickness=0, bd=0).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(16, 0))

        ndp = tk.BooleanVar(value=self._ndp_on)
        v6_ok = bool(self._v6env and self._v6env.dual_stack)
        if self._v6env is None:
            v6_hint = "未能读取本机 IPv6 路由表，此项暂不可用。"
        elif not v6_ok:
            v6_hint = "本网未检测到 IPv6 默认路由，此项不可用（不影响 ARP 阻断）。"
        else:
            v6_hint = ("本网检测到全局 IPv6。开启后会对每个目标做定向 NDP 投毒，"
                       "支持多目标并发、只断经网关的出站流量。\n"
                       "内置失控保护：每个目标独立自检，本机 IPv6 异常立即停手回填。")
        tk.Checkbutton(body, text="启用 IPv6 阻断（实验）—— 支持多目标",
                       variable=ndp, bg=ui.CARD, fg=ui.TEXT, font=self.F["small"],
                       selectcolor=ui.BG, activebackground=ui.CARD,
                       highlightthickness=0, bd=0,
                       state=("normal" if v6_ok else "disabled")).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(12, 0))
        tk.Label(body, text=v6_hint,
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"],
                 justify="left", wraplength=430).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(2, 0))

        guard = tk.BooleanVar(value=self._guard_on)
        guard_hint = ("持续守护本机免遭外部 ARP/NDP 投毒：周期核对并纠正网关真实 MAC。"
                      "即使不主动阻断任何设备也生效。检测到投毒会自动纠正并提示。")
        tk.Checkbutton(body, text="守护本机（主动防御）", variable=guard,
                       bg=ui.CARD, fg=ui.TEXT, font=self.F["small"],
                       selectcolor=ui.BG, activebackground=ui.CARD,
                       highlightthickness=0, bd=0).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(16, 0))
        tk.Label(body, text=guard_hint,
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"],
                 justify="left", wraplength=430).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(2, 0))

        auto = tk.BooleanVar(value=core.autostart_enabled())
        auto_hint = ("已写入注册表 Run 键，登录时自动以管理员身份启动（最小化到托盘）。"
                     if core.WINDOWS else "当前平台不支持开机自启。")
        tk.Checkbutton(body, text="开机自动启动（管理员）", variable=auto,
                       bg=ui.CARD, fg=ui.TEXT, font=self.F["small"],
                       selectcolor=ui.BG, activebackground=ui.CARD,
                       highlightthickness=0, bd=0,
                       state=("normal" if core.WINDOWS else "disabled")).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(16, 0))
        tk.Label(body, text=auto_hint,
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"],
                 justify="left", wraplength=430).grid(
            row=7, column=0, columnspan=3, sticky="w", pady=(2, 0))

        tk.Label(body, text=f"白名单：{core.WHITELIST_FILE.name}\n"
                            f"状态：{core.STATE_FILE.name}（均在程序目录）",
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"], justify="left").grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(16, 0))
        tk.Button(body, text="哨兵事件…", command=self._open_sentinel,
                  bg=ui.CARD_ALT, fg=ui.TEXT, font=self.F["tiny"],
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=ui.BG, activeforeground=ui.TEXT).grid(
            row=8, column=2, sticky="e", pady=(16, 0))

        tk.Label(body,
                 text="免责声明：本工具仅用于你拥有或已获授权的网络的学习研究。"
                      "阻断他人设备可能违反法律法规与网络使用条款。",
                 bg=ui.CARD, fg=ui.SAND_DK, font=self.F["tiny"],
                 justify="left", wraplength=430).grid(
            row=9, column=0, columnspan=3, sticky="w", pady=(14, 0))

        def save():
            try:
                val = max(0.5, min(10.0, float(iv.get())))
            except ValueError:
                messagebox.showwarning("无效", "间隔必须是 0.5 ~ 10 的数字。", parent=win)
                return
            self._opts = (val, dry.get())
            if self._killer:
                self._killer.interval = val
                self._killer.dry_run = dry.get()
            self._guard.dry_run = dry.get()   # 演练模式同样作用于守护

            if ndp.get() != self._ndp_on:
                self._ndp_on = ndp.get()
                if not self._ndp_on:
                    if self._ndp_mgr.active_ips():
                        threading.Thread(target=self._stop_ndp, daemon=True).start()
                    self.log("IPv6 阻断已关闭", "info")
                else:
                    self.log("IPv6 阻断已启用，仅对下一次阻断生效", "warn")

            if auto.get() != core.autostart_enabled():
                ok = core.set_autostart(auto.get())
                if ok:
                    self.log("开机自启已" + ("开启" if auto.get() else "关闭"), "info")
                else:
                    messagebox.showwarning("开机自启失败",
                        "无法写入注册表，请以管理员身份运行后再试。", parent=win)

            if guard.get() != self._guard_on:
                self._guard_on = guard.get()
                if self._guard_on:
                    ok = self._start_guard()
                    if ok:
                        core.set_guard_enabled(True)
                        self.log("本机守护已开启（主动防御）", "ok")
                    else:
                        self._guard_on = False
                        messagebox.showwarning("守护本机",
                            "暂时无法启动：请先扫描到网关与真实网关 MAC。", parent=win)
                else:
                    self._guard.stop()
                    core.set_guard_enabled(False)
                    self.log("本机守护已关闭", "info")
            self._sync_guard_btn()
            self._draw_chips()
            self.log(f"设置已保存：间隔 {val}s，演练 {'开' if dry.get() else '关'}", "info")
            self._render_banner()
            win.destroy()

        btns = tk.Frame(body, bg=ui.CARD)
        btns.grid(row=10, column=0, columnspan=3, sticky="e", pady=(20, 0))
        if not core.is_admin():
            tk.Button(btns, text="以管理员身份重启", command=self._restart_as_admin,
                      relief="flat", bd=0, bg=ui.SAND_BG, fg=ui.SAND_DK,
                      font=self.F["small"], padx=14, pady=6,
                      cursor="hand2", activebackground=ui.SAND_BG).pack(side="left")
        tk.Button(btns, text="取消", command=win.destroy, relief="flat", bd=0,
                  bg=ui.CARD_ALT, fg=ui.TEXT2, font=self.F["small"],
                  padx=16, pady=6, cursor="hand2").pack(side="right")
        tk.Button(btns, text="保存", command=save, relief="flat", bd=0,
                  bg=ui.SAGE, fg="#FFFFFF", font=self.F["small"], padx=16, pady=6,
                  cursor="hand2", activebackground=ui.SAGE_DK,
                  activeforeground="#FFFFFF").pack(side="right", padx=8)


def main():
    minimized = "--minimized" in sys.argv
    try:
        app = App()
        if minimized:
            app.withdraw()
        app.mainloop()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        pass
    except Exception:
        import traceback
        detail = traceback.format_exc()
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("WiFiKill 启动失败",
                                 detail[-1500:] + "\n\n完整日志请用源码方式运行查看。")
            root.destroy()
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()

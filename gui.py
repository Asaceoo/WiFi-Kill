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

import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from tkinter import messagebox, ttk

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
        self.geometry("1104x808")
        self.minsize(960, 680)
        self.configure(bg=ui.BG)

        fam = pick_family()
        self.F = {
            "h1": (fam, 23), "sub": (fam, 10), "body": (fam, 10),
            "small": (fam, 9), "tiny": (fam, 8),
            "k": (fam, 9), "v": (fam, 11), "mono": ("Consolas", 9),
        }

        self._q: queue.Queue = queue.Queue()
        self._busy = False
        self._devices: list[core.Device] = []
        self._net = core.NetInfo()
        self._killer: core.Killer | None = None
        self._whitelist: set[str] = core.load_whitelist()
        self._closing = False
        self._destroyed = False
        self._opts = (1.5, False)
        self._ndp_on = False              # IPv6 阻断开关，默认关（两道门之一）
        self._v6env = None                # ipv6.V6Env，扫描后探测
        self._ndp = None                  # ipv6.NdpBlocker，同一时刻最多一个
        self._ndp_ip = ""                 # 当前 IPv6 阻断的目标 IP
        self._ndp_state = ""              # "" / "ok" / "miss"（探明失败）
        self._tray = None
        self._tray_hinted = False
        self._quitting = False
        self._banner_state: tuple[str, str] | None = None
        self._status_text = "就绪"
        self._wl_hidden = False
        self._geo = {"w": 1040, "h": 760, "P": 32}

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
                     foreground=ui.TEXT, rowheight=34, borderwidth=0,
                     font=self.F["body"])
        st.configure("M.Treeview.Heading", background=ui.CARD,
                     foreground=ui.TEXT3, font=self.F["tiny"], relief="flat",
                     padding=(10, 10))
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
                                          "dtype", "state", "_sp"),
                                 show="headings", selectmode="extended")
        heads = {"no": "#", "ip": "IP 地址", "mac": "MAC 地址",
                 "vendor": "厂商", "dtype": "类型", "state": "状态", "_sp": ""}
        widths = {"no": 56, "ip": 148, "mac": 176, "vendor": 220,
                  "dtype": 118, "state": 112, "_sp": 40}
        for c in heads:
            self.tree.heading(c, text=heads[c], anchor="w")
            self.tree.column(c, width=widths[c], minwidth=widths[c] - 24,
                             anchor="w", stretch=(c == "_sp"))
        self.tree.tag_configure("blocked", foreground=ui.ROSE_DK)
        self.tree.tag_configure("gw", foreground=ui.TEXT3)
        self.tree.tag_configure("me", foreground=ui.SAGE_DK)
        self.tree.tag_configure("wl", foreground=ui.BLUSH)
        self.tree.tag_configure("flash", background=ui.SAGE_BG)

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
        for x in (self.btn_scan, self.btn_block, self.btn_all, self.btn_free):
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

        by = 92
        if self._banner_state:
            kind, text = self._banner_state
            bgc = ui.SAND_BG if kind != "info" else ui.SAGE_BG
            fgc = getattr(ui, "SAND_DK", ui.SAND) if kind != "info" else ui.SAGE_DK
            ui.rrect(cv, P, by, w - P, by + 34, 12, fill=bgc, outline="",
                     tags="static")
            cv.create_text(P + 16, by + 17, text=text, anchor="w",
                           font=self.F["small"], fill=fgc, tags="static")
            if kind == "npcap":
                cv.create_text(w - P - 16, by + 17, text="打开下载页 →",
                               anchor="e", font=self.F["small"], fill=fgc,
                               tags=("static", "bannerlink"))
                cv.tag_bind("bannerlink", "<Button-1>",
                            lambda e: webbrowser.open(NPCAP_URL))
            ny = by + 48
        else:
            ny = 92

        card_h = 100
        ui.card(cv, P, ny, w - P, ny + card_h, 16, tags="static")
        cols = [("iface", "网卡"), ("ip", "本机"), ("gw", "网关"), ("cidr", "网段")]
        inner_w = (w - P * 2 - 44) / 4
        self._net_items = {}
        for i, (key, cap) in enumerate(cols):
            cx = P + 22 + i * inner_w
            cv.create_text(cx, ny + 26, text=cap, anchor="w",
                           font=self.F["k"], fill=ui.TEXT3, tags="static")
            main = cv.create_text(cx, ny + 52, text="—", anchor="w",
                                  width=inner_w - 14, font=self.F["v"],
                                  fill=ui.TEXT, tags="static")
            sub = cv.create_text(cx, ny + 76, text="", anchor="w",
                                 width=inner_w - 14, font=self.F["small"],
                                 fill=ui.TEXT3, tags="static")
            self._net_items[key] = (main, sub)
        self._render_net()

        ty = ny + card_h + 20
        bx = P
        for btn in (self.btn_scan, self.btn_block, self.btn_all, self.btn_free):
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

        tbl_y = ty + 60
        # 剩余空间优先给表格，日志卡 104~140 自适应
        avail = max(320, h - tbl_y - 88)
        log_h = int(min(140, max(104, avail * 0.25)))
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
        cv.create_text(g["P"], g["h"] - 26, text=self._footer_text(), anchor="w",
                       font=self.F["small"], fill=ui.TEXT3, tags=("static", "footer"))
        cv.create_text(g["w"] - g["P"], g["h"] - 26, text=f"v{core.APP_VERSION}",
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

    def _footer_text(self) -> str:
        blocked = len(self._killer.targets()) if self._killer else 0
        return f"共 {len(self._devices)} 台设备 · 阻断中 {blocked} 台 · 关闭窗口将驻留托盘"

    # ------------------------------------------------------------ 动画

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
                self.after(16, tick)
        tick()

    def _flash(self, ip: str):
        try:
            if self.tree.exists(ip):
                tags = [t for t in self.tree.item(ip, "tags") if t != "flash"]
                self.tree.item(ip, tags=tuple(tags + ["flash"]))
                self.after(520, lambda: self._unflash(ip))
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
        self.logtext.configure(state="normal")
        self.logtext.insert("end", f"{time.strftime('%H:%M:%S')}   {msg}\n", level)
        self.logtext.see("end")
        lines = int(self.logtext.index("end-1c").split(".")[0])
        if lines > 400:
            self.logtext.delete("1.0", f"{lines - 400}.0")
        self.logtext.configure(state="disabled")

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
        self._status_text = text
        try:
            self.canvas.itemconfig("badgetext", text=text)
        except tk.TclError:
            pass

    def _update_buttons(self):
        idle = not self._busy
        has = bool(self.tree.selection())
        blocked = bool(self._killer and self._killer.targets())
        self.btn_scan.set_enabled(idle)
        self.btn_block.set_enabled(idle and has)
        self.btn_all.set_enabled(idle and bool(self._devices))
        self.btn_free.set_enabled(idle and blocked)
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
                                  "同时仅支持 1 台目标")
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
        items = st.get("targets") or []
        if not items:
            return
        names = "、".join(t["ip"] for t in items[:4])
        more = f" 等 {len(items)} 台" if len(items) > 4 else ""
        if messagebox.askyesno(
                "发现残留阻断",
                f"上次退出时仍有 {len(items)} 台设备处于阻断状态：\n{names}{more}\n\n现在恢复它们吗？"):
            self._restore_from_state(items)
        else:
            self.log("已忽略残留记录；可稍后点「全部放行」清理", "warn")

    def _restore_from_state(self, items):
        def work():
            ni = core.NetInfo(**self._net.__dict__)
            st = core.load_state()
            ni.gateway_mac = st.get("gateway_mac") or ni.gateway_mac
            ni.gateway_ip = st.get("gateway_ip") or ni.gateway_ip
            k = core.Killer(ni, dry_run=False)
            for it in items:
                k._targets[it["ip"]] = core.Target(it["ip"], it["mac"])
            n = k.restore_all()
            self._post(lambda: self.log(f"已恢复 {n} 台设备", "ok"))
            self._post(self.do_scan)
        threading.Thread(target=work, daemon=True).start()

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
                    self._post(lambda: self.log("无法确定网关，请检查是否已联网", "err"))
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
        self._net = ni
        self._devices = devs
        self._refresh_v6env(ni)
        self._render_net()
        self._render_rows()
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

    def _state_of(self, d: core.Device) -> tuple[str, str]:
        if d.note == "网关":
            return "网关", "gw"
        if d.note == "本机":
            return "本机", "me"
        if d.ip in self._whitelist or d.mac in self._whitelist:
            return "白名单", "wl"
        if self._killer and any(t.ip == d.ip for t in self._killer.targets()):
            if self._ndp and d.ip == self._ndp_ip:
                return "阻断中·双栈", "blocked"
            if self._ndp_state == "miss" and d.ip == self._ndp_ip:
                return "阻断中·仅v4", "v4only"
            return "阻断中", "blocked"
        return "未阻断", ""

    def _render_rows(self):
        sel = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        idx = 0
        for d in self._devices:
            state, tag = self._state_of(d)
            if self._wl_hidden and state == "白名单":
                continue
            idx += 1
            self.tree.insert("", "end", iid=d.ip, tags=(tag,) if tag else (),
                             values=(idx, d.ip, d.mac, d.vendor, d.dtype, state, ""))
        for iid in sel:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)
        blocked = len(self._killer.targets()) if self._killer else 0
        if self._badge_dot:
            self._badge_dot.set(ui.ROSE if blocked else ui.OLIVE, pulse=blocked > 0)
        self._update_buttons()

    # ------------------------------------------------------------ 阻断

    def _build_killer(self) -> core.Killer:
        code, msg = core.l2_check()
        if code != "ok":
            raise core.BlockError(msg)
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
                     if d.note not in ("网关", "本机")
                     and d.ip not in self._whitelist and d.mac not in self._whitelist]
            if not picks:
                messagebox.showinfo("无可阻断设备", "除网关/本机/白名单外没有目标。")
                return
            if not messagebox.askyesno("确认全阻断",
                                       f"将阻断 {len(picks)} 台设备。\n网关与本机已自动排除。\n\n继续？"):
                return
        else:
            ips = list(self.tree.selection())
            if not ips:
                return
            by_ip = {d.ip: d for d in self._devices}
            picks = [by_ip[i] for i in ips if i in by_ip]

        code, msg = core.l2_check()
        if code != "ok":
            self._render_banner(code, msg)
            messagebox.showwarning("无法阻断", f"{msg}\n\n请先处理顶部提示。")
            return

        # 第二道门：IPv6 阻断开启时只允许单目标
        if self._ndp_on and len(picks) > 1:
            messagebox.showwarning(
                "IPv6 阻断只支持单目标",
                "开启 IPv6 阻断后，同时只能阻断 1 台设备。\n\n"
                "原因：定向投毒需要逐台探明链路本地地址，"
                "多目标并行会让整网 IPv6 的失控风险不可控。\n"
                "需要批量阻断时，请先在「设置」里关闭 IPv6 阻断。")
            return

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

            v6msg = ""
            if added and self._ndp_on and picks:
                try:
                    v6msg = self._start_ndp(k.ni, picks[0])
                except Exception as e:
                    self._ndp_state = "miss"
                    v6msg = f"IPv6 阻断启动异常：{e}"

            def done():
                if added:
                    self.log(f"已阻断 {added} 台", "ok")
                if skipped:
                    self.log("跳过：" + "，".join(skipped), "warn")
                if v6msg:
                    self.log(v6msg, "ok" if self._ndp else "warn")
                self._render_rows()
                self._render_banner()
                for d in picks:
                    self._flash(d.ip)
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _start_ndp(self, ni, dev) -> str:
        """探明目标 LLA 并启动 IPv6 定向阻断。必须在工作线程里调用。"""
        import ipv6 as v6

        env = self._v6env
        if env is None or not env.dual_stack:
            self._ndp_state = "miss"
            return "本网未检测到 IPv6，跳过 IPv6 阻断"

        self._stop_ndp()
        lla, how = v6.find_lla(ni.iface, dev.mac, env.my_lla, sniff_seconds=12.0)
        if not lla:
            self._ndp_state = "miss"
            self._ndp_ip = dev.ip
            return (f"未能探明 {dev.ip} 的 IPv6 地址（{how}）—— "
                    f"该设备的 IPv6 流量未阻断，界面已标注「仅v4」")

        blocker = v6.NdpBlocker(ni, env, dev.ip, dev.mac, lla,
                                interval=self._opts[0])
        ok, why = blocker.start()
        if not ok:
            self._ndp_state = "miss"
            self._ndp_ip = dev.ip
            return f"IPv6 定向阻断未启动：{why}"

        self._ndp = blocker
        self._ndp_ip = dev.ip
        self._ndp_state = "ok"
        return f"IPv6 定向阻断已生效：{dev.ip} → {lla}（来源 {how}）"

    def _stop_ndp(self, restore: bool = True):
        b = self._ndp
        self._ndp = None
        self._ndp_ip = ""
        self._ndp_state = ""
        if not b:
            return 0
        try:
            n = b.stop(restore=restore)
            self.log(f"IPv6 阻断已停止，回填 {n} 次", "info")
            return n
        except Exception as e:
            self.log(f"IPv6 阻断停止异常：{e}", "warn")
            return 0

    def do_unblock_all(self):
        if not self._killer or not self._killer.targets():
            return
        n = len(self._killer.targets())
        if not messagebox.askyesno("确认放行", f"恢复全部 {n} 台设备的网络？"):
            return
        self._set_busy(True, "正在恢复…")

        def work():
            self._stop_ndp()
            ok = self._killer.restore_all()

            def done():
                self.log(f"已放行 {ok} 台，网络应已恢复", "ok")
                self._render_rows()
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _unblock_selected(self):
        if not self._killer:
            return
        sel = list(self.tree.selection())

        def work():
            if self._ndp_ip and self._ndp_ip in sel:
                self._stop_ndp()
            for ip in sel:
                self._killer.remove(ip)
            self._post(self._render_rows)
        threading.Thread(target=work, daemon=True).start()

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
        self.menu.add_command(label="加入白名单", command=lambda: self._wl(True))
        self.menu.add_command(label="移出白名单", command=lambda: self._wl(False))
        self.menu.add_separator()
        self.menu.add_command(label="复制 IP", command=lambda: self._copy("ip"))
        self.menu.add_command(label="复制 MAC", command=lambda: self._copy("mac"))
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

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
        if not self._killer or not self._killer.targets():
            self._show_window()
            self.log("当前没有阻断目标", "info")
            return
        self._set_busy(True, "正在放行…")

        def work():
            self._stop_ndp()
            n = self._killer.restore_all()

            def done():
                self.log(f"从托盘放行 {n} 台", "ok")
                if self._tray:
                    self._tray.notify("已全部放行", f"{n} 台设备网络已恢复")
                self._render_rows()
                self._set_busy(False)
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _quit(self):
        if self._quitting:
            return
        self._quitting = True
        active = self._killer.targets() if self._killer else []
        restore = True
        if active:
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
            except Exception:
                pass
            self._post(self._finish)
        threading.Thread(target=work, daemon=True).start()

    def _finish(self):
        self._destroyed = True
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
            v6_hint = ("本网检测到全局 IPv6。开启后会对单个目标做定向 NDP 投毒，"
                       "只断经网关的出站流量。\n"
                       "内置失控保护：阻断期间持续自检，本机 IPv6 异常立即停手回填。")
        tk.Checkbutton(body, text="启用 IPv6 阻断（实验）—— 同时只能断 1 台",
                       variable=ndp, bg=ui.CARD, fg=ui.TEXT, font=self.F["small"],
                       selectcolor=ui.BG, activebackground=ui.CARD,
                       highlightthickness=0, bd=0,
                       state=("normal" if v6_ok else "disabled")).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(12, 0))
        tk.Label(body, text=v6_hint,
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"],
                 justify="left", wraplength=430).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(2, 0))

        tk.Label(body, text=f"白名单：{core.WHITELIST_FILE.name}\n"
                            f"状态：{core.STATE_FILE.name}（均在程序目录）",
                 bg=ui.CARD, fg=ui.TEXT3, font=self.F["tiny"], justify="left").grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(16, 0))

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

            if ndp.get() != self._ndp_on:
                self._ndp_on = ndp.get()
                if not self._ndp_on:
                    if self._ndp:
                        threading.Thread(target=self._stop_ndp, daemon=True).start()
                    self.log("IPv6 阻断已关闭", "info")
                else:
                    self.log("IPv6 阻断已启用，仅对下一次阻断生效，且同时只支持 1 台", "warn")
            self.log(f"设置已保存：间隔 {val}s，演练 {'开' if dry.get() else '关'}", "info")
            self._render_banner()
            win.destroy()

        btns = tk.Frame(body, bg=ui.CARD)
        btns.grid(row=5, column=0, columnspan=3, sticky="e", pady=(20, 0))
        tk.Button(btns, text="取消", command=win.destroy, relief="flat", bd=0,
                  bg=ui.CARD_ALT, fg=ui.TEXT2, font=self.F["small"],
                  padx=16, pady=6, cursor="hand2").pack(side="right")
        tk.Button(btns, text="保存", command=save, relief="flat", bd=0,
                  bg=ui.SAGE, fg="#FFFFFF", font=self.F["small"], padx=16, pady=6,
                  cursor="hand2", activebackground=ui.SAGE_DK,
                  activeforeground="#FFFFFF").pack(side="right", padx=8)


def main():
    try:
        app = App()
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

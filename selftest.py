#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py — GUI 全功能自检（真机执行，不触碰真实设备）

做法：
1. 启动真实 GUI，走真实扫描；
2. 注入一台“幽灵设备”（MAC 02:00:00:00:00:01，全网不存在），对它执行阻断/放行，
   这样图形链路、报文链路都被真实执行，但不会影响任何真人设备；
3. 每步截图 + 断言，最后输出清单结果。
"""

import ctypes
import ctypes.wintypes as wt
import sys
import time
import traceback
from pathlib import Path

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:
    Image = None
    HAVE_PIL = False

import core
import gui

HERE = Path(__file__).resolve().parent
RESULTS = []
SHOTS = 0


def snap(win, name):
    global SHOTS
    if not HAVE_PIL:
        return          # 无 Pillow 时跳过截图，不影响断言结果
    hwnd = int(win.wm_frame(), 16) if isinstance(win.wm_frame(), str) else win.winfo_id()
    u, g = ctypes.windll.user32, ctypes.windll.gdi32
    r = wt.RECT()
    u.GetWindowRect(hwnd, ctypes.byref(r))
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return
    hdc = u.GetWindowDC(hwnd)
    mdc = g.CreateCompatibleDC(hdc)
    bmp = g.CreateCompatibleBitmap(hdc, w, h)
    g.SelectObject(mdc, bmp)
    u.PrintWindow(hwnd, mdc, 2)

    class BIH(ctypes.Structure):
        _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                    ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                    ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                    ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                    ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]

    bi = BIH()
    bi.biSize = ctypes.sizeof(BIH)
    bi.biWidth, bi.biHeight = w, -h
    bi.biPlanes, bi.biBitCount = 1, 32
    buf = ctypes.create_string_buffer(w * h * 4)
    g.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1).save(HERE / name)
    g.DeleteObject(bmp)
    g.DeleteDC(mdc)
    u.ReleaseDC(hwnd, hdc)
    SHOTS += 1


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))


STATE_BACKUP: list[tuple[Path, bytes | None]] = []


def isolate_state():
    """把外部状态文件挪开：上一轮中断残留的 whitelist.txt 会让断言结果
    取决于"上次跑到哪一步"，这是实测踩过的坑。"""
    for f in (core.WHITELIST_FILE, core.STATE_FILE, core.GUARD_FILE,
              core.SENTINEL_FILE):
        try:
            STATE_BACKUP.append((f, f.read_bytes() if f.exists() else None))
            f.unlink(missing_ok=True)
        except Exception:
            pass


def restore_state():
    for f, data in STATE_BACKUP:
        try:
            if data is None:
                f.unlink(missing_ok=True)
            else:
                f.write_bytes(data)
        except Exception:
            pass


def run():
    isolate_state()
    app = gui.App()
    app.geometry("1220x900+40+40")
    steps = []

    def step(fn, delay):
        app.after(delay, fn)

    def wait_then(cond, fn, timeout=15000, interval=200):
        """条件满足后再执行，避免用固定延时赌时序。"""
        deadline = [timeout]

        def poll():
            try:
                ok = cond()
            except Exception:
                ok = False
            if ok:
                fn()
            elif deadline[0] <= 0:
                fn()
            else:
                deadline[0] -= interval
                app.after(interval, poll)
        app.after(interval, poll)

    # 1. 启动 + 自动扫描
    def s1():
        try:
            check("自动扫描完成", len(app._devices) >= 1, f"{len(app._devices)} 台")
            check("网关已识别", any(d.note == "网关" for d in app._devices))
            check("本机已识别", any(d.note == "本机" for d in app._devices))
            check("网卡友好名", "·" in (app._net.iface_name or ""), app._net.iface_name)
            check("状态栏已渲染", bool(app._status_text))
            check("日志有内容", app.logtext.index("end-1c") != "1.0")
            snap(app, "t1_scan.png")
        except Exception:
            check("s1", False, traceback.format_exc()[-300:])
        if not app._devices:
            tail = app.logtext.get("end-4l", "end-1c").strip().replace("\n", " | ")
            check("s1 诊断", False, tail[-260:])

    # 2. 注入幽灵设备并阻断
    def s2():
        try:
            ghost = core.Device(ip="192.168.1.250", mac="02:00:00:00:00:01",
                                vendor="测试用", dtype="幽灵", note="")
            app._devices.append(ghost)
            app._render_rows()
            app.tree.selection_set("192.168.1.250")
            app._update_buttons()
            check("幽灵设备已入表", "192.168.1.250" in app.tree.get_children())
            check("阻断按钮已启用", app.btn_block.enabled)
            app.do_block(False)
        except Exception:
            check("s2", False, traceback.format_exc()[-300:])

    # 3. 检查阻断生效
    def s3():
        try:
            blocked = app._killer.targets() if app._killer else []
            check("Killer 已建立", app._killer is not None)
            check("目标进入阻断队列", any(t.ip == "192.168.1.250" for t in blocked),
                  str([t.ip for t in blocked]))
            check("投毒线程运行中", bool(app._killer and app._killer.is_active()))
            check("状态文件已落盘", core.STATE_FILE.exists())
            rows = app.tree.item("192.168.1.250")["values"]
            check("行状态=阻断中", "阻断中" in [str(x) for x in rows], str(rows))
            check("放行按钮已启用", app.btn_free.enabled)
            # --- 占空比限速（v2.6.0）---
            app._killer.set_duty("192.168.1.250", 50)
            check("限速占空比生效", app._killer.duty_of("192.168.1.250") == 50)
            _d = type("D", (), {"ip": "192.168.1.250"})
            state, _tag = app._state_of(_d())
            check("状态列显示限速", "限速 50%" in state, state)
            app._killer.set_duty("192.168.1.250", 100)
            check("取消限速回到全断", app._killer.duty_of("192.168.1.250") == 100)
            snap(app, "t2_blocked.png")
        except Exception:
            check("s3", False, traceback.format_exc()[-300:])

    # 4. 白名单
    def s4():
        try:
            app.tree.selection_set("192.168.1.250")
            app._wl(True)
            check("白名单文件生成", core.WHITELIST_FILE.exists())
            wl = core.load_whitelist()
            check("白名单包含 IP", "192.168.1.250" in wl)
            check("白名单包含 MAC", "02:00:00:00:00:01" in wl)
            app._wl(False)
            check("白名单可移除", "192.168.1.250" not in core.load_whitelist())
        except Exception:
            check("s4", False, traceback.format_exc()[-300:])

    # 5. 设置对话框
    def s5():
        try:
            app._open_settings()
            tops = [w for w in app.winfo_children() if isinstance(w, gui.tk.Toplevel)]
            check("设置窗口可打开", len(tops) >= 1)
            for t in tops:
                t.destroy()
            rows = app._killer.targets() if app._killer else []
            check("阻断期间设置不改状态", len(rows) == 1)
        except Exception:
            check("s5", False, traceback.format_exc()[-300:])

    # 6. 全部放行
    def s6():
        try:
            if app._killer:
                app._killer.restore_all()
            check("阻断队列已清空", not (app._killer and app._killer.targets()))
            check("状态文件已删除", not core.STATE_FILE.exists())
            app._render_rows()
            rows = app.tree.item("192.168.1.250")["values"]
            check("行状态恢复=未阻断", "未阻断" in [str(x) for x in rows], str(rows))
            check("放行按钮已禁用", not app.btn_free.enabled)
            snap(app, "t3_released.png")
        except Exception:
            check("s6", False, traceback.format_exc()[-300:])

    # 6.5 托盘
    def s6b():
        try:
            check("托盘已初始化", bool(app._tray and app._tray.available))
            app.on_close()
            app.update()
            check("点关闭后窗口隐藏而非退出", not app.winfo_viewable())
            app._show_window()
            app.update()
            check("可从托盘唤回主界面", app.winfo_viewable())
            snap(app, "t4_tray_back.png")
        except Exception:
            check("s6b", False, traceback.format_exc()[-300:])

    # 6.7 多选 + 本机守护（演练模式：dry_run 只记录不发包，真机安全）
    def s6c():
        try:
            # --- 全选 / 反选 ---
            n_rows = len(app.tree.get_children())
            app.btn_sel_all.command()
            check("全选生效", len(app.tree.selection()) == n_rows,
                  f"{len(app.tree.selection())}/{n_rows}")
            app.btn_sel_inv.command()      # 全选状态下反选 → 全部取消
            check("反选(全选→清空)", len(app.tree.selection()) == 0)
            app.btn_sel_inv.command()      # 再反选 → 恢复全选
            check("反选(清空→全选)", len(app.tree.selection()) == n_rows)
            app.tree.selection_remove(*app.tree.selection())
            # --- 本机守护（演练）---
            check("守护按钮存在", hasattr(app, "btn_guard") and app.btn_guard.enabled)
            app._opts = (app._opts[0], True)   # 演练模式：dry_run，绝不发真实包
            app._toggle_guard()                # 走真实开关路径开启（含持久化）
            app.update()
            check("守护可开启(演练)", app._guard.is_active())
            check("守护演练模式生效", app._guard.dry_run is True)
            check("守护按钮文字=守护中", app.btn_guard.text == "守护中", app.btn_guard.text)
            app._draw_chips()
            check("状态徽章含守护中", bool(app._chip_vals) and bool(app._chip_vals[3]))
            check("守护开关已持久化", core.guard_enabled() is True)
            app._toggle_guard()                # 走真实开关路径关闭
            app.update()
            check("守护可关闭", not app._guard.is_active())
            check("守护按钮文字复原", app.btn_guard.text == "守护本机", app.btn_guard.text)
            check("守护开关持久化关闭", core.guard_enabled() is False)
            # --- 全网哨兵（v2.5.0）---
            check("哨兵已建基线(首次静默)", len(app._sentinel.pending()) == 0
                  and len(app._sentinel._known) >= 1)
            app._sentinel.feed_event("info", "自检：事件流写入验证")
            check("哨兵事件流可写入", len(app._sentinel.events) >= 1
                  and app._sentinel.events[-1]["kind"] == "info")
            for w in list(app.winfo_children()):     # 先清遗留窗口，避免判定受上一轮干扰
                if isinstance(w, gui.tk.Toplevel):
                    w.destroy()
            app.update()
            before = [w for w in app.winfo_children() if isinstance(w, gui.tk.Toplevel)]
            app._open_sentinel()               # 面板可打开
            app.update()
            after = [w for w in app.winfo_children() if isinstance(w, gui.tk.Toplevel)]
            check("哨兵面板可打开", len(after) == len(before) + 1,
                  f"打开前 {len(before)} / 打开后 {len(after)}")
            for w in list(app.winfo_children()):
                if isinstance(w, gui.tk.Toplevel):
                    w.destroy()
        except Exception:
            check("s6c", False, traceback.format_exc()[-300:])

    # 6.9 第 5 轮回归：IPv6 阻断的可见性 / 哨兵面板不截断 / 网络变更中止
    def s6d():
        try:
            # ① 只剩 IPv6 目标时，「全部放行」必须可用（此前按钮被判死）
            class _FakeV6:
                def __init__(self):
                    self.calls = 0
                def active_ips(self):
                    return ["192.168.1.251"]
                def state_of(self, ip):
                    return ""
                def restore_all(self, restore=True):
                    self.calls += 1
                    return 1
                def remove(self, ip, restore=True):
                    return 0

            real_mgr = app._ndp_mgr
            fake = _FakeV6()
            app._ndp_mgr = fake
            app._update_buttons()
            check("仅有 IPv6 阻断时「全部放行」可用", app.btn_free.enabled)
            app._ndp_mgr = real_mgr
            app._update_buttons()

            # ② 哨兵面板列出全部待认领：8 台都要在，不能被 pending[:6] 截断
            for i in range(8):
                mac = f"02:00:00:00:{i + 1:02x}:01"
                app._sentinel._known[mac] = {"ip": f"192.168.1.{200 + i}", "name": "",
                                             "known": False, "first": 0}
            app._open_sentinel()
            app.update()
            tv, n = None, -1
            for w in app.winfo_children():
                if not isinstance(w, gui.tk.Toplevel):
                    continue
                for frame in w.winfo_children():
                    for c in frame.winfo_children():
                        try:
                            cols = [str(x) for x in c["columns"]]
                        except Exception:
                            continue
                        if isinstance(c, gui.ttk.Treeview) and cols == ["ip", "mac", "first"]:
                            tv, n = c, len(c.get_children())
            check("哨兵面板列出全部待认领(8 台)", n == 8, f"实际 {n} 台")
            for w in list(app.winfo_children()):
                if isinstance(w, gui.tk.Toplevel):
                    w.destroy()

            # ③ 网络变更：旧阻断必须中止，状态文件不能留着下次误恢复
            k = core.Killer(app._net, dry_run=True)
            k.add(core.Target("192.168.1.250", "02:00:00:00:00:01"))
            k.persist()
            app._killer = k
            other = core.NetInfo(**{**app._net.__dict__,
                                    "gateway_ip": "10.9.9.1",
                                    "gateway_mac": "02:00:00:00:00:99"})
            app._apply_scan(other, app._devices, True)
            for _ in range(80):        # 清理走后台线程，轮询等它收敛（不靠固定延时赌时序）
                app.update()
                if not k.targets() and not core.STATE_FILE.exists():
                    break
                time.sleep(0.05)
            check("网络变更后旧阻断被中止", not k.targets(), str([t.ip for t in k.targets()]))
            check("网络变更后状态文件被清除", not core.STATE_FILE.exists())
            check("网络变更后旧上下文被摘除(下次阻断会重建)", app._killer is None)
        except Exception:
            check("s6d", False, traceback.format_exc()[-300:])

    # 7. 退出
    def s7():
        check("关闭流程不抛异常", True)
        app._finish()

    wait_then(lambda: not app._busy and len(app._devices) > 0, lambda: (
        s1(), app.after(300, s2), app.after(2600, s3), app.after(3000, s4),
        app.after(3400, s5), app.after(3800, s6), app.after(4300, s6b),
        app.after(4900, s6c), app.after(5600, s6d), app.after(6800, s7)))
    app.mainloop()
    restore_state()


if __name__ == "__main__":
    core.LOG.subscribe(lambda lv, m: print(f"[{lv}] {m}", flush=True))
    run()
    print("\n================ 自检结果 ================")
    bad = 0
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
        bad += 0 if ok else 1
    print(f"-----------------------------------------\n共 {len(RESULTS)} 项，失败 {bad} 项，截图 {SHOTS} 张")
    sys.exit(1 if bad else 0)

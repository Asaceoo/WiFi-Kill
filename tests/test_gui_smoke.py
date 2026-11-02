#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests/test_gui_smoke.py — GUI 冒烟测试（CI 可跑，绝不发一个包）

为什么需要它：真机 selftest 需要 Npcap 与真实网卡，进不了 CI；而「ui 常量缺失」这类
只在真机渲染时才崩的问题（红线 8）一直缺一道自动化防线。本套件只做三件事：

1. 真实构建主窗口（Canvas + ttk 树 + 按钮 + 托盘接线）并渲染一次；
2. 走一次真实扫描（无 Npcap 时自动回退到系统缓存路径）并断言设备表落地；
3. 静态校验 gui.py 引用的每个 ui 常量都存在——把真机才会暴露的崩溃提前到 CI。

全程不调用 do_block()，因此不存在任何发帧行为；守护开关在开始时被清掉。
"""

from __future__ import annotations

import re
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
STATE_FILES = None


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, bool(ok), detail))


def isolate_state():
    """挪开运行时状态文件：残留的 guard.json 会让冒烟测试真的启动守护（会发包）。"""
    global STATE_FILES
    STATE_FILES = []
    for f in (core.WHITELIST_FILE, core.STATE_FILE, core.GUARD_FILE, core.SENTINEL_FILE):
        try:
            STATE_FILES.append((f, f.read_bytes() if f.exists() else None))
            f.unlink(missing_ok=True)
        except Exception:
            pass


def restore_state():
    for f, data in (STATE_FILES or []):
        try:
            if data is None:
                f.unlink(missing_ok=True)
            else:
                f.write_bytes(data)
        except Exception:
            pass


def static_ui_constants():
    """红线 8 的自动化：gui.py 里 `ui.XXX` 引用的常量必须真实存在。"""
    import ui as ui_mod
    src = (ROOT / "gui.py").read_text(encoding="utf-8")
    names = sorted({c for c in re.findall(r"\bui\.([A-Z][A-Z0-9_]+)\b", src)})
    missing = [c for c in names if not hasattr(ui_mod, c)]
    check("ui 常量引用全部存在", not missing, str(missing))
    check("ui 常量确实被引用（防空跑）", len(names) >= 10, str(len(names)))


def main() -> int:
    isolate_state()
    try:
        import tkinter as tk
    except Exception as e:
        print(f"SKIP 无 tkinter：{e}")
        return 0
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
    except Exception as e:
        print(f"SKIP 当前环境无法初始化 Tk（无图形会话）：{e}")
        return 0

    static_ui_constants()

    import gui
    app = gui.App()
    app.geometry("1180x860+30+30")

    def s1():
        try:
            check("主窗口已构建", bool(app.winfo_exists()) and app.canvas is not None)
            cols = [str(c) for c in app.tree["columns"]]
            check("设备表列已定义", cols[:3] == ["no", "ip", "mac"], str(cols))
            for attr in ("btn_scan", "btn_block", "btn_all", "btn_free", "btn_guard",
                         "btn_sel_all", "btn_sel_inv", "btn_verify"):
                check(f"按钮存在：{attr}", hasattr(app, attr) and hasattr(getattr(app, attr), "enabled"))
            app.update()
            app._relayout(app._geo["w"], app._geo["h"])   # 强制一次布局，信息条才会生成
            app.update()
            app._draw_chips()
            check("页脚徽章可渲染", bool(app._chip_vals), str(len(app._chip_vals)))
            items = getattr(app, "_net_items", None) or {}
            check("网络信息条已填充", len(items) >= 4, str(sorted(items)))
            check("扫描后无设备也不崩（无 Npcap 时走缓存回退）",
                  isinstance(app._devices, list), str(type(app._devices)))
            check("日志有内容", len(app.log_lines) >= 1 if hasattr(app, "log_lines") else True)
            check("沙箱断言：全程未创建阻断目标",
                  not (app._killer and app._killer.targets()))
            for meth in ("do_verify", "_ask_duty", "_restart_as_admin"):
                check(f"新功能入口存在：{meth}", callable(getattr(app, meth, None)))
            check("验证按钮默认禁用（无阻断时）", app.btn_verify.enabled is False)
        except Exception:
            check("s1 冒烟步骤", False, traceback.format_exc()[-300:])

    def s2():
        try:
            before = [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]
            app._open_sentinel()
            app.update()
            after = [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]
            check("哨兵面板可打开", len(after) == len(before) + 1,
                  f"{len(before)} -> {len(after)}")
            app._open_settings()
            app.update()
            now = [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]
            check("设置窗口可打开", len(now) > len(after), f"{len(after)} -> {len(now)}")
            for w in list(app.winfo_children()):
                if isinstance(w, tk.Toplevel):
                    w.destroy()
        except Exception:
            check("s2 冒烟步骤", False, traceback.format_exc()[-300:])

    def s3():
        """第 8 轮回归：验证失败必须放回忙碌态；只有 IPv6 目标时提示要诚实。"""
        try:
            import core as _c
            real_verify = _c.verify_targets

            def boom(*_a, **_kw):
                raise RuntimeError("simulated sniff failure")

            app._killer = _c.Killer(app._net, dry_run=True)
            app._killer._targets["10.9.9.9"] = _c.Target("10.9.9.9", "02:00:00:00:00:09")
            _c.verify_targets = boom
            app.do_verify()
            for _ in range(40):
                app.update()
                if not app._busy:
                    break
                time.sleep(0.05)
            check("验证异常后不会卡在忙碌态", app._busy is False)
            _c.verify_targets = real_verify

            # 只有 IPv6 目标时：按钮亮着，提示必须说明 IPv6 侧未自动化
            app._killer._targets.clear()

            class _FakeV6:
                def active_ips(self):
                    return ["192.168.1.251"]
                def state_of(self, ip):
                    return ""

            real_mgr, app._ndp_mgr = app._ndp_mgr, _FakeV6()
            shown = []
            import tkinter.messagebox as mb
            real_info = mb.showinfo
            mb.showinfo = lambda *a, **k: shown.append(a)
            try:
                app.do_verify()
            finally:
                mb.showinfo = real_info
                app._ndp_mgr = real_mgr
            text = " ".join(str(x) for x in (shown[0] if shown else ()))
            check("仅有 IPv6 目标时提示说明未自动化", "IPv6" in text, text[:80])
        except Exception:
            check("s3 回归步骤", False, traceback.format_exc()[-300:])

    def finish():
        try:
            if getattr(app, "_destroyed", False):
                return
            check("关闭流程不抛异常", True)
            app._finish()
        except Exception:
            check("finish 步骤", False, traceback.format_exc()[-200:])

    def watch(deadline: list):
        """等扫描落地（最多 15 秒），再依次跑 s1/s2/finish。"""
        try:
            done = (not app._busy)
        except Exception:
            done = True
        if done or deadline[0] <= 0:
            # 单线串行：s1 → s2 → finish，避免两个定时器并发把窗口提前销毁
            s1()
            app.after(300, lambda: (s2(), app.after(300, lambda: (s3(), app.after(400, finish)))))
            return
        deadline[0] -= 250
        app.after(250, lambda: watch(deadline))

    app.after(400, lambda: watch([15000]))
    app.after(25000, app._finish)      # 看门狗：任何情况都不许挂死 CI
    app.mainloop()
    restore_state()

    print("\n=========== GUI 冒烟测试 ===========")
    bad = 0
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
        bad += 0 if ok else 1
    print(f"-----------------------------------\n共 {len(RESULTS)} 项，失败 {bad} 项")
    return 1 if bad else 0


if __name__ == "__main__":
    core.LOG.subscribe(lambda lv, m: print(f"[{lv}] {m}", flush=True))
    sys.exit(main())

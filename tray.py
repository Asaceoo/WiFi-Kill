#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tray.py — 系统托盘（纯 ctypes 调 Win32 Shell_NotifyIcon，不引入第三方依赖）

为什么不用 pystray：它依赖 Pillow，会把打包体积拉大 3–5 MB；而托盘只需要
一个图标、一个右键菜单和几条消息，ctypes 直接调 Shell_NotifyIcon 更划算。

线程模型：托盘窗口与消息循环独占一个守护线程，所有用户动作通过回调
抛给调用方（GUI 侧再投递回 Tk 主线程），因此不会阻塞界面。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import sys
import threading

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B
WM_APP = 0x8000
WM_TRAY = WM_APP + 1

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
IMAGE_ICON = 1
LR_LOADFROMFILE, LR_DEFAULTSIZE = 0x0010, 0x0040
MF_STRING, MF_SEPARATOR = 0x0000, 0x0800
TPM_RETURNCMD, TPM_RIGHTBUTTON, TPM_NONOTIFY = 0x0100, 0x0002, 0x0080
IDI_APPLICATION = 32512

LRESULT = ctypes.c_ssize_t
HICON = ctypes.c_void_p

# 显式声明签名：ctypes 默认把指针当 32 位 int，64 位下会截断或 OverflowError
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = wt.HINSTANCE

user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT

user32.RegisterClassExW.restype = wt.ATOM          # argtypes 留空，便于传 byref

user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE,
                                   wt.LPVOID]
user32.CreateWindowExW.restype = wt.HWND

user32.LoadImageW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT,
                              ctypes.c_int, ctypes.c_int, wt.UINT]
user32.LoadImageW.restype = HICON
user32.LoadIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR]
user32.LoadIconW.restype = HICON

user32.CreatePopupMenu.restype = wt.HMENU
user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
user32.TrackPopupMenu.argtypes = [wt.HMENU, wt.UINT, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, wt.HWND, wt.LPVOID]
user32.TrackPopupMenu.restype = ctypes.c_int
user32.DestroyMenu.argtypes = [wt.HMENU]
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
user32.GetMessageW.restype = ctypes.c_int
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.restype = LRESULT
user32.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
user32.RegisterWindowMessageW.restype = wt.UINT
user32.DestroyWindow.argtypes = [wt.HWND]
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]

shell32.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.c_void_p]
shell32.Shell_NotifyIconW.restype = wt.BOOL

WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON), ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR), ("hIconSm", wt.HICON),
    ]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT),
        ("uFlags", wt.UINT), ("uCallbackMessage", wt.UINT), ("hIcon", wt.HICON),
        ("szTip", wt.WCHAR * 128), ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD),
        ("szInfo", wt.WCHAR * 256), ("uVersion", wt.UINT),
        ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
        ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", wt.HICON),
    ]


def _ico_path() -> str:
    try:
        import core
        return core.resource_path("wifikill.ico")
    except Exception:
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(base, "wifikill.ico")
        return p if os.path.exists(p) else ""


class TrayIcon:
    """右键菜单：显示主界面 / 全部放行 / 退出；双击托盘图标也可唤回主界面。"""

    def __init__(self, tip: str = "WiFiKill",
                 on_show=None, on_release=None, on_quit=None):
        self.tip = tip
        self.on_show = on_show
        self.on_release = on_release
        self.on_quit = on_quit
        self._hwnd = None
        self._thread = None
        self._ready = threading.Event()
        self._nid = None
        self._wndproc_ref = None      # 必须持有引用，否则回调被 GC
        self._class = "WiFiKillTrayWnd"
        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        self.available = False

    # ---------------------------------------------------------- 对外接口

    def start(self) -> bool:
        if os.name != "nt":
            return False
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="wifikill-tray")
        self._thread.start()
        self._ready.wait(2.0)
        return self.available

    def stop(self):
        if self._hwnd:
            try:
                user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
            except Exception:
                pass

    def notify(self, title: str, text: str):
        """弹出气泡提示（图标已存在时）。"""
        if not self._nid:
            return
        try:
            nid = self._nid
            nid.szInfoTitle = title[:63]
            nid.szInfo = text[:255]
            nid.uFlags = NIF_INFO
            nid.dwInfoFlags = 0x1
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        except Exception:
            pass

    # ---------------------------------------------------------- 内部

    def _run(self):
        try:
            hinst = kernel32.GetModuleHandleW(None)
            proc = WNDPROC(self._wndproc)
            self._wndproc_ref = proc

            wc = WNDCLASSEXW()
            wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wc.lpfnWndProc = proc
            wc.hInstance = hinst
            wc.lpszClassName = self._class
            if not user32.RegisterClassExW(ctypes.byref(wc)):
                return

            self._hwnd = user32.CreateWindowExW(
                0, self._class, "WiFiKill", 0, 0, 0, 0, 0, None, None, hinst, None)
            if not self._hwnd:
                return

            self._add_icon()
            if not self.available:
                return
            self._ready.set()

            msg = wt.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            pass
        finally:
            self._ready.set()

    def _add_icon(self):
        hicon = None
        p = _ico_path()
        if p:
            hicon = user32.LoadImageW(None, p, IMAGE_ICON, 0, 0,
                                      LR_LOADFROMFILE | LR_DEFAULTSIZE)
        if not hicon:
            hicon = user32.LoadIconW(None, wt.LPCWSTR(IDI_APPLICATION))

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = hicon
        nid.szTip = self.tip[:127]
        if shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
            self._nid = nid
            self.available = True

    def _menu(self):
        hmenu = user32.CreatePopupMenu()
        user32.AppendMenuW(hmenu, MF_STRING, 1001, "显示主界面")
        user32.AppendMenuW(hmenu, MF_STRING, 1002, "全部放行")
        user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(hmenu, MF_STRING, 1003, "退出")

        pt = wt.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self._hwnd)
        cmd = user32.TrackPopupMenu(
            hmenu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
            pt.x, pt.y, 0, self._hwnd, None)
        user32.PostMessageW(self._hwnd, 0, 0, 0)
        user32.DestroyMenu(hmenu)
        return cmd

    def _fire(self, fn):
        if fn:
            try:
                fn()
            except Exception:
                pass

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            ev = (lparam & 0xFFFF)
            if ev in (WM_RBUTTONUP, WM_CONTEXTMENU):
                cmd = self._menu()
                if cmd == 1001:
                    self._fire(self.on_show)
                elif cmd == 1002:
                    self._fire(self.on_release)
                elif cmd == 1003:
                    self._fire(self.on_quit)
            elif ev in (WM_LBUTTONDBLCLK, WM_LBUTTONUP):
                if ev == WM_LBUTTONDBLCLK:
                    self._fire(self.on_show)
            return 0
        if msg == self._taskbar_created and self._taskbar_created:
            self.available = False
            self._add_icon()
            return 0
        if msg == WM_CLOSE:
            if self._nid:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
                self._nid = None
            user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

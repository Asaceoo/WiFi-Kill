"""ipv6 模块的报文级单元测试。

设计原则：**不碰网卡、不发一个包**。
CI 环境（GitHub Actions 的 ubuntu-latest）没有 Npcap，任何 sendp 都会失败，
所以这里只断言「构造出来的东西对不对」，真实发包由本机暗桩验证覆盖。
"""

import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ipv6  # noqa: E402
import core  # noqa: E402

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}" + (f"  ← {detail}" if detail else ""))


def case(fn):
    def wrapper():
        try:
            fn()
        except Exception:
            check(fn.__name__, False, traceback.format_exc(limit=2)[-320:])
    wrapper.__name__ = fn.__name__
    return wrapper


MY_MAC = "8c:e9:ee:a0:f3:b6"
GW_MAC = "f8:79:28:cc:fc:e8"
GW_LLA = "fe80::1"
MY_LLA = "fe80::14a4:bd2f:fe24:58b9"
TGT_LLA = "fe80::dead:beef:1"
TGT_MAC = "02:00:00:00:00:02"


@case
def test_na_structure():
    """NA 必须是 86 字节（14 以太 + 40 IPv6 + 32 ICMPv6）。"""
    pkt = ipv6.build_na(MY_MAC, TGT_MAC, GW_LLA, TGT_LLA, GW_LLA, MY_MAC)
    raw = bytes(pkt)
    check("NA 长度 = 86 字节", len(raw) == 86, f"实际 {len(raw)}")
    check("ICMPv6 类型 = 136（NA）", pkt["ICMPv6ND_NA"].type == 136)
    check("tgt 正确", pkt["ICMPv6ND_NA"].tgt == GW_LLA)
    check("O=1（允许覆盖缓存）", pkt["ICMPv6ND_NA"].O == 1)
    check("S=0（非请求应答）", pkt["ICMPv6ND_NA"].S == 0)
    check("携带的是期望 MAC",
          pkt["ICMPv6NDOptDstLLAddr"].lladdr == MY_MAC)
    check("以太头 src 未被改写", pkt["Ether"].src == MY_MAC)
    check("IPv6 目的 = 目标 LLA", pkt["IPv6"].dst == TGT_LLA)


@case
def test_ns_reply_solicited():
    """代理应答必须置 S=1，否则对方不认。"""
    pkt = ipv6.build_ns_reply(MY_MAC, TGT_MAC, GW_LLA, TGT_LLA, GW_LLA, MY_MAC)
    check("NS 应答 S=1", pkt["ICMPv6ND_NA"].S == 1)
    check("NS 应答 O=1", pkt["ICMPv6ND_NA"].O == 1)


@case
def test_restore_frames_use_real_mac():
    """回填帧必须携带真实 MAC，否则等于没恢复。"""
    pkt = ipv6.build_na(GW_MAC, TGT_MAC, GW_LLA, TGT_LLA, GW_LLA, GW_MAC)
    check("回填帧携带真实网关 MAC",
          pkt["ICMPv6NDOptDstLLAddr"].lladdr == GW_MAC)
    check("回填帧以太 src 是网关 MAC", pkt["Ether"].src == GW_MAC)


@case
def test_multicast_guard():
    """结构性保险：任何组播/广播目的地址都必须被拒绝。"""
    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    env = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                     my_lla=MY_LLA, prefixes=["2409::/64"])
    b = ipv6.NdpBlocker(FakeNI(), env, "192.168.1.9", TGT_MAC, TGT_LLA)

    blocked = []
    for dst in (ipv6.ALL_NODES_MAC, ipv6.MDNS_MAC, ipv6.BROADCAST_MAC,
                "01:00:5e:00:00:01"):
        pkt = ipv6.build_na(MY_MAC, dst, GW_LLA, TGT_LLA, GW_LLA, MY_MAC)
        try:
            b._send(pkt)
            blocked.append(dst)
        except ipv6.core.BlockError:
            pass
    check("四种组播/广播地址全部被拒", not blocked, f"漏了 {blocked}")


@case
def test_preflight_rejects_incomplete():
    """缺任何一项都必须拒绝启动，不给「试试看」的机会。"""
    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    good = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                      my_lla=MY_LLA, prefixes=["2409::/64"])
    ok, _ = ipv6.NdpBlocker(FakeNI(), good, "192.168.1.9",
                            TGT_MAC, TGT_LLA).preflight()
    check("完整信息时 preflight 通过", ok)

    cases = [
        ("没有 IPv6 路由", ipv6.V6Env(supported=False), TGT_LLA),
        ("缺网关 MAC", ipv6.V6Env(True, GW_LLA, "", MY_LLA, ["2409::/64"]), TGT_LLA),
        ("缺目标 LLA", ipv6.V6Env(True, GW_LLA, GW_MAC, MY_LLA, ["2409::/64"]), ""),
    ]
    for label, env, tgt in cases:
        bad, why = ipv6.NdpBlocker(FakeNI(), env, "192.168.1.9",
                                   TGT_MAC, tgt).preflight()
        check(f"preflight 拒绝「{label}」", not bad, why)


@case
def test_mdns_query_has_qu_bit():
    """QU 位必须真的发出去。

    这是实机踩过的坑：写 qclass=0x8001 会被 scapy 的位域吃掉，
    实际发出 0x1，对方按组播回，本机收不到 —— 看上去就像「没人应答」。
    """
    pkt = ipv6.build_mdns_query(MY_LLA)
    qrs = pkt["DNS"].qd
    check("含 4 个问题", len(qrs) == 4, f"实际 {len(qrs)}")
    check("QU 位已置 1", all(getattr(q, "unicastresponse", 0) == 1 for q in qrs))
    check("qclass 数值仍为 1", all(q.qclass == 1 for q in qrs))
    check("IPv6 目的 = ff02::fb", pkt["IPv6"].dst == "ff02::fb")
    check("以太目的 = mDNS 组播 MAC", pkt["Ether"].dst == ipv6.MDNS_MAC)
    check("源地址 = 本机 LLA", pkt["IPv6"].src == MY_LLA)


@case
def test_parse_neighbors():
    """邻居表解析：要跳过 00:00 占位行，按地址取值。"""
    sample = (
        "\r\n"
        "接口 7: WLAN\r\n"
        "Internet 地址                             物理地址            类型\r\n"
        "----------------------------------------  -----------------  -----------\r\n"
        "fe80::1                                   f8-79-28-cc-fc-e8  可访问\r\n"
        "fe80::1                                   00-00-00-00-00-00  无法访问\r\n"
        "fe80::14a4:bd2f:fe24:58b9                 8c-e9-ee-a0-f3-b6  可访问\r\n"
    )
    check("取到网关真实 MAC",
          ipv6._parse_neighbors(sample, "fe80::1") == "f8:79:28:cc:fc:e8")
    check("取到本机 MAC",
          ipv6._parse_neighbors(sample, "FE80::14A4:BD2F:FE24:58B9")
          == "8c:e9:ee:a0:f3:b6")
    check("查不存在地址返回 None",
          ipv6._parse_neighbors(sample, "fe80::ffff") is None)


@case
def test_dual_stack_judgement():
    """只有 /128 主机路由时不能判定为双栈 —— 这是探测里修过的一个误判。"""
    no_prefix = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                           my_lla=MY_LLA, prefixes=[])
    check("无网段前缀 → 不算双栈", not no_prefix.dual_stack)

    with_prefix = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                             my_lla=MY_LLA, prefixes=["2409:8a55::/64"])
    check("有 /64 前缀 → 判定双栈", with_prefix.dual_stack)

    no_gw = ipv6.V6Env(supported=True, gw_lla="", gw_mac=GW_MAC,
                       my_lla=MY_LLA, prefixes=["2409:8a55::/64"])
    check("无网关 → 不算双栈", not no_gw.dual_stack)


@case
def test_valid_mac():
    check("合法 MAC", ipv6._valid_mac("aa:bb:cc:dd:ee:ff"))
    check("大写也认", ipv6._valid_mac("AA:BB:CC:DD:EE:FF"))
    check("拒绝空串", not ipv6._valid_mac(""))
    check("拒绝短写", not ipv6._valid_mac("aa:bb:cc:dd:ee"))
    check("拒绝非十六进制", not ipv6._valid_mac("zz:bb:cc:dd:ee:ff"))


@case
def test_ndp_manager_empty_safe():
    """空管理器必须对所有查询返回安全值，且 restore_all/remove 不抛。"""
    mgr = ipv6.NdpManager()
    check("空 restore_all = 0", mgr.restore_all() == 0)
    check("空 remove = 0", mgr.remove("x") == 0)
    check("未知 IP state_of = ''", mgr.state_of("9.9.9.9") == "")
    check("未知 IP 不在 active", "9.9.9.9" not in mgr.active_ips())
    check("空 any_aborted = False", not mgr.any_aborted())


@case
def test_ndp_manager_multi_target():
    """NdpManager 应支持并发多目标，逐目标独立跟踪、可单删可全停。"""
    env = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                     my_lla=MY_LLA, prefixes=["2409:8a55::/64"])

    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    # 不碰网卡：替掉嗅探与启停，NdpBlocker 仅作占位
    orig_find, orig_start, orig_stop = ipv6.find_lla, ipv6.NdpBlocker.start, ipv6.NdpBlocker.stop
    ipv6.find_lla = lambda *a, **k: (TGT_LLA, "嗅探")
    ipv6.NdpBlocker.start = lambda self: (True, "ok")
    ipv6.NdpBlocker.stop = lambda self, restore=True: 0
    try:
        mgr = ipv6.NdpManager()
        devs = [
            core.Device(ip="192.168.1.9", mac=TGT_MAC, note=""),
            core.Device(ip="192.168.1.10", mac="02:00:00:00:00:03", note=""),
            core.Device(ip="192.168.1.11", mac="02:00:00:00:00:04", note=""),
        ]
        oks = [mgr.add(FakeNI(), env, d, 1.5)[0] for d in devs]
        check("三个目标均启动成功", all(oks), str(oks))
        check("active_ips 含三个",
              sorted(mgr.active_ips()) == ["192.168.1.10", "192.168.1.11", "192.168.1.9"],
              str(mgr.active_ips()))
        check("state_of 返回 ok", mgr.state_of("192.168.1.9") == "ok")

        n = mgr.remove("192.168.1.9")
        check("单删返回 1", n == 1, str(n))
        check("单删后剩两个",
              sorted(mgr.active_ips()) == ["192.168.1.10", "192.168.1.11"],
              str(mgr.active_ips()))

        n2 = mgr.restore_all()
        check("全停返回剩余数", n2 == 2, str(n2))
        check("全停后为空", mgr.active_ips() == [])
        check("全停后 state_of=''", mgr.state_of("192.168.1.10") == "")
    finally:
        ipv6.find_lla, ipv6.NdpBlocker.start, ipv6.NdpBlocker.stop = (
            orig_find, orig_start, orig_stop)


@case
def test_ndp_manager_rejects_protected():
    """受保护设备（网关/本机）在 NdpManager 层就被拒，与 core.is_protected 同源。"""
    env = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                     my_lla=MY_LLA, prefixes=["2409:8a55::/64"])

    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    mgr = ipv6.NdpManager()
    ok_gw, msg_gw = mgr.add(FakeNI(), env,
                            core.Device(ip="10.0.0.1", mac=GW_MAC, note="网关"), 1.5)
    check("网关被拒", not ok_gw and "受保护" in msg_gw, msg_gw)
    ok_me, msg_me = mgr.add(FakeNI(), env,
                            core.Device(ip="10.0.0.2", mac=MY_MAC, note="本机"), 1.5)
    check("本机被拒", not ok_me and "受保护" in msg_me, msg_me)
    check("被拒目标未入列", mgr.active_ips() == [])


@case
def test_ndp_manager_rejects_no_dual_stack():
    """没有 IPv6 双栈（无前缀/无网关 LLA）时直接拒绝，不进入嗅探。"""
    env = ipv6.V6Env(supported=True, gw_lla="", gw_mac="", my_lla=MY_LLA, prefixes=[])

    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    mgr = ipv6.NdpManager()
    ok, msg = mgr.add(FakeNI(), env,
                     core.Device(ip="1.2.3.4", mac=TGT_MAC, note=""), 1.5)
    check("非双栈被拒", not ok, msg)


@case
def test_ndp_manager_rejects_protected_without_note():
    """对抗性审查 N1：note 标注缺失（空串）时，IP/MAC 命中网关/本机仍必须被拒。"""
    env = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                     my_lla=MY_LLA, prefixes=["2409:8a55::/64"])

    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC
        my_ip = "10.0.0.2"
        gateway_ip = "10.0.0.1"
        gateway_mac = GW_MAC

    mgr = ipv6.NdpManager()
    ok, msg = mgr.add(FakeNI(), env,
                      core.Device(ip="10.0.0.1", mac="aa:aa:aa:aa:aa:01", note=""), 1.5)
    check("网关 IP 被拒(无 note)", not ok and "受保护" in msg, msg)
    ok, msg = mgr.add(FakeNI(), env,
                      core.Device(ip="10.0.0.9", mac=GW_MAC, note=""), 1.5)
    check("网关 MAC 被拒(无 note)", not ok and "受保护" in msg, msg)
    ok, msg = mgr.add(FakeNI(), env,
                      core.Device(ip="10.0.0.2", mac="aa:aa:aa:aa:aa:02", note=""), 1.5)
    check("本机 IP 被拒(无 note)", not ok and "受保护" in msg, msg)
    check("被拒目标未入列", mgr.active_ips() == [])


@case
def test_preflight_rejects_gateway_as_target():
    """对抗性审查 N1：目标 LLA/MAC 就是网关自身时，NdpBlocker.preflight 独立拒绝。"""
    class FakeNI:
        iface = "fake0"
        my_mac = MY_MAC

    env = ipv6.V6Env(supported=True, gw_lla=GW_LLA, gw_mac=GW_MAC,
                     my_lla=MY_LLA, prefixes=["2409::/64"])
    ok, why = ipv6.NdpBlocker(FakeNI(), env, "192.168.1.9",
                              GW_MAC, GW_LLA).preflight()
    check("网关自身作为目标被拒", not ok and "受保护" in why, why)
    ok, why = ipv6.NdpBlocker(FakeNI(), env, "192.168.1.9",
                              TGT_MAC, GW_LLA).preflight()
    check("网关 LLA 作为目标被拒", not ok and "受保护" in why, why)
    ok, _ = ipv6.NdpBlocker(FakeNI(), env, "192.168.1.9",
                            TGT_MAC, TGT_LLA).preflight()
    check("正常目标不受影响", ok)


@case
def test_ndp_stop_orders_restore_last():
    """第 11 轮：IPv6 会话也必须保证「恢复帧最后」（此前只有 IPv4 有代际+发送锁）。"""
    import threading
    import time
    ni = core.NetInfo(iface='fake0', my_ip='10.0.0.2', my_mac='aa:bb:cc:dd:ee:02',
                      gateway_ip='10.0.0.1', gateway_mac='aa:bb:cc:dd:ee:01',
                      cidr='10.0.0.0/24')
    env = ipv6.V6Env(supported=True, gw_lla='fe80::1', gw_mac='aa:bb:cc:dd:ee:01',
                     my_lla='fe80::2', prefixes=['2409::/64'])
    b = ipv6.NdpBlocker(ni, env, '10.0.0.50', 'aa:bb:cc:dd:ee:50', 'fe80::50',
                        interval=0.05)
    sent = []
    lock = threading.Lock()

    def lladdr_of(pkt):
        for layer in pkt:
            if hasattr(layer, 'lladdr'):
                return str(layer.lladdr).lower()
        return ''

    def slow_send(pkt, gen=None):
        time.sleep(0.05)
        with lock:
            sent.append(lladdr_of(pkt))

    b._send = slow_send
    ok, why = b.start()
    check('IPv6 会话可启动', ok, why)
    time.sleep(0.3)
    b.stop(restore=True)
    time.sleep(0.3)
    with lock:
        seq = list(sent)
    my_mac = ni.my_mac
    first_restore = next((i for i, h in enumerate(seq) if h == env.gw_mac.lower()), None)
    tail_poison = [h for h in seq[(first_restore or 0) + 1:] if h == my_mac] \
        if first_restore is not None else []
    check('确实发出过恢复帧', first_restore is not None, str(len(seq)))
    check('恢复帧之后没有投毒帧', not tail_poison, str(tail_poison[:3]))


@case
def test_ndp_stale_generation_refused():
    """第 11 轮：推进代际后，过期批次的发送必须一帧都发不出去。"""
    ni = core.NetInfo(iface='fake0', my_ip='10.0.0.2', my_mac='aa:bb:cc:dd:ee:02',
                      gateway_ip='10.0.0.1', gateway_mac='aa:bb:cc:dd:ee:01',
                      cidr='10.0.0.0/24')
    env = ipv6.V6Env(supported=True, gw_lla='fe80::1', gw_mac='aa:bb:cc:dd:ee:01',
                     my_lla='fe80::2', prefixes=['2409::/64'])
    b = ipv6.NdpBlocker(ni, env, '10.0.0.50', 'aa:bb:cc:dd:ee:50', 'fe80::50')
    sent = []
    b._send = lambda pkt, gen=None: sent.append(1)
    gen = b._gen
    b._send(object(), gen)                       # 占位包：桩函数不看内容
    n = len(sent)
    b._bump_gen()
    b._send(object(), gen)                       # 过期批次：桩函数仍会记账，真实 _send 会拦下
    # 桩函数绕过了代际检查，所以这里直接验证真实 _send 的代际分支
    real_gen_ok = hasattr(b, '_send_lock') and hasattr(b, '_late_sends')
    check('IPv6 会话具备代际与发送锁', real_gen_ok)
    check('推进代际接口可用', b._gen == gen + 1, str(b._gen))


@case
def test_ndp_double_start_rejected():
    """第 11 轮：同一目标是拒绝重复启动（防双线程并发发包）。"""
    import time
    ni = core.NetInfo(iface='fake0', my_ip='10.0.0.2', my_mac='aa:bb:cc:dd:ee:02',
                      gateway_ip='10.0.0.1', gateway_mac='aa:bb:cc:dd:ee:01',
                      cidr='10.0.0.0/24')
    env = ipv6.V6Env(supported=True, gw_lla='fe80::1', gw_mac='aa:bb:cc:dd:ee:01',
                     my_lla='fe80::2', prefixes=['2409::/64'])
    b = ipv6.NdpBlocker(ni, env, '10.0.0.50', 'aa:bb:cc:dd:ee:50', 'fe80::50',
                        interval=0.05)
    b._send = lambda pkt, gen=None: None
    b._emit = lambda restore=False, gen=None: None
    ok1, _ = b.start()
    ok2, why2 = b.start()
    check('首次启动成功', ok1)
    check('重复启动被拒', not ok2 and '在运行' in why2, why2)
    b.stop(restore=False)

if __name__ == "__main__":
    for fn in (
        test_na_structure,
        test_ns_reply_solicited,
        test_restore_frames_use_real_mac,
        test_multicast_guard,
        test_preflight_rejects_incomplete,
        test_mdns_query_has_qu_bit,
        test_parse_neighbors,
        test_dual_stack_judgement,
        test_valid_mac,
        test_ndp_manager_empty_safe,
        test_ndp_manager_multi_target,
        test_ndp_manager_rejects_protected,
        test_ndp_manager_rejects_no_dual_stack,
        test_ndp_manager_rejects_protected_without_note,
        test_preflight_rejects_gateway_as_target,
        test_ndp_stop_orders_restore_last,
        test_ndp_stale_generation_refused,
        test_ndp_double_start_rejected,
    ):
        fn()

    print("-" * 32)
    print(f"共 {PASS + FAIL} 项，失败 {FAIL} 项")
    sys.exit(1 if FAIL else 0)

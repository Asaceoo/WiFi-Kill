"""本机守护（主动防御）单元测试。

核心原则：不发真实包。所有网络层（arp_table / l2_check / scapy / ipv6.build_na /
ipv6.ndp_table）都用 fake 注入，断言「只发送网关真实映射、不误伤、有去抖、dry_run 不发包」。
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core


# ------------------------------------------------------------------ fake 网络层


class _FakeLayer:
    def __init__(self, **kw):
        self.kw = kw

    def __truediv__(self, other):
        return _FakePkt(self, other)


class _FakePkt:
    def __init__(self, *layers):
        self.layers = list(layers)

    def __truediv__(self, other):
        return _FakePkt(*self.layers, other)


class _FakeScapy:
    def __init__(self):
        self.calls = []

    def Ether(self, **kw):
        return _FakeLayer(**kw)

    def ARP(self, **kw):
        return _FakeLayer(**kw)

    def sendp(self, pkt, **_kw):
        self.calls.append(pkt)


def _install_fakes(monkeypatch, *, scapy_calls=None, arp_tbl=None, drift=None,
                   gw_ip="192.168.1.1", gw_mac="aa:bb:cc:dd:ee:ff"):
    """注入fake网络层。drift: 返回给 arp_table 的「被篡改」MAC（None 表示正常）。"""
    fake = _FakeScapy()

    def fake_scapy():
        return fake

    monkeypatch.setattr(core, "scapy_mod", fake_scapy)
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))

    if arp_tbl is not None:
        monkeypatch.setattr(core, "arp_table", lambda: arp_tbl)
    else:
        monkeypatch.setattr(
            core, "arp_table",
            lambda: {gw_ip: (drift if drift else gw_mac)})
    if scapy_calls is not None:
        scapy_calls.append(fake)  # 让测试能读到 fake.calls
    return fake


def _mk_guard(monkeypatch, gw_mac="aa:bb:cc:dd:ee:ff", gw_ip="192.168.1.1",
              my_mac="11:22:33:44:55:66", drift=None):
    ni = core.NetInfo(iface="eth0", my_ip="192.168.1.50", my_mac=my_mac,
                      gateway_ip=gw_ip, gateway_mac=gw_mac, cidr="192.168.1.0/24")
    g = core.Guard(ni, interval=2.0, dry_run=False)
    g._gw_ip = gw_ip
    g._gw_mac = gw_mac
    fake = _install_fakes(monkeypatch, drift=drift, gw_ip=gw_ip, gw_mac=gw_mac)
    return g, fake


# ------------------------------------------------------------------ 用例


def test_guard_no_baseline_no_start(monkeypatch):
    """拿不到网关真实 MAC 时，start() 必须失败且不启动任何线程。"""
    ni = core.NetInfo(gateway_ip="192.168.1.1", gateway_mac="")  # 基准为空
    g = core.Guard(ni, interval=2.0)
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: None)
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))
    assert g.start() is False
    assert g.is_active() is False
    assert g._thread is None


def test_guard_reassert_sends_true_mapping(monkeypatch):
    """纠正时只宣告真实网关 MAC，绝不伪造。"""
    g, fake = _mk_guard(monkeypatch)
    g._reassert("测试")
    assert fake.calls, "应当调用了 sendp"
    pkt = fake.calls[-1]
    ether = next(l for l in pkt.layers if "dst" in l.kw)
    arp = next(l for l in pkt.layers if "hwsrc" in l.kw)
    # L2 源用本机 MAC（不冒充网关），L3 才宣告真实的「网关 IP ↔ 网关 MAC」映射
    assert ether.kw["dst"] == core.BROADCAST
    assert ether.kw["src"] == g.ni.my_mac
    assert arp.kw["hwsrc"] == g._gw_mac
    assert arp.kw["psrc"] == g._gw_ip
    assert arp.kw["hwdst"] == g.ni.my_mac
    assert arp.kw["pdst"] == g._gw_ip


def test_guard_tick_no_drift_no_send(monkeypatch):
    """缓存正常时不应纠错（不打扰网络）。"""
    g, fake = _mk_guard(monkeypatch, drift=None)
    g._tick()
    g._tick()
    assert g.anomaly_count == 0
    assert fake.calls == []


def test_guard_tick_drift_detected_with_debounce(monkeypatch):
    """连续 2 次漂移才判定为投毒（去抖），随后自动纠正。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g._tick()                       # 第 1 次：计 consecutive，不报警不发
    assert g.anomaly_count == 0 and fake.calls == []
    g._tick()                       # 第 2 次：判定投毒 → 纠正
    assert g.anomaly_count == 1
    assert fake.calls, "应当发送纠正包"


def test_guard_dry_run_no_send(monkeypatch):
    """演练模式：只记录，绝不发包。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g.dry_run = True
    g._tick()
    g._tick()
    assert fake.calls == [], "dry_run 下不应调用 sendp"
    assert "演练" in g.status()["last_action"]


def test_guard_v6_reassert_is_unicast_true_mapping(monkeypatch):
    """IPv6 重宣告必须单播到本机 MAC（绝不组播），且只发真实映射。"""
    import ipv6

    captured = {}

    def fake_build_na(eth_src, eth_dst, ipv6_src, ipv6_dst, tgt, lladdr, solicited=0):
        captured["eth_dst"] = eth_dst
        captured["lladdr"] = lladdr
        return _FakePkt(_FakeLayer(kind="na"))

    monkeypatch.setattr(ipv6, "build_na", fake_build_na)
    monkeypatch.setattr(ipv6, "ndp_table", lambda: {})  # 无漂移，只看重宣告

    g, fake = _mk_guard(monkeypatch)
    g.interval = 10.0  # every = round(10/10)=1，每次触发
    g._v6 = ("fe80::1", g._gw_mac, g.ni.my_mac, "eth0")
    g._maybe_v6(g._v6)

    assert captured["eth_dst"] == g.ni.my_mac, "必须单播到本机，绝不组播"
    assert captured["lladdr"] == g._gw_mac, "只宣告网关真实 MAC"
    assert fake.calls, "应当发送 NA"


def test_guard_v6_dry_run_no_send(monkeypatch):
    import ipv6
    monkeypatch.setattr(ipv6, "build_na", lambda **k: _FakePkt(_FakeLayer(kind="na")))
    monkeypatch.setattr(ipv6, "ndp_table", lambda: {})
    g, fake = _mk_guard(monkeypatch)
    g.interval = 10.0
    g.dry_run = True
    g._v6 = ("fe80::1", g._gw_mac, g.ni.my_mac, "eth0")
    g._maybe_v6(g._v6)
    assert fake.calls == [], "IPv6 dry_run 下不应发包"


def test_guard_start_stop_lifecycle(monkeypatch):
    """正常启动/停止，线程受控且为守护线程。"""
    ni = core.NetInfo(iface="eth0", my_ip="192.168.1.50",
                      my_mac="11:22:33:44:55:66",
                      gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff",
                      cidr="192.168.1.0/24")
    g = core.Guard(ni, interval=2.0)
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))
    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())
    assert g.start() is True
    assert g.is_active() is True
    assert g.status()["active"] is True
    g.stop()
    assert g.is_active() is False
    assert g.status()["last_action"] == "已停止"


def test_ndp_table_parse_windows(monkeypatch):
    """解析 netsh 输出，正确得到 网关LLA → MAC。"""
    import ipv6
    sample = (
        "接口 12: Wi-Fi\n\n"
        "Internet 地址                              物理地址           类型\n"
        "fe80::1                                    11-22-33-44-55-66  可路由(已学习)\n"
        "fe80::2a0:11ff:fe22:33                     aa-bb-cc-dd-ee-ff  已学习\n"
    )
    monkeypatch.setattr(core, "_run_hidden", lambda *a, **k: sample)
    tbl = ipv6.ndp_table()
    assert tbl.get("fe80::1") == "11:22:33:44:55:66"
    assert tbl.get("fe80::2a0:11ff:fe22:33") == "aa:bb:cc:dd:ee:ff"


def _mk_ni(gw_mac):
    return core.NetInfo(iface="eth0", my_ip="192.168.1.50", my_mac="11:22:33:44:55:66",
                        gateway_ip="192.168.1.1", gateway_mac=gw_mac,
                        cidr="192.168.1.0/24")


def test_guard_baseline_disagreement_fail_closed(monkeypatch):
    """缓存 MAC 与实时询问不一致时，fail closed：不启动、不钉死可疑映射。"""
    g = core.Guard(_mk_ni("aa:bb:cc:dd:ee:ff"), interval=2.0)
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: "11:22:33:44:55:66")  # 分歧
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))
    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())
    assert g.start() is False
    assert g.is_active() is False


def test_guard_baseline_agreement_starts(monkeypatch):
    """缓存 MAC 与实时询问一致时，正常启动。"""
    g = core.Guard(_mk_ni("aa:bb:cc:dd:ee:ff"), interval=2.0)
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: "aa:bb:cc:dd:ee:ff")  # 一致
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))
    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())
    assert g.start() is True
    g.stop()


# ------------------------------------------------------------------ 对抗性审查 F1/F2/F3


def test_guard_gateway_ip_change_rebaselines(monkeypatch):
    """F1：网关 IP 变化（换了网络）→ 重建基准；新缓存+实时一致才采纳，且当拍不发包。"""
    new_ip, new_mac = "10.0.0.1", "de:ad:be:ef:00:01"
    g, fake = _mk_guard(monkeypatch)      # 旧基准 192.168.1.1 / aa:bb:cc:dd:ee:ff
    g.ni = core.NetInfo(iface="eth0", my_ip="10.0.0.50", my_mac="11:22:33:44:55:66",
                        gateway_ip=new_ip, gateway_mac=new_mac, cidr="10.0.0.0/24")
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: new_mac)   # 实时与缓存一致
    monkeypatch.setattr(core, "arp_table", lambda: {new_ip: new_mac})
    g._tick()
    assert g._gw_ip == new_ip, "网关 IP 应更新"
    assert g._gw_mac == new_mac, "一致的新基准应被采纳"
    assert fake.calls == [], "重建基准当拍不应发包"


def test_guard_gateway_ip_change_fail_closed(monkeypatch):
    """F1：换网络后新基准不可达 → fail closed 清空基准，之后绝不再发包。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g.ni = core.NetInfo(iface="eth0", my_ip="10.0.0.50", my_mac="11:22:33:44:55:66",
                        gateway_ip="10.0.0.1", gateway_mac="de:ad:be:ef:00:01",
                        cidr="10.0.0.0/24")
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: None)   # 实时询问失败
    monkeypatch.setattr(core, "arp_table", lambda: {})
    g._tick()
    assert g._gw_mac == "", "fail closed 应清空基准"
    g._tick()
    g._tick()
    assert fake.calls == [], "基准为空后绝不再发包"


def test_guard_rebaseline_adopts_new_mac_when_consistent(monkeypatch):
    """F1：纠正反复不生效 → 重估基准；缓存+实时一致的新 MAC 才被采纳
    （避免把更换后的真实网关永久'纠正'回旧 MAC）。"""
    new_mac = "de:ad:be:ef:00:01"
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g._failed_corr = 2                   # 再漂移 1 次即触发重估
    g._consecutive = 1                   # 本拍即达去抖阈值（连续第 2 次漂移）
    g.ni = _mk_ni(new_mac)               # 扫描发现新网关 MAC（缓存）
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: new_mac)   # 实时一致
    g._tick()
    assert g._gw_mac == new_mac, "一致的新基准应被采纳"
    assert g._failed_corr == 0


def test_guard_rebaseline_fail_closed_when_disagreement(monkeypatch):
    """F1（关键安全语义）：重估时缓存与实时分歧 → 绝不采纳任何一方，
    fail closed 暂停纠正（实时询问可能被攻击者抢答，采纳等于自伤）。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g._failed_corr = 2
    g._consecutive = 1
    g.ni = _mk_ni("aa:bb:cc:dd:ee:ff")   # 缓存仍是旧基准
    monkeypatch.setattr(core, "arp_query", lambda *a, **k: "99:88:77:66:55:44")  # 分歧
    g._tick()
    assert g._gw_mac == "", "分歧时必须 fail closed 清空基准"
    sent = len(fake.calls)               # 重估前的最后一次旧基准纠正属正常语义
    g._tick()
    assert len(fake.calls) == sent, "fail closed 后绝不再新增发包"


def test_guard_cache_missing_debounce(monkeypatch):
    """F3：缓存缺失与漂移共用去抖——单次缺失不广播，连续 2 次才重新宣告；
    且缺失不计为投毒异常。"""
    g, fake = _mk_guard(monkeypatch)
    monkeypatch.setattr(core, "arp_table", lambda: {})
    g._tick()
    assert fake.calls == [] and g._consecutive == 1
    g._tick()
    assert fake.calls, "连续缺失 2 次应重新宣告真实映射"
    assert g.anomaly_count == 0, "缓存缺失不是投毒证据，不应计入异常数"


def test_guard_start_rejects_when_old_thread_alive(monkeypatch):
    """F2：stop 后旧线程未退出时 start 必须拒绝，避免双守护线程并发 _tick。"""
    ni = core.NetInfo(gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff")
    g = core.Guard(ni, interval=2.0)
    blocker = threading.Event()
    holder = threading.Thread(target=blocker.wait, daemon=True)
    holder.start()
    g._thread = holder
    g._stop.set()                        # is_active() 为 False，但旧线程还活着
    try:
        assert g.start() is False, "旧线程未退出时不得开新线程"
        assert holder.is_alive()
    finally:
        blocker.set()
        holder.join(timeout=2)
        g._thread = None


def test_guard_refresh_v6_after_rebaseline(monkeypatch):
    """G2：网络切换重估清空 _v6 后，refresh_v6 应恢复与基准一致的上下文；
    env 网关 MAC 与基准不一致时保持关闭（fail closed）。"""
    g, fake = _mk_guard(monkeypatch)
    release = threading.Event()
    holder = threading.Thread(target=release.wait, daemon=True)
    holder.start()
    g._thread = holder                   # _stop 未 set → is_active() 为 True
    try:
        class Env:
            supported = True
            gw_lla = "fe80::1"
            gw_mac = g._gw_mac           # 与基准一致
            my_lla = "fe80::50"

        g.v6env = Env()
        g._v6 = None
        g.refresh_v6()
        assert g._v6 is not None and g._v6[0] == "fe80::1", "一致上下文应被恢复"

        g._v6 = None
        Env.gw_mac = "de:ad:be:ef:99:99"  # 与基准分歧
        g.refresh_v6()
        assert g._v6 is None, "分歧的 v6 上下文不得启用"
    finally:
        release.set()
        holder.join(timeout=2)
        g._thread = None


def test_guard_drift_clears_local_arp(monkeypatch):
    """D1：漂移纠正时同步删除本机脏 ARP 条目（广播帧不会回环到本机栈）。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    calls = []
    monkeypatch.setattr(core, "_run_hidden", lambda cmd, enc: calls.append(cmd) or "")
    g._tick()                        # 第 1 拍：仅计数（去抖）
    assert not any(c and c[0] == "arp" for c in calls), "去抖期不得删除本机条目"
    g._tick()                        # 第 2 拍：判定投毒 → 广播纠正 + 本机自愈
    assert ["arp", "-d", "192.168.1.1"] in calls, calls


def test_guard_dry_run_skips_local_arp_clear(monkeypatch):
    """D1：演练模式绝不动本机真实 ARP 缓存。"""
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g.dry_run = True
    calls = []
    monkeypatch.setattr(core, "_run_hidden", lambda cmd, enc: calls.append(cmd) or "")
    g._tick()
    g._tick()
    assert calls == [], "演练模式不得改动本机 ARP 缓存"


def test_guard_v6_drift_clears_local_neighbor(monkeypatch):
    """D1：IPv6 漂移时删除本机邻居缓存条目（best-effort，netsh 需提权）。"""
    import ipv6
    monkeypatch.setattr(ipv6, "build_na", lambda **k: _FakePkt(_FakeLayer(kind="na")))
    monkeypatch.setattr(ipv6, "ndp_table", lambda: {"fe80::1": "ff:ff:ff:ff:ff:ff"})  # 漂移
    calls = []

    def fake_run(cmd, enc):
        calls.append(cmd)
        if "show" in cmd and "interfaces" in cmd:
            return ("   1   10  1500  connected  Loopback Pseudo-Interface 1\n"
                    "   7    5  1500  connected  WLAN\n")
        return ""

    monkeypatch.setattr(core, "_run_hidden", fake_run)
    monkeypatch.setattr(core, "friendly_iface", lambda g: "WLAN · Intel(R) Wi-Fi")
    g, fake = _mk_guard(monkeypatch)
    g.interval = 10.0                # every=1，每次都触发 v6 分支
    g._v6 = ("fe80::1", g._gw_mac, g.ni.my_mac, "\\Device\\NPF_{FAKE}")
    g._maybe_v6(g._v6)
    deletes = [c for c in calls if c[:5] == ["netsh", "interface", "ipv6", "delete", "neighbors"]]
    assert deletes, calls
    assert any("address=fe80::1" in c and "interface=7" in c for c in deletes), deletes


if __name__ == "__main__":
    import sys

    class _MP:
        """极简 monkeypatch 替身：命令行直跑时用；每个用例结束自动还原。"""
        def __init__(self):
            self._restores = []

        def setattr(self, obj, name, val):
            orig = getattr(obj, name, None)
            self._restores.append((obj, name, orig))
            setattr(obj, name, val)

        def restore(self):
            for obj, name, orig in reversed(self._restores):
                try:
                    setattr(obj, name, orig)
                except Exception:
                    pass

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        mp = _MP()
        try:
            t(mp)
            passed += 1
            print(f"ok   {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        finally:
            mp.restore()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)

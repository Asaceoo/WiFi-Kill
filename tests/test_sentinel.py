"""全网哨兵（Sentinel）单元测试。

核心原则：不发包、不碰真实网络。scapy sniff 与 SENTINEL_FILE 全部 fake 注入，
断言「首次静默建基线、新设备告警、5 分钟去重、认领/移出闭环、指认凶手、事件上限」。
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core


class _Dev:
    """极简设备替身。"""

    def __init__(self, ip, mac, note=""):
        self.ip, self.mac, self.note = ip, mac, note


def _tmp_sentinel(monkeypatch):
    """把 SENTINEL_FILE 指到临时目录，避免污染真实基线。"""
    tmp = tempfile.mkdtemp(prefix="sentinel-test-")
    path = Path(tmp) / "sentinel.json"          # 必须是 Path：save() 调 .with_suffix()
    monkeypatch.setattr(core, "SENTINEL_FILE", path)
    return path


class _FakeLayer:
    def __init__(self, **kw):
        self.kw = kw

    def __truediv__(self, other):
        return self


class _FakeScapy:
    def Ether(self, **kw):
        return _FakeLayer(**kw)

    def ARP(self, **kw):
        return _FakeLayer(**kw)

    def sendp(self, pkt, **kw):
        pass


def _mk_guard(monkeypatch, drift=None, gw_ip="192.168.1.1",
              gw_mac="aa:bb:cc:dd:ee:ff"):
    """本地守护替身（与 test_guard.py 同模式）。"""
    ni = core.NetInfo(iface="eth0", my_ip="192.168.1.50", my_mac="11:22:33:44:55:66",
                      gateway_ip=gw_ip, gateway_mac=gw_mac, cidr="192.168.1.0/24")
    g = core.Guard(ni, interval=2.0, dry_run=False)
    g._gw_ip = gw_ip
    g._gw_mac = gw_mac
    fake = _FakeScapy()
    monkeypatch.setattr(core, "scapy_mod", lambda: fake)
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))
    monkeypatch.setattr(core, "arp_table", lambda: {gw_ip: (drift or gw_mac)})
    return g, fake


def test_sentinel_first_run_silent_baseline(monkeypatch):
    """首次运行：全部扫描结果静默入册为现任住户，不告警。"""
    _tmp_sentinel(monkeypatch)
    notified = []
    s = core.Sentinel(notify=lambda t, m: notified.append((t, m)))
    new = s.feed_scan([_Dev("192.168.1.5", "AA:BB:CC:00:00:01"),
                       _Dev("192.168.1.6", "aa:bb:cc:00:00:02")])
    assert new == [], "首次运行不应告警"
    assert len(s.pending()) == 0, "首次入册应视为已认领"
    assert notified == [], "首次运行不应弹通知"


def test_sentinel_new_device_alerts(monkeypatch):
    """基线建立后新 MAC 出现：产生 new 事件 + 通知，等待认领。"""
    _tmp_sentinel(monkeypatch)
    notified = []
    s = core.Sentinel(notify=lambda t, m: notified.append((t, m)))
    s.feed_scan([_Dev("192.168.1.5", "aa:bb:cc:00:00:01")])
    notified.clear()

    new = s.feed_scan([_Dev("192.168.1.5", "aa:bb:cc:00:00:01"),
                       _Dev("192.168.1.99", "de:ad:be:ef:00:99")])
    assert len(new) == 1 and new[0]["mac"] == "de:ad:be:ef:00:99"
    assert s.events[-1]["kind"] == "new"
    assert len(notified) == 1 and "新设备" in notified[0][0]
    pend = s.pending()
    assert len(pend) == 1 and pend[0]["mac"] == "de:ad:be:ef:00:99"


def test_sentinel_notify_dedup_5min(monkeypatch):
    """同一事件 key 5 分钟内只弹一次通知（持续投毒不轰炸）。"""
    _tmp_sentinel(monkeypatch)
    notified = []
    s = core.Sentinel(notify=lambda t, m: notified.append((t, m)))
    s._notify_dedup("poison:x", "t1", "m1")
    s._notify_dedup("poison:x", "t2", "m2")          # 立刻重复 → 被去重
    s._notify_dedup("poison:y", "t3", "m3")          # 不同 key → 放行
    assert len(notified) == 2
    with s._lock:
        s._last_notify["poison:x"] -= core.NOTIFY_DEDUP_SECONDS + 1
    s._notify_dedup("poison:x", "t4", "m4")          # 过了 5 分钟 → 放行
    assert len(notified) == 3


def test_sentinel_claim_and_forget(monkeypatch):
    """认领后不再出现在待认领；移出基线后下次扫描重新告警。"""
    _tmp_sentinel(monkeypatch)
    s = core.Sentinel()
    s.feed_scan([_Dev("192.168.1.5", "aa:bb:cc:00:00:01")])
    s.feed_scan([_Dev("192.168.1.9", "de:ad:be:ef:00:09")])
    assert s.claim("de:ad:be:ef:00:09") is True
    assert s.pending() == []
    assert s.forget("de:ad:be:ef:00:09") is True
    new = s.feed_scan([_Dev("192.168.1.9", "de:ad:be:ef:00:09")])
    assert len(new) == 1, "移出基线的设备应重新告警"


def test_sentinel_persistence(monkeypatch):
    """基线与事件落盘，新实例恢复。"""
    path = _tmp_sentinel(monkeypatch)
    s = core.Sentinel()
    s.feed_scan([_Dev("192.168.1.5", "aa:bb:cc:00:00:01")])
    s.feed_event("poison", "投毒者已定位：de:ad:00:00:00:01", mac="de:ad:00:00:00:01")
    s2 = core.Sentinel()
    assert "aa:bb:cc:00:00:01" in s2._known
    assert s2.events[-1]["kind"] == "poison"
    assert os.path.exists(path)


def test_sentinel_events_cap(monkeypatch):
    """事件流上限 200 条，旧的被截断。"""
    _tmp_sentinel(monkeypatch)
    s = core.Sentinel()
    for i in range(core.SENTINEL_MAX_EVENTS + 30):
        s._add_event("info", "", "", f"事件 {i}")
    assert len(s.events) == core.SENTINEL_MAX_EVENTS
    assert s.events[-1]["text"] == f"事件 {core.SENTINEL_MAX_EVENTS + 29}"


def test_sniff_poisoner_finds_attacker(monkeypatch):
    """嗅探应返回「冒称网关 IP 且非真实网关」的帧的以太网源 MAC。"""
    captured = {}

    class _FakePkt:
        """同一对象同时充当 ARP 层与 Ether 层（sniff_poisoner 用类索引但只取 psrc/src/hwsrc）。"""

        def __init__(self, psrc, hwsrc, esrc):
            self.psrc, self.hwsrc, self.src = psrc, hwsrc, esrc

        def haslayer(self, name):
            return True          # 真实 scapy 类对象做索引，统一放行

        def __getitem__(self, name):
            return self

    class _FakeScapy:
        def sniff(self, iface=None, timeout=None, store=None, lfilter=None):
            captured["filter"] = lfilter
            pkts = [
                _FakePkt("192.168.1.1", "de:ad:00:00:00:42", "de:ad:00:00:00:42"),  # 凶手
                _FakePkt("192.168.1.1", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),  # 真网关
                _FakePkt("192.168.1.9", "de:ad:00:00:00:43", "de:ad:00:00:00:43"),  # 无关 IP
            ]
            return [p for p in pkts if lfilter(p)]

    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())
    got = core.sniff_poisoner(type("NI", (), {"iface": "eth0"})(),
                              "192.168.1.1", "aa:bb:cc:dd:ee:ff")
    assert got == "de:ad:00:00:00:42", got


def test_sniff_poisoner_empty_when_clean(monkeypatch):
    """抓不到冒称帧 → 返回空串，由调用方如实记录。"""
    class _FakeScapy:
        def sniff(self, **kw):
            return []

    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())
    got = core.sniff_poisoner(type("NI", (), {"iface": "eth0"})(),
                              "192.168.1.1", "aa:bb:cc:dd:ee:ff")
    assert got == ""


def test_guard_hunt_reports_poisoner(monkeypatch):
    """Guard 漂移触发嗅探，指认结果经 event_sink 进入事件流（含通知去重 key）。"""
    import threading

    def fake_sniff(ni, gw_ip, gw_mac, seconds=4.0):
        return "de:ad:00:00:00:42"

    monkeypatch.setattr(core, "sniff_poisoner", fake_sniff)
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    events = []
    g.event_sink = lambda kind, text, **kw: events.append((kind, text, kw))
    g._tick()
    g._tick()
    deadline = time.time() + 3
    while not events and time.time() < deadline:
        time.sleep(0.05)
    assert events, "漂移应触发指认事件"
    kind, text, kw = events[0]
    assert kind == "poison" and "de:ad:00:00:00:42" in text
    assert kw.get("notify_key", "").startswith("poison:")


def test_guard_hunt_dry_run_silent(monkeypatch):
    """演练模式不触发嗅探（不发真实侦测动作）。"""
    monkeypatch.setattr(core, "sniff_poisoner",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("不应嗅探")))
    g, fake = _mk_guard(monkeypatch, drift="ff:ff:ff:ff:ff:ff")
    g.dry_run = True
    events = []
    g.event_sink = lambda kind, text, **kw: events.append((kind, text))
    g._tick()
    g._tick()
    time.sleep(0.2)
    assert events == []


def test_baseline_cap_evicts_unclaimed_first(monkeypatch):
    """第 11 轮：私有 Wi-Fi 地址轮换不能把基线撑爆，且被认领的设备优先保留。

    探针复现：20 轮 × 50 台新 MAC 之后 known 从 20 涨到 1020，且没有上限常量，
    sentinel.json 与待认领列表只会一直涨。
    """
    _tmp_sentinel(monkeypatch)
    monkeypatch.setattr(core, "SENTINEL_MAX_KNOWN", 60)
    sen = core.Sentinel()
    base = [_Dev(f"10.0.0.{i + 2}", f"02:00:00:00:00:{i:02x}") for i in range(10)]
    sen.feed_scan(base)
    claimed = [d.mac for d in base[:3]]
    for m in claimed:
        sen.claim(m)

    rounds = 0
    while len(sen._known) <= 60 and rounds < 10:
        rounds += 1
        sen.feed_scan([_Dev(f"10.9.{rounds}.{i}",
                            f"06:aa:{rounds // 256:02x}:{rounds % 256:02x}:"
                            f"{i // 256:02x}:{i % 256:02x}") for i in range(40)])

    assert len(sen._known) <= 60, f"基线应有上限，实际 {len(sen._known)}"
    assert all(m in sen._known for m in claimed), "已认领的设备应优先保留"
    assert any(e["kind"] == "forget" for e in sen.events), "淘汰应留下事件记录"


def test_sentinel_corrupt_baseline_selfheals(monkeypatch):
    """基线被写坏时自愈，而不是每次扫描都炸。

    修复前：load() 原样收下 {"known": [...], "events": "boom"}，
    feed_scan 第一件事就是 self._known.get() → AttributeError('list' object
    has no attribute 'get')，而它跑在 GUI 的扫描回调里，表现为「哨兵一直没反应」。
    """
    path = _tmp_sentinel(monkeypatch)
    path.write_text(json.dumps({"known": ["x"], "events": "boom"}), encoding="utf-8")
    sen = core.Sentinel()
    assert isinstance(sen._known, dict), repr(sen._known)
    assert sen.events == [], repr(sen.events)
    new = sen.feed_scan([_Dev("192.168.1.5", "aa:bb:cc:dd:ee:05")])
    assert new == [], new                      # 视为空基线 = 首次运行，静默入册
    assert sen._known["aa:bb:cc:dd:ee:05"]["known"] is True
    # 记录项本身不是 dict 时同样要被剔除
    path.write_text(json.dumps({"known": {"aa:bb:cc:dd:ee:01": "oops"},
                                "events": [{"kind": "new"}, "junk"]}), encoding="utf-8")
    sen2 = core.Sentinel()
    assert sen2._known == {}, repr(sen2._known)
    assert len(sen2.events) == 1, repr(sen2.events)


if __name__ == "__main__":
    class _MP:
        """极简 monkeypatch 替身：每个用例结束自动还原。"""

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

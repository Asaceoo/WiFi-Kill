"""占空比限速单元测试。

不发真实包：_emit 被 fake 记录。断言「duty 决策比例正确、越界钳制、
set_duty 更新与持久化、运行中的阻断循环确实按占空比交替发投毒/恢复帧」。
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core


def _mk_killer(monkeypatch, duty=100):
    ni = core.NetInfo(iface="eth0", my_ip="192.168.1.50", my_mac="11:22:33:44:55:66",
                      gateway_ip="192.168.1.1", gateway_mac="aa:bb:cc:dd:ee:ff",
                      cidr="192.168.1.0/24")
    k = core.Killer(ni, interval=1.5, dry_run=False)
    t = core.Target(ip="192.168.1.9", mac="de:ad:be:ef:00:09", duty=duty)
    monkeypatch.setattr(core, "write_state", lambda data: None)
    return k, t


def test_duty_100_always_poisons(monkeypatch):
    k, t = _mk_killer(monkeypatch, duty=100)
    assert all(k._should_poison(t, i) for i in range(30))


def test_duty_50_half_and_half(monkeypatch):
    k, t = _mk_killer(monkeypatch, duty=50)
    decisions = [k._should_poison(t, i) for i in range(20)]
    assert decisions.count(True) == 10, decisions
    assert decisions.count(False) == 10
    # 连续性：阻断拍应连续（前 5 拍），恢复拍连续（后 5 拍）
    assert decisions[:5] == [True] * 5 and decisions[5:10] == [False] * 5


def test_duty_10_one_in_ten(monkeypatch):
    k, t = _mk_killer(monkeypatch, duty=10)
    decisions = [k._should_poison(t, i) for i in range(10)]
    assert decisions.count(True) == 1


def test_duty_clamped(monkeypatch):
    k, _ = _mk_killer(monkeypatch)
    assert k._should_poison(core.Target(ip="1.2.3.4", mac="de:ad:00:00:00:01", duty=5), 0) \
        is True, "duty<10 钳到 10 → 周期内仍有 1 拍阻断"
    assert k._should_poison(core.Target(ip="1.2.3.4", mac="de:ad:00:00:00:01", duty=500), 7) \
        is True, "duty>100 钳到 100 → 恒阻断"


def test_set_duty_updates_and_persists(monkeypatch):
    k, t = _mk_killer(monkeypatch)
    saved = []
    monkeypatch.setattr(core, "write_state", lambda data: saved.append(data))
    k._targets[t.ip] = t
    assert k.set_duty(t.ip, 50) is True
    assert t.duty == 50
    assert k.duty_of(t.ip) == 50
    assert saved, "set_duty 应触发持久化"
    assert saved[-1]["targets"][0]["duty"] == 50
    assert k.set_duty("1.2.3.4", 50) is False, "不存在的目标返回 False"


def test_loop_alternates_poison_and_restore(monkeypatch):
    """真循环集成：duty=50 时 restore 帧确实出现在阻断拍之间。"""
    k, t = _mk_killer(monkeypatch, duty=50)
    k.interval = 0.3          # 测试加速（运行时下限也是 0.3）
    k._targets[t.ip] = t
    calls = []
    monkeypatch.setattr(core, "l2_check", lambda: ("ok", "ok"))

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
            calls.append(kw.get("_restore", False))

    monkeypatch.setattr(core, "scapy_mod", lambda: _FakeScapy())

    # 替换 _emit 记录 restore 语义（不真发包）
    orig_emit = core.Killer._emit
    # 第 7 轮起 _loop 会带 gen 参数（会话代际），桩函数签名要跟着走
    k._emit = lambda tgt, restore=False, count=1, gen=None: calls.append(restore)

    k._stop.clear()
    th = core.Killer.start(k)
    deadline = time.time() + 4.0
    while len(calls) < 12 and time.time() < deadline:
        time.sleep(0.05)
    k.stop()
    assert len(calls) >= 10, f"应跑满一个周期以上，实际 {len(calls)} 拍"
    assert True in calls and False in calls, "duty=50 应交替出现阻断拍与恢复拍"


if __name__ == "__main__":
    class _MP:
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

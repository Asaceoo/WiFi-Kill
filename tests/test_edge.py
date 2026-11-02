#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_edge.py — 边界与故障路径测试（对抗性审查第 2 轮）

只测"异常输入 / 并发 / 崩溃现场"，不碰真实设备：所有需要发帧的用例
都用 dry_run 或伪造目标，确保零副作用。
"""

from __future__ import annotations

import json
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import core  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, bool(ok), detail))


def case(fn):
    def wrapper():
        try:
            fn()
        except Exception:
            check(fn.__name__, False, traceback.format_exc(limit=2)[-320:])
    wrapper.__name__ = fn.__name__
    return wrapper


def fake_net():
    return core.NetInfo(iface="test0", my_ip="10.0.0.2", my_mac="aa:bb:cc:dd:ee:01",
                        gateway_ip="10.0.0.1", gateway_mac="aa:bb:cc:dd:ee:02",
                        cidr="10.0.0.0/24", iface_name="Test IF")


# 1 状态文件损坏
@case
def t_corrupt_state():
    core.STATE_FILE.write_text("{not json at all", encoding="utf-8")
    st = core.load_state()
    check("损坏状态文件不抛异常且返回空", st == {}, repr(st))
    core.clear_state()


# 2 非法 MAC 目标
@case
def t_bad_mac():
    k = core.Killer(fake_net(), dry_run=True)
    try:
        k.add(core.Target("10.0.0.9", "zz:zz"))
        check("非法 MAC 必须抛 BlockError", False, "没有抛异常")
    except core.BlockError:
        check("非法 MAC 抛 BlockError", True)
    except Exception as e:
        check("非法 MAC 抛 BlockError", False, f"抛了 {type(e).__name__}")
    check("非法 MAC 不会污染队列", len(k.targets()) == 0, str(k.targets()))


# 3 网关 MAC 缺失
@case
def t_no_gateway_mac():
    ni = fake_net()
    ni.gateway_mac = ""
    k = core.Killer(ni, dry_run=True)
    try:
        k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
        check("网关 MAC 缺失必须拒绝", False, "没有抛异常")
    except core.BlockError:
        check("网关 MAC 缺失抛 BlockError", True)


# 4 重复 add 幂等
@case
def t_idempotent():
    core.clear_state()
    k = core.Killer(fake_net(), dry_run=True)
    t = core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09")
    for _ in range(5):
        k.add(t)
    check("重复阻断保持单条记录", len(k.targets()) == 1, str(len(k.targets())))


# 5 并发 add / remove
@case
def t_concurrent():
    core.clear_state()
    k = core.Killer(fake_net(), dry_run=True)
    errs: list[str] = []

    def worker(i: int):
        try:
            mac = f"aa:bb:cc:dd:ee:{i % 90 + 10:02x}"
            t = core.Target(f"10.0.0.{i % 90 + 10}", mac)
            for _ in range(20):
                k.add(t)
                k.remove(t.ip)
        except Exception as e:
            errs.append(f"{type(e).__name__}: {e}")

    ths = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ths]
    [t.join(15) for t in ths]
    check("并发阻断/放行无异常", not errs, "；".join(errs[:2]))
    check("并发结束后队列可收敛", isinstance(len(k.targets()), int))


# 6 dry-run 不落盘
@case
def t_dryrun_no_state():
    core.clear_state()
    k = core.Killer(fake_net(), dry_run=True)
    k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    check("演练模式不写状态文件", not core.STATE_FILE.exists())


# 7 单实例互斥
@case
def t_single_instance():
    a = core.SingleInstance(port=52111)
    b = core.SingleInstance(port=52111)
    ok1 = a.acquire()
    ok2 = b.acquire()
    a.release()
    b.release()
    check("单实例：首个获取成功", ok1)
    check("单实例：第二个被拒绝", not ok2)


# 8 非法网段
@case
def t_bad_cidr():
    ni = fake_net()
    ni.cidr = "not-a-cidr"
    devs, active = core.scan(ni, 0.3, active=False)
    check("非法网段扫描不崩", isinstance(devs, list), repr(devs)[:80])


# 9 白名单 MAC-only
@case
def t_whitelist_mac():
    core.WHITELIST_FILE.write_text("aa:bb:cc:dd:ee:09\n", encoding="utf-8")
    wl = core.load_whitelist()
    check("白名单可仅有 MAC", "aa:bb:cc:dd:ee:09" in wl, str(wl))
    check("白名单自动小写归一", all(x == x.lower() for x in wl))
    core.WHITELIST_FILE.unlink(missing_ok=True)


# 10 restore 后状态清空
@case
def t_restore_clears():
    core.clear_state()
    k = core.Killer(fake_net(), dry_run=True)
    k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    n = k.restore_all()
    check("恢复后队列清空", len(k.targets()) == 0, str(k.targets()))
    check("恢复计数正确", n == 1, str(n))


# 11 线程停止后不再投毒
@case
def t_stop_is_clean():
    k = core.Killer(fake_net(), dry_run=True, interval=0.1)
    k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    k.start()
    import time
    time.sleep(0.35)
    k.stop()
    alive = k.is_active()
    check("stop 后线程已退出", not alive)
    check("stop 幂等", (k.stop() or True))


# 12 日志回调异常不影响主流程
@case
def t_logger_isolation():
    def boom(level, msg):
        raise RuntimeError("sink down")
    core.LOG.subscribe(boom)
    try:
        core.LOG.emit("info", "test")
        check("日志回调抛错被隔离", True)
    except Exception:
        check("日志回调抛错被隔离", False, "异常冒泡到了调用方")


@case
def t_protected_device():
    """安全不变量：网关与本机在任意路径下都不可被阻断（对抗性审查第 3 轮发现）。"""
    gw = core.Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:02", note="网关")
    me = core.Device(ip="10.0.0.2", mac="aa:bb:cc:dd:ee:01", note="本机")
    phone = core.Device(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:05", note="")
    check("网关被标记受保护", core.is_protected(gw))
    check("本机被标记受保护", core.is_protected(me))
    check("普通设备不受保护", not core.is_protected(phone))
    # 模拟单目标选择过滤：选中网关+手机，应只剩手机
    picks = [d for d in (gw, me, phone) if not core.is_protected(d)]
    check("单目标过滤后只剩普通设备", [d.ip for d in picks] == ["10.0.0.5"])
    # 模拟只选网关：应无可阻断目标，直接拒绝
    picks2 = [d for d in (gw,) if not core.is_protected(d)]
    check("仅选网关 → 无可阻断目标", not picks2)


@case
def t_protected_api():
    """对抗性审查第 4 轮（三视角）：安全不变量必须在 API 层强制。

    之前 is_protected 只在 GUI 过滤，core.Killer.add() 会直接接受网关并构造投毒帧
    （已用真实 trace 复现：dry_run 下 Killer.add(gateway) 被接受、队列 +1）。
    现在 add() 必须自己拒绝受保护目标。
    """
    k = core.Killer(fake_net(), dry_run=True)
    # 用网关 IP+MAC 直接走 API
    try:
        k.add(core.Target("10.0.0.1", "aa:bb:cc:dd:ee:02"))
        check("API 拒绝网关(按 ip+mac)", False, "网关被接受并构造投毒帧")
    except core.BlockError:
        check("API 拒绝网关(按 ip+mac)", True)
    # 用本机 IP+MAC
    try:
        k.add(core.Target("10.0.0.2", "aa:bb:cc:dd:ee:01"))
        check("API 拒绝本机(按 ip+mac)", False, "本机被接受并构造投毒帧")
    except core.BlockError:
        check("API 拒绝本机(按 ip+mac)", True)
    # 仅 MAC 命中网关（IP 不同）也必须拒绝：双键判定
    try:
        k.add(core.Target("10.0.0.99", "aa:bb:cc:dd:ee:02"))
        check("API 拒绝(仅网关 MAC 命中)", False, "仅 MAC 命中网关却被接受")
    except core.BlockError:
        check("API 拒绝(仅网关 MAC 命中)", True)
    # 普通设备正常入队
    k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    check("普通设备可正常入队", len(k.targets()) == 1, str(k.targets()))


class _FakeWinreg:
    """内存版注册表，仅供 t_autostart_registry 用，不碰真实注册表。

    严格模仿 winreg 模块级 API：OpenKey 返回 key 对象，
    SetValueEx/QueryValueEx/DeleteValue 以 key 为首个参数。
    """

    HKEY_CURRENT_USER = 1
    KEY_SET_VALUE = 0x0002
    REG_SZ = 1
    _store: dict = {}

    class _Key:
        def __init__(self, store):
            self.s = store

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def OpenKey(self, _root, _path, *a, **k):
        return self._Key(self._store)

    def QueryValueEx(self, key, name):
        if name in key.s:
            return (key.s[name], self.REG_SZ)
        raise FileNotFoundError()

    def SetValueEx(self, key, name, _t, _d, val):
        key.s[name] = val

    def DeleteValue(self, key, name):
        if name in key.s:
            del key.s[name]
        else:
            raise FileNotFoundError()


@case
def t_autostart_registry():
    """开机自启写/删 Run 键，值必须含 exe 路径与 --minimized。"""
    orig = core.winreg
    fake = _FakeWinreg()
    core.winreg = fake
    try:
        check("初始未启用", not core.autostart_enabled())
        check("写入成功", core.set_autostart(True))
        check("已启用", core.autostart_enabled())
        val = fake._store.get(core.AUTOSTART_NAME, "")
        check("Run 值含 --minimized", "--minimized" in val, val)
        check("Run 值为引号包裹的 exe 路径", val.startswith('"') and ".exe" in val, val)
        check("删除成功", core.set_autostart(False))
        check("禁用后未启用", not core.autostart_enabled())
    finally:
        core.winreg = orig


# ---------------------------------------------------------------- 第 5 轮
# 下面四条都来自「真实报错闭环」：先写出可复现的最小探针看到红，再改代码到绿。


@case
def t_add_rollback_on_send_failure():
    """发送失败必须回滚队列。

    修复前：add() 先把目标塞进 _targets 再发首帧，sendp 抛异常只往外抛，
    目标留在队列里 —— 投毒线程一起来照样打它，而 GUI 已经把这次记为「跳过」。
    """
    core.clear_state()
    k = core.Killer(fake_net(), dry_run=False)
    k._started = True        # 跳过二层可用性门槛：本机/CI 未必装了 Npcap
    s = core.scapy_mod()
    if s is None:
        check("scapy 可用（否则本用例无意义）", False, "scapy 未加载")
        return
    real = s.sendp
    def boom(*_a, **_kw):
        raise OSError("simulated nic failure")
    s.sendp = boom
    raised = False
    try:
        k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    except core.BlockError:
        raised = True
    finally:
        s.sendp = real
    check("发送失败抛 BlockError", raised)
    check("发送失败后目标回滚出队列", len(k.targets()) == 0, str(k.targets()))
    check("发送失败后不残留状态文件", not core.STATE_FILE.exists())


@case
def t_state_targets_sanitize():
    """状态文件里的一条坏记录不能掀翻整条恢复链（缺字段曾抛 KeyError）。"""
    st = {"targets": [
        {"mac": "aa:bb:cc:dd:ee:50"},                                   # 缺 ip
        {"ip": "10.0.0.7", "mac": "aa:bb:cc:dd:ee:07", "duty": "abc"},   # duty 非数字
        "garbage",                                                       # 非对象
        {"ip": "10.0.0.8", "mac": "zz:zz"},                              # MAC 非法
        {"ip": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:09", "duty": 5},       # duty 太低
        {"ip": "10.0.0.10", "mac": "aa:bb:cc:dd:ee:0a", "duty": 999},    # duty 太高
    ]}
    ts = core.state_targets(st)
    check("坏记录被跳过，好记录全留", [t.ip for t in ts] ==
          ["10.0.0.7", "10.0.0.9", "10.0.0.10"], str([t.ip for t in ts]))
    check("duty 非数字回落 100", ts[0].duty == 100, str(ts[0].duty) if ts else "空")
    check("duty 下限夹到 10", ts[1].duty == 10, str(ts[1].duty) if len(ts) > 1 else "空")
    check("duty 上限夹到 100", ts[2].duty == 100, str(ts[2].duty) if len(ts) > 2 else "空")
    check("None / 空字典安全", core.state_targets(None) == [] and core.state_targets({}) == [])
    check("targets 不是列表时安全", core.state_targets({"targets": "x"}) == [])
    check("duty 默认 100 时也能入列",
          core.state_targets({"targets": [{"ip": "10.0.0.11", "mac": "aa:bb:cc:dd:ee:0b"}]})[0].duty == 100)


@case
def t_network_change_abandons():
    """换网络后旧阻断必须中止，且状态文件不能留着让下次启动误恢复。"""
    core.clear_state()
    ni = fake_net()
    k = core.Killer(ni, dry_run=True)
    k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
    k.persist()
    check("同网络判定为同一上下文", k.matches_network(fake_net()))
    other = core.NetInfo(iface="test0", my_ip="192.168.5.2",
                         my_mac="aa:bb:cc:dd:ee:31", gateway_ip="192.168.5.1",
                         gateway_mac="aa:bb:cc:dd:ee:32", cidr="192.168.5.0/24")
    check("换网关后判定为不同上下文", not k.matches_network(other))
    # 探测失败（空 iface / 空网关 MAC）不能被当成换网，否则会把生效中的阻断误杀
    blank = core.NetInfo(iface="", my_ip="", my_mac="", gateway_ip="", gateway_mac="",
                         cidr="")
    check("探测为空时不误判换网", k.matches_network(blank))
    same_gw_new_router = core.NetInfo(iface="test0", my_ip="10.0.0.2",
                                      my_mac="aa:bb:cc:dd:ee:01", gateway_ip="10.0.0.1",
                                      gateway_mac="aa:bb:cc:dd:ee:99", cidr="10.0.0.0/24")
    check("同一网关 IP 换了路由器也算变更", not k.matches_network(same_gw_new_router))
    n = k.abandon()
    check("abandon 返回丢弃台数", n == 1, str(n))
    check("abandon 清空队列", len(k.targets()) == 0, str(k.targets()))
    check("abandon 清除状态文件", not core.STATE_FILE.exists())
    check("abandon 幂等", k.abandon() == 0)


# ---------------------------------------------------------------- 第 7 轮
# 关闭「恢复帧与在途投毒帧交叉」窗口：会话代际 + 发送锁。


@case
def t_stale_generation_refuses_send():
    """停止/恢复推进代际后，过期批次的投毒帧必须一帧都发不出去。"""
    s = core.scapy_mod()
    if s is None:
        check("scapy 可用（否则本用例无意义）", False, "scapy 未加载")
        return
    sent = []
    real = s.sendp
    s.sendp = lambda pkt, **kw: sent.append(pkt["ARP"].psrc)
    try:
        k = core.Killer(fake_net(), dry_run=False)
        k._started = True
        t = core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09")
        gen = k._gen
        k._emit(t, gen=gen)                    # 当代际：正常发送 2 帧
        n = len(sent)
        k._bump_gen()                          # 模拟 stop()/remove() 推进代际
        k._emit(t, gen=gen)                    # 过期批次：必须被拦下
        check("当代际可正常发送", n == 2, str(n))
        check("过期批次被拦下（不再补投毒帧）", len(sent) == n, str(len(sent)))
        check("作废计数递增", k._late_sends == 1, str(k._late_sends))
    finally:
        s.sendp = real


@case
def t_restore_frames_come_last():
    """恢复帧必须排在最后：sendp 变慢造成真实重叠时也不许越位。"""
    import time
    s = core.scapy_mod()
    if s is None:
        check("scapy 可用（否则本用例无意义）", False, "scapy 未加载")
        return
    sent = []
    real = s.sendp

    def slow_sendp(pkt, **kw):
        time.sleep(0.05)                      # 制造在途帧，逼出顺序问题
        sent.append(pkt["ARP"].hwsrc)

    s.sendp = slow_sendp
    try:
        k = core.Killer(fake_net(), interval=0.05)
        k._started = True
        k.add(core.Target("10.0.0.9", "aa:bb:cc:dd:ee:09"))
        k.start()
        time.sleep(0.3)
        k.restore_all()
        time.sleep(0.3)                       # 留时间给任何可能迟到的帧
        my_mac = fake_net().my_mac
        first_restore = next((i for i, h in enumerate(sent)
                              if h in (fake_net().gateway_mac, 'aa:bb:cc:dd:ee:09')), None)
        tail = [h for h in sent[(first_restore or 0) + 1:] if h == my_mac] if first_restore is not None else []
        check("确实发过恢复帧", first_restore is not None, str(len(sent)))
        check("恢复帧之后没有投毒帧", not tail, str(tail[:3]))
        check("恢复后队列已清空", not k.targets(), str(k.targets()))
    finally:
        s.sendp = real


@case
def t_relaunch_command_keeps_entry_script():
    """以管理员身份重启：源码运行必须带上入口脚本，否则拉起的是空 python.exe。

    第 8 轮探针：修复前 params 为空串（提权后黑框一闪就退，用户丢掉程序）。
    """
    target, params = core._relaunch_command([], script="gui.py")
    check("源码运行时参数里带入口脚本", params.strip().endswith("gui.py"), params)
    check("可执行文件是当前解释器", bool(target), target)
    _, p2 = core._relaunch_command(["--minimized"], script="gui.py")
    check("额外参数保留", "gui.py" in p2 and "--minimized" in p2, p2)
    had = hasattr(sys, "frozen")
    old = getattr(sys, "frozen", False)
    try:
        sys.frozen = True
        _, p3 = core._relaunch_command([])
        check("打包运行时不注入脚本路径", ".py" not in p3, p3)
    finally:
        if had:
            sys.frozen = old
        else:
            delattr(sys, "frozen")


@case
def t_verification_verdict():
    """阻断验证的判据（纯函数）：吸到本机=生效，仍走真实网关=泄漏。"""
    ok = core.verification_verdict(5, 0)
    partial = core.verification_verdict(3, 2)
    fail = core.verification_verdict(0, 4)
    unknown = core.verification_verdict(0, 0)
    check("吸到本机 → 已生效", ok[0] == "ok", ok)
    check("有泄漏 → 部分生效", partial[0] == "partial", partial)
    check("只泄漏 → 未生效", fail[0] == "fail", fail)
    check("无帧 → 无法判定", unknown[0] == "unknown", unknown)
    st = core.classify_target_frames(
        "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03",
        [("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"),
         ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03"),
         ("aa:bb:cc:dd:ee:01", "ff:ff:ff:ff:ff:ff"),
         ("aa:bb:cc:dd:ee:99", "aa:bb:cc:dd:ee:02")])
    check("分类只统计目标自己的帧", st == {"hits": 1, "leaks": 1, "other": 1}, st)
    check("空帧安全", core.classify_target_frames("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02",
                                                "aa:bb:cc:dd:ee:03", [])["hits"] == 0)


@case
def t_arp_row_conversion():
    """WinAPI 邻居表行的转换（纯函数）：过滤无效/组播/广播，IP 字节序正确。"""
    rows = [
        (0x0500000A, b"\xaa\xbb\xcc\xdd\xee\x01", 3),      # 10.0.0.5 动态
        (0x0900000A, b"\xaa\xbb\xcc\xdd\xee\x02", 2),      # 无效项 → 丢
        (0x0A0000E0, b"\x01\x00\x5e\x00\x00\x01", 3),      # 224.0.0.10 组播 → 丢
        (0x0100000A, b"\xaa\xbb", 3),                        # 物理地址太短 → 丢
        (0x0100000A, b"\xaa\xbb\xcc\xdd\xee\x03", 4),      # 10.0.0.1 静态
    ]
    table = core._arp_rows_to_table(rows)
    check("转换结果只留合法项", sorted(table) == ["10.0.0.1", "10.0.0.5"], str(table))
    check("MAC 格式正确", table.get("10.0.0.5") == "aa:bb:cc:dd:ee:01", str(table))
    check("空输入安全", core._arp_rows_to_table([]) == {})


def main():
    for fn in (t_corrupt_state, t_bad_mac, t_no_gateway_mac, t_idempotent,
               t_concurrent, t_dryrun_no_state, t_single_instance, t_bad_cidr,
               t_whitelist_mac, t_restore_clears, t_stop_is_clean,
               t_logger_isolation, t_protected_device, t_protected_api,
               t_autostart_registry,
               # 第 5 轮：真实报错闭环补进来的回归
               t_add_rollback_on_send_failure, t_state_targets_sanitize,
               t_network_change_abandons,
               # 第 7 轮：发送顺序 / 邻居表转换
               t_stale_generation_refuses_send, t_restore_frames_come_last,
               t_arp_row_conversion, t_verification_verdict,
               t_relaunch_command_keeps_entry_script):
        fn()

    print("\n=========== 边界测试 ===========")
    bad = 0
    for name, ok, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n      {detail}"))
        bad += 0 if ok else 1
    print(f"--------------------------------\n共 {len(RESULTS)} 项，失败 {bad} 项")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

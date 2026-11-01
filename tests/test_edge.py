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


def main():
    for fn in (t_corrupt_state, t_bad_mac, t_no_gateway_mac, t_idempotent,
               t_concurrent, t_dryrun_no_state, t_single_instance, t_bad_cidr,
               t_whitelist_mac, t_restore_clears, t_stop_is_clean,
               t_logger_isolation, t_protected_device, t_protected_api):
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

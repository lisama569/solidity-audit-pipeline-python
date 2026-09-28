"""版本对比任务测试：四类结论、挪动匹配、多基线隔离、并发幂等、基线拒绝、
取消/重试/重启持久化，以及不回归的普通审计行为。"""
import threading

import pytest

from app.errors import IngestError
from app.models import ErrorCode, TaskStatus
from app.store import TaskStore
from app.comparisons import ComparisonManager
from app.tasks import TaskManager

BASE = """
contract Vault {
    mapping(address => uint) balances;
    function keep() public {
        msg.sender.call{value: 1}("");
        balances[msg.sender] = 0;
    }
    function fixedFn(address t) public {
        uint mode = 1;
        t.delegatecall("");
    }
    function sevchg(address payable to) public {
        to.send(1);
    }
}
"""

# 顶部注入无关合约、整体挪动、纯重命名、函数重排
NEW = """
contract Helper { uint helper; }
contract Vault {
    mapping(address => uint) ledger;
    function newFn(address to, uint amount) public {
        bool flag = true;
        to.call{value: amount}("");
    }
    function sevchg(address payable to) public {
        to.call{value: 1}("");
    }
    function keep() public {
        msg.sender.call{value: 1}("");
        ledger[msg.sender] = 0;
    }
}
"""

OTHER_BASE = """
contract Vault {
    mapping(address => uint) balances;
    function keep() public {
        msg.sender.call{value: 1}("");
        balances[msg.sender] = 0;
    }
}
"""


@pytest.fixture()
def mgr(tmp_path):
    store = TaskStore(str(tmp_path / "audit.db"))
    tm = TaskManager(store, timeout_seconds=10.0, auto_recover=False)
    cm = ComparisonManager(store, tm, timeout_seconds=10.0, auto_recover=False)
    yield tm, cm
    cm.shutdown()
    tm.shutdown()


def _f(src: str, name: str = "Vault.sol"):
    return [(name, src.encode())]


def _baseline(tm, src=BASE, name="Vault.sol"):
    t = tm.submit(_f(src, name))
    done = tm.wait_for(t.task_id)
    assert done.status is TaskStatus.SUCCEEDED
    return done


def test_end_to_end_four_categories(mgr):
    tm, cm = mgr
    base = _baseline(tm)
    rec = cm.submit_compare(_f(NEW), base.task_id)
    done = cm.wait_for(rec.compare_id, deadline=10)
    assert done.status is TaskStatus.SUCCEEDED
    r = done.result
    assert r.baseline_task_id == base.task_id
    assert r.current_task_id is not None
    assert r.counts == {"NEW": 1, "FIXED": 1, "PERSISTENT": 2,
                        "SEVERITY_CHANGED": 1}
    print(f"[compare] 端到端四类 -> {r.counts} hash={r.comparison_hash[:16]}")


def test_code_shift_matches_as_persistent(mgr):
    tm, cm = mgr
    base = _baseline(tm)
    done = cm.wait_for(cm.submit_compare(_f(NEW), base.task_id).compare_id)
    persist = [d for d in done.result.deltas if d.category.value == "PERSISTENT"]
    # keep 整体从 L5 挪到 L14 且 balances->ledger，两条规则仍判仍然存在
    assert {d.current.function for d in persist} == {"keep"}
    assert all(d.baseline.line == 5 and d.current.line == 13 for d in persist)
    print("[compare] 代码位置整体挪动+重命名 -> 原问题仍 PERSISTENT，不抖动")


def test_same_version_different_baselines_independent(mgr):
    tm, cm = mgr
    b1 = _baseline(tm, BASE)
    b2 = _baseline(tm, OTHER_BASE)
    r1 = cm.wait_for(cm.submit_compare(_f(NEW), b1.task_id).compare_id)
    r2 = cm.wait_for(cm.submit_compare(_f(NEW), b2.task_id).compare_id)
    assert r1.compare_id != r2.compare_id          # 不同基线 -> 独立对比记录
    assert r1.result.counts != r2.result.counts    # 独立结论
    assert r1.result.comparison_hash != r2.result.comparison_hash
    # 各自都能看出相对哪条基线
    assert r1.result.baseline_task_id == b1.task_id
    assert r2.result.baseline_task_id == b2.task_id
    print(f"[compare] 同新版本对两基线 -> 独立记录与结论 "
          f"{r1.result.counts} vs {r2.result.counts}")


def test_concurrent_duplicate_submission_single_consistent_result(mgr):
    tm, cm = mgr
    base = _baseline(tm)
    barrier = threading.Barrier(12)
    out = []

    def submit():
        barrier.wait()
        out.append(cm.submit_compare(_f(NEW), base.task_id))

    threads = [threading.Thread(target=submit) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r.compare_id for r in out}
    assert len(ids) == 1, f"并发重复提交产生 {len(ids)} 条对比记录"
    done = cm.wait_for(ids.pop(), deadline=10)
    assert done.status is TaskStatus.SUCCEEDED
    # 再顺序重复提交，结论完全一致
    again = cm.submit_compare(_f(NEW), base.task_id)
    assert again.compare_id == done.compare_id
    assert again.result.comparison_hash == done.result.comparison_hash
    print(f"[compare] 12 路并发重复 -> 单对比 {done.compare_id[:8]} "
          f"hash={done.result.comparison_hash[:16]}")


def test_baseline_not_found_rejected(mgr):
    tm, cm = mgr
    _baseline(tm)  # 确保系统里已有任务，但不影响找不到的判断
    with pytest.raises(IngestError) as e:
        cm.submit_compare(_f(NEW), "nonexistent-task-id")
    assert e.value.code is ErrorCode.BASELINE_NOT_FOUND
    print("[compare] 基线不存在 -> BASELINE_NOT_FOUND（拒绝，不降级）")


def test_baseline_not_ready_rejected(mgr):
    tm, cm = mgr
    # 直接构造一个 QUEUED 基线任务（未经审计完成）
    from app.models import TaskRecord
    import time
    rec = TaskRecord(task_id="queued-base", fingerprint="fp-x",
                     status=TaskStatus.QUEUED, created_at=time.time(),
                     updated_at=time.time())
    tm.store.upsert(rec)
    with pytest.raises(IngestError) as e:
        cm.submit_compare(_f(NEW), "queued-base")
    assert e.value.code is ErrorCode.BASELINE_NOT_READY
    print("[compare] 基线未完成 -> BASELINE_NOT_READY（拒绝，不返回半截）")


def test_baseline_mismatch_rejected(mgr):
    tm, cm = mgr
    other = _baseline(tm, "contract Other { uint z; }\n", "Other.sol")
    with pytest.raises(IngestError) as e:
        cm.submit_compare(_f(NEW, "Vault.sol"), other.task_id)
    assert e.value.code is ErrorCode.BASELINE_MISMATCH
    # 拒绝时不应产生任何对比记录
    assert cm.get(other.task_id) is None
    print("[compare] 基线与当前提交不同源 -> BASELINE_MISMATCH（拒绝）")


def test_retry_after_failure_no_duplicate_and_succeeds(mgr, monkeypatch):
    tm, cm = mgr
    base = _baseline(tm)
    import app.comparisons as cmp_mod
    orig = cmp_mod.diffing.compare_reports
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("模拟对比崩溃")
        return orig(*a, **k)

    monkeypatch.setattr(cmp_mod.diffing, "compare_reports", flaky)
    rec = cm.submit_compare(_f(NEW), base.task_id)
    failed = cm.wait_for(rec.compare_id, deadline=10)
    assert failed.status is TaskStatus.FAILED
    cm.retry(rec.compare_id)
    done = cm.wait_for(rec.compare_id, deadline=10)
    assert done.status is TaskStatus.SUCCEEDED
    assert done.attempts == 2
    # 重试不产生重复记录：同一对 (新版本, 基线) 仍只有这一条
    again = cm.submit_compare(_f(NEW), base.task_id)
    assert again.compare_id == rec.compare_id
    monkeypatch.undo()
    print(f"[compare] 失败重试 attempts={done.attempts} -> SUCCEEDED，无重复记录")


def test_result_persists_across_restart(mgr, tmp_path):
    tm, cm = mgr
    base = _baseline(tm)
    done = cm.wait_for(cm.submit_compare(_f(NEW), base.task_id).compare_id)
    assert done.status is TaskStatus.SUCCEEDED
    h = done.result.comparison_hash
    cid = done.compare_id

    # 模拟重启：全新管理器读同一数据库
    store2 = TaskStore(str(tmp_path / "audit.db"))
    tm2 = TaskManager(store2, timeout_seconds=10.0, auto_recover=False)
    cm2 = ComparisonManager(store2, tm2, timeout_seconds=10.0, auto_recover=True)
    try:
        loaded = cm2.get(cid)
        assert loaded.status is TaskStatus.SUCCEEDED
        assert loaded.result.comparison_hash == h
        # 重启后重复提交直接复用同一条
        again = cm2.submit_compare(_f(NEW), base.task_id)
        assert again.compare_id == cid
        print(f"[compare] 重启后对比结论不丢 hash={h[:16]}，重复提交复用")
    finally:
        cm2.shutdown()
        tm2.shutdown()


def test_ordinary_audit_dedup_still_works(mgr):
    # 不回归：普通审计重复提交仍是单任务单结论
    tm, cm = mgr
    t1 = tm.submit(_f(BASE))
    t2 = tm.submit(_f(BASE))
    assert t1.task_id == t2.task_id
    done = tm.wait_for(t1.task_id)
    assert done.status is TaskStatus.SUCCEEDED
    print("[compare] 普通审计重复提交去重不回归")


def test_cancel_queued_comparison_then_retry(tmp_path):
    import time
    import app.comparisons as cmp_mod
    store = TaskStore(str(tmp_path / "audit.db"))
    tm = TaskManager(store, timeout_seconds=300.0, auto_recover=False)
    # 对比执行器单 worker：第一个（事件阻塞的）对比占住后，第二个停在 QUEUED
    cm = ComparisonManager(store, tm, timeout_seconds=300.0, worker_count=1,
                           auto_recover=False)
    base = _baseline(tm, BASE)
    other_base = _baseline(tm, OTHER_BASE)
    orig = cmp_mod.diffing.compare_reports
    entered = threading.Event()
    release = threading.Event()

    def slow(*a, **k):
        entered.set()
        release.wait(timeout=300)
        return orig(*a, **k)

    cmp_mod.diffing.compare_reports = slow
    try:
        first = cm.submit_compare(_f(NEW), base.task_id)  # 占住唯一 worker
        assert entered.wait(timeout=10)
        queued = cm.submit_compare(_f(NEW), other_base.task_id)
        # 轮询确认第二个稳定停在 QUEUED（不依赖墙钟时长）
        deadline = time.time() + 5
        while time.time() < deadline:
            if cm.get(queued.compare_id).status is TaskStatus.QUEUED:
                break
            time.sleep(0.01)
        assert cm.get(queued.compare_id).status is TaskStatus.QUEUED

        cancelled = cm.cancel(queued.compare_id)
        assert cancelled.status is TaskStatus.CANCELLED
        assert cancelled.error_code == ErrorCode.TASK_CANCELLED.value

        # 恢复正常计算并放行第一个
        cmp_mod.diffing.compare_reports = orig
        release.set()
        assert cm.wait_for(first.compare_id, deadline=15).status is \
            TaskStatus.SUCCEEDED

        # 第二个此前被取消；现在重试 -> SUCCEEDED 且仍是同一条记录（无重复）
        cm.retry(queued.compare_id)
        done = cm.wait_for(queued.compare_id, deadline=15)
        assert done.status is TaskStatus.SUCCEEDED
        assert done.compare_id == queued.compare_id
        again = cm.submit_compare(_f(NEW), other_base.task_id)
        assert again.compare_id == queued.compare_id
        print("[compare] 排队对比取消 -> CANCELLED，重试 SUCCEEDED 且无重复记录")
    finally:
        release.set()
        cmp_mod.diffing.compare_reports = orig
        cm.shutdown()
        tm.shutdown()

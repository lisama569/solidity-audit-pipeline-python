"""版本对比任务测试：基线拒绝、不同基线独立、并发重复一致、
排队/取消/重试不产生重复记录、重启后对比结论不丢。"""
import threading

import pytest

from app.errors import BaselineError
from app.models import ErrorCode, TaskStatus
from app.store import TaskStore
from app.tasks import TaskManager

BASE = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
    function leak() public { msg.sender.send(1); }
}
"""
CUR = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        require(msg.sender.call{value: amount}(""));
    }
    function leak() public { msg.sender.send(1); }
    function evil(address t) public { t.delegatecall(""); }
}
"""
OTHER_BASE = """
contract Wallet {
    mapping(address => uint) vault;
    function pay(address r) public {
        r.delegatecall("");
        vault[r] = 1;
    }
}
"""


def _f(src, name="Vault.sol"):
    return [(name, src.encode())]


@pytest.fixture()
def mgr(tmp_path):
    m = TaskManager(TaskStore(str(tmp_path / "a.db")), timeout_seconds=10.0)
    yield m
    m.shutdown()


def _baseline(mgr, src=BASE, name="Vault.sol"):
    t = mgr.submit(_f(src, name))
    done = mgr.wait_for(t.task_id)
    assert done.status is TaskStatus.SUCCEEDED
    return done


def test_diff_end_to_end_categories(mgr):
    b = _baseline(mgr)
    d = mgr.submit_diff(_f(CUR), b.task_id)
    done = mgr.wait_for(d.task_id)
    assert done.kind == "diff"
    assert done.status is TaskStatus.SUCCEEDED
    diff = done.diff
    assert diff.baseline_task_id == b.task_id
    assert diff.baseline_fingerprint == b.fingerprint
    assert diff.counts["NEW"] == 1
    assert diff.counts["FIXED"] == 1
    assert diff.counts["PERSISTING"] == 1
    funcs_new = [e.current_finding.function for e in diff.entries
                 if e.category.value == "NEW"]
    assert funcs_new == ["evil"]
    print(f"[difftask] 端到端对比 -> {diff.counts} 基线={b.task_id[:8]}")


def test_baseline_rejections_distinct(mgr):
    # 不存在
    with pytest.raises(BaselineError) as e1:
        mgr.submit_diff(_f(CUR), "missing-id")
    assert e1.value.code is ErrorCode.BASELINE_NOT_FOUND

    # 未完成：制造一个 QUEUED 基线
    m2 = TaskManager(mgr._store, timeout_seconds=30.0, worker_count=1,
                     auto_recover=False)
    try:
        import time
        from app import engine
        orig = engine.audit
        engine.audit = lambda *a, **k: (time.sleep(0.5), orig(*a, **k))[1]
        queued = m2.submit(_f(BASE, "Slow.sol"))
        time.sleep(0.05)
        with pytest.raises(BaselineError) as e2:
            mgr.submit_diff(_f(BASE, "Slow.sol"), queued.task_id)
        assert e2.value.code is ErrorCode.BASELINE_NOT_READY
    finally:
        engine.audit = orig
        m2.shutdown()

    # 已完成但对不上（无共同路径）
    b = _baseline(mgr, OTHER_BASE, "Wallet.sol")
    with pytest.raises(BaselineError) as e3:
        mgr.submit_diff(_f(CUR, "TotallyDifferent.sol"), b.task_id)
    assert e3.value.code is ErrorCode.BASELINE_UNRELATED
    print("[difftask] 三类基线拒绝 -> NOT_FOUND / NOT_READY / UNRELATED")


def test_same_version_different_baselines_independent(mgr):
    b1 = _baseline(mgr, BASE, "Vault.sol")
    b2 = _baseline(mgr, OTHER_BASE, "Wallet.sol")  # 不同合约
    # 当前提交同时包含两个文件，才能与两条基线都"对得上"
    cur_both = [("Vault.sol", CUR.encode()), ("Wallet.sol", OTHER_BASE.encode())]
    d1 = mgr.submit_diff(cur_both, b1.task_id)
    d2 = mgr.submit_diff(cur_both, b2.task_id)
    assert d1.task_id != d2.task_id  # 不同基线 -> 独立任务，不复用
    r1 = mgr.wait_for(d1.task_id)
    r2 = mgr.wait_for(d2.task_id)
    assert r1.status is TaskStatus.SUCCEEDED and r2.status is TaskStatus.SUCCEEDED
    assert r1.diff.baseline_fingerprint == b1.fingerprint
    assert r2.diff.baseline_fingerprint == b2.fingerprint
    assert r1.diff.diff_id != r2.diff.diff_id
    # 重复提交同一对仍复用各自任务
    assert mgr.submit_diff(cur_both, b1.task_id).task_id == d1.task_id
    assert mgr.submit_diff(cur_both, b2.task_id).task_id == d2.task_id
    print(f"[difftask] 同版本不同基线独立 -> {d1.task_id[:8]} vs {d2.task_id[:8]}")


def test_concurrent_duplicate_diff_submission_single_task(mgr):
    b = _baseline(mgr)
    results, barrier = [], threading.Barrier(16)

    def submit():
        barrier.wait()
        results.append(mgr.submit_diff(_f(CUR), b.task_id))

    threads = [threading.Thread(target=submit) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r.task_id for r in results}
    assert len(ids) == 1, f"并发对比提交产生 {len(ids)} 个任务"
    done = mgr.wait_for(ids.pop())
    assert done.status is TaskStatus.SUCCEEDED
    hashes = {done.diff.diff_hash}
    # 再次提交：命中已完成任务，结论完全一致
    again = mgr.submit_diff(_f(CUR), b.task_id)
    assert again.task_id == done.task_id
    assert again.diff.diff_hash in hashes
    print(f"[difftask] 16 路并发重复对比 -> 单任务 {done.task_id[:8]} "
          f"hash={done.diff.diff_hash[:16]}")


def test_diff_order_independent_and_separate_from_audit(mgr):
    # 先审计新版本，再提交对比；与"直接提交对比"结论一致
    b = _baseline(mgr)
    cur_audit = mgr.submit(_f(CUR))
    mgr.wait_for(cur_audit.task_id)
    d1 = mgr.submit_diff(_f(CUR), b.task_id)
    r1 = mgr.wait_for(d1.task_id)

    # 新版本自身的普通审计仍是独立任务
    assert cur_audit.task_id != d1.task_id
    assert mgr.get(cur_audit.task_id).kind == "audit"
    assert r1.kind == "diff"
    assert r1.diff.diff_hash
    print("[difftask] 先审计后对比：审计/对比互不串用")


def test_diff_cancel_queued_then_retry_no_duplicates(tmp_path):
    from app import engine
    import app.tasks as tasks_mod
    import time
    store = TaskStore(str(tmp_path / "a.db"))
    # 单 worker + 慢审计，先占满 worker 让 diff 排队
    m = TaskManager(store, timeout_seconds=30.0, worker_count=1,
                    auto_recover=False)
    orig = engine.audit

    def slow(*a, **k):
        time.sleep(0.5)
        return orig(*a, **k)

    tasks_mod.engine.audit = slow
    try:
        # 基线需先完成：用单独的快速管理器算好并存库
        m0 = TaskManager(store, timeout_seconds=30.0, auto_recover=False)
        b = m0.wait_for(m0.submit(_f(BASE)).task_id, deadline=10.0)
        assert b.status is TaskStatus.SUCCEEDED
        m0.shutdown()

        blocker = m.submit(_f(OTHER_BASE, "Wallet.sol"))  # 占住唯一 worker
        d = m.submit_diff(_f(CUR), b.task_id)
        assert m.get(d.task_id).status is TaskStatus.QUEUED
        cancelled = m.cancel(d.task_id)
        assert cancelled.status is TaskStatus.CANCELLED
        m.wait_for(blocker.task_id, deadline=10.0)
        time.sleep(0.8)  # 排队被取消的对比永不执行
        assert m.get(d.task_id).status is TaskStatus.CANCELLED
        assert m.get(d.task_id).diff is None

        # 重试 -> 同一任务 id，成功后只有一份结论
        m.retry(d.task_id)
        done = m.wait_for(d.task_id, deadline=10.0)
        assert done.status is TaskStatus.SUCCEEDED
        assert done.attempts == 1
        assert done.diff is not None and done.diff.counts["total"] == 3
        # 数据库里这一对仍只有一个 diff 任务
        again = m.submit_diff(_f(CUR), b.task_id)
        assert again.task_id == d.task_id
        print(f"[difftask] 对比取消后重试 -> 无重复任务 {d.task_id[:8]}")
    finally:
        tasks_mod.engine.audit = orig
        m.shutdown()


def test_diff_retry_after_failure_consistent(tmp_path):
    import app.tasks as tasks_mod
    store = TaskStore(str(tmp_path / "a.db"))
    m0 = TaskManager(store, timeout_seconds=30.0, auto_recover=False)
    b = m0.wait_for(m0.submit(_f(BASE)).task_id, deadline=10.0)
    m0.shutdown()

    m = TaskManager(store, timeout_seconds=30.0, auto_recover=False)
    orig_compare = tasks_mod.diffing.compare_reports
    calls = {"n": 0}

    def flaky_compare(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("模拟对比计算崩溃")
        return orig_compare(*a, **k)

    tasks_mod.diffing.compare_reports = flaky_compare
    try:
        d = m.submit_diff(_f(CUR), b.task_id)
        failed = m.wait_for(d.task_id, deadline=10.0)
        assert failed.status is TaskStatus.FAILED
        assert failed.error_code == ErrorCode.INTERNAL_ERROR.value
        # 失败后（尚未重试）再次提交同一对：复用同一条记录，不新增任务
        resubmitted = m.submit_diff(_f(CUR), b.task_id)
        assert resubmitted.task_id == d.task_id
        assert resubmitted.status is TaskStatus.FAILED
        m.retry(d.task_id)
        done = m.wait_for(d.task_id, deadline=10.0)
        assert done.status is TaskStatus.SUCCEEDED
        assert done.attempts == 2
        assert done.diff.counts["total"] == 3
        # 重试不产生新任务/新结论
        assert m.submit_diff(_f(CUR), b.task_id).task_id == d.task_id
        print(f"[difftask] 对比失败重试 -> attempts=2 hash={done.diff.diff_hash[:16]}")
    finally:
        tasks_mod.diffing.compare_reports = orig_compare
        m.shutdown()


def test_diff_survives_restart(tmp_path):
    db = str(tmp_path / "a.db")
    m1 = TaskManager(TaskStore(db), timeout_seconds=30.0, auto_recover=False)
    b = m1.wait_for(m1.submit(_f(BASE)).task_id, deadline=10.0)
    d1 = m1.submit_diff(_f(CUR), b.task_id)
    done = m1.wait_for(d1.task_id, deadline=10.0)
    assert done.status is TaskStatus.SUCCEEDED
    saved_hash = done.diff.diff_hash
    m1.shutdown()

    # 模拟重启：新管理器读同一数据库
    m2 = TaskManager(TaskStore(db), timeout_seconds=30.0, auto_recover=True)
    try:
        again = m2.submit_diff(_f(CUR), b.task_id)
        assert again.task_id == d1.task_id
        assert again.status is TaskStatus.SUCCEEDED
        assert again.diff.diff_hash == saved_hash
        print(f"[difftask] 对比结论跨重启复用 hash={saved_hash[:16]}")
    finally:
        m2.shutdown()


# --- 严重程度变化的真实提交 -> 审计 -> 对比链路 ---

SEV_BASE = """
contract Vault {
    function withdraw(address payable to, uint amount) public {
        to.send(amount);
    }
}
"""
SEV_CUR = """
contract Vault {
    function withdraw(address payable to, uint amount) public {
        to.call{value: amount}("");
    }
}
"""
# 严重程度降低的反向演进（带 value 的低层 call 未检查 -> send 未检查）
SEV_DOWN_CUR = """
contract Vault {
    function withdraw(address payable r, uint v) public {
        r.send(v);
    }
}
"""
SEV_DOWN_BASE = """
contract Vault {
    function withdraw(address payable r, uint v) public {
        r.call{value: v}("");
    }
}
"""
# 顶部插入无关合约、纯重命名、函数重排后的严重程度变化
SEV_MOVED_CUR = """
contract Helpers { function noop() public pure returns (uint) { return 1; } }

contract Wallet {
    mapping(address => uint) credit;
    function pay2(address payable who, uint sum) public {
        who.call{value: sum}("");
    }
    function drip(address x) public { x.send(9); }
}
"""
SEV_MOVED_BASE = """
contract Vault {
    mapping(address => uint) balances;
    function drip2(address y) public { y.send(9); }
    function withdraw(address payable to, uint amount) public {
        to.send(amount);
    }
}
"""


def _sev_diff(mgr, base_src, cur_src, name="Vault.sol"):
    b = _baseline(mgr, base_src, name)
    d = mgr.submit_diff(_f(cur_src, name), b.task_id)
    done = mgr.wait_for(d.task_id, deadline=10.0)
    return b, done


def test_severity_change_end_to_end(mgr):
    b, done = _sev_diff(mgr, SEV_BASE, SEV_CUR)
    assert done.status is TaskStatus.SUCCEEDED
    diff = done.diff
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["NEW"] == 0
    assert diff.counts["FIXED"] == 0
    assert diff.counts["PERSISTING"] == 0
    e = diff.entries[0]
    assert e.category.value == "SEVERITY_CHANGED"
    assert e.baseline_severity.name == "LOW"
    assert e.current_severity.name == "MEDIUM"
    assert e.baseline_finding.function == "withdraw"
    assert e.current_finding.function == "withdraw"
    assert diff.baseline_fingerprint == b.fingerprint
    print(f"[difftask] 真实链路严重程度升高 -> {diff.counts} "
          f"{e.baseline_severity.name}->{e.current_severity.name}")


def test_severity_decrease_end_to_end(mgr):
    b, done = _sev_diff(mgr, SEV_DOWN_BASE, SEV_DOWN_CUR)
    assert done.status is TaskStatus.SUCCEEDED
    diff = done.diff
    assert diff.counts["SEVERITY_CHANGED"] == 1
    e = [e for e in diff.entries if e.category.value == "SEVERITY_CHANGED"][0]
    assert e.baseline_severity.name == "MEDIUM"
    assert e.current_severity.name == "LOW"
    print("[difftask] 真实链路严重程度降低 MEDIUM->LOW")


def test_severity_change_moved_and_renamed_end_to_end(mgr):
    b, done = _sev_diff(mgr, SEV_MOVED_BASE, SEV_MOVED_CUR)
    assert done.status is TaskStatus.SUCCEEDED
    diff = done.diff
    assert diff.counts["SEVERITY_CHANGED"] == 1
    assert diff.counts["PERSISTING"] == 1
    assert diff.counts["NEW"] == 0 and diff.counts["FIXED"] == 0
    changed = [e for e in diff.entries
               if e.category.value == "SEVERITY_CHANGED"][0]
    assert changed.baseline_severity.name == "LOW"
    assert changed.current_severity.name == "MEDIUM"
    print("[difftask] 整体挪动+纯重命名+重排后真实链路仍判严重程度变化")


def test_severity_change_concurrent_and_restart_consistent(tmp_path):
    import threading

    db = str(tmp_path / "sev.db")
    m1 = TaskManager(TaskStore(db), timeout_seconds=30.0, auto_recover=False)
    b = m1.wait_for(m1.submit(_f(SEV_BASE)).task_id, deadline=10.0)
    assert b.status is TaskStatus.SUCCEEDED

    barrier = threading.Barrier(16)
    results = []

    def submit():
        barrier.wait()
        results.append(m1.submit_diff(_f(SEV_CUR), b.task_id))

    threads = [threading.Thread(target=submit) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r.task_id for r in results}
    assert len(ids) == 1
    done = m1.wait_for(ids.pop(), deadline=10.0)
    assert done.status is TaskStatus.SUCCEEDED
    saved = done.diff
    assert saved.counts["SEVERITY_CHANGED"] == 1
    snapshot = [
        (e.category.value, e.signature,
         e.baseline_severity.name if e.baseline_severity else None,
         e.current_severity.name if e.current_severity else None)
        for e in saved.entries
    ]
    m1.shutdown()

    # 重启后再查：任务复用，分类/条数/顺序/哈希全部一致
    m2 = TaskManager(TaskStore(db), timeout_seconds=30.0, auto_recover=True)
    try:
        again = m2.submit_diff(_f(SEV_CUR), b.task_id)
        assert again.task_id == done.task_id
        assert again.status is TaskStatus.SUCCEEDED
        assert again.diff.diff_hash == saved.diff_hash
        assert dict(again.diff.counts) == dict(saved.counts)
        again_snapshot = [
            (e.category.value, e.signature,
             e.baseline_severity.name if e.baseline_severity else None,
             e.current_severity.name if e.current_severity else None)
            for e in again.diff.entries
        ]
        assert again_snapshot == snapshot
    finally:
        m2.shutdown()
    print(f"[difftask] 严重程度变化并发/重启一致 hash={saved.diff_hash[:16]}")

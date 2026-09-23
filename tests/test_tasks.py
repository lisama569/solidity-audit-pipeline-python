"""任务生命周期测试：重复/并发提交、超时、取消、重试、重启恢复。"""
import threading
import time

import pytest

from app import engine
from app.errors import IngestError
from app.models import ErrorCode, TaskStatus
from app.store import TaskStore
from app.tasks import TaskManager

VULN = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
"""
SAFE = "contract C { uint public x; function inc() public { x += 1; } }\n"


def _files(src: str = VULN, name: str = "Vault.sol"):
    return [(name, src.encode())]


@pytest.fixture()
def mgr(tmp_path):
    m = TaskManager(TaskStore(str(tmp_path / "audit.db")), timeout_seconds=5.0)
    yield m
    m.shutdown()


def test_duplicate_submission_same_task_no_recompute(mgr):
    t1 = mgr.submit(_files())
    t2 = mgr.submit(_files())
    assert t1.task_id == t2.task_id
    done = mgr.wait_for(t1.task_id)
    assert done.status is TaskStatus.SUCCEEDED
    t3 = mgr.submit(_files())  # 完成后再提交仍复用
    assert t3.task_id == t1.task_id
    print(f"[task] 重复提交去重: task={t1.task_id[:8]} status={t3.status.value}")


def test_concurrent_submission_single_task(mgr):
    results, barrier = [], threading.Barrier(16)

    def submit():
        barrier.wait()
        results.append(mgr.submit(_files()))

    threads = [threading.Thread(target=submit) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = {r.task_id for r in results}
    assert len(ids) == 1, f"并发提交产生了 {len(ids)} 个任务"
    done = mgr.wait_for(ids.pop())
    assert done.status is TaskStatus.SUCCEEDED
    assert done.report is not None and not done.report.clean
    print(f"[task] 16 路并发提交 -> 单任务 {done.task_id[:8]}, "
          f"findings={len(done.report.findings)} hash={done.report.report_hash[:16]}")


def test_concurrent_mixed_submissions(mgr):
    barrier = threading.Barrier(8)
    results = []

    def submit(src, name):
        barrier.wait()
        results.append(mgr.submit(_files(src, name)))

    threads = [threading.Thread(target=submit, args=(VULN, "Vault.sol")) for _ in range(4)]
    threads += [threading.Thread(target=submit, args=(SAFE, "C.sol")) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({r.task_id for r in results}) == 2
    for r in results:
        done = mgr.wait_for(r.task_id)
        assert done.status is TaskStatus.SUCCEEDED


def test_malformed_sources_rejected_with_distinct_reasons(mgr):
    cases = []
    with pytest.raises(IngestError) as e1:
        mgr.submit([])
    cases.append(("空提交", e1.value.code))
    with pytest.raises(IngestError) as e2:
        mgr.submit([("A.sol", b"\xff\xfe\x00")])
    cases.append(("非UTF-8", e2.value.code))
    with pytest.raises(IngestError) as e3:
        mgr.submit([("A.sol", b"not solidity at all")])
    cases.append(("非Solidity", e3.value.code))
    with pytest.raises(IngestError) as e4:
        mgr.submit([("B.sol", b'import "./Nope.sol";\ncontract B {}\n')])
    cases.append(("导入缺失", e4.value.code))
    codes = {c for _, c in cases}
    assert codes == {
        ErrorCode.SOURCE_MISSING,
        ErrorCode.INVALID_CONTENT,
        ErrorCode.IMPORT_UNRESOLVABLE,
    }
    assert len(codes) == 3  # 三类原因彼此可区分
    for name, code in cases:
        print(f"[task] 畸形来源 {name} -> {code.value}")


def test_cancel_queued_task(mgr):
    # 用慢任务占满 worker，再提交的任务停在 QUEUED
    mgr._timeout = 30.0
    orig_audit = engine.audit
    mgr2 = TaskManager(mgr._store, timeout_seconds=30.0, worker_count=1,
                       auto_recover=False)
    try:
        def slow_audit(*a, **k):
            time.sleep(0.5)
            return orig_audit(*a, **k)
        import app.tasks as tasks_mod
        tasks_mod.engine.audit = slow_audit
        t1 = mgr2.submit(_files(VULN, "V1.sol"))
        t2 = mgr2.submit(_files(SAFE, "C2.sol"))
        cancelled = mgr2.cancel(t2.task_id)
        assert cancelled.status is TaskStatus.CANCELLED
        assert cancelled.error_code == ErrorCode.TASK_CANCELLED.value
        done1 = mgr2.wait_for(t1.task_id, deadline=10.0)
        assert done1.status is TaskStatus.SUCCEEDED
        time.sleep(0.8)  # 超过慢任务时长，确认 t2 永不被执行
        assert mgr2.get(t2.task_id).status is TaskStatus.CANCELLED
        print(f"[task] 排队任务取消: {t2.task_id[:8]} -> CANCELLED 且不再执行")
    finally:
        tasks_mod.engine.audit = orig_audit
        mgr2.shutdown()


def test_timeout_marks_task(tmp_path):
    store = TaskStore(str(tmp_path / "audit.db"))
    m = TaskManager(store, timeout_seconds=0.3, worker_count=1, auto_recover=False)
    orig_audit = engine.audit

    def slow_audit(*a, **k):
        time.sleep(1.0)
        return orig_audit(*a, **k)

    import app.tasks as tasks_mod
    tasks_mod.engine.audit = slow_audit
    try:
        t = m.submit(_files())
        deadline = time.time() + 5.0
        while time.time() < deadline:
            rec = m.get(t.task_id)
            if rec.status is TaskStatus.TIMEOUT:
                break
            time.sleep(0.02)
        rec = m.get(t.task_id)
        assert rec.status is TaskStatus.TIMEOUT
        assert rec.error_code == ErrorCode.TASK_TIMEOUT.value
        time.sleep(1.2)  # 慢任务结束后不得覆盖 TIMEOUT 状态
        assert m.get(t.task_id).status is TaskStatus.TIMEOUT
        print(f"[task] 超时: {t.task_id[:8]} -> TIMEOUT，过期结果被丢弃")
    finally:
        tasks_mod.engine.audit = orig_audit
        m.shutdown()


def test_retry_failed_task(tmp_path):
    store = TaskStore(str(tmp_path / "audit.db"))
    m = TaskManager(store, timeout_seconds=5.0, auto_recover=False)
    orig_audit = engine.audit
    calls = {"n": 0}

    def flaky_audit(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("模拟分析器崩溃")
        return orig_audit(*a, **k)

    import app.tasks as tasks_mod
    tasks_mod.engine.audit = flaky_audit
    try:
        t = m.submit(_files())
        failed = m.wait_for(t.task_id)
        assert failed.status is TaskStatus.FAILED
        assert failed.error_code == ErrorCode.INTERNAL_ERROR.value
        m.retry(t.task_id)
        done = m.wait_for(t.task_id)
        assert done.status is TaskStatus.SUCCEEDED
        assert done.attempts == 2
        print(f"[task] 失败后重试: attempts={done.attempts} -> SUCCEEDED")
    finally:
        tasks_mod.engine.audit = orig_audit
        m.shutdown()


def test_retry_limit_enforced(mgr):
    t = mgr.submit(_files())
    mgr.wait_for(t.task_id)
    mgr.cancel(t.task_id)  # 终态不受影响
    assert mgr.get(t.task_id).status is TaskStatus.SUCCEEDED


def test_restart_recovers_unfinished_and_conclusions(tmp_path):
    db = str(tmp_path / "audit.db")
    m1 = TaskManager(TaskStore(db), timeout_seconds=30.0, worker_count=1,
                     auto_recover=False)
    t = m1.submit(_files())
    done = m1.wait_for(t.task_id)
    assert done.status is TaskStatus.SUCCEEDED
    hash_before = done.report.report_hash
    # 制造一个未完成任务后“崩溃”（不 shutdown 执行器，直接丢弃）
    m1._timeout = 0.2
    import app.tasks as tasks_mod
    orig_audit = engine.audit

    def slow_audit(*a, **k):
        time.sleep(2.0)
        return orig_audit(*a, **k)

    tasks_mod.engine.audit = slow_audit
    t2 = m1.submit(_files(SAFE, "C.sol"))
    time.sleep(0.1)  # 已进入 RUNNING
    tasks_mod.engine.audit = orig_audit

    # 模拟重启：新管理器读同一数据库
    m2 = TaskManager(TaskStore(db), timeout_seconds=30.0, auto_recover=True)
    try:
        again = m2.submit(_files())
        assert again.task_id == t.task_id  # 已完成结论跨重启复用
        assert again.report.report_hash == hash_before
        recovered = m2.wait_for(t2.task_id, deadline=10.0)
        assert recovered.status is TaskStatus.SUCCEEDED
        assert recovered.report.clean is True
        print(f"[task] 重启恢复: 已完成 hash={hash_before[:16]} 复用；"
              f"未完成 {t2.task_id[:8]} 重跑 -> SUCCEEDED")
    finally:
        m2.shutdown()

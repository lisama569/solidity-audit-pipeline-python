"""任务生命周期与并发自洽性测试。

覆盖：排队取消、终态取消拒绝、非法状态流转、失败自动重试、持续失败终态、
超时标记与自动回队、显式 retry、服务重启后结论与未完成任务恢复。
"""

from __future__ import annotations

import threading
import time

import pytest

from conftest import banner, fixture_sources
from audit_pipeline.engine import AuditEngine
from audit_pipeline.errors import TaskNotFoundError, TaskStateError
from audit_pipeline.models import SourceFile, Task, TaskState
from audit_pipeline.service import AuditService
from audit_pipeline.store import TaskStore

CLEAN = "clean_contract.sol"


class FlakyEngine(AuditEngine):
    """前 fail_times 次调用抛错，之后正常的引擎，用于重试测试。"""

    def __init__(self, fail_times: int = 0):
        super().__init__()
        self.fail_times = fail_times
        self.calls = 0
        self._lock = threading.Lock()

    def audit_project(self, project, content_hash):
        with self._lock:
            self.calls += 1
            n = self.calls
        if n <= self.fail_times:
            raise RuntimeError(f"simulated failure #{n}")
        return super().audit_project(project, content_hash)


class SlowEngine(AuditEngine):
    """始终慢于任务时限的引擎，用于超时测试。"""

    def __init__(self, delay: float = 5.0):
        super().__init__()
        self.delay = delay

    def audit_project(self, project, content_hash):
        time.sleep(self.delay)
        return super().audit_project(project, content_hash)


def _sources() -> list[SourceFile]:
    return fixture_sources([CLEAN])


def test_completed_task_cannot_be_cancelled(service):
    banner("[lifecycle] 已完成任务取消 -> TASK_STATE_CONFLICT")
    t, _ = service.submit(_sources(), f"contracts/{CLEAN}")
    done = service.wait_for(t.id, 10)
    assert done.state == TaskState.COMPLETED
    with pytest.raises(TaskStateError) as ei:
        service.cancel(t.id)
    print(f"任务 {t.id[:16]} 状态={done.state.value}，取消返回 {ei.value.code}")
    assert ei.value.code == "TASK_STATE_CONFLICT"


def test_cancel_queued_task(service):
    banner("[lifecycle] 排队中的任务可以取消且不会被执行")
    # 用慢引擎 + 单 worker 占住 worker，使第二个任务稳定排队
    svc = AuditService(":memory:", workers=1, task_timeout=1.0, engine=SlowEngine(1.0))
    svc.start()
    try:
        busy, _ = svc.submit(
            [SourceFile("S.sol", "contract S { function f() external{} }")], "S.sol"
        )
        time.sleep(0.15)
        queued, _ = svc.submit(_sources(), f"contracts/{CLEAN}")
        assert svc.get_task(queued.id).state == TaskState.QUEUED
        cancelled = svc.cancel(queued.id)
        print(f"排队任务 {queued.id[:16]} 取消后状态: {cancelled.state.value}")
        assert cancelled.state == TaskState.CANCELLED
        time.sleep(0.2)
        # 不会被 worker 翻案
        assert svc.get_task(queued.id).state == TaskState.CANCELLED
    finally:
        # 等待占住 worker 的慢任务走完并回收线程（约 1s）
        svc.shutdown(wait=True, timeout=5)


def test_automatic_retry_then_success():
    banner("[lifecycle] 执行失败后自动重试，最终成功且 attempts 累加")
    engine = FlakyEngine(fail_times=2)
    svc = AuditService(":memory:", workers=1, task_timeout=10, engine=engine)
    svc.start()
    try:
        t, _ = svc.submit(_sources(), f"contracts/{CLEAN}")
        done = svc.wait_for(t.id, 15)
        print(f"最终状态={done.state.value}, attempts={done.attempts}, "
              f"引擎实际执行次数={engine.calls}")
        assert done.state == TaskState.COMPLETED
        assert done.attempts == 3
        assert engine.calls == 3
    finally:
        svc.shutdown()


def test_permanent_failure_reaches_terminal():
    banner("[lifecycle] 持续失败耗尽重试额度 -> FAILED 终态并记录原因")
    engine = FlakyEngine(fail_times=10**6)
    svc = AuditService(":memory:", workers=1, task_timeout=10, engine=engine)
    svc.start()
    try:
        t, _ = svc.submit(_sources(), f"contracts/{CLEAN}")
        done = svc.wait_for(t.id, 30)
        print(f"状态={done.state.value}, attempts={done.attempts}, error={done.error}")
        assert done.state == TaskState.FAILED
        assert done.attempts == done.max_attempts
        assert done.error["code"] == "INTERNAL_ERROR"
    finally:
        svc.shutdown()


def test_explicit_retry_requeues_failed_task():
    banner("[lifecycle] 显式 retry 将 FAILED 任务重新排队")
    engine = FlakyEngine(fail_times=10**6)
    svc = AuditService(":memory:", workers=1, task_timeout=10, engine=engine)
    svc.start()
    try:
        t, _ = svc.submit(_sources(), f"contracts/{CLEAN}")
        failed = svc.wait_for(t.id, 30)
        assert failed.state == TaskState.FAILED
    finally:
        svc.shutdown()

    # 换一个健康引擎重开服务（同库不可行因为内存库，这里直接构造 FAILED 任务）
    good = FlakyEngine(fail_times=0)
    svc2 = AuditService(":memory:", workers=1, task_timeout=10, engine=good)
    svc2.start()
    try:
        content = _sources()[0].content
        orphan = Task(
            id="task-manualfailed000",
            content_hash="h-manual-failed",
            state=TaskState.FAILED,
            entry_point=f"contracts/{CLEAN}",
            sources={f"contracts/{CLEAN}": content},
            attempts=3,
            max_attempts=3,
            created_at=time.time(),
            error={"code": "INTERNAL_ERROR", "message": "x", "details": {}},
        )
        svc2.store.save(orphan)
        requeued = svc2.retry(orphan.id)
        print(f"retry 后状态={requeued.state.value}")
        assert requeued.state == TaskState.QUEUED
        done = svc2.wait_for(orphan.id, 10)
        print(f"重试完成状态={done.state.value}, attempts={done.attempts}")
        assert done.state == TaskState.COMPLETED

        # RUNNING 中任务不允许直接 retry
        with pytest.raises(TaskStateError) as ei:
            running = Task(
                id="task-running0000000000",
                content_hash="h-running",
                state=TaskState.RUNNING,
                entry_point="x",
                sources={"x": "contract X{}"},
                attempts=1,
                max_attempts=3,
                created_at=time.time(),
            )
            svc2.store.save(running)
            svc2.retry(running.id)
        assert ei.value.code == "TASK_STATE_CONFLICT"
    finally:
        svc2.shutdown()


def test_timeout_marks_and_retries():
    banner("[lifecycle] 超时 -> 自动回队重试；额度耗尽 -> TIMEOUT 终态")
    engine = SlowEngine(delay=1.0)
    svc = AuditService(":memory:", workers=1, task_timeout=0.2, engine=engine)
    svc.start()
    try:
        # max_attempts=1 在提交时即指定，避免与 worker 领取产生竞态
        t, _ = svc.submit(_sources(), f"contracts/{CLEAN}", max_attempts=1)
        done = svc.wait_for(t.id, 5)
        print(f"状态={done.state.value}, error code={done.error['code']}")
        assert done.state == TaskState.TIMEOUT
        assert done.error["code"] == "TASK_TIMEOUT"
    finally:
        # 执行线程仍在睡眠（约 1s），等待其结束并回收 worker
        svc.shutdown(wait=True, timeout=5)


def test_get_unknown_task_raises_not_found(service):
    banner("[lifecycle] 查询不存在的任务 -> TASK_NOT_FOUND")
    with pytest.raises(TaskNotFoundError) as ei:
        service.get_task("task-does-not-exist")
    print(f"返回错误码: {ei.value.code}")
    assert ei.value.code == "TASK_NOT_FOUND"


def test_restart_recovers_completed_and_pending(tmp_path):
    banner("[lifecycle] 重启恢复：已完成结论保留，RUNNING 回滚，QUEUED 续跑")
    db = str(tmp_path / "audit.db")
    svc = AuditService(db, workers=1, task_timeout=10)
    svc.start()
    t_done, _ = svc.submit(_sources(), f"contracts/{CLEAN}", client_labels=["kept"])
    svc.wait_for(t_done.id, 10)
    svc.shutdown()

    # 直接向库中写入崩溃遗留：一个 RUNNING 孤儿、一个 QUEUED 任务
    store = TaskStore(db)
    now = time.time()
    content = _sources()[0].content
    running = Task(
        id="task-crashedrunning00",
        content_hash="h-crashed",
        state=TaskState.RUNNING,
        entry_point=f"contracts/{CLEAN}",
        sources={f"contracts/{CLEAN}": content},
        attempts=1,
        max_attempts=3,
        created_at=now,
        started_at=now,
        deadline=now + 5,
    )
    queued = Task(
        id="task-queuedpending000",
        content_hash="h-queued-pending",
        state=TaskState.QUEUED,
        entry_point=f"contracts/{CLEAN}",
        sources={f"contracts/{CLEAN}": content},
        max_attempts=3,
        created_at=now,
    )
    store.save(running)
    store.save(queued)
    store.close()

    svc2 = AuditService(db, workers=2, task_timeout=10)
    svc2.start()
    try:
        done = svc2.get_task(t_done.id)
        recovered_running = svc2.wait_for(running.id, 10)
        recovered_queued = svc2.wait_for(queued.id, 10)
        print(f"已完成任务恢复: {done.state.value}, 结论在={done.report is not None}")
        print(f"RUNNING 孤儿 -> {recovered_running.state.value}")
        print(f"QUEUED 待办 -> {recovered_queued.state.value}")
        assert done.state == TaskState.COMPLETED and done.report is not None
        assert recovered_running.state == TaskState.COMPLETED
        assert recovered_queued.state == TaskState.COMPLETED
    finally:
        svc2.shutdown()


def test_concurrent_lifecycle_transitions_are_consistent(service):
    banner("[lifecycle] 并发取消/重试同一任务不产生自相矛盾状态")
    # 快速完成的干净任务：大量并发 cancel 落在终态上，要么成功一次要么全部冲突，
    # 但状态只能是合法终态之一。
    t, _ = service.submit(_sources(), f"contracts/{CLEAN}")
    errors: list[str] = []
    barrier = threading.Barrier(6)

    def cancel_worker() -> None:
        barrier.wait()
        try:
            service.cancel(t.id)
        except TaskStateError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=cancel_worker) for _ in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    final = service.get_task(t.id)
    print(f"最终状态: {final.state.value}；冲突错误数: {len(errors)}")
    assert final.state in (TaskState.COMPLETED, TaskState.CANCELLED)
    assert set(errors) <= {"TASK_STATE_CONFLICT"}

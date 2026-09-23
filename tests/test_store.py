"""持久化测试：任务与结论跨“重启”（重建 TaskStore 实例）可恢复。"""
import time

from app.models import TaskRecord, TaskStatus
from app.store import TaskStore


def _record(task_id: str, status: TaskStatus) -> TaskRecord:
    now = time.time()
    return TaskRecord(task_id=task_id, fingerprint="fp-" + task_id, status=status,
                      created_at=now, updated_at=now)


def test_roundtrip_and_restart_recovery(tmp_path):
    db = str(tmp_path / "audit.db")
    store = TaskStore(db)
    store.upsert(_record("t-done", TaskStatus.SUCCEEDED))
    store.upsert(_record("t-queued", TaskStatus.QUEUED))
    store.upsert(_record("t-running", TaskStatus.RUNNING))

    # 模拟服务重启：全新实例读同一数据库
    store2 = TaskStore(db)
    assert store2.get("t-done").status is TaskStatus.SUCCEEDED
    unfinished = {r.task_id for r in store2.recover_unfinished()}
    assert unfinished == {"t-queued", "t-running"}
    print(f"[store] 重启恢复未完成任务: {sorted(unfinished)}")


def test_report_cache_survives_restart(tmp_path):
    from app.engine import audit
    from app.ingest import fingerprint, normalize_sources, resolve_imports
    from app.models import SourceFile

    db = str(tmp_path / "audit.db")
    sources = normalize_sources([SourceFile("C.sol", "contract C { uint x; }\n")])
    fp = fingerprint(sources)
    report = audit(fp, sources, resolve_imports(sources))

    TaskStore(db).save_report(fp, report)
    loaded = TaskStore(db).load_report(fp)
    assert loaded == report
    print(f"[store] 结论缓存跨重启一致: hash={loaded.report_hash[:16]}")


def test_get_by_fingerprint_dedup(tmp_path):
    db = str(tmp_path / "audit.db")
    store = TaskStore(db)
    rec = _record("t1", TaskStatus.QUEUED)
    store.upsert(rec)
    assert store.get_by_fingerprint("fp-t1").task_id == "t1"
    assert store.get_by_fingerprint("nope") is None

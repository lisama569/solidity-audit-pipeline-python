"""Solidity 静态审计流水线服务入口。

API：
- POST   /audits                          提交审计（multipart 文件列表），重复内容自动去重
- GET    /audits/{task_id}                查询任务状态与结论
- POST   /audits/{task_id}/cancel         取消排队/运行中的任务
- POST   /audits/{task_id}/retry          重试失败/超时/取消的任务
- POST   /comparisons                    指定基线提交新版本对比
- GET    /comparisons/{compare_id}        查询对比状态与分类结论
- POST   /comparisons/{compare_id}/cancel 取消排队/运行中的对比
- POST   /comparisons/{compare_id}/retry  重试失败/超时/取消的对比
"""
from __future__ import annotations

import os

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from app.comparisons import ComparisonManager, comparison_to_dict
from app.errors import IngestError
from app.store import TaskStore
from app.tasks import TaskManager, record_to_dict

app = FastAPI(title="Solidity Audit Pipeline")
manager: TaskManager | None = None
comparator: ComparisonManager | None = None


def get_manager() -> TaskManager:
    """惰性初始化，避免导入本模块时产生数据库文件副作用。"""
    global manager, comparator
    if manager is None:
        db_path = os.environ.get("AUDIT_DB_PATH", "audit.db")
        timeout = float(os.environ.get("AUDIT_TASK_TIMEOUT", "30"))
        store = TaskStore(db_path)
        manager = TaskManager(store, timeout_seconds=timeout)
        comparator = ComparisonManager(store, manager, timeout_seconds=timeout)
    return manager


def get_comparator() -> ComparisonManager:
    get_manager()
    assert comparator is not None
    return comparator


@app.on_event("startup")
def _startup() -> None:
    get_manager().recover()
    get_comparator().recover()


@app.on_event("shutdown")
def _shutdown() -> None:
    if comparator is not None:
        comparator.shutdown()
    if manager is not None:
        manager.shutdown()


@app.get("/")
def read_root() -> dict[str, str]:
    return {"service": "solidity-audit-pipeline"}


@app.post("/audits", status_code=202)
async def submit_audit(files: list[UploadFile] | None = File(default=None)) -> dict:
    """提交审计任务。相同内容重复提交返回同一任务（幂等）。"""
    payload = [(f.filename or "unnamed.sol", await f.read()) for f in (files or [])]
    try:
        record = get_manager().submit(payload)
    except IngestError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": exc.code.value, "detail": exc.detail},
        ) from exc
    return record_to_dict(record)


@app.get("/audits/{task_id}")
def get_audit(task_id: str) -> dict:
    record = get_manager().get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)


@app.post("/audits/{task_id}/cancel")
def cancel_audit(task_id: str) -> dict:
    record = get_manager().cancel(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)


@app.post("/audits/{task_id}/retry")
def retry_audit(task_id: str) -> dict:
    try:
        record = get_manager().retry(task_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)


@app.post("/comparisons", status_code=202)
async def submit_comparison(
    baseline_task_id: str = Form(...),
    files: list[UploadFile] | None = File(default=None),
) -> dict:
    """提交新版本相对基线的对比。相同 (新版本, 基线) 幂等。"""
    payload = [(f.filename or "unnamed.sol", await f.read()) for f in (files or [])]
    try:
        record = get_comparator().submit_compare(payload, baseline_task_id)
    except IngestError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": exc.code.value, "detail": exc.detail},
        ) from exc
    return comparison_to_dict(record)


@app.get("/comparisons/{compare_id}")
def get_comparison(compare_id: str) -> dict:
    record = get_comparator().get(compare_id)
    if record is None:
        raise HTTPException(status_code=404, detail="对比任务不存在")
    return comparison_to_dict(record)


@app.post("/comparisons/{compare_id}/cancel")
def cancel_comparison(compare_id: str) -> dict:
    record = get_comparator().cancel(compare_id)
    if record is None:
        raise HTTPException(status_code=404, detail="对比任务不存在")
    return comparison_to_dict(record)


@app.post("/comparisons/{compare_id}/retry")
def retry_comparison(compare_id: str) -> dict:
    try:
        record = get_comparator().retry(compare_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="对比任务不存在")
    return comparison_to_dict(record)

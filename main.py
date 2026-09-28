"""Solidity 静态审计流水线服务入口。

API：
- POST   /audits                          提交审计（multipart 文件列表），重复内容自动去重
- GET    /audits/{task_id}                查询任务状态与结论
- POST   /audits/{task_id}/cancel         取消排队/运行中的任务
- POST   /audits/{task_id}/retry          重试失败/超时/取消的任务
- POST   /audits/{task_id}/compare        以 {task_id} 为基线，提交新版本做版本对比
"""
from __future__ import annotations

import os

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.errors import BaselineError, IngestError
from app.store import TaskStore
from app.tasks import TaskManager, record_to_dict

app = FastAPI(title="Solidity Audit Pipeline")
manager: TaskManager | None = None


def get_manager() -> TaskManager:
    """惰性初始化，避免导入本模块时产生数据库文件副作用。"""
    global manager
    if manager is None:
        db_path = os.environ.get("AUDIT_DB_PATH", "audit.db")
        timeout = float(os.environ.get("AUDIT_TASK_TIMEOUT", "30"))
        manager = TaskManager(TaskStore(db_path), timeout_seconds=timeout)
    return manager


@app.on_event("startup")
def _startup() -> None:
    get_manager().recover()


@app.on_event("shutdown")
def _shutdown() -> None:
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


@app.post("/audits/{task_id}/compare", status_code=202)
async def compare_audit(
    task_id: str,
    files: list[UploadFile] | None = File(default=None),
) -> dict:
    """以已完成的历史审计 {task_id} 为基线，提交新版本做版本对比。

    基线不存在/未完成/与当前提交对不上时返回 400，error_code 分别为
    BASELINE_NOT_FOUND / BASELINE_NOT_READY / BASELINE_UNRELATED，
    绝不降级为普通单版本审计。
    """
    payload = [(f.filename or "unnamed.sol", await f.read()) for f in (files or [])]
    manager = get_manager()
    try:
        record = manager.submit_diff(payload, task_id)
    except BaselineError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": exc.code.value, "detail": exc.detail},
        ) from exc
    except IngestError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": exc.code.value, "detail": exc.detail},
        ) from exc
    return record_to_dict(record)

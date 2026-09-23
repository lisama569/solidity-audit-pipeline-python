"""Solidity 静态审计流水线服务入口。

API：
- POST   /audits                 提交审计（multipart 文件列表），重复内容自动去重
- GET    /audits/{task_id}       查询任务状态与结论
- POST   /audits/{task_id}/cancel  取消排队/运行中的任务
- POST   /audits/{task_id}/retry   重试失败/超时/取消的任务
"""
from __future__ import annotations

import os

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.errors import IngestError
from app.store import TaskStore
from app.tasks import TaskManager, record_to_dict

DB_PATH = os.environ.get("AUDIT_DB_PATH", "audit.db")
TIMEOUT = float(os.environ.get("AUDIT_TASK_TIMEOUT", "30"))

store = TaskStore(DB_PATH)
manager = TaskManager(store, timeout_seconds=TIMEOUT)

app = FastAPI(title="Solidity Audit Pipeline")


@app.on_event("startup")
def _startup() -> None:
    manager.recover()


@app.on_event("shutdown")
def _shutdown() -> None:
    manager.shutdown()


@app.get("/")
def read_root() -> dict[str, str]:
    return {"service": "solidity-audit-pipeline"}


@app.post("/audits", status_code=202)
async def submit_audit(files: list[UploadFile] | None = File(default=None)) -> dict:
    """提交审计任务。相同内容重复提交返回同一任务（幂等）。"""
    payload = [(f.filename or "unnamed.sol", await f.read()) for f in (files or [])]
    try:
        record = manager.submit(payload)
    except IngestError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": exc.code.value, "detail": exc.detail},
        ) from exc
    return record_to_dict(record)


@app.get("/audits/{task_id}")
def get_audit(task_id: str) -> dict:
    record = manager.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)


@app.post("/audits/{task_id}/cancel")
def cancel_audit(task_id: str) -> dict:
    record = manager.cancel(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)


@app.post("/audits/{task_id}/retry")
def retry_audit(task_id: str) -> dict:
    try:
        record = manager.retry(task_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if record is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return record_to_dict(record)

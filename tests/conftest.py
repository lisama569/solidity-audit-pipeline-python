"""pytest 公共夹具与辅助。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_pipeline.models import SourceFile  # noqa: E402
from audit_pipeline.service import AuditService  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def fixture_sources(names: list[str]) -> list[SourceFile]:
    """以给定顺序读取 fixture 为 SourceFile 列表。"""
    return [SourceFile(path=f"contracts/{n}", content=read_fixture(n)) for n in names]


@pytest.fixture
def service():
    """每个测试独立的内存库服务，测试结束等待 worker 干净退出。"""
    svc = AuditService(":memory:", workers=3, task_timeout=10.0)
    svc.start()
    try:
        yield svc
    finally:
        # 必须等待 worker 退出，避免上一个用例的守护线程残留并影响后续用例
        svc.shutdown(wait=True, timeout=5)


def banner(title: str) -> None:
    """在测试输出中打印醒目的输入标识与判定依据分隔。"""
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)

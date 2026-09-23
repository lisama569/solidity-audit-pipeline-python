"""审计引擎：执行规则、合并去重、生成稳定结论。"""
from __future__ import annotations

from app.models import AuditReport
from app.rules import RawHit


def merge_hits(hits: list[RawHit]) -> AuditReport:
    """合并同一问题的多规则命中，生成稳定排序与编号的结论。"""
    raise NotImplementedError


def audit(fingerprint_str: str, sources: dict[str, str], ordered_paths: list[str]) -> AuditReport:
    """完整审计流程：运行规则并归一结论。"""
    raise NotImplementedError

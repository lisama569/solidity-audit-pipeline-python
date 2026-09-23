"""基于规则的漏洞识别：重入、危险外部调用。"""
from __future__ import annotations

from dataclasses import dataclass

from app.models import Severity


@dataclass(frozen=True)
class RawHit:
    """单条规则的原始命中（尚未归一）。"""

    rule_id: str
    severity: Severity
    file: str
    line: int
    contract: str
    function: str
    message: str


RULE_REENTRANCY = "REENTRANCY"
RULE_DANGEROUS_CALL = "DANGEROUS_EXTERNAL_CALL"


def run_rules(sources: dict[str, str], ordered_paths: list[str]) -> list[RawHit]:
    """对归一后的来源运行全部规则，返回原始命中列表。"""
    raise NotImplementedError

"""审计引擎：执行规则、合并去重、生成稳定可复现的结论。

可复现性保证：
- 同一问题（file, line, contract, function）被多条规则命中时合并为一条 Finding；
- finding_id 由位置与规则集合的内容哈希派生，与运行次数、提交顺序无关；
- findings 按 (severity 降序, file, line, finding_id) 稳定排序；
- report_hash 覆盖全部结论内容，可用于跨次运行的一致性校验。
"""
from __future__ import annotations

import hashlib

from app.models import AuditReport, Finding, IssueRef, Severity
from app.rules import RawHit, run_rules


def _finding_id(file: str, line: int, contract: str, function: str,
                rule_ids: tuple[str, ...]) -> str:
    h = hashlib.sha256()
    for part in (file, str(line), contract, function, ",".join(rule_ids)):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "F-" + h.hexdigest()[:12]


def merge_hits(hits: list[RawHit], fingerprint_str: str = "") -> AuditReport:
    """合并同一问题的多规则命中，生成稳定排序与编号的结论。"""
    groups: dict[tuple[str, int, str, str], list[RawHit]] = {}
    for hit in hits:
        key = (hit.file, hit.line, hit.contract, hit.function)
        groups.setdefault(key, []).append(hit)

    findings: list[Finding] = []
    for (file, line, contract, function), group in groups.items():
        rule_ids = tuple(sorted({h.rule_id for h in group}))
        severity = Severity(max(h.severity for h in group))
        message = "；".join(h.message for h in sorted(group, key=lambda h: h.rule_id))
        # 同一 (规则, 问题身份) 可能因多处调用产生多条命中，取最高严重度后去重
        issue_map: dict[tuple[str, str], Severity] = {}
        for h in group:
            if not h.issue_key:
                continue
            k = (h.rule_id, h.issue_key)
            prev = issue_map.get(k)
            if prev is None or int(h.severity) > int(prev):
                issue_map[k] = h.severity
        issues = tuple(
            IssueRef(rule_id=r, issue_key=k, severity=s)
            for (r, k), s in sorted(issue_map.items())
        )
        findings.append(
            Finding(
                finding_id=_finding_id(file, line, contract, function, rule_ids),
                rule_ids=rule_ids,
                severity=severity,
                file=file,
                line=line,
                contract=contract,
                function=function,
                message=message,
                issues=issues,
            )
        )

    findings.sort(key=lambda f: (-int(f.severity), f.file, f.line, f.finding_id))

    h = hashlib.sha256()
    for f in findings:
        h.update(
            "|".join(
                [f.finding_id, ",".join(f.rule_ids), str(int(f.severity)),
                 f.file, str(f.line), f.contract, f.function, f.message]
            ).encode("utf-8")
        )
        h.update(b"\x00")

    return AuditReport(
        fingerprint=fingerprint_str,
        findings=tuple(findings),
        clean=not findings,
        report_hash=h.hexdigest(),
    )


def audit(fingerprint_str: str, sources: dict[str, str],
          ordered_paths: list[str]) -> AuditReport:
    """完整审计流程：运行规则并归一结论。"""
    return merge_hits(run_rules(sources, ordered_paths), fingerprint_str)

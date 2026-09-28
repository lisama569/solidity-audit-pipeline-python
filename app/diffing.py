"""版本对比：把基线与新版本两份 AuditReport 按问题稳定身份匹配并分类。

纯函数模块，不做 IO：输出只由两份报告内容决定，与提交次数、并发时序、
执行先后完全无关。匹配粒度为「单条规则视角下的问题」（IssueRef），
issue_key 由规则层从问题代码结构计算，对代码整体挪动、纯重命名、纯注释
变化保持稳定；只有问题实质变化时才会落入新增/已修复/严重度变化。

多重集语义：同一 (rule_id, issue_key) 出现多次时按稳定顺序第 N 个配对，
同一条问题不会同时被记成新增与已修复。
"""
from __future__ import annotations

import hashlib
from collections import Counter

from app.models import (
    AuditReport,
    ComparisonReport,
    DeltaCategory,
    Finding,
    FindingDelta,
    FindingSide,
    IssueRef,
)

# 稳定排序的类别优先级
_CATEGORY_ORDER = {
    DeltaCategory.NEW: 0,
    DeltaCategory.FIXED: 1,
    DeltaCategory.SEVERITY_CHANGED: 2,
    DeltaCategory.PERSISTENT: 3,
}


def _finding_sort_key(f: Finding):
    return (-int(f.severity), f.file, f.line, f.finding_id)


def _side(f: Finding) -> FindingSide:
    return FindingSide(
        finding_id=f.finding_id,
        severity=f.severity,
        file=f.file,
        line=f.line,
        contract=f.contract,
        function=f.function,
        message=f.message,
    )


def _instances(
    report: AuditReport,
) -> dict[tuple[str, str], list[tuple[IssueRef, Finding]]]:
    """展开为 {身份: 按 Finding 稳定排序的 (IssueRef, Finding) 列表}。"""
    out: dict[tuple[str, str], list[tuple[IssueRef, Finding]]] = {}
    for f in sorted(report.findings, key=_finding_sort_key):
        for ref in f.issues:
            out.setdefault((ref.rule_id, ref.issue_key), []).append((ref, f))
    return out


def _delta_id(
    category: DeltaCategory,
    rule_id: str,
    issue_key: str,
    baseline_fid: str | None,
    current_fid: str | None,
    index: int,
) -> str:
    h = hashlib.sha256()
    for part in (
        category.value, rule_id, issue_key,
        baseline_fid or "", current_fid or "", str(index),
    ):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "D-" + h.hexdigest()[:12]


def compare_reports(
    *,
    baseline: AuditReport,
    current: AuditReport,
    baseline_task_id: str,
    current_task_id: str,
) -> ComparisonReport:
    """对比两份审计结论，返回稳定编号、稳定排序、带分类统计的对比结果。"""
    base_inst = _instances(baseline)
    cur_inst = _instances(current)

    raw: list[tuple] = []  # (类别, 规则, key, 基线sev, 新版sev, 基线f, 新版f)

    for key in sorted(set(base_inst) | set(cur_inst)):
        blist = base_inst.get(key, [])
        clist = cur_inst.get(key, [])
        rule_id, issue_key = key
        pairs = max(len(blist), len(clist))
        for i in range(pairs):
            b = blist[i] if i < len(blist) else None
            c = clist[i] if i < len(clist) else None
            bref, bf = b if b else (None, None)
            cref, cf = c if c else (None, None)
            if b is not None and c is not None:
                if int(bref.severity) == int(cref.severity):
                    cat = DeltaCategory.PERSISTENT
                else:
                    cat = DeltaCategory.SEVERITY_CHANGED
                raw.append((cat, rule_id, issue_key,
                            bref.severity, cref.severity, bf, cf))
            elif b is not None:
                raw.append((DeltaCategory.FIXED, rule_id, issue_key,
                            bref.severity, None, bf, None))
            else:
                raw.append((DeltaCategory.NEW, rule_id, issue_key,
                            None, cref.severity, None, cf))

    # 稳定排序：类别 -> 严重度(取该侧可用值降序) -> 文件 -> 行 -> 规则 -> key
    def sort_key(item):
        cat, rule_id, issue_key, bsev, csev, bf, cf = item
        sev = csev if csev is not None else bsev
        anchor = cf if cf is not None else bf
        return (
            _CATEGORY_ORDER[cat],
            -int(sev),
            anchor.file,
            anchor.line,
            rule_id,
            issue_key,
        )

    raw.sort(key=sort_key)

    counts = {c.value: 0 for c in DeltaCategory}
    deltas: list[FindingDelta] = []
    seen: Counter = Counter()
    for (cat, rule_id, issue_key, bsev, csev, bf, cf) in raw:
        counts[cat.value] += 1
        index = seen[(rule_id, issue_key)]
        seen[(rule_id, issue_key)] += 1
        deltas.append(
            FindingDelta(
                delta_id=_delta_id(
                    cat, rule_id, issue_key,
                    bf.finding_id if bf else None,
                    cf.finding_id if cf else None,
                    index,
                ),
                category=cat,
                rule_id=rule_id,
                issue_key=issue_key,
                baseline_severity=bsev,
                current_severity=csev,
                baseline=_side(bf) if bf else None,
                current=_side(cf) if cf else None,
            )
        )

    h = hashlib.sha256()
    # 哈希只依赖两份报告内容与分类结果，不含运行时生成的任务 id，
    # 因此同一对 (基线报告, 新版本报告) 无论何种提交/并发时序，哈希恒等。
    h.update(baseline.fingerprint.encode())
    h.update(b"\x00")
    h.update(current.fingerprint.encode())
    h.update(b"\x00")
    for dl in deltas:
        h.update(
            "|".join(
                [
                    dl.category.value,
                    dl.rule_id,
                    dl.issue_key,
                    str(int(dl.baseline_severity)) if dl.baseline_severity is not None else "",
                    str(int(dl.current_severity)) if dl.current_severity is not None else "",
                ]
            ).encode("utf-8")
        )
        h.update(b"\x00")

    return ComparisonReport(
        baseline_task_id=baseline_task_id,
        current_task_id=current_task_id,
        baseline_fingerprint=baseline.fingerprint,
        current_fingerprint=current.fingerprint,
        baseline_report_hash=baseline.report_hash,
        current_report_hash=current.report_hash,
        deltas=tuple(deltas),
        counts=counts,
        comparison_hash=h.hexdigest(),
    )

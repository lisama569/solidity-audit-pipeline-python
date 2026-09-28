"""版本对比：跨版本稳定问题匹配与差异分类（新增/已修复/仍存在/严重度变化）。

可复现性保证：
- 匹配签名只依赖问题实质（站点稳定签名 + 命中规则集合），与行号、函数/合约
  顺序、整体位移、标识符命名、注释无关；
- 同签名按多重集确定性配对（按严重程度/位置稳定键排序后逐对配对），
  配对与分类只依赖两份报告内容本身；
- 结论按 (分类, 签名) 稳定排序并整体计算 diff_hash，
  重复/并发/乱序提交、先跑哪一边，结论都完全一致。
"""
from __future__ import annotations

import hashlib

from app.models import (
    AuditReport,
    DiffCategory,
    DiffEntry,
    DiffReport,
    Finding,
)

# (file, contract, function, line) -> 站点稳定签名
SiteSignatureMap = dict[tuple[str, str, str, int], str]

# 分类展示与排序顺序
_CATEGORY_ORDER = (
    DiffCategory.NEW,
    DiffCategory.FIXED,
    DiffCategory.PERSISTING,
    DiffCategory.SEVERITY_CHANGED,
)


def compute_site_signatures(
    sources: dict[str, str], ordered_paths: list[str]
) -> SiteSignatureMap:
    """委托 rules 层为外部调用站点计算跨版本稳定签名。"""
    from app.rules import compute_site_signatures as _impl

    return _impl(sources, ordered_paths)


def _finding_signature(f: Finding, site_sigs: SiteSignatureMap) -> str:
    """单条结论的匹配签名 = 站点实质签名 + 命中规则集合。

    规则集合纳入签名：问题命中面（规则组合）变化属于实质变化；
    严重程度不纳入签名，这样同问题严重度升降会被识别为 SEVERITY_CHANGED。
    """
    site = site_sigs.get((f.file, f.contract, f.function, f.line))
    if site is None:
        # 理论上不应发生（签名与结论由同一份源码生成）；退化为位置键，
        # 保证流程不中断，且仍然确定。
        h = hashlib.sha256()
        h.update(b"pos\x00")
        for part in (f.file, f.contract, f.function, str(f.line)):
            h.update(part.encode("utf-8"))
            h.update(b"\x00")
        site = "S-" + h.hexdigest()[:14]
    h = hashlib.sha256()
    h.update(site.encode("utf-8"))
    h.update(b"\x00")
    h.update(",".join(f.rule_ids).encode("utf-8"))
    return "M-" + h.hexdigest()[:14]


def _finding_sort_key(f: Finding):
    return (-int(f.severity), f.file, f.line, f.finding_id)


def _index_by_signature(
    report: AuditReport, site_sigs: SiteSignatureMap
) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {}
    for f in report.findings:
        sig = _finding_signature(f, site_sigs)
        groups.setdefault(sig, []).append(f)
    for sig in groups:
        groups[sig].sort(key=_finding_sort_key)
    return groups


def compare_reports(
    current: AuditReport,
    baseline: AuditReport,
    baseline_task_id: str,
    current_sigs: SiteSignatureMap,
    baseline_sigs: SiteSignatureMap,
) -> DiffReport:
    """对比两份审计结论，产出稳定分类与统计的 DiffReport。"""
    cur_groups = _index_by_signature(current, current_sigs)
    base_groups = _index_by_signature(baseline, baseline_sigs)

    entries: list[DiffEntry] = []
    all_sigs = sorted(set(cur_groups) | set(base_groups))
    for sig in all_sigs:
        cur_list = cur_groups.get(sig, [])
        base_list = base_groups.get(sig, [])
        paired = min(len(cur_list), len(base_list))
        for i in range(paired):
            b, c = base_list[i], cur_list[i]
            if c.severity is b.severity:
                category = DiffCategory.PERSISTING
            else:
                category = DiffCategory.SEVERITY_CHANGED
            entries.append(
                DiffEntry(
                    category=category,
                    signature=sig,
                    rule_ids=c.rule_ids,
                    baseline_finding=b,
                    current_finding=c,
                    baseline_severity=b.severity,
                    current_severity=c.severity,
                )
            )
        # 同签名多重集多出的基线侧 -> 已修复
        for b in base_list[paired:]:
            entries.append(
                DiffEntry(
                    category=DiffCategory.FIXED,
                    signature=sig,
                    rule_ids=b.rule_ids,
                    baseline_finding=b,
                    current_finding=None,
                    baseline_severity=b.severity,
                    current_severity=None,
                )
            )
        # 同签名多重集多出的新版本侧 -> 新增
        for c in cur_list[paired:]:
            entries.append(
                DiffEntry(
                    category=DiffCategory.NEW,
                    signature=sig,
                    rule_ids=c.rule_ids,
                    baseline_finding=None,
                    current_finding=c,
                    baseline_severity=None,
                    current_severity=c.severity,
                )
            )

    category_rank = {cat: i for i, cat in enumerate(_CATEGORY_ORDER)}

    def entry_key(e: DiffEntry):
        side = e.current_finding or e.baseline_finding
        # side 必不为 None（FIXED 有基线侧，其余至少有新版本侧）
        f: Finding = side  # type: ignore[assignment]
        return (
            category_rank[e.category],
            e.signature,
            -int(f.severity),
            f.file,
            f.line,
            f.finding_id,
        )

    entries.sort(key=entry_key)

    counts = {cat.value: 0 for cat in _CATEGORY_ORDER}
    for e in entries:
        counts[e.category.value] += 1
    counts["total"] = len(entries)

    pair_id = hashlib.sha256()
    pair_id.update(current.fingerprint.encode("utf-8"))
    pair_id.update(b"\x00")
    pair_id.update(baseline.fingerprint.encode("utf-8"))
    diff_id = "D-" + pair_id.hexdigest()[:16]

    h = hashlib.sha256()
    h.update(current.fingerprint.encode("utf-8"))
    h.update(b"\x00")
    h.update(baseline.fingerprint.encode("utf-8"))
    h.update(b"\x00")
    h.update(current.report_hash.encode("utf-8"))
    h.update(b"\x00")
    h.update(baseline.report_hash.encode("utf-8"))
    h.update(b"\x00")
    for e in entries:
        h.update(e.category.value.encode("utf-8"))
        h.update(b"\x00")
        h.update(e.signature.encode("utf-8"))
        h.update(b"\x00")
        h.update(",".join(e.rule_ids).encode("utf-8"))
        h.update(b"\x00")
        bs = int(e.baseline_severity) if e.baseline_severity is not None else -1
        cs = int(e.current_severity) if e.current_severity is not None else -1
        h.update(f"{bs}:{cs}".encode("utf-8"))
        h.update(b"\x00")

    return DiffReport(
        diff_id=diff_id,
        current_fingerprint=current.fingerprint,
        baseline_fingerprint=baseline.fingerprint,
        baseline_task_id=baseline_task_id,
        current_report_hash=current.report_hash,
        baseline_report_hash=baseline.report_hash,
        entries=tuple(entries),
        counts=counts,
        diff_hash=h.hexdigest(),
    )

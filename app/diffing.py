"""版本对比：跨版本稳定问题匹配与差异分类（新增/已修复/仍存在/严重度变化）。

可复现性保证：
- 匹配签名只依赖问题实质（站点稳定签名 + 命中规则集合），与行号、函数/合约
  顺序、整体位移、标识符命名、注释无关；站点签名在规则层把外部调用原语
  （send/call/...）及其选项/参数统一抹掉，因此"同一处调用仅原语改变
  （严重程度随之升降）"仍是同一站点，会被识别为 SEVERITY_CHANGED；
- 同签名组内先按严重程度桶配 PERSISTING，两侧剩余**数量相等**时才逐对
  判为 SEVERITY_CHANGED；数量失衡（旧问题删除、旁边又冒出同形新问题）时
  保守记为 FIXED/NEW，绝不硬并；
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
    Severity,
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


def _group_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    """把同签名组内的结论按严重程度分桶，桶内保持稳定排序。"""
    buckets: dict[Severity, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(f.severity, []).append(f)
    for bucket in buckets.values():
        bucket.sort(key=_finding_sort_key)
    return buckets


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

        # 同签名组内配对分两步：
        # 1) 严重程度相同的先配成 PERSISTING（多重集按稳定键逐对）；
        # 2) 两侧剩余项数量相等时才逐对配成 SEVERITY_CHANGED；数量不等说明该
        #    签名组发生了删除/新增（如旧问题删掉、旁边又冒出一个同形新问题），
        #    此时保守地记为 FIXED/NEW，绝不硬并成严重程度变化。
        cur_by_sev = _group_by_severity(cur_list)
        base_by_sev = _group_by_severity(base_list)
        leftover_cur: list[Finding] = []
        leftover_base: list[Finding] = []
        for sev in sorted(set(cur_by_sev) | set(base_by_sev)):
            cs = cur_by_sev.get(sev, [])
            bs = base_by_sev.get(sev, [])
            same = min(len(cs), len(bs))
            for i in range(same):
                b, c = bs[i], cs[i]
                entries.append(
                    DiffEntry(
                        category=DiffCategory.PERSISTING,
                        signature=sig,
                        rule_ids=c.rule_ids,
                        baseline_finding=b,
                        current_finding=c,
                        baseline_severity=b.severity,
                        current_severity=c.severity,
                    )
                )
            leftover_base.extend(bs[same:])
            leftover_cur.extend(cs[same:])

        leftover_cur.sort(key=_finding_sort_key)
        leftover_base.sort(key=_finding_sort_key)
        if len(leftover_cur) == len(leftover_base):
            for b, c in zip(leftover_base, leftover_cur):
                entries.append(
                    DiffEntry(
                        category=DiffCategory.SEVERITY_CHANGED,
                        signature=sig,
                        rule_ids=c.rule_ids,
                        baseline_finding=b,
                        current_finding=c,
                        baseline_severity=b.severity,
                        current_severity=c.severity,
                    )
                )
        else:
            # 数量失衡：两侧剩余都不强行配对，保守按删除/新增处理
            for b in leftover_base:
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
            for c in leftover_cur:
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

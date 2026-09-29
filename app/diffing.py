"""版本对比：跨版本稳定问题匹配与差异分类（新增/已修复/仍存在/严重度变化）。

可复现性保证：
- 站点身份与问题实质匹配，与行号、函数/合约顺序、整体位移、标识符命名、
  注释无关；外部调用的转账形态（send/transfer(x) 与 call{value:x}(...)）
  是同一站点的不同写法，操作符是严重程度的判定因素而刻意不属于站点身份，
  因此同一站点 send->call 这类严重度升降会被识别为 SEVERITY_CHANGED，
  而不是拆成「新增 + 已修复」；
- 匹配分两阶段：
  1) 原位配对：结构槽位（合约分组 + 函数序号 + 调用序号）相同、命中规则
     集合相同、且函数体规范化文本一致的结论直接配对；
  2) 重排/位移兜底：剩余结论在同一合约分组内，按规范化函数体与规则集合
     汇集候选，做最小位移一一匹配（同槽位优先、序号距离最近优先），
     覆盖前置插入/删除函数导致的序号位移与函数重排；若某结论的原槽位在
     另一侧被函数体已变且不再产出结论的调用站点占据（原地修复证据），
     则不参与跨槽位配对，避免与旁边新增的不同问题硬合并；
- 配对与分类只依赖两份报告内容本身；结论按 (分类, 签名等稳定键) 排序并
  整体计算 diff_hash，重复/并发/乱序提交、先跑哪一边，结论都完全一致。
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

# (file, contract, function, line) -> 站点身份信息
SiteSignatureMap = dict[tuple[str, str, str, int], "SiteInfo"]

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
    """委托 rules 层为外部调用站点计算跨版本身份信息。"""
    from app.rules import compute_site_signatures as _impl

    return _impl(sources, ordered_paths)


def _finding_sort_key(f: Finding):
    return (-int(f.severity), f.file, f.line, f.finding_id)


def _pos_key(f: Finding) -> tuple[str, str, str, int]:
    return (f.file, f.contract, f.function, f.line)


def _match_rule_signature(rule_ids: tuple[str, ...]) -> str:
    """问题实质的规则面签名：命中规则集合（去重排序后）。"""
    return ",".join(rule_ids)


def _pair_signature(sig_b: str, sig_c: str) -> str:
    """配对条目的展示签名：取两侧站点稳定签名的确定性组合。"""
    lo, hi = sorted((sig_b, sig_c))
    h = hashlib.sha256()
    h.update(lo.encode("utf-8"))
    h.update(b"\x00")
    h.update(hi.encode("utf-8"))
    return "M-" + h.hexdigest()[:14]


def _index_findings(
    report: AuditReport, site_infos: SiteSignatureMap
):
    """把结论与全部调用站点按身份信息建索引。

    返回 (by_ordinal, items, ordinal_sites)：
    - by_ordinal:    (ordinal_key, 规则集合) -> 排序后的 Finding 列表
    - items:         Finding -> SiteInfo（缺站点信息时使用确定性退化信息）
    - ordinal_sites: ordinal_key -> SiteInfo（**全部**外部调用站点，
                     含已被修复、不再产出结论的站点，作为"原地修复"证据）
    """
    from app.rules import SiteInfo

    by_ordinal: dict[tuple[str, str], list[Finding]] = {}
    items: dict[Finding, SiteInfo] = {}
    ordinal_sites: dict[str, SiteInfo] = {}

    for info in site_infos.values():
        ordinal_sites[info.ordinal_key] = info

    for f in report.findings:
        info = site_infos.get(_pos_key(f))
        if info is None:
            # 理论上不应发生（站点信息与结论由同一份源码生成）；退化为
            # 仅依赖位置的确定性键，保证流程不中断。
            h = hashlib.sha256()
            h.update(b"pos\x00")
            for part in (f.file, f.contract, f.function, str(f.line)):
                h.update(part.encode("utf-8"))
                h.update(b"\x00")
            digest = h.hexdigest()[:14]
            info = SiteInfo(
                group_key="G-" + digest,
                ordinal_key="O-" + digest,
                function_ordinal=0,
                call_ordinal=1,
                body_canon="B-" + digest,
                stable_sig="S-" + digest,
            )
        items[f] = info
        rule_sig = _match_rule_signature(f.rule_ids)
        by_ordinal.setdefault((info.ordinal_key, rule_sig), []).append(f)

    for lst in by_ordinal.values():
        lst.sort(key=_finding_sort_key)
    return by_ordinal, items, ordinal_sites


def _make_entry(
    category: DiffCategory,
    signature: str,
    b: Finding | None,
    c: Finding | None,
) -> DiffEntry:
    rule_ids = c.rule_ids if c is not None else b.rule_ids
    return DiffEntry(
        category=category,
        signature=signature,
        rule_ids=rule_ids,
        baseline_finding=b,
        current_finding=c,
        baseline_severity=b.severity if b is not None else None,
        current_severity=c.severity if c is not None else None,
    )


def compare_reports(
    current: AuditReport,
    baseline: AuditReport,
    baseline_task_id: str,
    current_sigs: SiteSignatureMap,
    baseline_sigs: SiteSignatureMap,
) -> DiffReport:
    """对比两份审计结论，产出稳定分类与统计的 DiffReport。"""
    cur_ordinal, cur_items, cur_sites = _index_findings(current, current_sigs)
    base_ordinal, base_items, base_sites = _index_findings(baseline, baseline_sigs)

    paired_b: set[Finding] = set()
    paired_c: set[Finding] = set()
    pairs: list[tuple[Finding, Finding]] = []

    def _take_pair(b: Finding, c: Finding) -> None:
        paired_b.add(b)
        paired_c.add(c)
        pairs.append((b, c))

    # 阶段 1：原位（同一结构槽位）配对。要求 ordinal_key 与规则集合相同，
    # 且两边函数体规范化文本一致——这保证「原问题删除、同槽位被另一个问题
    # 占据」不会在这里被错误合并。send(amount) -> call{value:amount}("")
    # 这类操作符演进因函数体规范化结果一致，也在本阶段配对并识别为严重
    # 程度变化。
    for okey in sorted(set(cur_ordinal) & set(base_ordinal)):
        cur_list = cur_ordinal[okey]
        base_list = base_ordinal[okey]
        for c, b in zip(cur_list, base_list):
            if cur_items[c].body_canon != base_items[b].body_canon:
                continue
            _take_pair(b, c)

    # 阶段 2：重排/位移兜底。对阶段 1 未配上的结论，在同一合约分组内按
    # (body_canon, 规则集合) 汇集候选，并做**最小位移**一一匹配：
    # 优先把结构槽位相同（函数序号/调用序号一致）的候选配在一起，再按
    # 序号距离从近到远配对。这样当多个站点规范化后函数体恰好相同（例如
    # 多个函数里都只有一句 send(1)）时，也会优先把序号最近的结论配在
    # 一起——同槽位的严重度变化永远胜出，不会错配到远处的站点。
    #
    # 防误合并条件（两侧对称，基于"全部外部调用站点"的槽位占用情况）：
    # 若候选的原结构槽位在另一侧仍存在外部调用站点、该站点函数体已变且
    # 不产出任何结论 -> 这是「原问题在原地被修复」的直接证据（如给 send
    # 加 require），该候选不参与跨槽位重排，避免与旁边新增的不同问题
    # 硬合并成严重程度变化。
    cur_remain: list[Finding] = [
        f for f in current.findings if f not in paired_c
    ]
    base_remain: list[Finding] = [
        f for f in baseline.findings if f not in paired_b
    ]

    def _same_key(b: Finding, c: Finding) -> bool:
        ib, ic = base_items[b], cur_items[c]
        return (
            ib.group_key == ic.group_key
            and ib.body_canon == ic.body_canon
            and _match_rule_signature(b.rule_ids)
            == _match_rule_signature(c.rule_ids)
        )

    def _fixed_in_place(b: Finding) -> bool:
        info = base_items[b]
        site = cur_sites.get(info.ordinal_key)
        if site is None or site.body_canon == info.body_canon:
            return False
        return not any(
            cur_items[f].ordinal_key == info.ordinal_key for f in current.findings
        )

    def _added_in_place(c: Finding) -> bool:
        info = cur_items[c]
        site = base_sites.get(info.ordinal_key)
        if site is None or site.body_canon == info.body_canon:
            return False
        return not any(
            base_items[f].ordinal_key == info.ordinal_key for f in baseline.findings
        )

    base_eligible = [f for f in base_remain if not _fixed_in_place(f)]
    cur_eligible = [f for f in cur_remain if not _added_in_place(f)]

    # 生成全部可行配对，按（槽位相同优先, 函数序号距离, 调用序号距离,
    # 基线稳定键, 新版本稳定键）排序后贪心选取未占用候选。
    edges: list[tuple[int, int, int, Finding, Finding]] = []
    for b in base_eligible:
        ib = base_items[b]
        for c in cur_eligible:
            if not _same_key(b, c):
                continue
            ic = cur_items[c]
            same_slot = int(
                (ib.function_ordinal, ib.call_ordinal)
                != (ic.function_ordinal, ic.call_ordinal)
            )
            dist_fn = abs(ib.function_ordinal - ic.function_ordinal)
            dist_call = abs(ib.call_ordinal - ic.call_ordinal)
            edges.append((same_slot, dist_fn, dist_call, b, c))
    edges.sort(key=lambda e: (
        e[0], e[1], e[2],
        _finding_sort_key(e[3]), _finding_sort_key(e[4]),
    ))
    used_b: set[Finding] = set()
    used_c: set[Finding] = set()
    for _, _, _, b, c in edges:
        if b in used_b or c in used_c:
            continue
        used_b.add(b)
        used_c.add(c)
        _take_pair(b, c)

    entries: list[DiffEntry] = []

    # 已配对：严重程度相同 -> 仍存在；不同 -> 严重程度变化。
    # 稳定签名取基线/新版本站点签名的确定性组合，确保任一侧命名/行号变化
    # 都不改变条目的展示签名。
    for b, c in pairs:
        si_b, si_c = base_items[b], cur_items[c]
        sig = _pair_signature(si_b.stable_sig, si_c.stable_sig)
        category = (
            DiffCategory.PERSISTING
            if c.severity is b.severity
            else DiffCategory.SEVERITY_CHANGED
        )
        entries.append(_make_entry(category, sig, b, c))

    # 未配对：基线侧 -> 已修复；新版本侧 -> 新增。
    for b in baseline.findings:
        if b not in paired_b:
            entries.append(
                _make_entry(DiffCategory.FIXED, base_items[b].stable_sig, b, None)
            )
    for c in current.findings:
        if c not in paired_c:
            entries.append(
                _make_entry(DiffCategory.NEW, cur_items[c].stable_sig, None, c)
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

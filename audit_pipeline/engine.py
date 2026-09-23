"""审计引擎：解析 -> 规则求值 -> 结论归一与稳定排序。

引擎本身无状态、无时间/随机/环境依赖，对同一输入永远产出同一报告，
这是"可复现"保证的核心环节。
"""

from __future__ import annotations

import hashlib
import json

from .models import AuditReport, Finding, Severity, SourceFile
from .resolver import ResolvedProject, resolve_project
from .rules import Rule, default_rules


def compute_content_hash(sources: list[SourceFile], entry_point: str) -> str:
    """对归一化后的 (路径 -> 内容) 映射与入口计算稳定的 SHA-256。

    先按路径排序再序列化，因此与提交顺序无关；重复提交、乱序提交、
    并发提交只要文件集合一致，哈希必然一致。
    """
    payload = {
        "entry_point": entry_point,
        "sources": {sf.path: sf.content for sf in sorted(sources, key=lambda s: s.path)},
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def compute_project_hash(project: ResolvedProject) -> str:
    """对 *已归一化* 的项目（normpath 后的路径键 + 归一化入口）计算哈希。

    与 :func:`compute_content_hash` 的区别：这里路径已经过 resolver 的
    normpath 处理，因此 ``A.sol`` 与 ``./A.sol``、``dir/../A.sol`` 等
    不同书写形式都会得到同一哈希，确保"相同合约"在路径书写不同时仍去重。
    """
    payload = {
        "entry_point": project.entry,
        "sources": {path: project.sources[path] for path in sorted(project.sources)},
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """合并同一问题被多条规则命中的结论。

    合并键：类别 + 首个（最小）定位。同一调用点被重入规则与危险调用规则
    同时命中时合并为一条，rule_ids 收集全部来源，severity 取最高，
    标题/描述/证据选择确定性最高的一条。
    """
    # 按主定位聚合：(文件, 合约, 函数, 行, 列)
    by_location: dict[tuple, list[Finding]] = {}
    for f in findings:
        loc = f.locations[0]
        loc_key = (loc.file, loc.contract, loc.function, loc.line, loc.column)
        by_location.setdefault(loc_key, []).append(f)

    merged: list[Finding] = []

    for loc_key, group in by_location.items():
        # 严重程度最高者优先；并列时按规则 id 排序，保证主文案选择可复现
        group_sorted = sorted(
            group,
            key=lambda f: (-f.severity.rank, min(f.rule_ids), f.title),
        )
        primary = group_sorted[0]
        rule_ids = sorted({rid for f in group for rid in f.rule_ids})
        severity = max((f.severity for f in group), key=lambda s: s.rank)
        # 类别按严重度最高者
        category = primary.category
        # 证据与定位按 (规则顺序, 文本) 去重排序
        evidence = sorted({line for f in group for line in f.evidence})
        locations = sorted(
            { (l.file, l.line, l.column, l.contract, l.function, l.snippet)
              for f in group for l in f.locations }
        )
        from .models import Location

        loc_objects = [
            Location(file=a, line=b, column=c, contract=d, function=e, snippet=f_)
            for (a, b, c, d, e, f_) in locations
        ]
        description_parts = []
        for f in group_sorted:
            description_parts.append(f"[{'/'.join(f.rule_ids)}] {f.description}")
        merged.append(
            Finding(
                key=primary.key,
                rule_ids=rule_ids,
                category=category,
                title=primary.title,
                severity=severity,
                description=" ".join(description_parts),
                locations=loc_objects,
                evidence=evidence,
            )
        )
    return merged


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """确定性排序：严重程度降序 -> 文件 -> 行 -> 列 -> 类别 -> 标题。"""
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            f.locations[0].sort_key(),
            f.category,
            f.title,
            f.key,
        ),
    )


def assign_ids(findings: list[Finding]) -> None:
    """按排序顺序分配稳定编号 F-0001, F-0002 ...（就地修改）。"""
    for idx, f in enumerate(findings, start=1):
        f.id = f"F-{idx:04d}"


class AuditEngine:
    """无状态审计引擎。"""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else default_rules()

    def audit_project(self, project: ResolvedProject, content_hash: str) -> AuditReport:
        raw: list[Finding] = []
        for rule in self.rules:  # 规则按固定注册顺序执行
            raw.extend(rule.evaluate(project))

        merged = merge_findings(raw)
        ordered = sort_findings(merged)
        assign_ids(ordered)

        rules_evaluated = [r.id for r in self.rules]
        if ordered:
            conclusion = (
                f"发现 {len(ordered)} 个潜在问题"
                f"（最高严重程度 {ordered[0].severity.value}）。"
            )
        else:
            conclusion = "未命中任何审计规则：在已评估的规则集合下未发现已知风险模式。"
        return AuditReport(
            content_hash=content_hash,
            findings=ordered,
            rules_evaluated=rules_evaluated,
            no_findings=not ordered,
            conclusion=conclusion,
        )

    def audit(self, sources: list[SourceFile], entry_point: str) -> AuditReport:
        project = resolve_project(sources, entry_point)
        content_hash = compute_project_hash(project)
        return self.audit_project(project, content_hash)

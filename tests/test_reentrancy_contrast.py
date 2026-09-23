"""重入规则对照测试：跨函数重入 / 同函数重入 / 受锁保护 / 干净合约。

核心断言：
    - 跨函数样本命中 CRITICAL 且证据指向未加锁的兄弟写函数；
    - 同函数样本命中 HIGH；
    - 受锁保护样本与干净样本均无结论（no_findings=True）；
    - 同一调用点被重入与危险调用两条规则命中时合并为一条，rule_ids 齐全；
    - 编号、严重程度顺序、行号定位在重复运行间稳定。
"""

from __future__ import annotations

import json

from conftest import banner, fixture_sources
from audit_pipeline.engine import AuditEngine
from audit_pipeline.models import TaskState

CASES = {
    "cross_function_reentrancy.sol": "CRITICAL",
    "same_function_reentrancy.sol": "HIGH",
    "guarded_reentrancy.sol": None,       # 期望无结论
    "clean_contract.sol": None,           # 期望无结论
}


def _audit(name: str):
    engine = AuditEngine()
    sources = fixture_sources([name])
    report = engine.audit(sources, f"contracts/{name}")
    return report


def test_cross_function_reentrancy_detected():
    banner("[contrast] 跨函数重入样本 -> CRITICAL，且证据含未加锁兄弟函数")
    report = _audit("cross_function_reentrancy.sol")
    assert not report.no_findings
    top = report.findings[0]
    print(f"输入标识: contracts/cross_function_reentrancy.sol")
    print(f"结论编号: {top.id}  严重程度: {top.severity.value}")
    print(f"标题: {top.title}")
    print(f"定位: {top.locations[0].file}:{top.locations[0].line}")
    for line in top.evidence:
        print(f"判定依据证据: {line}")
    assert top.severity.value == "CRITICAL"
    assert "跨函数" in top.title
    assert any("setBalance" in e for e in top.evidence)
    # 两条规则命中同一调用点，必须合并
    assert set(top.rule_ids) == {"REENTRANCY-001", "DANGEROUS-CALL-001"}
    assert len(report.findings) == 1


def test_same_function_reentrancy_detected():
    banner("[contrast] 同函数重入样本 -> HIGH")
    report = _audit("same_function_reentrancy.sol")
    top = report.findings[0]
    print(f"输入标识: contracts/same_function_reentrancy.sol")
    print(f"结论编号: {top.id}  严重程度: {top.severity.value}  行: {top.locations[0].line}")
    for line in top.evidence:
        print(f"判定依据证据: {line}")
    assert top.severity.value == "HIGH"
    assert "同函数" in top.title
    assert any("state_updated_after_call" in e for e in top.evidence)


def test_guarded_reentrancy_has_no_findings():
    banner("[contrast] 受锁保护样本 -> 无结论（锁 + 返回值检查双重保护）")
    report = _audit("guarded_reentrancy.sol")
    print("输入标识: contracts/guarded_reentrancy.sol")
    print(f"结论: {report.conclusion}")
    print(f"no_findings={report.no_findings}, findings={len(report.findings)}")
    assert report.no_findings
    assert report.findings == []


def test_clean_contract_has_explicit_clean_conclusion():
    banner("[contrast] 干净样本 -> 明确的'未命中规则'结论")
    report = _audit("clean_contract.sol")
    print("输入标识: contracts/clean_contract.sol")
    print(f"结论: {report.conclusion}")
    assert report.no_findings
    assert report.rules_evaluated == ["REENTRANCY-001", "DANGEROUS-CALL-001"]


def test_cross_vs_guarded_are_sharply_distinguished():
    banner("[contrast] 跨函数样本与受锁样本必须给出相反结论")
    cross = _audit("cross_function_reentrancy.sol")
    guarded = _audit("guarded_reentrancy.sol")
    print(f"cross findings={len(cross.findings)}; guarded findings={len(guarded.findings)}")
    assert len(cross.findings) >= 1
    assert len(guarded.findings) == 0


def test_ids_and_ordering_stable_across_runs():
    banner("[contrast] 编号/严重程度顺序/定位在重复运行间稳定")
    signatures = set()
    for _ in range(4):
        engine = AuditEngine()
        report = engine.audit(
            fixture_sources(["cross_function_reentrancy.sol"]),
            "contracts/cross_function_reentrancy.sol",
        )
        signatures.add(
            json.dumps(
                [
                    (f.id, f.severity.value, f.locations[0].line, f.locations[0].column)
                    for f in report.findings
                ],
                sort_keys=True,
            )
        )
    print(f"4 次运行的(编号,严重度,行,列)签名种类数: {len(signatures)}")
    assert len(signatures) == 1


def test_severity_ordering_is_descending():
    banner("[contrast] 多结论时按严重程度降序、编号递增")
    # 构造同时含 delegatecall(高危) 与未检查 call(中危) 的合约
    src = """
contract Mix {
    address lib;
    mapping(address => uint) balances;
    function proxy() external {
        lib.delegatecall(abi.encodeWithSignature("x()"));
    }
    function withdraw(uint amount) external {
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""
    from audit_pipeline.models import SourceFile

    engine = AuditEngine()
    report = engine.audit([SourceFile("Mix.sol", src)], "Mix.sol")
    print(f"输入标识: Mix.sol（合成多样本）")
    for f in report.findings:
        print(f"  {f.id} {f.severity.value:8} {f.title} @line {f.locations[0].line}")
    severities = [f.severity.rank for f in report.findings]
    assert severities == sorted(severities, reverse=True)
    assert [f.id for f in report.findings] == [
        f"F-{i:04d}" for i in range(1, len(report.findings) + 1)
    ]


def test_full_pipeline_contrast_via_service(service):
    banner("[contrast] 通过完整服务流水线对两类样本得到对照结论")
    cross_sources = fixture_sources(["cross_function_reentrancy.sol"])
    guarded_sources = fixture_sources(["guarded_reentrancy.sol"])
    t1, _ = service.submit(cross_sources, "contracts/cross_function_reentrancy.sol")
    t2, _ = service.submit(guarded_sources, "contracts/guarded_reentrancy.sol")
    r1 = service.wait_for(t1.id, 10)
    r2 = service.wait_for(t2.id, 10)
    assert r1.state == TaskState.COMPLETED and r2.state == TaskState.COMPLETED
    print(f"跨函数: {r1.report.findings[0].id} "
          f"{r1.report.findings[0].severity.value}")
    print(f"受锁保护: no_findings={r2.report.no_findings} -> {r2.report.conclusion}")
    assert r1.report.findings[0].severity.value == "CRITICAL"
    assert r2.report.no_findings is True

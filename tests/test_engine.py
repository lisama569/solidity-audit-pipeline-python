"""引擎层测试：多规则命中合并去重、空结论、结论可复现。"""
from app.engine import audit
from app.ingest import fingerprint, normalize_sources, resolve_imports
from app.models import Severity, SourceFile
from app.rules import RULE_DANGEROUS_CALL, RULE_REENTRANCY

MERGE_CASE = """
contract Vault {
    mapping(address => uint) balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }
}
"""

SAFE = "contract C { uint public x; function inc() public { x += 1; } }\n"


def _report(src: str):
    sources = normalize_sources([SourceFile("Vault.sol", src)])
    fp = fingerprint(sources)
    return audit(fp, sources, resolve_imports(sources))


def test_multi_rule_hit_merged_into_one_finding():
    report = _report(MERGE_CASE)
    assert len(report.findings) == 1
    f = report.findings[0]
    assert set(f.rule_ids) == {RULE_REENTRANCY, RULE_DANGEROUS_CALL}
    assert f.severity == Severity.HIGH  # 取各命中最高严重程度
    print(f"[engine] 合并命中 -> {f.finding_id} rules={f.rule_ids} sev={f.severity.name}")


def test_clean_report_when_no_rule_hit():
    report = _report(SAFE)
    assert report.clean is True
    assert report.findings == ()
    print(f"[engine] 未命中任何规则 -> clean=True hash={report.report_hash[:16]}")


def test_report_reproducible():
    r1, r2 = _report(MERGE_CASE), _report(MERGE_CASE)
    assert r1 == r2
    assert r1.report_hash == r2.report_hash
    ids = [f.finding_id for f in r1.findings]
    print(f"[engine] 可复现 -> hash={r1.report_hash[:16]} ids={ids}")


def test_finding_sort_stable_by_severity():
    src = """
contract A {
    mapping(address => uint) balances;
    function a() public {
        msg.sender.call{value: 1}("");
        balances[msg.sender] = 0;
    }
    function b(address t) public {
        t.delegatecall("");
    }
}
"""
    report = _report(src)
    sevs = [f.severity for f in report.findings]
    assert sevs == sorted(sevs, reverse=True)

"""对比算法测试：四类分类、代码整体挪动/纯重命名容忍、稳定编号排序与可复现。"""
from app.diffing import compare_reports
from app.engine import audit
from app.ingest import fingerprint, normalize_sources, resolve_imports
from app.models import DeltaCategory, Severity, SourceFile

BASE = """
contract Vault {
    mapping(address => uint) balances;
    function keep() public {
        msg.sender.call{value: 1}("");
        balances[msg.sender] = 0;
    }
    function fixedFn(address t) public {
        uint mode = 1;
        t.delegatecall("");
    }
    function sevchg(address payable to) public {
        to.send(1);
    }
}
"""

# 顶部注入无关合约、整体上下挪动、纯重命名 balances->ledger、函数重排
NEW_MOVED = """
// 顶部无关注释
contract Helper { uint helper; }
contract Vault {
    mapping(address => uint) ledger;
    function sevchg(address payable to) public {
        to.call{value: 1}("");
    }
    function newFn(address to, uint amount) public {
        bool flag = true;
        to.call{value: amount}("");
    }
    function keep() public {
        msg.sender.call{value: 1}("");
        ledger[msg.sender] = 0;
    }
}
"""


def _report(src: str):
    s = normalize_sources([SourceFile("Vault.sol", src)])
    return audit(fingerprint(s), s, resolve_imports(s))


def _by_cat(result):
    out: dict[str, list] = {}
    for d in result.deltas:
        out.setdefault(d.category.value, []).append(d)
    return out


def test_four_categories_classified():
    b, n = _report(BASE), _report(NEW_MOVED)
    r = compare_reports(baseline=b, current=n,
                        baseline_task_id="tb", current_task_id="tn")
    cats = _by_cat(r)
    assert r.counts == {"NEW": 1, "FIXED": 1, "PERSISTENT": 2,
                        "SEVERITY_CHANGED": 1}
    assert cats["NEW"][0].current.function == "newFn"
    assert cats["FIXED"][0].baseline.function == "fixedFn"
    persist_fns = {d.current.function for d in cats["PERSISTENT"]}
    assert persist_fns == {"keep", "keep"}  # keep 的两条规则都仍在
    sev = cats["SEVERITY_CHANGED"][0]
    assert sev.baseline.function == "sevchg"
    assert sev.baseline_severity == Severity.LOW
    assert sev.current_severity == Severity.MEDIUM
    print(f"[diff] 四类分类 -> {r.counts}")


def test_code_shift_and_rename_treated_as_persistent():
    # keep 在新版本中从 L5 挪到 L14、变量改名 balances->ledger，
    # 其两条问题都必须仍是 PERSISTENT，不得出现 keep 相关的新增/修复抖动
    b, n = _report(BASE), _report(NEW_MOVED)
    r = compare_reports(baseline=b, current=n,
                        baseline_task_id="tb", current_task_id="tn")
    for d in r.deltas:
        if d.category in (DeltaCategory.NEW, DeltaCategory.FIXED):
            fn = (d.current.function if d.current else d.baseline.function)
            assert fn == ("newFn" if d.category is DeltaCategory.NEW
                          else "fixedFn")
    keep_lines = [
        (d.baseline.line, d.current.line)
        for d in r.deltas
        if d.current and d.current.function == "keep"
    ]
    assert all(bl == 5 and cl == 14 for bl, cl in keep_lines)
    print(f"[diff] 整体挪动+重命名 -> keep 仍为 PERSISTENT L5->L14")


def test_result_names_baseline_and_reproducible():
    b, n = _report(BASE), _report(NEW_MOVED)
    r1 = compare_reports(baseline=b, current=n,
                         baseline_task_id="BASE", current_task_id="CUR")
    r2 = compare_reports(baseline=b, current=n,
                         baseline_task_id="BASE", current_task_id="CUR")
    assert r1 == r2
    assert r1.baseline_task_id == "BASE"
    assert r1.current_task_id == "CUR"
    assert r1.baseline_report_hash == b.report_hash
    assert r1.current_report_hash == n.report_hash
    print(f"[diff] 相对基线 BASE 可复现 hash={r1.comparison_hash[:16]}")


def test_different_baseline_is_independent_conclusion():
    # 同一份基线内容，即使任务 id 不同，对比内容哈希也相同（内容寻址）
    b = _report(BASE)
    n = _report(NEW_MOVED)
    r_a = compare_reports(baseline=b, current=n,
                          baseline_task_id="A", current_task_id="C")
    r_same = compare_reports(baseline=b, current=n,
                             baseline_task_id="OTHER-ID", current_task_id="C")
    assert r_a.deltas == r_same.deltas
    assert r_a.comparison_hash == r_same.comparison_hash

    # 不同的基线内容（结论本身不同）-> 各自独立、可分辨的对比结论
    other_base = (
        "contract Vault {\n"
        "    mapping(address => uint) balances;\n"
        "    function keep() public {\n"
        '        msg.sender.call{value: 1}("");\n'
        "        balances[msg.sender] = 0;\n"
        "    }\n"
        "}\n"
    )
    b2 = _report(other_base)
    assert b2.report_hash != b.report_hash
    r_b = compare_reports(baseline=b2, current=n,
                          baseline_task_id="B2", current_task_id="C")
    assert r_b.comparison_hash != r_a.comparison_hash
    assert r_b.counts != r_a.counts
    print(f"[diff] 不同基线内容 -> 独立 hash {r_a.comparison_hash[:8]} "
          f"vs {r_b.comparison_hash[:8]}")


def test_delta_order_stable_with_hundreds_of_findings():
    # 构造大量互不相同的函数（各自带不同上下文），验证分类/顺序/统计稳定
    def build(n: int, prefix: str):
        fns = []
        for i in range(n):
            fns.append(
                f"    function f_{prefix}_{i}(address t) public {{\n"
                f"        uint tag_{i} = {i};\n"
                f'        t.delegatecall("");\n'
                f"    }}\n"
            )
        return "contract Big {\n" + "".join(fns) + "}\n"

    base_src = build(150, "b")
    # 新版本：保留前 120 个（原样）、后 30 个消失（修复）、新增 30 个
    kept = "\n".join(
        f'    function f_b_{i}(address t) public {{ uint tag_{i} = {i}; '
        f't.delegatecall(""); }}'
        for i in range(120)
    )
    added = "\n".join(
        f'    function g_{i}(address z, uint q) public {{ uint mark_{i} = {i}; '
        f'bool guard_{i} = (q > 0); z.delegatecall("x"); }}'
        for i in range(30)
    )
    new_src = "contract Big {\n" + kept + "\n" + added + "\n}\n"

    b, n = _report(base_src), _report(new_src)
    r1 = compare_reports(baseline=b, current=n,
                         baseline_task_id="tb", current_task_id="tn")
    r2 = compare_reports(baseline=b, current=n,
                         baseline_task_id="tb", current_task_id="tn")
    assert r1 == r2
    assert r1.counts["FIXED"] == 30
    assert r1.counts["NEW"] == 30
    assert r1.counts["PERSISTENT"] == 120
    ids = [d.delta_id for d in r1.deltas]
    assert len(ids) == len(set(ids))  # 编号唯一
    # 顺序稳定：两次完全一致，且类别按固定优先级排列
    cats_in_order = [d.category.value for d in r1.deltas]
    assert cats_in_order == sorted(
        cats_in_order,
        key=lambda c: {"NEW": 0, "FIXED": 1,
                       "SEVERITY_CHANGED": 2, "PERSISTENT": 3}[c],
    )
    print(f"[diff] 大规模结论({len(ids)}条) 分类/顺序/编号稳定 -> {r1.counts}")


def test_identical_reports_all_persistent():
    b = _report(BASE)
    r = compare_reports(baseline=b, current=b,
                        baseline_task_id="t", current_task_id="t")
    assert r.counts["NEW"] == 0 and r.counts["FIXED"] == 0
    assert r.counts["SEVERITY_CHANGED"] == 0
    assert r.counts["PERSISTENT"] == len(
        [i for f in b.findings for i in f.issues]
    )

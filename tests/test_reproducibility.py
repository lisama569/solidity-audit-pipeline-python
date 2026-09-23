"""重复提交、乱序提交、并发提交的结论可复现性测试。

要求：同一批合约无论提交多少次、以什么顺序、从多少个线程同时提交，
只产生一个任务、一份结论，编号/严重程度/定位完全一致。
"""

from __future__ import annotations

import json
import threading

import pytest

from conftest import banner, fixture_sources, read_fixture
from audit_pipeline.engine import AuditEngine, compute_content_hash
from audit_pipeline.models import SourceFile, TaskState

CROSS = "cross_function_reentrancy.sol"
GUARDED = "guarded_reentrancy.sol"
CLEAN = "clean_contract.sol"
DEPMULTI = [CROSS, "dep_token.sol", CLEAN]


def _report_signature(report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True)


def test_hash_is_order_independent():
    banner("[repro] 内容哈希与提交顺序无关")
    a = fixture_sources(DEPMULTI)
    b = list(reversed(a))
    ha = compute_content_hash(a, f"contracts/{CROSS}")
    hb = compute_content_hash(b, f"contracts/{CROSS}")
    print(f"输入标识: {DEPMULTI}")
    print(f"正序哈希: {ha}")
    print(f"逆序哈希: {hb}")
    assert ha == hb


def test_engine_report_is_deterministic():
    banner("[repro] 引擎对同一输入重复求值结论逐字节一致")
    engine = AuditEngine()
    srcs = fixture_sources([CROSS])
    reports = [engine.audit(srcs, f"contracts/{CROSS}") for _ in range(5)]
    sigs = {_report_signature(r) for r in reports}
    print(f"输入标识: contracts/{CROSS}")
    print(f"5 次求值的不同签名数: {len(sigs)}")
    assert len(sigs) == 1
    r = reports[0]
    assert not r.no_findings
    assert [f.id for f in r.findings] == ["F-0001"]
    f0 = r.findings[0]
    print(f"判定依据: {f0.title} | severity={f0.severity.value} | "
          f"line={f0.locations[0].line} | rules={f0.rule_ids}")
    assert f0.severity.value == "CRITICAL"
    assert set(f0.rule_ids) == {"REENTRANCY-001", "DANGEROUS-CALL-001"}


def test_duplicate_submission_dedupes(service):
    banner("[repro] 相同合约重复提交只产生一个任务、不重复计算")
    srcs = fixture_sources([CROSS])
    t1, created1 = service.submit(srcs, f"contracts/{CROSS}", client_labels=["first"])
    done = service.wait_for(t1.id, 10)
    assert done.state == TaskState.COMPLETED
    first_report = _report_signature(done.report)

    # 完成后再次提交同一内容
    t2, created2 = service.submit(srcs, f"contracts/{CROSS}", client_labels=["second"])
    print(f"输入标识: contracts/{CROSS}（第二次提交）")
    print(f"首次任务: {t1.id} created={created1}")
    print(f"重复任务: {t2.id} created={created2}")
    assert created2 is False
    assert t2.id == t1.id
    assert _report_signature(t2.report) == first_report
    all_tasks = service.list_tasks()
    assert len(all_tasks) == 1
    print(f"判定依据: 任务总数={len(all_tasks)}，复用已完成结论，无重复计算")


def test_different_order_submission_dedupes(service):
    banner("[repro] 不同提交顺序的相同合约集合去重为同一任务")
    a = fixture_sources(DEPMULTI)
    b = list(reversed(a))
    t1, c1 = service.submit(a, f"contracts/{CROSS}", client_labels=["order-A"])
    service.wait_for(t1.id, 10)
    t2, c2 = service.submit(b, f"contracts/{CROSS}", client_labels=["order-B"])
    print(f"正序输入: {DEPMULTI}")
    print(f"逆序输入: {list(reversed(DEPMULTI))}")
    print(f"任务1={t1.id} created={c1}；任务2={t2.id} created={c2}")
    assert c2 is False
    assert t1.id == t2.id
    assert len(service.list_tasks()) == 1
    print("判定依据: 内容哈希相同 -> 命中幂等表，结论逐字节一致")


def test_concurrent_duplicate_submissions(service):
    banner("[repro] 多线程并发提交相同合约，恰好创建一个任务")
    srcs = fixture_sources([CROSS])
    results: list[tuple] = []
    barrier = threading.Barrier(8)

    def worker(idx: int) -> None:
        barrier.wait()
        task, created = service.submit(srcs, f"contracts/{CROSS}", client_labels=[f"w{idx}"])
        results.append((task.id, created))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ids = {tid for tid, _ in results}
    created_flags = [created for _, created in results]
    print(f"并发线程数: 8；返回任务 id 种类数: {len(ids)}")
    print(f"created=True 的次数: {sum(created_flags)}（必须恰为 1）")
    assert len(ids) == 1
    assert sum(created_flags) == 1
    assert len(service.list_tasks()) == 1
    only_id = next(iter(ids))
    only = service.wait_for(only_id, 10)
    assert only.state == TaskState.COMPLETED
    print(f"判定依据: 唯一任务 {only.id} 已完成，报告条数={len(only.report.findings)}")


def test_different_path_spelling_dedupes(service):
    banner("[repro] 路径书写不同但归一化后相同的提交去重为同一任务")
    src = read_fixture(CLEAN)
    variants = [
        ([SourceFile("dir/A.sol", src)], "dir/A.sol"),
        ([SourceFile("dir/./A.sol", src)], "dir/A.sol"),
        ([SourceFile("dir/../dir/A.sol", src)], "dir/./A.sol"),
    ]
    ids = []
    for srcs, entry in variants:
        t, created = service.submit(srcs, entry)
        ids.append(t.id)
        print(f"entry={entry!r:18} -> task={t.id[:16]} created={created}")
    assert len(set(ids)) == 1
    assert len(service.list_tasks()) == 1
    print("判定依据: normpath 后路径与内容哈希一致 -> 同一任务")


def test_distinct_inputs_are_not_deduped(service):
    banner("[repro] 不同合约集合不会被错误去重")
    t1, _ = service.submit(fixture_sources([CROSS]), f"contracts/{CROSS}")
    t2, _ = service.submit(fixture_sources([CLEAN]), f"contracts/{CLEAN}")
    t3, _ = service.submit(fixture_sources([GUARDED]), f"contracts/{GUARDED}")
    for t in (t1, t2, t3):
        service.wait_for(t.id, 10)
    print(f"cross={t1.id[:18]} clean={t2.id[:18]} guarded={t3.id[:18]}")
    assert len({t1.id, t2.id, t3.id}) == 3
    assert len(service.list_tasks()) == 3
    print("判定依据: 三份内容哈希不同 -> 三个独立任务")

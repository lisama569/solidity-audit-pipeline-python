import pytest

from app.errors import IngestError
from app.ingest import decode_sources, fingerprint, normalize_sources, resolve_imports
from app.models import ErrorCode, SourceFile

A = 'pragma solidity ^0.8.0;\ncontract A { function f() public {} }\n'
B = 'import "./A.sol";\ncontract B { function g() public {} }\n'


def test_fingerprint_order_independent():
    s1 = normalize_sources([SourceFile("A.sol", A), SourceFile("B.sol", B)])
    s2 = normalize_sources([SourceFile("B.sol", B), SourceFile("A.sol", A)])
    assert fingerprint(s1) == fingerprint(s2)
    print(f"[ingest] 顺序无关指纹: {fingerprint(s1)[:16]}")


def test_empty_submission_source_missing():
    with pytest.raises(IngestError) as ei:
        normalize_sources([])
    assert ei.value.code is ErrorCode.SOURCE_MISSING
    print(f"[ingest] 空提交 -> {ei.value.code.value}")


def test_empty_content_source_missing():
    with pytest.raises(IngestError) as ei:
        normalize_sources([SourceFile("A.sol", "  \n")])
    assert ei.value.code is ErrorCode.SOURCE_MISSING


def test_non_utf8_invalid_content():
    with pytest.raises(IngestError) as ei:
        decode_sources([("A.sol", b"\xff\xfe\x00bad")])
    assert ei.value.code is ErrorCode.INVALID_CONTENT
    print(f"[ingest] 非UTF-8 -> {ei.value.code.value}")


def test_garbage_invalid_content():
    with pytest.raises(IngestError) as ei:
        normalize_sources([SourceFile("A.sol", "hello world not solidity")])
    assert ei.value.code is ErrorCode.INVALID_CONTENT


def test_unresolvable_import():
    src = normalize_sources([SourceFile("B.sol", B)])
    with pytest.raises(IngestError) as ei:
        resolve_imports(src)
    assert ei.value.code is ErrorCode.IMPORT_UNRESOLVABLE
    print(f"[ingest] 导入缺失 -> {ei.value.code.value}")


def test_circular_import():
    a = 'import "./B.sol";\ncontract A {}\n'
    b = 'import "./A.sol";\ncontract B {}\n'
    src = normalize_sources([SourceFile("A.sol", a), SourceFile("B.sol", b)])
    with pytest.raises(IngestError) as ei:
        resolve_imports(src)
    assert ei.value.code is ErrorCode.IMPORT_UNRESOLVABLE


def test_topological_order_deterministic():
    src = normalize_sources([SourceFile("B.sol", B), SourceFile("A.sol", A)])
    assert resolve_imports(src) == ["A.sol", "B.sol"]

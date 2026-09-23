"""畸形来源接入测试：失败原因必须彼此可区分，且绝不产生半成品任务。

错误码矩阵：
    SOURCE_MISSING       入口缺失 / 被导入文件未提交
    UNRESOLVED_IMPORT    裸包名等无法映射的 import
    INVALID_CONTENT      空内容、非法字符、未闭合、结构性损坏
    INVALID_SUBMISSION   空来源、非法路径、归一化后重复
"""

from __future__ import annotations

import pytest

from conftest import banner, read_fixture
from audit_pipeline.models import SourceFile
from audit_pipeline.service import AuditService


def _expect_error(service, sources, entry, expected_code):
    with pytest.raises(Exception) as exc_info:
        service.submit(sources, entry)
    actual = exc_info.value.code
    print(f"输入标识: entry={entry!r} sources={[s.path for s in sources]}")
    print(f"期望错误码: {expected_code} | 实际错误码: {actual}")
    print(f"判定依据: {exc_info.value.message} | details={exc_info.value.details}")
    assert actual == expected_code
    # 关键不变式：拒绝后不得留下任何任务
    assert service.list_tasks() == [], "畸形输入不得产生半成品任务"


def test_missing_entry_point(service):
    banner("[malformed] 入口合约未提交 -> SOURCE_MISSING")
    _expect_error(
        service,
        [SourceFile("contracts/Other.sol", "contract Other {}")],
        "contracts/Missing.sol",
        "SOURCE_MISSING",
    )


def test_missing_imported_file(service):
    banner("[malformed] import 的依赖未随来源提交 -> SOURCE_MISSING")
    src = 'pragma solidity ^0.8.0;\nimport "./Ghost.sol";\ncontract A { Ghost g; }'
    _expect_error(
        service,
        [SourceFile("contracts/A.sol", src)],
        "contracts/A.sol",
        "SOURCE_MISSING",
    )


def test_unresolved_bare_package(service):
    banner("[malformed] 裸包名导入无法在本地集合解析 -> UNRESOLVED_IMPORT")
    src = 'import "@openzeppelin/contracts/token/ERC20.sol";\ncontract A {}'
    _expect_error(service, [SourceFile("A.sol", src)], "A.sol", "UNRESOLVED_IMPORT")


def test_unresolved_path_escape(service):
    banner("[malformed] import 路径越出提交根目录 -> UNRESOLVED_IMPORT")
    src = 'import "../../etc/passwd.sol";\ncontract A {}'
    _expect_error(service, [SourceFile("contracts/A.sol", src)], "contracts/A.sol",
                  "UNRESOLVED_IMPORT")


@pytest.mark.parametrize(
    "label,content",
    [
        ("empty", ""),
        ("whitespace-only", "   \n\t  "),
        ("unclosed-string", 'contract A { string s = "abc; }'),
        ("unclosed-brace", "contract A { uint256 x; "),
        ("garbled-token", "contract A { function f() external { @@@@ } }"),
        ("contract-without-name", "contract { uint x; }"),
    ],
)
def test_invalid_contents(service, label, content):
    banner(f"[malformed] 非法内容({label}) -> INVALID_CONTENT")
    _expect_error(service, [SourceFile("A.sol", content)], "A.sol", "INVALID_CONTENT")


def test_empty_source_set(service):
    banner("[malformed] 空来源集合 -> INVALID_SUBMISSION")
    _expect_error(service, [], "A.sol", "INVALID_SUBMISSION")


def test_path_traversal_rejected(service):
    banner("[malformed] 路径越界/绝对路径 -> INVALID_SUBMISSION")
    for bad_path in ["../secret.sol", "/etc/passwd", "dir//../../x.sol"]:
        with pytest.raises(Exception) as ei:
            service.submit([SourceFile(bad_path, "contract A{}")], bad_path)
        print(f"  路径 {bad_path!r} -> {ei.value.code}: {ei.value.message}")
        assert ei.value.code == "INVALID_SUBMISSION"


def test_normalized_duplicate_paths(service):
    banner("[malformed] 归一化后相同的重复路径 -> INVALID_SUBMISSION")
    src = "contract A {}"
    _expect_error(
        service,
        [SourceFile("dir/A.sol", src), SourceFile("dir/./A.sol", src)],
        "dir/A.sol",
        "INVALID_SUBMISSION",
    )


def test_one_bad_apple_rejects_all(service):
    banner("[malformed] 多文件提交中任一文件非法则整体拒绝、不留任务")
    good = read_fixture("clean_contract.sol")
    sources = [
        SourceFile("contracts/Good.sol", good),
        SourceFile("contracts/Bad.sol", "contract Bad {"),
    ]
    _expect_error(service, sources, "contracts/Good.sol", "INVALID_CONTENT")


def test_error_codes_are_distinguishable(service):
    banner("[malformed] 三类来源错误在同批调用上给出彼此不同的错误码")
    seen = {}
    cases = [
        (
            "missing",
            [SourceFile("A.sol", "contract A{}")],
            "MISSING.sol",
            "SOURCE_MISSING",
        ),
        (
            "unresolved",
            [SourceFile("A.sol", 'import "pkg/x.sol"; contract A{}')],
            "A.sol",
            "UNRESOLVED_IMPORT",
        ),
        (
            "invalid",
            [SourceFile("A.sol", "contract {")],
            "A.sol",
            "INVALID_CONTENT",
        ),
    ]
    for label, srcs, entry, code in cases:
        try:
            service.submit(srcs, entry)
        except Exception as exc:
            seen[label] = exc.code
            assert exc.code == code
    print(f"三类错误码: {seen}")
    assert len(set(seen.values())) == 3

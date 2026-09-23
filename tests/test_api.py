"""HTTP API 集成测试：提交幂等、状态码、错误区分、结论可解释。"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from conftest import banner, read_fixture
from audit_pipeline.api import create_app
from audit_pipeline.service import AuditService


@pytest.fixture
def client():
    svc = AuditService(":memory:", workers=2)
    app = create_app(svc, start=False)
    svc.start()
    with TestClient(app) as c:
        yield c, svc
    svc.shutdown()


def _payload(name: str, *, labels=None):
    return {
        "entry_point": f"contracts/{name}",
        "client_labels": labels or [],
        "sources": [
            {"path": f"contracts/{name}", "content": read_fixture(name)}
        ],
    }


def _wait(client, tid, svc, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/audit/tasks/{tid}").json()
        if data["state"] in ("COMPLETED", "FAILED", "CANCELLED", "TIMEOUT"):
            return data
        time.sleep(0.03)
    raise AssertionError("task did not finish")


def test_submit_and_dedup_status_codes(client):
    banner("[api] 首次 202、重复 200，且结论可解释")
    c, svc = client
    r1 = c.post("/audit/tasks", json=_payload("cross_function_reentrancy.sol"))
    assert r1.status_code == 202
    assert r1.json()["deduplicated"] is False
    tid = r1.json()["id"]

    r2 = c.post("/audit/tasks", json=_payload("cross_function_reentrancy.sol"))
    assert r2.status_code == 200
    assert r2.json()["id"] == tid
    print(f"首次 HTTP {r1.status_code}，重复 HTTP {r2.status_code}，任务 {tid[:16]}")

    data = _wait(c, tid, svc)
    assert data["state"] == "COMPLETED"
    f0 = data["report"]["findings"][0]
    print(f"判定依据: {f0['id']} {f0['severity']} {f0['title']}")
    print(f"定位: {f0['locations'][0]['file']}:{f0['locations'][0]['line']}")
    assert f0["severity"] == "CRITICAL"
    assert f0["rule_ids"] == ["DANGEROUS-CALL-001", "REENTRANCY-001"]


def test_guarded_contract_clean_conclusion(client):
    banner("[api] 受锁保护合约返回明确的无风险结论")
    c, svc = client
    r = c.post("/audit/tasks", json=_payload("guarded_reentrancy.sol"))
    data = _wait(c, r.json()["id"], svc)
    print("conclusion:", data["report"]["conclusion"])
    assert data["report"]["no_findings"] is True
    assert data["report"]["findings"] == []


def test_malformed_inputs_return_distinct_codes(client):
    banner("[api] 缺失/不可解析/非法内容分别返回不同错误码")
    c, _ = client
    cases = [
        ({"entry_point": "M.sol", "sources": [{"path": "A.sol", "content": "contract A{}"}]},
         "SOURCE_MISSING"),
        ({"entry_point": "A.sol",
          "sources": [{"path": "A.sol", "content": 'import "pkg/x.sol"; contract A{}'}]},
         "UNRESOLVED_IMPORT"),
        ({"entry_point": "A.sol",
          "sources": [{"path": "A.sol", "content": "contract {"}]},
         "INVALID_CONTENT"),
    ]
    codes = []
    for payload, expected in cases:
        r = c.post("/audit/tasks", json=payload)
        body = r.json()
        print(f"HTTP {r.status_code} code={body['error']['code']} expected={expected}")
        assert r.status_code == 422
        assert body["error"]["code"] == expected
        codes.append(body["error"]["code"])
    assert len(set(codes)) == 3


def test_task_not_found_and_list(client):
    banner("[api] 未知任务 404，任务列表可枚举")
    c, _ = client
    assert c.get("/audit/tasks/nope").status_code == 404
    listed = c.get("/audit/tasks").json()
    assert listed["count"] == 0
    print("GET /audit/tasks/nope -> 404；空列表 count=0")


def test_cancel_completed_conflicts(client):
    banner("[api] 取消已完成任务 -> 409 TASK_STATE_CONFLICT")
    c, svc = client
    r = c.post("/audit/tasks", json=_payload("clean_contract.sol"))
    tid = r.json()["id"]
    _wait(c, tid, svc)
    rc = c.post(f"/audit/tasks/{tid}/cancel")
    print(f"HTTP {rc.status_code} body={rc.json()['error']['code']}")
    assert rc.status_code == 409

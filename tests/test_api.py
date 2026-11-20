"""API 冒烟测试:页面、示例、计划、续排、失败、校验错误。"""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
client = TestClient(app)


def example_body():
    def load(name):
        return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))

    return {
        "topology": load("topology.json"),
        "routes": load("routes.json"),
        "requirements": load("requirements.json"),
    }


def test_index_page_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "换表轮次规划器" in r.text


def test_example_endpoint():
    r = client.get("/api/example")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"topology", "routes", "requirements"}


def test_plan_ok():
    r = client.post("/api/plan", json={**example_body(), "switched": []})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "ok"
    assert len(d["rounds"]) == 3
    assert sorted(r0 for rnd in d["rounds"] for r0 in rnd) == sorted(
        ["R1", "R2", "R3", "R4", "R5"]
    )


def test_plan_replan_with_switched():
    r = client.post("/api/plan", json={**example_body(), "switched": ["R4", "R5"]})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "ok"
    assert d["switched"] == ["R4", "R5"]
    assert len(d["rounds"]) == 2


def test_plan_failure_shape():
    body = example_body()
    body["requirements"]["requirements"][0]["allowed_egress"] = ["E2"]
    r = client.post("/api/plan", json={**body, "switched": []})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "failed"
    assert d["reason"] == "current_unsafe"
    assert d["failure_state"] == []
    f0 = d["failures"][0]
    assert f0["verdict"] == "wrong_egress"
    assert f0["verdict_zh"] == "错出口"
    assert f0["path"][0]["router"] == "R1"


def test_validation_error_returns_400():
    body = example_body()
    body["requirements"]["requirements"][0]["allowed_egress"] = ["NOPE"]
    r = client.post("/api/plan", json={**body, "switched": []})
    assert r.status_code == 400
    assert "不存在的出口" in r.json()["detail"]

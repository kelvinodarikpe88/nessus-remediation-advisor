from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.runtime import RateLimiter

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
KEY = {"x-api-key": "test-key"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_missing_key_is_401(client):
    assert client.get("/v1/intel").status_code == 401


def test_wrong_key_is_401(client):
    assert client.get("/v1/intel", headers={"x-api-key": "nope"}).status_code == 401


def test_key_in_bearer_header_works(client):
    response = client.get("/v1/intel", headers={"authorization": "Bearer test-key"})
    assert response.status_code == 200


def test_open_probes_need_no_key(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    assert client.get("/version").json()["service"] == "nessus-remediation-advisor"
    assert "http_requests_total" in client.get("/metrics").text


def test_request_id_is_echoed(client):
    response = client.get("/v1/intel", headers={**KEY, "x-request-id": "abc123"})
    assert response.headers["x-request-id"] == "abc123"


def test_plan_endpoint_returns_waves(client):
    xml = (FIXTURES / "sample.nessus").read_text()
    response = client.post("/v1/plan", headers=KEY, json={"nessus_xml": xml})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["findings"] == 9
    assert len(body["waves"]) == 5
    assert body["waves"][0]["note_source"] == "template"


def test_malformed_document_is_422(client):
    response = client.post("/v1/plan", headers=KEY, json={"nessus_xml": "<html>" + "x" * 40})
    assert response.status_code == 422


def test_rate_limiter_refuses_past_the_budget():
    limiter = RateLimiter(limit=2, window=60)
    assert limiter.allow("caller")
    assert limiter.allow("caller")
    assert not limiter.allow("caller")
    assert limiter.retry_after("caller") >= 1

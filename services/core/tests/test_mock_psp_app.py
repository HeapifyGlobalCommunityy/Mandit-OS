"""The standalone Mock PSP app (mock_psp.main) serves its database routes.

Regression: the app handed MockPspService a synchronous Session, so every route that
awaits `session.execute` failed with 500; the unit tests did not notice because they wrap
the session themselves.
"""

from fastapi.testclient import TestClient

from mock_psp.main import app


def test_status_route_answers_not_found_instead_of_500():
    with TestClient(app) as client:
        resp = client.get("/psp/v1/payments/psp_missing")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "PAYMENT_NOT_FOUND"


def test_lookup_by_idempotency_key_route():
    with TestClient(app) as client:
        resp = client.get("/psp/v1/payments", params={"idempotency_key": "pay_missing:auth"})
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "PAYMENT_NOT_FOUND"

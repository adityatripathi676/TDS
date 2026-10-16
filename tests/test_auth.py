from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from app.api.routes import router
from app.core.auth import create_access_token, decode_access_token, verify_analyst_credentials
from app.main import app


class AuthSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_verify_analyst_credentials(self) -> None:
        self.assertTrue(verify_analyst_credentials("admin", "admin123"))
        self.assertFalse(verify_analyst_credentials("admin", "wrongpassword"))
        self.assertFalse(verify_analyst_credentials("hacker", "admin123"))

    def test_token_creation_and_decoding(self) -> None:
        token = create_access_token({"sub": "admin", "role": "analyst"}, expires_delta_minutes=30)
        decoded = decode_access_token(token)
        self.assertEqual(decoded["sub"], "admin")
        self.assertEqual(decoded["role"], "analyst")

    def test_expired_token_raises_exception(self) -> None:
        token = create_access_token({"sub": "admin"}, expires_delta_minutes=-10)
        with self.assertRaises(Exception) as ctx:
            decode_access_token(token)
        self.assertIn("expired", str(ctx.exception).lower())

    def test_unprotected_health_endpoint(self) -> None:
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

    def test_protected_endpoint_returns_401_without_token(self) -> None:
        res = self.client.get("/api/metrics")
        self.assertEqual(res.status_code, 401)

    def test_login_success_returns_token(self) -> None:
        res = self.client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("access_token", body)
        self.assertEqual(body["token_type"], "bearer")

    def test_protected_endpoint_succeeds_with_valid_token(self) -> None:
        login_res = self.client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        token = login_res.json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}
        res = self.client.get("/api/metrics", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("total_events", res.json())


if __name__ == "__main__":
    unittest.main()

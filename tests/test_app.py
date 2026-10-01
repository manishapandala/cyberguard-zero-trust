"""HTTP boundary tests for CyberGuard."""

import unittest

from app import MAX_EVENT_CHARS, app


class CyberGuardApiTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_analyze_requires_event(self):
        response = self.client.post("/api/analyze", json={})
        self.assertEqual(response.status_code, 400)

    def test_analyze_rejects_oversized_event(self):
        response = self.client.post("/api/analyze", json={"event": "x" * (MAX_EVENT_CHARS + 1)})
        self.assertEqual(response.status_code, 400)

    def test_batch_is_bounded(self):
        response = self.client.post("/api/batch", json={"events": ["event"] * 1_001})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

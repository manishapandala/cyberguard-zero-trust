import unittest

from cyberguard import CyberGuard, score_event, severity_for


class CyberGuardAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.guard = CyberGuard()

    def test_backup_event_has_critical_score_and_controls(self):
        event = '2024-07-31T00:00:00,177.52.183.80,192.168.1.50,HTTPS,blocked,suspicious,ids,45164,"Mozilla/5.0",/download?backup.sql'
        result = self.guard.assess(event)
        self.assertEqual(result.attack_type, "Unauthorized backup access")
        self.assertEqual(result.severity, "critical")
        self.assertIn("NIST AC-6", result.controls)

    def test_benign_event_has_low_risk(self):
        event = '2024-04-07T00:00:00,192.168.1.248,192.168.1.15,HTTP,allowed,benign,application,20652,"Mozilla/5.0",/home'
        result = self.guard.assess(event)
        self.assertEqual(result.status, "Non-malicious")
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.severity, "low")

    def test_invalid_record_is_rejected(self):
        with self.assertRaises(ValueError):
            self.guard.assess("invalid,row")

    def test_batch_skips_blank_lines(self):
        event = '2024-04-07T00:00:00,192.168.1.248,192.168.1.15,HTTP,allowed,benign,application,20652,"Mozilla/5.0",/home'
        self.assertEqual(len(self.guard.assess_many([event, "  "])), 1)

    def test_tool_indicator_adds_risk(self):
        record = {"threat_label": "suspicious", "action": "allowed", "user_agent": "SQLMap/1.6-dev"}
        self.assertEqual(score_event(record, "Malicious", "SQL injection attempt"), 95)

    def test_severity_boundaries(self):
        self.assertEqual(severity_for(85), "critical")
        self.assertEqual(severity_for(65), "high")
        self.assertEqual(severity_for(35), "medium")
        self.assertEqual(severity_for(5), "low")


if __name__ == "__main__":
    unittest.main()

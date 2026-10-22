#!/usr/bin/env python3
"""
Unit tests for governance_auditor.py
"""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.governance_auditor import audit_requirements_traceability, verify_peer_review

class TestGovernanceAuditor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_peer_review_compliant(self):
        pr_file = self.root / "pr.json"
        pr_data = {
            "author": {"login": "dev1"},
            "reviewers": [{"login": "senior_qa", "state": "APPROVED"}]
        }
        pr_file.write_text(json.dumps(pr_data))
        res = verify_peer_review(pr_file)
        self.assertEqual(res["verdict"], "PASS")
        self.assertTrue(res["two_person_rule_satisfied"])

    def test_peer_review_author_equals_reviewer_violation(self):
        pr_file = self.root / "pr_invalid.json"
        pr_data = {
            "author": {"login": "dev1"},
            "reviewers": [{"login": "dev1", "state": "APPROVED"}]
        }
        pr_file.write_text(json.dumps(pr_data))
        res = verify_peer_review(pr_file)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertFalse(res["two_person_rule_satisfied"])
        self.assertIn("cannot approve own pull request", res["details"])

    def test_rtm_audit_no_reqs_fallback(self):
        res = audit_requirements_traceability(self.root)
        self.assertEqual(res["verdict"], "PASS")
        self.assertEqual(res["traceability_coverage_pct"], 100.0)

    def test_rtm_audit_with_unmapped_req(self):
        req_dir = self.root / "docs" / "requirements"
        req_dir.mkdir(parents=True)
        (req_dir / "REQ-AUTH-001.md").write_text("Spec")
        res = audit_requirements_traceability(self.root)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertEqual(res["traceability_coverage_pct"], 0.0)

    def test_rtm_audit_with_mapped_req(self):
        req_dir = self.root / "docs" / "requirements"
        req_dir.mkdir(parents=True)
        (req_dir / "REQ-AUTH-001.md").write_text("Spec")
        tests_dir = self.root / "tests"
        tests_dir.mkdir(parents=True)
        (tests_dir / "test_REQ-AUTH-001.py").write_text("# Test for REQ-AUTH-001")
        res = audit_requirements_traceability(self.root)
        self.assertEqual(res["verdict"], "PASS")
        self.assertEqual(res["traceability_coverage_pct"], 100.0)

if __name__ == "__main__":
    unittest.main()

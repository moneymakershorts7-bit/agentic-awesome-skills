#!/usr/bin/env python3
"""
Unit tests for qa_master_gate.py
"""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.qa_master_gate import run_qa_master_gate, evaluate_sarif_findings

class TestQAMasterGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clean_audit_dir_passes(self):
        exit_code = run_qa_master_gate(self.audit_dir)
        self.assertEqual(exit_code, 0)
        scorecard_file = self.audit_dir / "unified_quality_scorecard.json"
        self.assertTrue(scorecard_file.exists())
        scorecard = json.loads(scorecard_file.read_text(encoding="utf-8"))
        self.assertEqual(scorecard["verdict"], "PASS")

    def test_sarif_critical_findings_fails_gate(self):
        sarif_file = self.audit_dir / "security.sarif"
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestSAST"}},
                    "results": [
                        {
                            "ruleId": "CWE-89",
                            "level": "error",
                            "message": {"text": "SQL Injection detected"}
                        }
                    ]
                }
            ]
        }
        sarif_file.write_text(json.dumps(sarif_data))
        exit_code = run_qa_master_gate(self.audit_dir)
        self.assertEqual(exit_code, 1)
        scorecard = json.loads((self.audit_dir / "unified_quality_scorecard.json").read_text(encoding="utf-8"))
        self.assertEqual(scorecard["verdict"], "FAIL")
        self.assertIn("critical/error findings detected", scorecard["violations"][0])

    def test_low_mutation_score_fails_gate(self):
        test_summary = self.audit_dir / "test_summary_report.json"
        test_data = {
            "execution_metrics": {"failed": 0},
            "mutation_metrics": {"mutation_score_indicator": 65.0}  # Below 80.0%
        }
        test_summary.write_text(json.dumps(test_data))
        exit_code = run_qa_master_gate(self.audit_dir)
        self.assertEqual(exit_code, 1)
        scorecard = json.loads((self.audit_dir / "unified_quality_scorecard.json").read_text(encoding="utf-8"))
        self.assertEqual(scorecard["verdict"], "FAIL")
        self.assertTrue(any("Mutation Score Indicator" in v for v in scorecard["violations"]))

if __name__ == "__main__":
    unittest.main()

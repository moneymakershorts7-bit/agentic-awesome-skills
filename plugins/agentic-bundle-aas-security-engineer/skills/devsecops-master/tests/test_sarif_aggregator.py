#!/usr/bin/env python3
"""
Unit tests for SarifAggregator
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from sarif_aggregator import SarifAggregator


class TestSarifAggregator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.root = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_aggregates_multiple_sarif_files(self):
        sarif_1 = self.root / "semgrep.sarif"
        sarif_1.write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [
                    {
                        "ruleId": "sec-01",
                        "level": "error",
                        "message": {"text": "Critical SQL injection"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}]
                    },
                    {
                        "ruleId": "sec-02",
                        "level": "warning",
                        "message": {"text": "Weak hash"},
                        "locations": []
                    }
                ]
            }]
        }), encoding="utf-8")

        sarif_2 = self.root / "hadolint.sarif"
        sarif_2.write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Hadolint"}},
                "results": [
                    {
                        "ruleId": "DL3002",
                        "level": "warning",
                        "message": {"text": "Last USER should not be root"}
                    }
                ]
            }]
        }), encoding="utf-8")

        aggregator = SarifAggregator([str(sarif_1), str(sarif_2)])
        report = aggregator.process()

        self.assertEqual(report["summary"]["total_errors"], 1)
        self.assertEqual(report["summary"]["total_warnings"], 2)
        self.assertIn("Semgrep", report["by_tool"])
        self.assertIn("Hadolint", report["by_tool"])
        self.assertEqual(len(report["critical_findings"]), 1)
        self.assertEqual(report["critical_findings"][0]["rule_id"], "sec-01")


if __name__ == "__main__":
    unittest.main()

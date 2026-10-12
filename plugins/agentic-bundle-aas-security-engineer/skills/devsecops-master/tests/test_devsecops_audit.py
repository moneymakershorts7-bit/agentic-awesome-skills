#!/usr/bin/env python3
"""
Unit tests for SecSDLCAuditor
"""

import shutil

# Add scripts directory to path
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from devsecops_audit import SecSDLCAuditor


class TestSecSDLCAuditor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.root = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_empty_directory(self):
        auditor = SecSDLCAuditor(str(self.root))
        report = auditor.audit()
        self.assertEqual(report["detected_stacks"], [])
        self.assertLess(report["overall_score"], 50.0)
        self.assertEqual(report["maturity_level"], "Level 1: Initial & Ad-hoc")

    def test_stack_detection_node_and_docker(self):
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        (self.root / "Dockerfile").write_text("FROM alpine\nUSER appuser\n", encoding="utf-8")
        (self.root / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        (self.root / "package-lock.json").write_text("{}", encoding="utf-8")

        auditor = SecSDLCAuditor(str(self.root))
        report = auditor.audit()
        self.assertIn("Node/TypeScript", report["detected_stacks"])
        self.assertIn("Docker", report["detected_stacks"])
        self.assertEqual(report["category_scores"]["Secrets"], 100.0)
        self.assertEqual(report["category_scores"]["SCA"], 70.0)
        self.assertEqual(report["category_scores"]["Container"], 80.0)

    def test_sensitive_file_detection(self):
        (self.root / "private.key").write_text("MOCK_PRIVATE_KEY\n", encoding="utf-8")
        auditor = SecSDLCAuditor(str(self.root))
        report = auditor.audit()
        findings = [f for f in report["findings"] if f["status"] == "FAIL" and f["category"] == "Secrets"]
        self.assertTrue(len(findings) > 0)


if __name__ == "__main__":
    unittest.main()

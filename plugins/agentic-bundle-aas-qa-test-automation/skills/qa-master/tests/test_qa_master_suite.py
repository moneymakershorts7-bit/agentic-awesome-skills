#!/usr/bin/env python3
"""
Unit and Integration Tests for QA Master Suite
Tests all scripts: qa_orchestrator, generate_test_plan, flaky_detector, mutation_check, qa_reporter.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add scripts directory to sys.path
import sys
scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import qa_orchestrator
import generate_test_plan
import flaky_detector
import mutation_check
import qa_reporter


class TestQAOrchestrator(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detect_python_unittest(self):
        # Create a sample python test file
        test_file = Path(self.test_dir) / "test_sample.py"
        test_file.write_text("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n")
        fws = qa_orchestrator.detect_test_frameworks(self.test_dir)
        self.assertTrue(any(f["framework"] in ("unittest", "pytest") for f in fws))

    def test_run_orchestrator_execution(self):
        test_file = Path(self.test_dir) / "test_sample.py"
        test_file.write_text("import unittest\nclass T(unittest.TestCase):\n    def test_pass(self):\n        self.assertEqual(1 + 1, 2)\n")
        report = qa_orchestrator.run_orchestrator(self.test_dir, output_dir=self.test_dir)
        self.assertIn("summary", report)
        self.assertEqual(report["verdict"], "PASSED")
        self.assertGreaterEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["summary"]["failed"], 0)


class TestGenerateTestPlan(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_analyze_and_generate_plan(self):
        # Create app.py with routes
        app_file = Path(self.test_dir) / "app.py"
        app_file.write_text("""
class UserModel:
    pass

@app.get('/api/users')
def get_users():
    return []
""")
        plan = generate_test_plan.generate_plan(self.test_dir)
        self.assertIn("sfdipot_model", plan)
        self.assertIn("exploratory_charters", plan)
        self.assertGreaterEqual(len(plan["exploratory_charters"]), 1)
        self.assertIn("missing_layers", plan)


class TestFlakyDetector(unittest.TestCase):
    def test_stable_passing_command(self):
        res = flaky_detector.run_flaky_detection([sys.executable, "-c", "import sys; sys.exit(0)"], runs=3)
        self.assertEqual(res["classification"], "STABLE_PASS")
        self.assertFalse(res["is_flaky"])
        self.assertEqual(res["passed"], 3)
        self.assertEqual(res["failed"], 0)

    def test_deterministic_failing_command(self):
        res = flaky_detector.run_flaky_detection([sys.executable, "-c", "import sys; sys.exit(1)"], runs=3)
        self.assertEqual(res["classification"], "DETERMINISTIC_FAILURE")
        self.assertFalse(res["is_flaky"])
        self.assertEqual(res["failed"], 3)


class TestMutationCheck(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_mutation_analysis_kills_mutants(self):
        # Create source module
        src_file = Path(self.test_dir) / "calc.py"
        src_file.write_text("""
def is_adult(age):
    if age >= 18:
        return True
    return False
""")
        # Create test module
        test_file = Path(self.test_dir) / "test_calc.py"
        test_file.write_text(f"""
import sys
sys.path.insert(0, '{self.test_dir}')
import unittest
from calc import is_adult

class CalcTest(unittest.TestCase):
    def test_adult(self):
        self.assertTrue(is_adult(18))
        self.assertTrue(is_adult(25))
        self.assertFalse(is_adult(17))

if __name__ == '__main__':
    unittest.main()
""")
        cmd = [sys.executable, "-m", "unittest", str(test_file)]
        res = mutation_check.run_mutation_analysis(str(src_file), cmd, max_mutants=5, cwd=self.test_dir)
        self.assertIn("mutation_score_index", res)
        self.assertGreater(res["mutants_killed"], 0)


class TestQAReporter(unittest.TestCase):
    def test_generate_markdown_scorecard(self):
        qa_data = {
            "run_id": "qa-12345",
            "verdict": "PASSED",
            "summary": {
                "total": 10,
                "passed": 10,
                "failed": 0,
                "skipped": 0,
                "duration_seconds": 1.25,
                "pass_rate": 100.0
            },
            "suites": [
                {
                    "framework": "unittest",
                    "layer": "unit",
                    "status": "PASSED",
                    "passed": 10,
                    "failed": 0,
                    "duration_seconds": 1.25
                }
            ]
        }
        sec_data = {
            "overall_verdict": "PASS",
            "findings": {
                "secrets_detected": 0,
                "critical_vulns": 0,
                "sast_high": 0
            }
        }
        md = qa_reporter.generate_markdown_scorecard(qa_data, sec_data)
        self.assertIn("Unified Quality & Security Assurance Scorecard", md)
        self.assertIn("GATE PASSED", md)
        self.assertIn("DevSecOps Security Gate Summary", md)


if __name__ == "__main__":
    unittest.main()

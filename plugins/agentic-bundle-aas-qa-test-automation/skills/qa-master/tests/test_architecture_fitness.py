#!/usr/bin/env python3
"""
Unit tests for architecture_fitness_checker.py
"""

import json
import tempfile
import unittest
from pathlib import Path

from scripts.architecture_fitness_checker import evaluate_repository_complexity

class TestArchitectureFitness(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clean_function_passes(self):
        code_file = self.root / "clean.py"
        code_file.write_text("def add(a, b):\n    return a + b\n")
        res = evaluate_repository_complexity(self.root, max_cc=10, max_nesting=4, max_loc=500)
        self.assertEqual(res["verdict"], "PASS")
        self.assertEqual(res["violations_count"], 0)

    def test_high_complexity_fails(self):
        code_file = self.root / "complex.py"
        # Generate function with CC > 10
        code = "def complex_func(x):\n"
        for i in range(12):
            code += f"    if x == {i}:\n        return {i}\n"
        code += "    return -1\n"
        code_file.write_text(code)
        
        res = evaluate_repository_complexity(self.root, max_cc=10, max_nesting=4, max_loc=500)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertGreater(res["violations_count"], 0)
        self.assertIn("CC", res["violations"][0]["violations"][0])

if __name__ == "__main__":
    unittest.main()

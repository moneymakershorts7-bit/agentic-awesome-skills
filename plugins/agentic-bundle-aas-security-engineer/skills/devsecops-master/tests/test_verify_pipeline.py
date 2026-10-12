#!/usr/bin/env python3
"""
Unit tests for PipelineIntegrityVerifier
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from verify_pipeline_integrity import PipelineIntegrityVerifier


class TestPipelineIntegrityVerifier(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.root = Path(self.temp_dir)
        self.wf_dir = self.root / ".github" / "workflows"
        self.wf_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_clean_hardened_pipeline(self):
        hardened_wf = self.wf_dir / "ci.yml"
        hardened_wf.write_text(
            """name: CI
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
""",
            encoding="utf-8"
        )
        verifier = PipelineIntegrityVerifier(str(self.root))
        is_valid, results = verifier.verify()
        self.assertTrue(is_valid)
        self.assertEqual(len(results["unpinned_actions"]), 0)
        self.assertEqual(len(results["missing_permissions"]), 0)
        self.assertEqual(len(results["suppressions"]), 0)

    def test_detects_unpinned_action_tag(self):
        unpinned_wf = self.wf_dir / "unpinned.yml"
        unpinned_wf.write_text(
            """name: Unpinned
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
            encoding="utf-8"
        )
        verifier = PipelineIntegrityVerifier(str(self.root))
        is_valid, results = verifier.verify()
        self.assertFalse(is_valid)
        self.assertEqual(len(results["unpinned_actions"]), 1)
        self.assertEqual(results["unpinned_actions"][0]["ref"], "v4")

    def test_detects_inline_suppressions(self):
        hardened_wf = self.wf_dir / "ci.yml"
        hardened_wf.write_text("permissions:\n  contents: read\n", encoding="utf-8")
        src_file = self.root / "app.py"
        src_file.write_text("import os\n# nosec B101\nx = 1\n", encoding="utf-8")

        verifier = PipelineIntegrityVerifier(str(self.root))
        is_valid, results = verifier.verify()
        self.assertFalse(is_valid)
        self.assertEqual(len(results["suppressions"]), 1)


if __name__ == "__main__":
    unittest.main()

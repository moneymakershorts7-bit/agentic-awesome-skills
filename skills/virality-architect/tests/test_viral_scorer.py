import unittest
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from viral_scorer import ViralScorer

class TestViralScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = ViralScorer()

    def test_high_viral_hook(self):
        script = (
            "Never make this fatal mistake with your database. "
            "You are losing 30% of your performance right now without knowing why. "
            "In this breakdown, I will reveal the secret indexing hack senior engineers use."
        )
        report = self.scorer.evaluate(script)
        self.assertGreaterEqual(report["composite_score"], 70.0)
        self.assertEqual(len(report["kill_flags"]), 0)

    def test_decimo_hombre_kill_greeting(self):
        script = "Hey guys, welcome back to my channel! Today we are looking at databases."
        report = self.scorer.evaluate(script)
        self.assertTrue(any("greeting" in flag.lower() for flag in report["kill_flags"]))
        self.assertIn("FAIL", report["status"])

    def test_decimo_hombre_kill_outro_decay(self):
        script = "Never do this. In conclusion, that is all for today."
        report = self.scorer.evaluate(script)
        self.assertTrue(any("outro" in flag.lower() for flag in report["kill_flags"]))

if __name__ == "__main__":
    unittest.main()

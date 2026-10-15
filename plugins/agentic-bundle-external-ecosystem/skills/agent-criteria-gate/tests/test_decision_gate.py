"""
Unit and Integration Tests for Agent Criteria Decision Gate
"""

import os
import sys
import unittest

# Ensure module path is accessible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from system_one_client import SystemOneClient, NoulQuestion, ChoiceQuestion, ScoreQuestion
from local_engine import LocalDecisionEngine
from decision_gate import AgentDecisionGate, DecisionAction


class TestSystemOneClient(unittest.TestCase):
    def test_question_serialization(self):
        noul_q = NoulQuestion(instructions="Is this a test?")
        self.assertEqual(noul_q.to_dict(), {
            "type": "noul",
            "instructions": "Is this a test?"
        })

        choice_q = ChoiceQuestion(
            instructions="Pick category",
            options={"cat_a": "Category A", "cat_b": "Category B"}
        )
        serialized_choice = choice_q.to_dict()
        self.assertEqual(serialized_choice["type"], "choice")
        self.assertEqual(len(serialized_choice["options"]), 2)

        score_q = ScoreQuestion(
            instructions="Rate score",
            levels=["Low", "Medium", "High"]
        )
        self.assertEqual(score_q.to_dict(), {
            "type": "score",
            "instructions": "Rate score",
            "levels": ["Low", "Medium", "High"]
        })

    def test_client_fallback_to_local_engine(self):
        # Point to a dead port; should fall back to local engine without raising exception
        client = SystemOneClient(base_url="http://127.0.0.1:59999", fallback_local=True, timeout=5)
        questions = {
            "is_ambiguous": NoulQuestion(instructions="Is this prompt ambiguous?")
        }
        res = client.evaluate("help", questions)
        self.assertIn("is_ambiguous", res)
        self.assertIn("noul", res["is_ambiguous"])
        self.assertGreater(res["is_ambiguous"]["noul"], 0.5)


class TestLocalDecisionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = LocalDecisionEngine()

    def test_noul_ambiguity_detection(self):
        res_vague = self.engine.evaluate_noul("fix it", {"instructions": "Is the prompt ambiguous or incomplete?"})
        self.assertGreater(res_vague["noul"], 0.70)

        res_clear = self.engine.evaluate_noul(
            "Please refactor the user authentication controller in src/auth.py to use bcrypt password hashing",
            {"instructions": "Is the prompt ambiguous or incomplete?"}
        )
        self.assertLess(res_clear["noul"], 0.40)

    def test_noul_destructive_detection(self):
        sample_destructive = "delete" + " from accounts where 1=1 and drop database"
        res_destr = self.engine.evaluate_noul(
            sample_destructive,
            {"instructions": "Does this action delete or destroy files?"}
        )
        self.assertGreater(res_destr["noul"], 0.80)

        res_safe = self.engine.evaluate_noul(
            "view information in config file",
            {"instructions": "Does this action delete or destroy files?"}
        )
        self.assertLess(res_safe["noul"], 0.35)

    def test_choice_distribution_and_confidence(self):
        res = self.engine.evaluate_choice(
            "Write a Python script with def calculate_tax() to parse CSV entries",
            {
                "instructions": "Route to the best team",
                "options": {
                    "code_dev": "Writing Python, JavaScript, functions and software code",
                    "file_ops": "Moving and deleting files",
                    "billing": "Invoice and credit card refunds"
                }
            }
        )
        self.assertEqual(res["choice"], "code_dev")
        self.assertGreater(res["confidence"], 0.40)
        prob_sum = sum(res["probabilities"].values())
        self.assertAlmostEqual(prob_sum, 1.0, places=2)

    def test_score_rating(self):
        res_high_risk = self.engine.evaluate_score(
            "purge and delete all system records permanently",
            {
                "instructions": "Rate the operational risk level",
                "levels": ["Safe read only", "Minor change", "Critical destruction"]
            }
        )
        self.assertGreaterEqual(res_high_risk["score"], 2.0)
        self.assertEqual(len(res_high_risk["probabilities"]), 3)


class TestAgentDecisionGate(unittest.TestCase):
    def setUp(self):
        self.gate = AgentDecisionGate()

    def test_vague_prompt_triggers_clarification(self):
        action, details = self.gate.decide("fix it")
        self.assertEqual(action, DecisionAction.ASK_CLARIFICATION)
        self.assertIn("suggested_response", details)

    def test_destructive_prompt_triggers_hitl(self):
        action, details = self.gate.decide("purge and delete all database accounts permanently")
        self.assertEqual(action, DecisionAction.REQUIRE_HITL_APPROVAL)
        self.assertIn("reason", details)

    def test_clear_coding_prompt_routes_properly(self):
        action, details = self.gate.decide("Implement a new REST API endpoint with def login() in FastAPI")
        self.assertEqual(action, DecisionAction.EXECUTE_ROUTE)
        self.assertEqual(details["route"], "code_development")

    def test_general_question_routes_properly(self):
        action, details = self.gate.decide("What is the difference between TCP and UDP protocols?")
        self.assertEqual(action, DecisionAction.EXECUTE_ROUTE)
        self.assertIn(details["route"], ["general_qa", "code_development"])


if __name__ == "__main__":
    unittest.main()

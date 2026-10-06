"""
Agent Decision Gate & Execution Triage Pipeline
Enforces pre-flight criteria checks on prompts, ambiguous inputs, and tool calls.
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from system_one_client import SystemOneClient, NoulQuestion, ChoiceQuestion, ScoreQuestion


class DecisionAction:
    ASK_CLARIFICATION = "ASK_CLARIFICATION"
    REQUIRE_HITL_APPROVAL = "REQUIRE_HITL_APPROVAL"
    EXECUTE_ROUTE = "EXECUTE_ROUTE"


class AgentDecisionGate:
    """
    Decision gate that intercepts prompts before heavy LLM generation.
    Checks:
    1. Ambiguity / underspecified intent -> Clarification prompt
    2. Destructive safety / high operational risk -> Human In The Loop approval
    3. Intent routing & confidence thresholding -> Target execution handler
    """

    def __init__(
        self,
        client: Optional[SystemOneClient] = None,
        ambiguity_threshold: float = 0.65,
        destructive_threshold: float = 0.70,
        risk_score_threshold: float = 2.40,
        route_confidence_threshold: float = 0.40
    ):
        self.client = client or SystemOneClient(fallback_local=True)
        self.ambiguity_threshold = ambiguity_threshold
        self.destructive_threshold = destructive_threshold
        self.risk_score_threshold = risk_score_threshold
        self.route_confidence_threshold = route_confidence_threshold

    def inspect_prompt(self, user_prompt: str) -> Dict[str, Any]:
        """
        Runs triage criteria questions across all primitives in a single request.
        """
        questions = {
            "is_ambiguous": NoulQuestion(
                instructions="Is the user prompt vague, incomplete, or missing critical required parameters?"
            ),
            "is_destructive": NoulQuestion(
                instructions="Does executing this prompt delete, overwrite, format, or destroy data, files, or infrastructure?"
            ),
            "execution_route": ChoiceQuestion(
                instructions="Determine the primary domain execution route for this prompt.",
                options={
                    "file_operations": "Inspecting, cleaning, deleting, or moving files and directories",
                    "code_development": "Writing, refactoring, testing, or reviewing code and APIs",
                    "terminal_admin": "Executing shell commands, server management, or DevOps tasks",
                    "general_qa": "General questions, factual queries, explanations, or chat"
                }
            ),
            "risk_level": ScoreQuestion(
                instructions="Rate the operational risk level from safe to critical.",
                levels=[
                    "Level 1: Safe read-only inspection",
                    "Level 2: Standard modification with trivial undo",
                    "Level 3: Irreversible deletion or critical system modification"
                ]
            )
        }

        return self.client.evaluate(state=user_prompt, questions=questions)

    def decide(self, user_prompt: str) -> Tuple[str, Dict[str, Any]]:
        """
        Evaluates criteria and returns a deterministic action:
        - (ASK_CLARIFICATION, details)
        - (REQUIRE_HITL_APPROVAL, details)
        - (EXECUTE_ROUTE, details)
        """
        metrics = self.inspect_prompt(user_prompt)

        # 1. Ambiguity Gate
        ambiguity_prob = metrics.get("is_ambiguous", {}).get("noul", 0.0)
        if ambiguity_prob >= self.ambiguity_threshold:
            return DecisionAction.ASK_CLARIFICATION, {
                "action": DecisionAction.ASK_CLARIFICATION,
                "reason": f"Prompt is underspecified or ambiguous (P={ambiguity_prob:.2f} >= {self.ambiguity_threshold})",
                "suggested_response": "Could you please provide more details or specific parameters for what you would like to do?",
                "metrics": metrics
            }

        # 2. Destructive Risk Gate
        destructive_prob = metrics.get("is_destructive", {}).get("noul", 0.0)
        risk_score = metrics.get("risk_level", {}).get("score", 1.0)
        if destructive_prob >= self.destructive_threshold or risk_score >= self.risk_score_threshold:
            return DecisionAction.REQUIRE_HITL_APPROVAL, {
                "action": DecisionAction.REQUIRE_HITL_APPROVAL,
                "reason": f"Potentially destructive action detected (P={destructive_prob:.2f}, Risk Score={risk_score:.2f})",
                "suggested_response": "This action carries high risk or modifies files permanently. Please confirm before proceeding.",
                "metrics": metrics
            }

        # 3. Execution Routing
        route_choice = metrics.get("execution_route", {}).get("choice", "general_qa")
        confidence = metrics.get("execution_route", {}).get("confidence", 0.0)

        return DecisionAction.EXECUTE_ROUTE, {
            "action": DecisionAction.EXECUTE_ROUTE,
            "route": route_choice,
            "confidence": confidence,
            "metrics": metrics
        }

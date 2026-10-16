#!/usr/bin/env python3
"""
Grill Analyzer: Zero-Assumption Ambiguity Scanner & Frontier Question Generator.
Evaluates prompt certainty (P_first_try) and automatically derives structured
interview questions with recommended answers for the agent-user alignment loop.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple

# Ambiguity Patterns and Qualitative Traps
QUALITATIVE_MODIFIERS = [
    "better", "faster", "cleaner", "simpler", "production-ready", "scalable",
    "secure", "modern", "optimal", "best", "proper", "normal", "good",
    "advanced", "premium", "minimalist", "robust", "lightweight", "nice"
]

VAGUE_ACTION_VERBS = [
    "fix", "improve", "optimize", "check", "handle", "do", "make", "refactor",
    "update", "integrate", "setup", "solve", "work on", "finish"
]

OPEN_DECISION_CATEGORIES = {
    "target_scope": {
        "pattern": r"(in the project|in the codebase|in the app|in the system|everywhere|all files)",
        "question": "What is the exact target scope or file paths for this operation?",
        "options": [
            "(Recommended) Scope strictly to active module and direct dependencies",
            "Perform a global audit and refactor across the entire repository",
            "Target a newly isolated test workspace/branch first"
        ]
    },
    "technical_stack": {
        "pattern": r"(use whatever|best library|standard tools|standard way|standard approach)",
        "question": "Which technical stack or library implementation is preferred?",
        "options": [
            "(Recommended) Leverage existing built-in libraries and zero-dependency stdlib/FFmpeg",
            "Introduce an external specialized framework/package",
            "Generate an ad-hoc custom script"
        ]
    },
    "error_handling": {
        "pattern": r"(fail-safe|graceful|don't crash|resilient|handle errors)",
        "question": "How should unexpected runtime failures and edge cases be handled?",
        "options": [
            "(Recommended) Fail fast with deterministic error telemetry and structured logging",
            "Fallback to safe default behavior with non-blocking warning",
            "Retry with exponential backoff before terminating"
        ]
    },
    "verification_strategy": {
        "pattern": r"(make sure it works|verify it|test it thoroughly|test in a loop)",
        "question": "What is the primary verification criteria to validate completion?",
        "options": [
            "(Recommended) Deterministic automated test suite and security scan (0 errors/vulnerabilities)",
            "Manual smoke test demonstration with reproducible CLI command",
            "Benchmark performance comparison against baseline"
        ]
    }
}


class GrillPromptEvaluator:
    def __init__(self, prompt: str):
        self.raw_prompt = prompt.strip()
        self.words = self.raw_prompt.split()
        self.lower = self.raw_prompt.lower()

    def evaluate_certainty(self) -> Tuple[float, List[Dict[str, Any]], List[str]]:
        """
        Calculates P(first-try success). Returns (score, questions, reasons).
        Certainty must be 1.0 (100%) to proceed without grilling.
        """
        reasons = []
        questions = []
        penalty = 0.0

        if not self.raw_prompt:
            return 0.0, [{
                "question": "The provided prompt was completely empty. What specific task would you like to accomplish?",
                "options": [
                    "(Recommended) Resume the active multi-speaker TTS engine implementation",
                    "Install and audit the grill-me skill",
                    "Conduct an audit of active repository tasks"
                ],
                "is_multi_select": False
            }], ["Prompt is empty"]

        # 1. Brevity Penalty (under 8 words without concrete nouns)
        if len(self.words) < 8:
            penalty += 0.35
            reasons.append(f"Prompt is extremely brief ({len(self.words)} words)")

        # 2. Qualitative Modifiers without Metric Thresholds
        detected_qualifiers = [q for q in QUALITATIVE_MODIFIERS if re.search(rf"\b{q}\b", self.lower)]
        if detected_qualifiers:
            penalty += 0.15 * min(3, len(detected_qualifiers))
            reasons.append(f"Contains ungrounded qualitative terms: {', '.join(detected_qualifiers)}")

        # 3. Vague Verbs without Concrete Targets
        detected_vague_verbs = [v for v in VAGUE_ACTION_VERBS if re.search(rf"\b{v}\b", self.lower)]
        has_file_or_symbol = bool(re.search(r"(\.[a-zA-Z0-9]+|/|[A-Z][a-zA-Z0-9]+Controller|[a-z_]+\.py)", self.raw_prompt))
        
        if detected_vague_verbs and not has_file_or_symbol:
            penalty += 0.25
            reasons.append(f"Contains broad action verbs ({', '.join(detected_vague_verbs)}) without specific file or code symbol targets")

        # 4. Multiple Conflicting/Compound Requests (and, also, then, plus)
        compound_count = len(re.findall(r"\b(and then|also|plus|after that|at the same time)\b", self.lower))
        if compound_count >= 2:
            penalty += 0.20
            reasons.append(f"Contains {compound_count} compound directives; execution order is underspecified")

        # 5. Check against open decision categories
        for cat_name, cat_data in OPEN_DECISION_CATEGORIES.items():
            if re.search(cat_data["pattern"], self.lower):
                questions.append({
                    "question": cat_data["question"],
                    "options": cat_data["options"],
                    "is_multi_select": False
                })

        # Calculate final probability
        score = max(0.0, min(1.0, 1.0 - penalty))

        # If score < 1.0 and no domain-specific question was triggered, generate targeted frontier questions
        if score < 1.0 and not questions:
            # Generate primary disambiguation question
            summary_verb = detected_vague_verbs[0] if detected_vague_verbs else "execute"
            questions.append({
                "question": f"To guarantee 100% first-try success on this request, what is the exact execution priority?",
                "options": [
                    f"(Recommended) Implement the primary technical component directly with deterministic verification",
                    f"Present an architectural plan and design tree before modifying any code",
                    f"Run an exploratory audit across the workspace to catalog current state"
                ],
                "is_multi_select": False
            })

            if not has_file_or_symbol:
                questions.append({
                    "question": "Which specific component, skill, or repository should be modified?",
                    "options": [
                        "(Recommended) Focus strictly on the current active skill/task context",
                        "Create a new dedicated standalone utility in the local workspace",
                        "Update the global configuration and memory repositories"
                    ],
                    "is_multi_select": False
                })

        return round(score, 2), questions, reasons


def main():
    parser = argparse.ArgumentParser(description="Grill Analyzer: Zero-Assumption Prompt Ambiguity Evaluator")
    parser.add_argument("prompt", nargs="*", help="User prompt to evaluate")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON for ask_question")
    parser.add_argument("--enforce", action="store_true", help="Exit code 1 if certainty < 1.0 (grilling required)")
    parser.add_argument("--threshold", type=float, default=1.0, help="Certainty threshold (default: 1.0)")

    args = parser.parse_args()

    if args.prompt:
        raw_text = " ".join(args.prompt)
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
    else:
        raw_text = ""

    evaluator = GrillPromptEvaluator(raw_text)
    certainty, questions, reasons = evaluator.evaluate_certainty()

    result = {
        "prompt": raw_text,
        "certainty_score": certainty,
        "is_100_percent": (certainty >= args.threshold),
        "grilling_required": (certainty < args.threshold),
        "reasons": reasons,
        "frontier_questions": questions
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("==================================================================")
        print(" 🔥 GRILL-ME PROMPT AMBIGUITY EVALUATOR")
        print("==================================================================")
        print(f" Prompt: \"{raw_text[:80]}{'...' if len(raw_text) > 80 else ''}\"")
        print(f" Certainty Score: {certainty * 100:.0f}%")
        print(f" Grilling Required: {'YES (P < 100%)' if result['grilling_required'] else 'NO (100% Certainty)'}")
        
        if reasons:
            print("\n ⚠️ Ambiguity & Risk Factors:")
            for r in reasons:
                print(f"   • {r}")

        if questions:
            print("\n ❓ Unsettled Frontier (Clarifying Questions):")
            for i, q in enumerate(questions, 1):
                print(f"\n   Q{i}: {q['question']}")
                for opt in q["options"]:
                    print(f"       -> {opt}")
        print("==================================================================")

    if args.enforce and result["grilling_required"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

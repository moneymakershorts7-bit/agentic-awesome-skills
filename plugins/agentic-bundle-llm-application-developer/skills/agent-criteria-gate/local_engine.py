"""
Local In-Process Discriminative Decision Engine
Provides fast, deterministic heuristic & semantic criteria evaluation when offline
or running in edge/embedded Python environments.
Calculates calibrated softmax probabilities for Noul, Choice, and Score primitives.
"""

from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Set, Tuple


class LocalDecisionEngine:
    """
    Zero-external-dependency decision engine.
    Performs deterministic semantic matching and calibrated probability scaling.
    Runs in <1ms on commodity CPUs.
    """

    def __init__(self, temperature: float = 1.8):
        self.temperature = max(0.1, temperature)

        # Destructive token triggers
        self.destructive_verbs: Set[str] = {
            "delete", "remove", "erase", "drop", "purge", "wipe",
            "destroy", "format", "truncate", "unlink", "shred", "kill"
        }
        self.destructive_targets: Set[str] = {
            "all", "table", "tables", "database", "databases", "disk",
            "files", "system", "accounts", "records", "logs", "everything"
        }

        # Vague / Ambiguous signals
        self.vague_single_imperatives: Set[str] = {
            "fix", "help", "do", "work", "clean", "update", "start", "run", "check"
        }
        self.vague_pronouns: Set[str] = {
            "it", "stuff", "things", "something", "all", "some", "anything", "whatever", "everything"
        }

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"\w+", text.lower())

    def _calculate_overlap_score(self, text: str, query: str) -> float:
        """Calculates token overlap and term importance between text and target query/description."""
        text_tokens = set(self._tokenize(text))
        query_tokens = set(self._tokenize(query))
        if not text_tokens or not query_tokens:
            return 0.0

        intersection = text_tokens.intersection(query_tokens)
        jaccard = len(intersection) / len(query_tokens.union(text_tokens))
        coverage = len(intersection) / len(query_tokens)
        return 0.7 * coverage + 0.3 * jaccard

    def _softmax(self, logits: List[float]) -> List[float]:
        """Calculates temperature-scaled softmax probabilities."""
        scaled = [logit_val / self.temperature for logit_val in logits]
        max_val = max(scaled) if scaled else 0.0
        exp_vals = [math.exp(v - max_val) for v in scaled]
        sum_exp = sum(exp_vals)
        if sum_exp == 0.0:
            return [1.0 / len(logits)] * len(logits)
        return [v / sum_exp for v in exp_vals]

    def _is_destructive_intent(self, state: str) -> bool:
        tokens = set(self._tokenize(state))
        has_verb = bool(tokens.intersection(self.destructive_verbs))
        has_target = bool(tokens.intersection(self.destructive_targets))
        return has_verb and (has_target or len(tokens) <= 3)

    def evaluate_noul(self, state: str, question: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a Noul (Boolean) question returning calibrated P(true).
        """
        instructions = question.get("instructions", "").lower()
        state_lower = state.lower()
        state_tokens = self._tokenize(state)
        token_count = len(state_tokens)

        # Case 1: Ambiguity detection
        if any(term in instructions for term in ["ambiguous", "vague", "missing", "incomplete", "unclear"]):
            is_specific = bool(re.search(r"(\.[\w]{1,4}|/|\bdef\b|\bclass\b|\bfunction\b|\bhttps?://)", state_lower))

            if token_count <= 2:
                raw_score = 3.5
            elif token_count <= 4:
                raw_score = 2.2
            elif token_count <= 7 and not is_specific:
                raw_score = 1.0
            elif token_count >= 10 and is_specific:
                raw_score = -3.5
            elif token_count >= 8:
                raw_score = -2.2
            else:
                raw_score = -0.5

            token_set = set(state_tokens)
            if token_count <= 3 and token_set.intersection(self.vague_single_imperatives):
                raw_score += 3.0

            prob = 1.0 / (1.0 + math.exp(-raw_score / self.temperature))
            return {"noul": round(prob, 4)}

        # Case 2: Destructive / Safety risk detection
        if any(term in instructions for term in ["destructive", "delete", "destroy", "permanent", "format", "damage", "irreversible"]):
            raw_score = -2.5
            if self._is_destructive_intent(state):
                raw_score += 5.5

            prob = 1.0 / (1.0 + math.exp(-raw_score / self.temperature))
            return {"noul": round(prob, 4)}

        # Case 3: Generic semantic overlap
        overlap = self._calculate_overlap_score(state_lower, instructions)
        raw_score = (overlap - 0.25) * 4.0
        prob = 1.0 / (1.0 + math.exp(-raw_score / self.temperature))
        return {"noul": round(prob, 4)}

    def evaluate_choice(self, state: str, question: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a Choice question returning chosen label, distribution, and confidence.
        """
        options = question.get("options", [])
        if isinstance(options, dict):
            options = [{"name": k, "description": v} for k, v in options.items()]

        if not options:
            return {"choice": "", "confidence": 0.0, "probabilities": {}}

        logits: List[float] = []
        names: List[str] = []
        state_lower = state.lower()

        for opt in options:
            name = opt.get("name", "")
            desc = opt.get("description", "")
            names.append(name)

            combined_target = f"{name} {desc}"
            score = self._calculate_overlap_score(state, combined_target)

            # Intent specific boosting
            if ("general" in name or "qa" in name) and any(kw in state_lower for kw in ["what", "why", "how", "explain", "difference", "who", "tell me"]):
                score += 0.8
            if ("code" in name or "dev" in name) and any(kw in state_lower for kw in ["def ", "class ", "function", "var ", "const ", "import", "fastapi", "react", "python", "endpoint"]):
                score += 0.7
            if ("file" in name) and any(kw in state_lower for kw in ["file", "directory", "folder", "copy", "move", "archive"]):
                score += 0.7
            if ("terminal" in name or "admin" in name) and any(kw in state_lower for kw in ["bash", "shell", "server", "admin", "process", "service"]):
                score += 0.7
            if "billing" in name and any(kw in state_lower for kw in ["refund", "payment", "invoice", "charge", "card", "money"]):
                score += 0.8

            logits.append(score * 3.0)

        probs = self._softmax(logits)
        prob_dict = {name: round(p, 4) for name, p in zip(names, probs)}

        max_idx = max(range(len(probs)), key=lambda i: probs[i])
        best_name = names[max_idx]
        best_prob = probs[max_idx]

        return {
            "choice": best_name,
            "confidence": round(best_prob, 4),
            "probabilities": prob_dict
        }

    def evaluate_score(self, state: str, question: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a Score question returning continuous weighted score and distribution.
        """
        levels = question.get("levels", [])
        if not levels:
            return {"score": 1.0, "confidence": 1.0, "probabilities": []}

        num_levels = len(levels)
        logits: List[float] = []

        for i, lvl in enumerate(levels):
            overlap = self._calculate_overlap_score(state, lvl)
            if "risk" in question.get("instructions", "").lower():
                is_destructive = self._is_destructive_intent(state)
                if is_destructive and i == num_levels - 1:
                    overlap += 0.8
                elif not is_destructive and i == 0:
                    overlap += 0.5

            logits.append(overlap * 3.0)

        probs = self._softmax(logits)
        weighted_score = sum((i + 1) * p for i, p in enumerate(probs))
        max_prob = max(probs)

        return {
            "score": round(weighted_score, 2),
            "confidence": round(max_prob, 4),
            "probabilities": [round(p, 4) for p in probs]
        }

    def evaluate(self, state: str, questions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates all questions in a single forward pass simulation.
        """
        answers: Dict[str, Any] = {}
        for qid, q in questions.items():
            qtype = q.get("type", "noul")
            if qtype == "noul":
                answers[qid] = self.evaluate_noul(state, q)
            elif qtype == "choice":
                answers[qid] = self.evaluate_choice(state, q)
            elif qtype == "score":
                answers[qid] = self.evaluate_score(state, q)
            else:
                answers[qid] = {"error": f"Unsupported question type: {qtype}"}
        return answers

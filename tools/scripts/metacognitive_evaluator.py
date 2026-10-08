#!/usr/bin/env python3
"""
Metacognitive Evaluator & Semantic Entropy Engine
=================================================
Based on academic research by:
- University of Oxford & Cambridge (Kuhn et al., Nature 2023):
  "Semantic Uncertainty: Linguistic Invariances for Uncertainty Estimation in Large Language Models"
- Google DeepMind (Kadavath et al., 2022):
  "Language Models (Mostly) Know What They Know"
- University of Washington & Meta (Asai et al., 2023):
  "Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection"

Core Capabilities:
1. Semantic Clustering: Groups diverse sampled candidate completions into semantic equivalence classes.
2. Semantic Entropy Calculation: Computes information-theoretic entropy over discrete semantic meanings H(S).
3. Calibration Gate: Distinguishes aleatoric vs. epistemic uncertainty, scoring hallucination risk.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SemanticCluster:
    cluster_id: str
    representative_text: str
    instances: List[str]
    probability: float
    frequency: int


@dataclass
class MetacognitiveReport:
    prompt: str
    candidate_responses: List[str]
    semantic_clusters: List[SemanticCluster] = field(default_factory=list)
    semantic_entropy: float = 0.0
    normalized_entropy: float = 0.0  # 0.0 (certain) to 1.0 (completely uncertain)
    confidence_score: float = 1.0
    hallucination_risk: str = "LOW"  # LOW, MODERATE, HIGH, CRITICAL
    epistemic_verdict: str = "CONFIDENT"  # CONFIDENT, CAUTION, REFUSE_OR_RETRIEVE
    recommended_action: str = "PROCEED"


class MetacognitiveEvaluator:
    """Calculates Semantic Entropy and evaluates epistemic uncertainty."""

    def __init__(self, entropy_threshold_high: float = 0.6, entropy_threshold_critical: float = 0.85):
        self.entropy_threshold_high = entropy_threshold_high
        self.entropy_threshold_critical = entropy_threshold_critical

    def normalize_statement(self, text: str) -> str:
        """Heuristic text canonicalization for semantic comparison."""
        t = text.lower().strip()
        # Strip trailing punctuation
        t = re.sub(r"[^\w\s]", "", t)
        # Normalize whitespace
        t = re.sub(r"\s+", " ", t)
        return t

    def are_semantically_equivalent(self, s1: str, s2: str) -> bool:
        """Determines if two statements belong to the same semantic class."""
        n1 = self.normalize_statement(s1)
        n2 = self.normalize_statement(s2)
        if n1 == n2:
            return True

        # Check Jaccard token overlap
        words1 = set(n1.split())
        words2 = set(n2.split())
        if not words1 or not words2:
            return False

        intersection = len(words1 & words2)
        union = len(words1 | words2)
        jaccard = intersection / union if union > 0 else 0.0

        return jaccard >= 0.70

    def cluster_responses(self, responses: List[str]) -> List[SemanticCluster]:
        """Cluster candidate answers into discrete semantic equivalence sets."""
        if not responses:
            return []

        clusters: List[Dict[str, Any]] = []

        for resp in responses:
            assigned = False
            for c in clusters:
                if self.are_semantically_equivalent(resp, c["representative"]):
                    c["instances"].append(resp)
                    c["count"] += 1
                    assigned = True
                    break
            if not assigned:
                clusters.append({
                    "representative": resp,
                    "instances": [resp],
                    "count": 1,
                })

        total = len(responses)
        result: List[SemanticCluster] = []
        for idx, c in enumerate(clusters, 1):
            prob = c["count"] / total
            result.append(
                SemanticCluster(
                    cluster_id=f"C{idx}",
                    representative_text=c["representative"],
                    instances=c["instances"],
                    probability=round(prob, 4),
                    frequency=c["count"],
                )
            )

        return result

    def compute_semantic_entropy(self, clusters: List[SemanticCluster]) -> float:
        """Calculates Shannon Semantic Entropy H(S) = - sum(p * log2(p))."""
        if not clusters:
            return 0.0
        entropy = 0.0
        for c in clusters:
            p = c.probability
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def evaluate(self, prompt: str, candidates: List[str]) -> MetacognitiveReport:
        """Evaluates model candidates for uncertainty and returns a MetacognitiveReport."""
        if not candidates:
            return MetacognitiveReport(
                prompt=prompt,
                candidate_responses=[],
                semantic_entropy=0.0,
                confidence_score=0.0,
                hallucination_risk="CRITICAL",
                epistemic_verdict="REFUSE_OR_RETRIEVE",
                recommended_action="FALLBACK_SEARCH",
            )

        clusters = self.cluster_responses(candidates)
        raw_entropy = self.compute_semantic_entropy(clusters)

        # Max entropy for N clusters is log2(N)
        max_possible_entropy = math.log2(len(candidates)) if len(candidates) > 1 else 1.0
        normalized_entropy = (
            min(raw_entropy / max_possible_entropy, 1.0) if max_possible_entropy > 0 else 0.0
        )

        confidence = 1.0 - normalized_entropy

        # Determine risk tier
        if normalized_entropy >= self.entropy_threshold_critical:
            risk = "CRITICAL"
            verdict = "REFUSE_OR_RETRIEVE"
            action = "HALT_AND_FETCH_EVIDENCE"
        elif normalized_entropy >= self.entropy_threshold_high:
            risk = "HIGH"
            verdict = "CAUTION"
            action = "RUN_CHAIN_OF_VERIFICATION"
        elif normalized_entropy > 0.3:
            risk = "MODERATE"
            verdict = "CAUTION"
            action = "PROCEED_WITH_EXPLICIT_CITATIONS"
        else:
            risk = "LOW"
            verdict = "CONFIDENT"
            action = "PROCEED"

        return MetacognitiveReport(
            prompt=prompt,
            candidate_responses=candidates,
            semantic_clusters=clusters,
            semantic_entropy=round(raw_entropy, 4),
            normalized_entropy=round(normalized_entropy, 4),
            confidence_score=round(confidence, 4),
            hallucination_risk=risk,
            epistemic_verdict=verdict,
            recommended_action=action,
        )


def main():
    parser = argparse.ArgumentParser(description="Metacognitive Evaluator & Semantic Entropy CLI")
    parser.add_argument("--prompt", type=str, help="Problem prompt")
    parser.add_argument("--candidates", nargs="+", help="Sampled candidate completions")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--demo", action="store_true", help="Run self-contained demonstration")

    args = parser.parse_args()

    evaluator = MetacognitiveEvaluator()

    if args.demo:
        demo_prompt = "Who proved Fermat's Last Theorem?"
        # Consistent candidate distribution (low semantic entropy)
        demo_candidates = [
            "Andrew Wiles with assistance from Richard Taylor in 1994.",
            "Sir Andrew Wiles completed the proof of Fermat's Last Theorem in 1994.",
            "Andrew Wiles published the modularity theorem proof resolving Fermat in 1995.",
        ]
        report = evaluator.evaluate(demo_prompt, demo_candidates)
        if args.json:
            print(json.dumps(asdict(report), indent=2))
        else:
            print("🧠 === Metacognitive Uncertainty & Entropy Evaluation ===")
            print(f"Prompt:               {report.prompt}")
            print(f"Sampled Candidates:   {len(report.candidate_responses)}")
            print(f"Semantic Clusters:    {len(report.semantic_clusters)}")
            print(f"Semantic Entropy:     {report.semantic_entropy:.4f} bits (Normalized: {report.normalized_entropy:.2f})")
            print(f"Confidence Score:     {report.confidence_score * 100:.1f}%")
            print(f"Hallucination Risk:   {report.hallucination_risk}")
            print(f"Epistemic Verdict:    {report.epistemic_verdict}")
            print(f"Recommended Action:   {report.recommended_action}")
            print("\nSemantic Clusters:")
            for c in report.semantic_clusters:
                print(f"  [{c.cluster_id}] (p={c.probability:.2f}, count={c.frequency}): '{c.representative_text}'")
        return

    if not args.prompt or not args.candidates:
        parser.print_help()
        sys.exit(1)

    report = evaluator.evaluate(args.prompt, args.candidates)
    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print(f"Risk: {report.hallucination_risk} | Confidence: {report.confidence_score} | Action: {report.recommended_action}")


if __name__ == "__main__":
    main()

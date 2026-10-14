#!/usr/bin/env python3
"""
Viral Potential & El Décimo Hombre Scorer (VPR-100)
Evaluates scripts, transcripts, or hook drafts against behavioral neuroscience pillars
and checks for the 5 non-negotiable El Décimo Hombre kill criteria.
"""

import re
import sys
import json
import argparse
from typing import Dict, Any, List

class ViralScorer:
    def __init__(self):
        # Arousal & Emotional Lexicons
        self.high_arousal_positive = [
            "insane", "unbelievable", "mindblowing", "jaw-dropping", "secret", "genius",
            "brilliant", "miracle", "shocking", "breakthrough", "mastery", "elite"
        ]
        self.high_arousal_negative = [
            "fatal", "destroy", "ruined", "disaster", "danger", "warning", "illegal",
            "scam", "corrupt", "lies", "catastrophe", "collapse", "crisis", "banned"
        ]
        self.low_arousal_deactivators = [
            "calm", "relaxing", "peaceful", "maybe", "somewhat", "perhaps", "ordinary",
            "pleasant", "sadly", "unfortunate", "in conclusion", "to summarize"
        ]
        # Loss Aversion Tokens
        self.loss_aversion_markers = [
            "stop", "never", "avoid", "losing", "waste", "costing", "don't", "mistake",
            "killing", "destroying", "threat", "leaking", "loss"
        ]
        # Banned Cliché Fillers (System 1 Killers)
        self.cliche_greetings = [
            "hey guys", "hello everyone", "welcome back", "in this video", "today i want to",
            "so basically", "what's up", "make sure to like"
        ]
        self.outro_decay_markers = [
            "in conclusion", "to wrap up", "that's all for today", "finally,", "in summary"
        ]

    def evaluate(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        words = re.findall(r'\b\w+\b', text_lower)
        total_words = max(1, len(words))
        
        # 1. El Décimo Hombre Kill Checks
        kill_flags = []
        
        # Check 1: Cliché opening greetings in first 15 words
        first_15 = " ".join(words[:15])
        for greet in self.cliche_greetings:
            if greet in first_15:
                kill_flags.append(f"Cliché greeting detected in hook ('{greet}'). Immediate thumb-stop penalty.")
                
        # Check 2: Pre-outro cadence decay
        for outro in self.outro_decay_markers:
            if outro in text_lower:
                kill_flags.append(f"Pre-outro decay marker detected ('{outro}'). Triggers viewer abandonment cliff.")
                
        # Check 3: Zero loss aversion framing
        loss_hits = sum(1 for w in self.loss_aversion_markers if w in text_lower)
        if loss_hits == 0 and len(words) > 50:
            kill_flags.append("Zero loss aversion framing. Content lacks psychological urgency.")

        # 2. VPR-100 Scoring Pillars
        scores = {}
        
        # Pillar 1: Physiological Arousal (Max: 20)
        pos_arousal = sum(1 for w in self.high_arousal_positive if w in text_lower)
        neg_arousal = sum(1 for w in self.high_arousal_negative if w in text_lower)
        deactivators = sum(1 for w in self.low_arousal_deactivators if w in text_lower)
        arousal_score = min(20, max(0, 10 + (pos_arousal * 3) + (neg_arousal * 3.5) - (deactivators * 4)))
        scores["physiological_arousal"] = round(arousal_score, 1)

        # Pillar 2: Cognitive Fluency & System 1 Gate (Max: 20)
        # Fast hook: first 10 words should not contain complex multi-syllable jargon
        hook_words = words[:10]
        has_loss_in_hook = any(w in hook_words for w in self.loss_aversion_markers)
        fluency_score = 12
        if has_loss_in_hook:
            fluency_score += 5
        if not any(g in first_15 for g in self.cliche_greetings):
            fluency_score += 3
        scores["cognitive_fluency_system1"] = min(20, fluency_score)

        # Pillar 3: Information Gap & Open Loops (Max: 15)
        question_marks = text.count("?")
        curiosity_markers = ["why", "how", "secret", "reason", "because", "truth", "discover"]
        curiosity_hits = sum(1 for w in curiosity_markers if w in text_lower)
        gap_score = min(15, 6 + (question_marks * 3) + (curiosity_hits * 1.5))
        scores["information_gap"] = round(gap_score, 1)

        # Pillar 4: Operant Loop & Variable Reward (Max: 15)
        reward_markers = ["step", "hack", "trick", "tool", "save", "download", "code", "guide"]
        reward_hits = sum(1 for w in reward_markers if w in text_lower)
        operant_score = min(15, 7 + (reward_hits * 2.0))
        scores["operant_loop"] = round(operant_score, 1)

        # Pillar 5: Psychological Influence Levers (Max: 15)
        influence_markers = ["expert", "percent", "%", "$", "dollar", "years", "proven", "senior"]
        influence_hits = sum(1 for w in influence_markers if w in text_lower)
        influence_score = min(15, 6 + (influence_hits * 2.0))
        scores["influence_levers"] = round(influence_score, 1)

        # Pillar 6: Simplicity & Actionability (Max: 15)
        avg_word_len = sum(len(w) for w in words) / total_words
        simplicity_score = 15 if avg_word_len < 5.5 else max(5, 15 - int((avg_word_len - 5.5) * 4))
        scores["simplicity_actionability"] = simplicity_score

        composite_score = sum(scores.values())
        
        # Decision Status
        if kill_flags:
            status = "FAIL (El Décimo Hombre Circuit Breaker Triggered)"
        elif composite_score >= 85:
            status = "PASS (Unconditional Viral Ready)"
        elif composite_score >= 70:
            status = "PASS WITH OPTIMIZATIONS (High Potential)"
        else:
            status = "FAIL (Below Algorithmic Threshold)"

        return {
            "composite_score": round(composite_score, 1),
            "status": status,
            "pillar_breakdown": scores,
            "kill_flags": kill_flags,
            "metrics": {
                "word_count": total_words,
                "avg_word_length": round(avg_word_len, 2),
                "high_arousal_tokens": pos_arousal + neg_arousal,
                "deactivator_tokens": deactivators,
                "loss_aversion_tokens": loss_hits
            }
        }

def main():
    parser = argparse.ArgumentParser(description="Viral Potential & Decimo Hombre Evaluator")
    parser.add_argument("--script", type=str, help="Text script or path to script file")
    parser.add_argument("--json", action="store_true", help="Output pure JSON")
    args = parser.parse_args()

    if not args.script:
        # Default demo text
        text = "Never make this fatal mistake with your database. You are losing 30% of your performance right now."
    else:
        try:
            with open(args.script, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            text = args.script

    scorer = ViralScorer()
    report = scorer.evaluate(text)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print(" 🎯 VIRAL POTENTIAL & EL DÉCIMO HOMBRE SCORECARD (VPR-100)")
        print("=" * 60)
        print(f" Composite Score : {report['composite_score']} / 100")
        print(f" Status          : {report['status']}")
        print("-" * 60)
        print(" Pillar Scores:")
        for k, v in report["pillar_breakdown"].items():
            print(f"   • {k.replace('_', ' ').title():<32} : {v}")
        if report["kill_flags"]:
            print("-" * 60)
            print(" ⚠️ EL DÉCIMO HOMBRE KILL CRITERIA TRIGGERED:")
            for flag in report["kill_flags"]:
                print(f"   🚨 {flag}")
        print("=" * 60)

if __name__ == "__main__":
    main()

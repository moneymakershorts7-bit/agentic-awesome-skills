#!/usr/bin/env python3
"""
SPROUT: Snapshot-Based Rollout & Verifier-Guided Backtracking Engine
===================================================================
Based on 2025/2026 academic research:
- "SPROUT: SnaPshot-based RollOUT for Long-Horizon Agent Tasks" (OpenReview / arXiv 2025-2026)
- "Taming Imperfect Process Verifiers: A Sampling Perspective on Backtracking" (Rohatgi et al., 2025)

Core Architecture:
1. Checkpoint Registry: Captures lightweight filesystem and execution state snapshots before risky mutations.
2. Step-Level Process Verifier (PRM): Scores tool executions and code changes at each intermediate step.
3. Verifier-Guided Backtracking: When a test failure or contract violation is detected, restores the highest-value
   ancestral checkpoint instead of discarding the entire trajectory or looping erratically.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SnapshotState:
    snapshot_id: str
    step: int
    timestamp: float
    description: str
    context_data: Dict[str, Any]
    process_score: float = 1.0  # Step-level PRM score (0.0 to 1.0)
    is_valid: bool = True
    failure_reason: Optional[str] = None


@dataclass
class BacktrackReport:
    task_goal: str
    total_steps: int
    backtracks_executed: int
    snapshots_taken: int
    active_path: List[SnapshotState] = field(default_factory=list)
    recovery_status: str = "SUCCESS"
    final_output: str = ""


class SproutBacktrackingEngine:
    """Implements Snapshot-Based Rollout (SPROUT) and Verifier-Guided Backtracking."""

    def __init__(self, prm_threshold: float = 0.65, max_backtracks: int = 5):
        self.prm_threshold = prm_threshold
        self.max_backtracks = max_backtracks
        self.checkpoints: List[SnapshotState] = []
        self.backtrack_count = 0

    def capture_snapshot(self, step: int, description: str, context_data: Dict[str, Any]) -> SnapshotState:
        """Captures an immutable snapshot of current state."""
        snap_id = f"snap_step_{step:02d}_{int(time.time() * 1000) % 10000}"
        snapshot = SnapshotState(
            snapshot_id=snap_id,
            step=step,
            timestamp=time.time(),
            description=description,
            context_data=copy.deepcopy(context_data),
            process_score=1.0,
            is_valid=True,
        )
        self.checkpoints.append(snapshot)
        return snapshot

    def step_verifier(self, snapshot: SnapshotState, step_result: Dict[str, Any]) -> float:
        """Evaluates intermediate tool outcome (Process Reward Model approximation)."""
        score = 1.0
        # Check for error outputs or exit codes
        if step_result.get("exit_code", 0) != 0:
            score -= 0.5
        if step_result.get("syntax_error", False):
            score -= 0.4
        if step_result.get("test_failures", 0) > 0:
            score -= 0.3 * step_result["test_failures"]

        # Clamp between 0.0 and 1.0
        score = max(0.0, min(1.0, score))
        snapshot.process_score = score
        if score < self.prm_threshold:
            snapshot.is_valid = False
            snapshot.failure_reason = step_result.get("error_message", "Step score below threshold")
        return score

    def backtrack_to_best_checkpoint(self) -> Optional[SnapshotState]:
        """Rolls back to the most recent valid checkpoint with high PRM score."""
        if self.backtrack_count >= self.max_backtracks:
            return None

        # Scan backwards for the latest valid checkpoint
        for snap in reversed(self.checkpoints):
            if snap.is_valid and snap.process_score >= self.prm_threshold:
                self.backtrack_count += 1
                # Prune subsequent invalid checkpoints
                idx = self.checkpoints.index(snap)
                self.checkpoints = self.checkpoints[: idx + 1]
                return snap
        return None

    def run_sprout_simulation(self, goal: str, planned_steps: List[Dict[str, Any]]) -> BacktrackReport:
        """Executes a multi-step workflow with SPROUT checkpointing and backtracking."""
        self.checkpoints.clear()
        self.backtrack_count = 0

        # Root snapshot
        current_state = {"workspace_clean": True, "files_modified": []}
        self.capture_snapshot(0, "Initial Clean Baseline", current_state)

        for step_idx, step in enumerate(planned_steps, 1):
            desc = step.get("description", f"Step {step_idx}")
            simulated_result = step.get("result", {"exit_code": 0})

            # Checkpoint before modification
            snap = self.capture_snapshot(step_idx, desc, current_state)

            # Evaluate step with Process Verifier
            score = self.step_verifier(snap, simulated_result)

            if not snap.is_valid:
                # Trigger Verifier-Guided Backtracking
                restored = self.backtrack_to_best_checkpoint()
                if restored:
                    current_state = copy.deepcopy(restored.context_data)
                else:
                    return BacktrackReport(
                        task_goal=goal,
                        total_steps=step_idx,
                        backtracks_executed=self.backtrack_count,
                        snapshots_taken=len(self.checkpoints),
                        active_path=self.checkpoints,
                        recovery_status="FAILED_EXHAUSTED_BACKTRACKS",
                        final_output="Exceeded backtrack budget without recovery.",
                    )
            else:
                # Apply simulated state update
                current_state["files_modified"].append(step.get("file", f"file_{step_idx}.py"))

        return BacktrackReport(
            task_goal=goal,
            total_steps=len(planned_steps),
            backtracks_executed=self.backtrack_count,
            snapshots_taken=len(self.checkpoints),
            active_path=self.checkpoints,
            recovery_status="SUCCESS",
            final_output=f"Successfully achieved '{goal}' with {self.backtrack_count} rollbacks.",
        )


def main():
    parser = argparse.ArgumentParser(description="SPROUT Verifier-Guided Backtracking CLI")
    parser.add_argument("--goal", type=str, help="Target goal for agentic workflow")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--demo", action="store_true", help="Run self-contained SPROUT demonstration")

    args = parser.parse_args()

    engine = SproutBacktrackingEngine()

    if args.demo:
        demo_goal = "Refactor authentication middleware with zero regressions"
        demo_steps = [
            {"description": "1. Extract token decoding helper", "file": "auth.py", "result": {"exit_code": 0}},
            {"description": "2. Inject buggy regex pattern", "file": "auth.py", "result": {"exit_code": 1, "test_failures": 2, "error_message": "Regex recursion crash"}},
            {"description": "3. Apply verified atomic patch", "file": "auth.py", "result": {"exit_code": 0}},
        ]
        report = engine.run_sprout_simulation(demo_goal, demo_steps)
        if args.json:
            print(json.dumps(asdict(report), indent=2))
        else:
            print("🌱 === SPROUT Verifier-Guided Backtracking Report ===")
            print(f"Goal:               {report.task_goal}")
            print(f"Status:             {'✅ ' + report.recovery_status if report.recovery_status == 'SUCCESS' else '❌ ' + report.recovery_status}")
            print(f"Total Snapshots:    {report.snapshots_taken}")
            print(f"Backtracks Done:    {report.backtracks_executed}")
            print("\nActive Execution Path:")
            for s in report.active_path:
                print(f"  [{s.snapshot_id}] (Score: {s.process_score:.2f}) -> {s.description}")
            print(f"\nFinal Result: {report.final_output}")
        return

    if not args.goal:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

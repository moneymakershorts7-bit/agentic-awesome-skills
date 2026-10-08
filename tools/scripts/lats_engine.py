#!/usr/bin/env python3
"""
Language Agent Tree Search (LATS) Engine
========================================
Based on academic research by UIUC, MIT & Princeton (Zhou et al., 2023):
"Language Agent Tree Search Unifies Reasoning, Acting, and Planning in Language Models"

MCTS (Monte Carlo Tree Search) for LLM Agents:
1. Selection: Traverse tree using UCB1 / PUCT score to select highest-potential unexpanded node.
2. Expansion: Generate multiple distinct reasoning actions / candidate steps.
3. Evaluation / Simulation: Score candidate action using heuristic value estimation or external feedback.
4. Backpropagation: Update visit counts, cumulative rewards, and reflective critiques along trajectory.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LATSNode:
    node_id: str
    state_description: str
    action: str
    parent_id: Optional[str] = None
    visits: int = 0
    total_value: float = 0.0
    prior_probability: float = 1.0
    depth: int = 0
    reflection: Optional[str] = None
    is_terminal: bool = False
    children_ids: List[str] = field(default_factory=list)

    @property
    def q_value(self) -> float:
        return self.total_value / self.visits if self.visits > 0 else 0.0

    def ucb1(self, parent_visits: int, exploration_constant: float = 1.414) -> float:
        if self.visits == 0:
            return float("inf")
        exploitation = self.q_value
        exploration = exploration_constant * math.sqrt(math.log(max(parent_visits, 1)) / self.visits)
        return exploitation + exploration


@dataclass
class LATSResult:
    goal: str
    best_trajectory: List[Dict[str, Any]]
    total_nodes_evaluated: int
    max_depth_reached: int
    optimal_value: float
    tree_summary: Dict[str, Any]


class LanguageAgentTreeSearch:
    """Programmatic MCTS search engine for Agent Trajectories."""

    def __init__(
        self,
        max_iterations: int = 15,
        max_depth: int = 5,
        exploration_weight: float = 1.414,
        branching_factor: int = 3,
    ):
        self.max_iterations = max_iterations
        self.max_depth = max_depth
        self.exploration_weight = exploration_weight
        self.branching_factor = branching_factor
        self.nodes: Dict[str, LATSNode] = {}
        self.counter = 0

    def _create_node(
        self,
        state: str,
        action: str,
        parent_id: Optional[str] = None,
        depth: int = 0,
        prior: float = 1.0,
    ) -> LATSNode:
        self.counter += 1
        node_id = f"node_{self.counter}"
        node = LATSNode(
            node_id=node_id,
            state_description=state,
            action=action,
            parent_id=parent_id,
            depth=depth,
            prior_probability=prior,
        )
        self.nodes[node_id] = node
        if parent_id and parent_id in self.nodes:
            self.nodes[parent_id].children_ids.append(node_id)
        return node

    def select(self, root_id: str) -> LATSNode:
        """Select leaf node using UCB1."""
        current = self.nodes[root_id]
        while current.children_ids and not current.is_terminal:
            # Check if any child is unvisited
            unvisited = [self.nodes[cid] for cid in current.children_ids if self.nodes[cid].visits == 0]
            if unvisited:
                return unvisited[0]

            # Choose best child via UCB1
            current = max(
                (self.nodes[cid] for cid in current.children_ids),
                key=lambda child: child.ucb1(current.visits, self.exploration_weight),
            )
        return current

    def expand(self, node: LATSNode, candidate_actions: Optional[List[str]] = None) -> List[LATSNode]:
        """Expand node by generating child nodes."""
        if node.depth >= self.max_depth or node.is_terminal:
            return []

        if not candidate_actions:
            # Generate default synthetic reasoning actions for demonstration/fallback
            actions = [
                f"Sub-goal {i+1}: Decompose and solve prerequisite constraints for '{node.state_description[:30]}...'"
                for i in range(self.branching_factor)
            ]
        else:
            actions = candidate_actions[: self.branching_factor]

        children = []
        for act in actions:
            child_state = f"State after: {act}"
            child = self._create_node(
                state=child_state,
                action=act,
                parent_id=node.node_id,
                depth=node.depth + 1,
            )
            children.append(child)
        return children

    def evaluate(self, node: LATSNode, goal: str) -> float:
        """Heuristic / LLM value function scoring state quality (0.0 to 1.0)."""
        # Reward depth progression, keyword matches, and structural completeness
        base_score = 0.5 + (node.depth / (self.max_depth * 2.0))
        if any(term in node.action.lower() for term in ["solve", "verify", "optimize", "complete"]):
            base_score += 0.2
        return min(max(base_score, 0.0), 1.0)

    def backpropagate(self, node: LATSNode, value: float):
        """Propagate evaluation score up to root."""
        curr: Optional[LATSNode] = node
        while curr is not None:
            curr.visits += 1
            curr.total_value += value
            if curr.parent_id:
                curr = self.nodes.get(curr.parent_id)
            else:
                curr = None

    def search(self, goal: str, initial_plan: Optional[List[str]] = None) -> LATSResult:
        """Execute full Monte Carlo Tree Search loop."""
        self.nodes.clear()
        self.counter = 0

        root = self._create_node(state=f"Root: {goal}", action="START", depth=0)

        for _ in range(self.max_iterations):
            selected = self.select(root.node_id)
            if not selected.is_terminal and selected.depth < self.max_depth:
                children = self.expand(selected, initial_plan)
                eval_target = children[0] if children else selected
            else:
                eval_target = selected

            val = self.evaluate(eval_target, goal)
            self.backpropagate(eval_target, val)

        # Extract best trajectory
        trajectory = []
        curr = root
        while curr.children_ids:
            # Pick best child by visit count (robust child) or Q-value
            best_child = max(
                (self.nodes[cid] for cid in curr.children_ids),
                key=lambda c: (c.visits, c.q_value),
            )
            trajectory.append({
                "depth": best_child.depth,
                "action": best_child.action,
                "q_value": round(best_child.q_value, 3),
                "visits": best_child.visits,
            })
            curr = best_child

        max_depth = max((n.depth for n in self.nodes.values()), default=0)
        best_val = trajectory[-1]["q_value"] if trajectory else 0.0

        return LATSResult(
            goal=goal,
            best_trajectory=trajectory,
            total_nodes_evaluated=len(self.nodes),
            max_depth_reached=max_depth,
            optimal_value=best_val,
            tree_summary={"total_nodes": len(self.nodes), "root_visits": root.visits},
        )


def main():
    parser = argparse.ArgumentParser(description="Language Agent Tree Search (LATS) CLI")
    parser.add_argument("--goal", type=str, help="High-level goal or problem statement")
    parser.add_argument("--iterations", type=int, default=12, help="Number of MCTS iterations")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum tree search depth")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--demo", action="store_true", help="Run self-contained demonstration")

    args = parser.parse_args()

    lats = LanguageAgentTreeSearch(
        max_iterations=args.iterations,
        max_depth=args.max_depth,
    )

    if args.demo:
        demo_goal = "Architect high-throughput resilient distributed event pipeline"
        result = lats.search(demo_goal)
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print("🌲 === Language Agent Tree Search (LATS) MCTS Result ===")
            print(f"Goal:                   {result.goal}")
            print(f"Nodes Evaluated:        {result.total_nodes_evaluated}")
            print(f"Max Depth:              {result.max_depth_reached}")
            print(f"Optimal Trajectory Q:   {result.optimal_value:.3f}")
            print("\nOptimal Path:")
            for step in result.best_trajectory:
                print(f"  [Depth {step['depth']}] (Visits: {step['visits']}, Q: {step['q_value']:.2f}) -> {step['action']}")
        return

    if not args.goal:
        parser.print_help()
        sys.exit(1)

    result = lats.search(args.goal)
    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print(f"Optimal Path Found ({len(result.best_trajectory)} steps, evaluated {result.total_nodes_evaluated} nodes):")
        for step in result.best_trajectory:
            print(f"  Step {step['depth']}: {step['action']} (Q={step['q_value']})")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CLI interface for Agent Criteria Gate and System One evaluation.
Usage:
    python3 cli.py "User prompt here"
    python3 cli.py --benchmark
    python3 cli.py --server http://127.0.0.1:8000 "Delete temporary records"
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from decision_gate import AgentDecisionGate
from system_one_client import SystemOneClient


def main():
    parser = argparse.ArgumentParser(description="Agent Criteria Decision Gate")
    parser.add_argument("prompt", nargs="?", default=None, help="The prompt or state text to evaluate")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="System One / Kev endpoint URL")
    parser.add_argument("--benchmark", action="store_true", help="Run latency benchmark on CPU")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")

    args = parser.parse_args()

    client = SystemOneClient(base_url=args.server, fallback_local=True)
    gate = AgentDecisionGate(client=client)

    if args.benchmark:
        prompts = [
            "fix it",
            "permanently purge and drop database tables",
            "Write a FastAPI endpoint for user authentication",
            "What is the capital of France?",
            "Delete old temporary backup files from scratch folder",
            "Help me configure Nginx with SSL certificates"
        ]
        print("Running System One Decision Gate Latency Benchmark (100 iterations)...")
        start_time = time.perf_counter()
        total_runs = 100
        for i in range(total_runs):
            p = prompts[i % len(prompts)]
            gate.decide(p)
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        avg_ms = elapsed_ms / total_runs
        print(f"Completed {total_runs} evaluations in {elapsed_ms:.2f} ms")
        print(f"Average CPU latency per multi-criteria evaluation: {avg_ms:.3f} ms / eval")
        print(f"Throughput: {1000.0 / avg_ms:.1f} evaluations/sec")
        return 0

    if not args.prompt:
        parser.print_help()
        return 1

    action, details = gate.decide(args.prompt)

    if args.json:
        print(json.dumps(details, indent=2))
    else:
        print(f"=== System One Decision Gate Result ===")
        print(f"Prompt: '{args.prompt}'")
        print(f"Decision Action: {action}")
        print(f"Reason: {details.get('reason', 'N/A')}")
        if action == "EXECUTE_ROUTE":
            print(f"Target Route: {details.get('route')} (Confidence: {details.get('confidence', 0):.2f})")
        elif "suggested_response" in details:
            print(f"Agent Suggestion: {details.get('suggested_response')}")
        print("\nCriteria Metrics:")
        for qid, qres in details.get("metrics", {}).items():
            print(f"  • {qid}: {qres}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

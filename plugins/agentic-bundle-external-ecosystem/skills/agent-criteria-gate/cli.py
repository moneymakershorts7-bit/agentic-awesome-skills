#!/usr/bin/env python3
"""
CLI interface for Agent Criteria Gate and System One evaluation.
Supports:
  1. Prompt Pre-Flight Triage (Ambiguity, Safety HITL, Intent Routing)
  2. Hierarchical Codebase Discovery (jevgrep-style structural navigation & AST slicing)
  3. CPU Latency Benchmarking

Usage:
    python3 cli.py "User prompt here"
    python3 cli.py search "How are auth tokens validated?" ./src
    python3 cli.py --search "How are auth tokens validated?" ./src
    python3 cli.py --benchmark
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from decision_gate import AgentDecisionGate, DecisionAction
from discovery_gate import CodebaseDiscoveryGate
from system_one_client import SystemOneClient


def main():
    raw_args = sys.argv[1:]
    is_search_mode = False
    
    if raw_args and raw_args[0] == "search":
        is_search_mode = True
        raw_args = raw_args[1:]

    parser = argparse.ArgumentParser(description="Agent Criteria Decision & Discovery Gate")
    parser.add_argument("query", nargs="?", default=None, help="Prompt or discovery question")
    parser.add_argument("path", nargs="?", default=".", help="Root path for search/discovery (defaults to '.')")
    parser.add_argument("--search", action="store_true", help="Force codebase structural discovery mode")
    parser.add_argument("--budget", type=int, default=256 * 1024, help="Navigation byte budget in bytes (default 256KB)")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="System One / Kev endpoint URL")
    parser.add_argument("--benchmark", action="store_true", help="Run latency benchmark on CPU")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")

    args = parser.parse_args(raw_args)
    if is_search_mode:
        args.search = True

    client = SystemOneClient(base_url=args.server, fallback_local=True)
    gate = AgentDecisionGate(client=client)

    if args.benchmark:
        prompts = [
            "fix it",
            "permanently purge and drop database tables",
            "Write a FastAPI endpoint for user authentication",
            "What is the difference between TCP and UDP protocols?",
            "Where is token validation checked in the middleware?",
            "Help me configure Nginx with SSL certificates"
        ]
        print("Running System One Multi-Criteria Benchmark (100 iterations)...")
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

    if not args.query:
        parser.print_help()
        return 1

    # Codebase discovery mode
    if args.search or args.query.startswith("find "):
        clean_query = args.query.replace("find ", "").strip()
        disc_gate = CodebaseDiscoveryGate(client=client, max_navigation_bytes=args.budget)
        result = disc_gate.discover(query=clean_query, root_path=args.path)

        if args.json:
            print(json.dumps(result.to_data_envelope(), indent=2))
        else:
            print(f"=== Codebase Discovery Gate Result ===")
            print(f"Query: '{result.query}'")
            print(f"Root:  {result.root_path}")
            print(f"Status: {result.status.upper()} (Budget Exhausted: {result.stats.budget_exhausted})")
            print(f"Stats: {result.stats.files_scanned} files previewed ({result.stats.bytes_inspected} bytes), {result.stats.declarations_extracted} declarations, {result.stats.retracted_count} retracted in {result.stats.elapsed_ms}ms\n")
            print(f"--- Relevant Structural Declarations ({len(result.evidence)}) ---")
            for i, decl in enumerate(result.evidence[:10], 1):
                print(f"[{i}] {decl.file_path}:L{decl.start_line}-L{decl.end_line} ({decl.kind}: {decl.name}, score: {decl.relevance_score})")
                print(f"    Sig: {decl.signature}")
                if decl.docstring:
                    print(f"    Doc: {decl.docstring[:100]}...")
            if len(result.evidence) > 10:
                print(f"\n... and {len(result.evidence) - 10} more declarations.")
        return 0

    # Decision gate inspection
    action, details = gate.decide(args.query)

    if action == DecisionAction.DISCOVER_CODEBASE and not args.json:
        print(f"=== System One Decision Gate Routed to Discovery ===")
        print(f"Prompt: '{args.query}' (Action: DISCOVER_CODEBASE)")
        disc_gate = CodebaseDiscoveryGate(client=client, max_navigation_bytes=args.budget)
        result = disc_gate.discover(query=args.query, root_path=args.path)
        print(f"Discovery Status: {result.status.upper()} ({len(result.evidence)} matching declarations found in {result.stats.elapsed_ms}ms)")
        for i, decl in enumerate(result.evidence[:5], 1):
            print(f"  [{i}] {decl.file_path}:L{decl.start_line} -> {decl.signature} (Score: {decl.relevance_score})")
        return 0

    if args.json:
        print(json.dumps(details, indent=2))
    else:
        print(f"=== System One Decision Gate Result ===")
        print(f"Prompt: '{args.query}'")
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

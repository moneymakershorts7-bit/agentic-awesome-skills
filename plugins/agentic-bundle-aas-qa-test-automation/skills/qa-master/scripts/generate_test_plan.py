#!/usr/bin/env python3
"""
QA Master - Heuristic Test Plan & Charter Generator
Analyzes repository structure, entry points, APIs, and components to produce
an SFDIPOT model, risk-weighted test layers, and Session-Based Exploratory Charters.
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List


def analyze_codebase(repo_path: str) -> Dict[str, Any]:
    """Scan directory structure and identify components, APIs, and test assets."""
    repo = Path(repo_path).resolve()
    
    structure = {
        "source_files": 0,
        "test_files": 0,
        "languages": set(),
        "api_routes": [],
        "components": [],
        "data_models": [],
        "has_unit_tests": False,
        "has_e2e_tests": False,
        "has_contract_tests": False,
        "has_perf_tests": False,
    }

    # Common exclusions
    exclude_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".cache"}

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            path = Path(root) / f
            ext = path.suffix.lower()
            rel_path = str(path.relative_to(repo))

            if ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java"):
                structure["source_files"] += 1
                if ext == ".py":
                    structure["languages"].add("Python")
                elif ext in (".ts", ".tsx"):
                    structure["languages"].add("TypeScript")
                elif ext in (".js", ".jsx"):
                    structure["languages"].add("JavaScript")
                elif ext == ".go":
                    structure["languages"].add("Go")
                elif ext == ".rs":
                    structure["languages"].add("Rust")

                # Test detection
                is_test = "test" in f.lower() or "spec" in f.lower()
                if is_test:
                    structure["test_files"] += 1
                    if "e2e" in rel_path.lower() or "playwright" in rel_path.lower() or "cypress" in rel_path.lower():
                        structure["has_e2e_tests"] = True
                    elif "contract" in rel_path.lower() or "pact" in rel_path.lower():
                        structure["has_contract_tests"] = True
                    else:
                        structure["has_unit_tests"] = True

                # Performance test detection
                if "k6" in f.lower() or "artillery" in f.lower() or "locust" in f.lower():
                    structure["has_perf_tests"] = True

                # Inspect routes/endpoints in source
                if not is_test and ext in (".py", ".ts", ".js"):
                    try:
                        content = path.read_text(encoding="utf-8", errors="ignore")
                        # Match route patterns (express, fastAPI, flask, next.js)
                        routes = re.findall(r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', content)
                        for method, route in routes:
                            structure["api_routes"].append(f"{method.upper()} {route}")
                        # Next.js / API route file conventions
                        if "api/" in rel_path.lower():
                            structure["api_routes"].append(f"ROUTE {rel_path}")
                        # Models
                        if "class " in content and ("Model" in content or "Schema" in content or "Entity" in content):
                            structure["data_models"].append(rel_path)
                    except Exception:
                        pass

    structure["languages"] = list(structure["languages"])
    structure["api_routes"] = list(set(structure["api_routes"]))[:25]
    structure["data_models"] = list(set(structure["data_models"]))[:20]
    return structure


def generate_sfdipot_plan(codebase_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate SFDIPOT heuristic decomposition."""
    return {
        "structure": {
            "languages": codebase_info["languages"],
            "total_source_files": codebase_info["source_files"],
            "total_test_files": codebase_info["test_files"],
            "test_to_code_ratio": round(codebase_info["test_files"] / max(1, codebase_info["source_files"]), 2)
        },
        "function": [
            "Core business rules and algorithmic validation",
            "State mutation transitions and boundary invariants",
            "Error recovery and exception handling pathways"
        ],
        "data": {
            "models_identified": codebase_info["data_models"],
            "test_data_invariants": [
                "Empty/Null input boundaries",
                "Unicode & Big List of Naughty Strings injection",
                "Large payloads & boundary numeric values"
            ]
        },
        "interfaces": {
            "detected_endpoints": codebase_info["api_routes"],
            "coverage_types": ["REST/JSON Schema", "HTTP status codes (4xx/5xx)", "Auth header validation"]
        },
        "platform": [
            "Linux CI Runner container",
            "Node.js / Python runtime parity with production",
            "Browser engines: Chromium, WebKit, Firefox"
        ],
        "operations": [
            "Concurrent user journeys",
            "Administrative state toggles",
            "Clean teardown without resource leaks"
        ],
        "time": [
            "Asynchronous race conditions & event sequencing",
            "Network timeout handling (<10s)",
            "Timestamp formatting & UTC timezone invariants"
        ]
    }


def generate_exploratory_charters(codebase_info: Dict[str, Any]) -> List[Dict[str, str]]:
    """Synthesize Session-Based Exploratory Charters."""
    charters = []
    
    charters.append({
        "id": "SBTM-01",
        "title": "API Boundary & Exception Handling",
        "charter": "Explore detected API routes with malformed payloads, SQL injection fragments, and truncated headers to discover unhandled 500 crashes and sensitive stack trace leaks.",
        "oracles": "FEW HICCUPPS: Standards (RFC HTTP), Explainability",
        "target": "API Layer"
    })

    charters.append({
        "id": "SBTM-02",
        "title": "Concurrency & State Consistency",
        "charter": "Explore core business workflows under simulated rapid parallel invocations and network throttling to discover race conditions, stale cache reads, or state desynchronization.",
        "oracles": "FEW HICCUPPS: User Expectations, Product Consistency",
        "target": "Domain State"
    })

    if codebase_info.get("data_models"):
        charters.append({
            "id": "SBTM-03",
            "title": "Data Persistence & Schema Boundary",
            "charter": f"Explore data model persistence ({', '.join(codebase_info['data_models'][:3])}) with boundary values and unexpected data types to discover silent truncation or database integrity errors.",
            "oracles": "FEW HICCUPPS: World (Math), Claims (Schema)",
            "target": "Data Persistence"
        })

    return charters


def generate_plan(repo_path: str, output_path: str = None) -> Dict[str, Any]:
    """Generate complete QA Test Plan."""
    info = analyze_codebase(repo_path)
    sfdipot = generate_sfdipot_plan(info)
    charters = generate_exploratory_charters(info)

    missing_layers = []
    if not info["has_unit_tests"]:
        missing_layers.append("Unit Tests (Layer 1)")
    if not info["has_e2e_tests"]:
        missing_layers.append("End-to-End Browser Tests (Layer 4)")
    if not info["has_contract_tests"]:
        missing_layers.append("Consumer-Driven Contract Tests (Layer 2)")
    if not info["has_perf_tests"]:
        missing_layers.append("Performance & Load Smoke Tests (Layer 6)")

    plan = {
        "version": "1.0.0",
        "repository": os.path.abspath(repo_path),
        "missing_layers": missing_layers,
        "sfdipot_model": sfdipot,
        "exploratory_charters": charters,
        "recommendations": [
            "Implement unit tests for core domain logic using Classical xUnit school.",
            "Add Big List of Naughty Strings fuzzing tests to all public API endpoints.",
            "Enforce Mutation Testing (MSI >= 70%) on critical validation modules."
        ]
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2)

    return plan


def main():
    parser = argparse.ArgumentParser(description="QA Master - Test Plan & Charter Generator")
    parser.add_argument("--repo", default=".", help="Target repository directory")
    parser.add_argument("--output", default=None, help="Output file path (JSON)")
    args = parser.parse_args()

    plan = generate_plan(args.repo, args.output)
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()

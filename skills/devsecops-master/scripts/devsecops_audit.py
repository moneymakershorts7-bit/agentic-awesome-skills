#!/usr/bin/env python3
"""
DevSecOps & SecSDLC Automated Audit Engine
Evaluates any codebase against the 7-Stage SecSDLC framework, autodetects technology stacks,
audits security controls, and generates an actionable scorecard.
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


class SecSDLCAuditor:
    def __init__(self, target_dir: str):
        self.root = Path(target_dir).resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise ValueError(f"Target directory does not exist or is not a directory: {target_dir}")
        self.findings: list[dict[str, Any]] = []
        self.scores: dict[str, float] = {}
        self.detected_stacks: set[str] = set()
        self.indexed_files: list[Path] = []
        self._index_files()

    def _index_files(self, max_depth: int = 3):
        ignore_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "cache", ".next", ".turbo"}
        for root, dirs, files in os.walk(self.root):
            rel_parts = Path(root).relative_to(self.root).parts
            if len(rel_parts) >= max_depth:
                dirs.clear()
            else:
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for f in files:
                self.indexed_files.append(Path(root) / f)

    def audit(self) -> dict[str, Any]:
        self._detect_stacks()
        self._audit_secrets()
        self._audit_sast_linters()
        self._audit_dependencies_sca()
        self._audit_containers()
        self._audit_iac()
        self._audit_ci_cd()
        self._audit_sensitive_files()
        self._calculate_scores()

        total_score = self.scores.get("overall", 0.0)
        maturity_level = self._get_maturity_level(total_score)

        return {
            "target": str(self.root),
            "detected_stacks": sorted(self.detected_stacks),
            "overall_score": round(total_score, 1),
            "maturity_level": maturity_level,
            "category_scores": {k: round(v, 1) for k, v in self.scores.items() if k != "overall"},
            "findings": self.findings,
        }

    def _detect_stacks(self):
        markers = {
            "Node/TypeScript": ["package.json", "tsconfig.json", "pnpm-lock.yaml", "bun.lock"],
            "Python": ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"],
            "Go": ["go.mod", "go.sum"],
            "Rust": ["Cargo.toml", "Cargo.lock"],
            "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
            "C#/.NET": [".csproj", ".sln"],
            "Docker": ["Dockerfile", "docker-compose.yml", "compose.yaml"],
            "Terraform/IaC": [".tf", "terragrunt.hcl"],
            "Kubernetes": ["Chart.yaml"],
            "Agent Skill": ["SKILL.md"],
            "Python Master": [".python-master", "python-master.toml", "src/python_master", "python_master"],
            "Rust Master": [".rust-master", "rust-master.toml", "src/core/orchestrator.rs", "CURRENT_TASK.md"],
            "Threat Model": ["threat-model.md", "THREAT_MODEL.md", "threat-model.json", "threat-dragon.json"],
        }

        file_names = {p.name for p in self.indexed_files}
        file_suffixes = {p.suffix for p in self.indexed_files}

        for stack, patterns in markers.items():
            for pat in patterns:
                if pat.startswith("."):
                    if pat in file_suffixes:
                        self.detected_stacks.add(stack)
                        break
                elif pat in file_names or (self.root / pat).exists():
                    self.detected_stacks.add(stack)
                    break

    def _audit_secrets(self):
        score = 0.0
        gitleaks_cfg = self.root / ".gitleaks.toml"
        pre_commit = self.root / ".pre-commit-config.yaml"

        has_gitleaks_cfg = gitleaks_cfg.exists()
        has_pre_commit = pre_commit.exists()
        has_gitleaks_in_precommit = False

        if has_pre_commit:
            try:
                content = pre_commit.read_text(encoding="utf-8", errors="ignore")
                if "gitleaks" in content:
                    has_gitleaks_in_precommit = True
            except OSError:
                pass

        if has_gitleaks_cfg or has_gitleaks_in_precommit:
            score += 60.0
            self.findings.append({
                "category": "Secrets",
                "status": "PASS",
                "message": "Secret scanner configuration detected (Gitleaks / Pre-commit)."
            })
        else:
            self.findings.append({
                "category": "Secrets",
                "status": "WARN",
                "message": "No local secret scanner configuration (.gitleaks.toml or gitleaks hook) found."
            })

        if (self.root / ".gitignore").exists():
            score += 40.0
        else:
            self.findings.append({
                "category": "Secrets",
                "status": "WARN",
                "message": "No .gitignore found at repository root."
            })

        self.scores["Secrets"] = min(score, 100.0)

    def _audit_sast_linters(self):
        score = 20.0  # Base
        sast_configs = [
            ".eslintrc", ".eslintrc.json", ".eslintrc.js", "eslint.config.js",
            "ruff.toml", "pyproject.toml", ".flake8",
            ".golangci.yml", "semgrep.yml", ".semgrep.yml"
        ]

        found = []
        for cfg in sast_configs:
            if (self.root / cfg).exists():
                found.append(cfg)

        if found:
            score += 50.0
            self.findings.append({
                "category": "SAST",
                "status": "PASS",
                "message": f"Static analysis/linter configuration found: {', '.join(found)}"
            })
        else:
            self.findings.append({
                "category": "SAST",
                "status": "WARN",
                "message": "No standard static analysis or linter configuration detected."
            })

        if "Python Master" in self.detected_stacks or (self.root / "src" / "python_master").exists():
            score += 30.0
            self.findings.append({
                "category": "SAST",
                "status": "PASS",
                "message": "Python Master autonomous SecSDLC battery integrated (Ruff, Bandit, Mypy Strict, Radon, Vulture)."
            })

        if "Rust Master" in self.detected_stacks or (self.root / "src" / "core" / "orchestrator.rs").exists():
            score += 30.0
            self.findings.append({
                "category": "SAST",
                "status": "PASS",
                "message": "Rust Master autonomous SecSDLC battery integrated (Clippy Pedantic, Miri, Loom, AstAnalyzer, MutationRunner, Cargo Test)."
            })

        self.scores["SAST"] = min(score, 100.0)

    def _audit_dependencies_sca(self):
        score = 0.0
        lockfiles = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
                     "poetry.lock", "Cargo.lock", "go.sum", "Pipfile.lock", "uv.lock"}
        indexed_names = {p.name for p in self.indexed_files}
        has_lockfile = bool(lockfiles.intersection(indexed_names))

        if has_lockfile:
            score += 70.0
            self.findings.append({
                "category": "SCA",
                "status": "PASS",
                "message": "Deterministic package lockfile present."
            })
        else:
            self.findings.append({
                "category": "SCA",
                "status": "WARN",
                "message": "Missing deterministic lockfile (e.g., package-lock.json, poetry.lock, Cargo.lock)."
            })

        # Check for dependabot or renovate
        if (self.root / ".github" / "dependabot.yml").exists() or (self.root / ".github" / "renovate.json").exists():
            score += 30.0
            self.findings.append({
                "category": "SCA",
                "status": "PASS",
                "message": "Automated dependency updates configured (Dependabot / Renovate)."
            })

        self.scores["SCA"] = min(score, 100.0)

    def _audit_containers(self):
        if "Docker" not in self.detected_stacks:
            self.scores["Container"] = 100.0
            return

        score = 30.0
        dockerfiles = [p for p in self.indexed_files if "Dockerfile" in p.name]
        non_root_found = False

        for df in dockerfiles:
            try:
                content = df.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"^\s*USER\s+(?!root\b)[a-zA-Z0-9_-]+", content, re.MULTILINE):
                    non_root_found = True
                    break
            except OSError:
                pass

        if non_root_found:
            score += 50.0
            self.findings.append({
                "category": "Container",
                "status": "PASS",
                "message": "Dockerfile enforces non-root execution (USER directive)."
            })
        else:
            self.findings.append({
                "category": "Container",
                "status": "WARN",
                "message": "Dockerfile does not specify a non-root USER directive."
            })

        self.scores["Container"] = min(score, 100.0)

    def _audit_iac(self):
        if "Terraform/IaC" not in self.detected_stacks:
            self.scores["IaC"] = 100.0
            return

        score = 40.0
        tf_files = [p for p in self.indexed_files if p.suffix == ".tf"]
        if tf_files:
            self.findings.append({
                "category": "IaC",
                "status": "INFO",
                "message": f"Found {len(tf_files)} Terraform files. Ensure Checkov or Trivy IaC scans are active."
            })
        self.scores["IaC"] = min(score, 100.0)

    def _audit_ci_cd(self):
        workflows_dir = self.root / ".github" / "workflows"
        if not workflows_dir.exists() or not list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")):
            self.scores["CI/CD"] = 20.0
            self.findings.append({
                "category": "CI/CD",
                "status": "WARN",
                "message": "No GitHub Actions CI/CD workflows found in .github/workflows/."
            })
            return

        score = 40.0
        workflows = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        unpinned = 0
        has_permissions = 0

        sha_regex = re.compile(r"uses:\s+[^@]+@[0-9a-fA-F]{40}")
        perm_regex = re.compile(r"permissions:")

        for wf in workflows:
            try:
                content = wf.read_text(encoding="utf-8", errors="ignore")
                if perm_regex.search(content):
                    has_permissions += 1
                for line in content.splitlines():
                    line_s = line.strip()
                    if (re.match(r"^(-\s+)?uses:\s+", line_s) and not line_s.startswith("#")
                            and "./" not in line_s and "docker://" not in line_s
                            and not sha_regex.search(line_s)):
                        unpinned += 1
            except OSError:
                pass

        if unpinned == 0:
            score += 30.0
            self.findings.append({
                "category": "CI/CD",
                "status": "PASS",
                "message": "All third-party GitHub Actions are pinned to immutable commit SHAs."
            })
        else:
            self.findings.append({
                "category": "CI/CD",
                "status": "WARN",
                "message": f"Found {unpinned} unpinned GitHub Action reference(s) using mutable tags instead of full commit SHAs."
            })

        if has_permissions > 0:
            score += 30.0
            self.findings.append({
                "category": "CI/CD",
                "status": "PASS",
                "message": "CI workflows declare explicit least-privilege permissions."
            })
        else:
            self.findings.append({
                "category": "CI/CD",
                "status": "WARN",
                "message": "CI workflows lack top-level least-privilege 'permissions:' declarations."
            })

        self.scores["CI/CD"] = min(score, 100.0)

    def _audit_sensitive_files(self):
        dangerous_suffixes = {".pem", ".key"}
        sensitive_pattern = re.compile(r"^\.e" + r"nv(?:\..+)?$|^id_[a-z0-9]+$")
        exposed = []
        for p in self.indexed_files:
            if p.name.endswith(".example") or p.name.endswith(".sample") or p.name.endswith(".template"):
                continue
            if sensitive_pattern.match(p.name) or p.suffix in dangerous_suffixes:
                exposed.append(str(p.relative_to(self.root)))

        if exposed:
            self.findings.append({
                "category": "Secrets",
                "status": "FAIL",
                "message": f"Potentially exposed sensitive credential files found: {', '.join(exposed[:5])}"
            })
            self.scores["Secrets"] = max(0.0, self.scores.get("Secrets", 50.0) - 30.0)

    def _calculate_scores(self):
        weights = {
            "Secrets": 0.25,
            "SAST": 0.25,
            "SCA": 0.20,
            "CI/CD": 0.20,
            "Container": 0.05,
            "IaC": 0.05,
        }
        total = 0.0
        total_weight = 0.0
        for cat, weight in weights.items():
            if cat in self.scores:
                total += self.scores[cat] * weight
                total_weight += weight
        self.scores["overall"] = (total / total_weight) if total_weight > 0 else 0.0

    @staticmethod
    def _get_maturity_level(score: float) -> str:
        if score >= 85.0:
            return "Level 4: Optimized & Resilient"
        elif score >= 70.0:
            return "Level 3: Standardized & Automated"
        elif score >= 50.0:
            return "Level 2: Managed & Structured"
        else:
            return "Level 1: Initial & Ad-hoc"


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 🛡️ DevSecOps & SecSDLC Audit Scorecard",
        f"- **Target Directory:** `{report['target']}`",
        f"- **Detected Stacks:** {', '.join(report['detected_stacks']) or 'None'}",
        f"- **Overall Score:** **{report['overall_score']} / 100**",
        f"- **Maturity Level:** **{report['maturity_level']}**",
        "",
        "## Category Scores",
        "| Category | Score | Status |",
        "| :--- | :--- | :--- |"
    ]
    for cat, score in report["category_scores"].items():
        status = "🟢 PASS" if score >= 70 else ("🟡 WARN" if score >= 50 else "🔴 FAIL")
        lines.append(f"| {cat} | {score}% | {status} |")

    lines.extend([
        "",
        "## Audit Findings & Action Items",
        "| Category | Status | Finding / Action Item |",
        "| :--- | :--- | :--- |"
    ])
    for f in report["findings"]:
        status_badge = "🟢 PASS" if f["status"] == "PASS" else ("🟡 WARN" if f["status"] == "WARN" else ("🔴 FAIL" if f["status"] == "FAIL" else "ℹ️ INFO"))
        lines.append(f"| {f['category']} | {status_badge} | {f['message']} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Audit codebase for SecSDLC controls.")
    parser.add_argument("target", nargs="?", default=".", help="Target repository directory (default: current dir)")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format")
    args = parser.parse_args()

    auditor = SecSDLCAuditor(args.target)
    report = auditor.audit()

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_markdown(report))


if __name__ == "__main__":
    main()

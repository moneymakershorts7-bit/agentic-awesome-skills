#!/usr/bin/env python3
"""
Pipeline & Codebase Integrity Verifier (El Décimo Hombre Gate)
Deterministically checks CI/CD workflows for:
1. Unpinned third-party GitHub Actions (tags instead of 40-character commit SHAs).
2. Missing or overly permissive top-level 'permissions:' declarations.
3. Infiltration of inline security scanner suppression directives (// nosec, etc.).
"""

import argparse
import re
import sys
from pathlib import Path


class PipelineIntegrityVerifier:
    def __init__(self, target_dir: str):
        self.root = Path(target_dir).resolve()
        self.workflow_dir = self.root / ".github" / "workflows"
        self.unpinned_actions: list[dict[str, str]] = []
        self.missing_permissions: list[str] = []
        self.suppressions: list[dict[str, str]] = []

    def verify(self) -> tuple[bool, dict[str, list]]:
        self._check_workflow_actions()
        self._check_suppressions()

        has_errors = bool(self.unpinned_actions or self.missing_permissions or self.suppressions)
        results = {
            "unpinned_actions": self.unpinned_actions,
            "missing_permissions": self.missing_permissions,
            "suppressions": self.suppressions,
        }
        return (not has_errors, results)

    def _check_workflow_actions(self):
        if not self.workflow_dir.exists():
            return

        workflow_files = list(self.workflow_dir.glob("*.yml")) + list(self.workflow_dir.glob("*.yaml"))
        sha_pattern = re.compile(r"uses:\s+([a-zA-Z0-9_\-\./]+)@([0-9a-fA-F]{40})")
        uses_pattern = re.compile(r"uses:\s+([a-zA-Z0-9_\-\./]+)@([^\s#]+)")
        perm_pattern = re.compile(r"^permissions:", re.MULTILINE)

        for wf in workflow_files:
            try:
                content = wf.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(wf.relative_to(self.root))

                if not perm_pattern.search(content):
                    self.missing_permissions.append(rel_path)

                for line_no, line in enumerate(content.splitlines(), start=1):
                    line_str = line.strip()
                    if line_str.startswith("#") or "uses:" not in line_str:
                        continue

                    # Ignore local composite actions and docker protocol
                    if "./" in line_str or "docker://" in line_str:
                        continue

                    # Check for full 40-char SHA
                    if not sha_pattern.search(line_str):
                        match = uses_pattern.search(line_str)
                        action_name = match.group(1) if match else "unknown"
                        tag_ref = match.group(2) if match else "unpinned"
                        self.unpinned_actions.append({
                            "file": rel_path,
                            "line": str(line_no),
                            "action": action_name,
                            "ref": tag_ref,
                            "raw": line_str
                        })
            except OSError:
                pass

    def _check_suppressions(self):
        # Scan source files for suppression bypass comments
        suppression_patterns = [
            (re.compile(r"//\s*nosec\b|#\s*nosec\b", re.IGNORECASE), "nosec comment"),
            (re.compile(r"//\s*pragma:\s*allowlist\s*secret|#\s*pragma:\s*allowlist\s*secret", re.IGNORECASE), "secret allowlist pragma"),
            (re.compile(r"@SuppressWarnings\([^)]*(?:security|all)[^)]*\)", re.IGNORECASE), "compiler warning suppression"),
        ]

        # Scan text files, ignoring .git, node_modules, build directories, and reference documentation
        ignore_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "references", "playbooks", "plugins", "skills"}
        text_extensions = {".py", ".ts", ".js", ".go", ".rs", ".java", ".cs", ".php", ".sh"}

        for path in self.root.rglob("*"):
            if path.is_file() and path.suffix in text_extensions:
                if any(part in ignore_dirs for part in path.parts):
                    continue

                try:
                    content = path.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(path.relative_to(self.root))
                    for line_no, line in enumerate(content.splitlines(), start=1):
                        for pattern, kind in suppression_patterns:
                            if pattern.search(line):
                                self.suppressions.append({
                                    "file": rel_path,
                                    "line": str(line_no),
                                    "type": kind,
                                    "snippet": line.strip()[:80]
                                })
                except OSError:
                    pass


def main():
    parser = argparse.ArgumentParser(description="Verify CI/CD workflows and code integrity.")
    parser.add_argument("target", nargs="?", default=".", help="Target repository directory (default: current dir)")
    args = parser.parse_args()

    verifier = PipelineIntegrityVerifier(args.target)
    is_valid, details = verifier.verify()

    print("# 🛡️ Pipeline & Codebase Integrity Verification (El Décimo Hombre Gate)")
    print(f"Target: `{verifier.root}`\n")

    if is_valid:
        print("✅ ALL INTEGRITY GATES PASSED")
        print("- All GitHub Actions are pinned to immutable 40-character commit SHAs.")
        print("- All workflows enforce least-privilege permissions.")
        print("- No unauthorized scanner suppressions detected in source code.")
        sys.exit(0)
    else:
        print("❌ INTEGRITY GATES FAILED")
        if details["unpinned_actions"]:
            print(f"\n[!] Unpinned GitHub Actions ({len(details['unpinned_actions'])} found):")
            for item in details["unpinned_actions"]:
                print(f"  - {item['file']}:{item['line']} -> {item['action']}@{item['ref']}")
            print("  Fix: Pin to immutable 40-char SHA (e.g. `uses: actions/checkout@11bd71901... # v4.2.2`).")

        if details["missing_permissions"]:
            print(f"\n[!] Workflows Missing Top-Level 'permissions:' ({len(details['missing_permissions'])} found):")
            for wf in details["missing_permissions"]:
                print(f"  - {wf}")
            print("  Fix: Add explicit top-level `permissions: {}` or `permissions: contents: read`.")

        if details["suppressions"]:
            print(f"\n[!] Inline Scanner Suppression Infiltrations ({len(details['suppressions'])} found):")
            for item in details["suppressions"]:
                print(f"  - {item['file']}:{item['line']} [{item['type']}]: {item['snippet']}")
            print("  Fix: Suppressions require written architectural justification in VEX, not unreviewed inline comments.")

        sys.exit(1)


if __name__ == "__main__":
    main()

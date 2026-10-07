"""Skill symlink validation utility.

Validates that skill symlinks in .qoder/skills/ point to valid,
current repository paths and detects stale or outdated symlinks.
"""
import logging
import subprocess
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)


class SymlinkValidator:
    """Validate skill symlinks point to current repository paths."""

    def __init__(self, repo_root: Path = None):
        """Initialize validator with repository root path.

        Args:
            repo_root: Repository root directory. Auto-detected if None.
        """
        self.repo_root = repo_root or self._detect_repo_root()
        self.skills_dir = self.repo_root / ".qoder" / "skills"

    def _detect_repo_root(self) -> Path:
        """Detect current repository root using git."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Failed to detect repo root via git: {e}")

        # Fallback: use script location
        return Path(__file__).parent.parent.parent

    def validate_all(self) -> Tuple[bool, List[str]]:
        """Validate all skill symlinks.

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        if not self.skills_dir.exists():
            logger.debug("Skills directory not found: %s", self.skills_dir)
            return True, []

        issues = []
        for symlink in sorted(self.skills_dir.iterdir()):
            if not symlink.is_symlink():
                continue

            target = symlink.resolve()
            issues.extend(self._validate_symlink(symlink, target))

        return len(issues) == 0, issues

    def _validate_symlink(self, symlink: Path, target: Path) -> List[str]:
        """Validate a single symlink.

        Args:
            symlink: Path to the symlink
            target: Resolved target path

        Returns:
            List of issue descriptions
        """
        issues = []

        if not target.exists():
            issues.append(f"Broken symlink: {symlink.name} -> {target}")
            return issues

        target_str = str(target)

        # Check for outdated repository paths
        old_repos = ["sec_skill_dev"]
        current_repo = "claude_sec_skill_dev"

        for old_repo in old_repos:
            if old_repo in target_str and current_repo not in target_str:
                expected_target = target_str.replace(old_repo, current_repo)
                issues.append(
                    f"Outdated symlink: {symlink.name} -> {target} "
                    f"(should be: {expected_target})"
                )
                break

        return issues

    def auto_fix(self) -> Tuple[bool, List[str]]:
        """Auto-fix outdated symlinks.

        Returns:
            Tuple of (success, list_of_messages)
        """
        _, issues = self.validate_all()
        if not issues:
            return True, ["All symlinks are valid"]

        messages = []
        for issue in issues:
            if issue.startswith("Broken symlink:"):
                messages.append(f"Cannot auto-fix broken symlink: {issue}")
                continue

            if issue.startswith("Outdated symlink:"):
                parts = issue.split("(should be: ")
                if len(parts) == 2:
                    symlink_name = parts[0].replace("Outdated symlink: ", "").split(" -> ")[0]
                    expected_target = parts[1].rstrip(")")

                    symlink_path = self.skills_dir / symlink_name
                    try:
                        symlink_path.unlink()
                        symlink_path.symlink_to(expected_target)
                        messages.append(f"Fixed: {symlink_name} -> {expected_target}")
                    except OSError as e:
                        messages.append(f"Failed to fix {symlink_name}: {e}")

        return all(m.startswith("Fixed:") or m.startswith("All") for m in messages), messages

    def get_status_report(self) -> str:
        """Get human-readable status report.

        Returns:
            Status report string
        """
        is_valid, issues = self.validate_all()

        if is_valid:
            return "[OK] All skill symlinks validated successfully"

        lines = ["[WARN] Skill symlink validation issues:"]
        for issue in issues:
            lines.append(f"  - {issue}")
        lines.append(f"\nTotal issues: {len(issues)}")

        if any("Outdated" in i for i in issues):
            lines.append("\n[FIX] Run with --fix-symlinks to auto-update outdated symlinks")

        return "\n".join(lines)

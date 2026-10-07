"""PoC binary integrity verification and auto-recovery.

Maintains checksums.json in poc-bin/ and verifies all PoC binaries
at startup. Detects corruption, missing binaries, and stale builds.
"""
import hashlib
import json
import logging
import os
import subprocess
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

_CHECKSUMS_FILE = "checksums.json"


class IntegrityStatus:
    OK = "ok"
    MISSING = "missing"
    CORRUPTED = "corrupted"
    STALE = "stale"


class BinaryCheckResult:
    """Result for a single binary check."""

    def __init__(self, name: str, status: str, message: str = ""):
        self.name = name
        self.status = status
        self.message = message

    @property
    def is_ok(self) -> bool:
        return self.status == IntegrityStatus.OK


class IntegrityReport:
    """Summary of all binary integrity checks."""

    def __init__(self, results: List[BinaryCheckResult]):
        self.results = results

    @property
    def all_ok(self) -> bool:
        return all(r.is_ok for r in self.results)

    @property
    def failed(self) -> List[BinaryCheckResult]:
        return [r for r in self.results if not r.is_ok]

    def format_report(self) -> str:
        lines = ["PoC Binary Integrity Report", "=" * 60]
        ok_count = sum(1 for r in self.results if r.is_ok)
        fail_count = len(self.results) - ok_count

        lines.append("Total: {} binaries, {} OK, {} issues".format(
            len(self.results), ok_count, fail_count))
        lines.append("")

        if self.all_ok:
            lines.append("All binaries verified successfully.")
            return "\n".join(lines)

        for r in self.failed:
            lines.append("[{status}] {name}: {msg}".format(
                status=r.status.upper(), name=r.name, msg=r.message))

        return "\n".join(lines)


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_directory(dir_path: str) -> str:
    """Compute a combined hash of all files in a directory."""
    h = hashlib.sha256()
    if not os.path.isdir(dir_path):
        return ""
    for root, dirs, files in os.walk(dir_path):
        dirs.sort()
        for name in sorted(files):
            filepath = os.path.join(root, name)
            rel = os.path.relpath(filepath, dir_path)
            h.update(rel.encode('utf-8'))
            try:
                with open(filepath, 'rb') as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
            except OSError:
                continue
    return h.hexdigest()


class PoCIntegrityChecker:
    """Verifies and manages PoC binary integrity."""

    def __init__(self, poc_bin_dir: str, poc_src_dir: str = None):
        """Initialize checker.

        Args:
            poc_bin_dir: Path to poc-bin/ directory containing ELF binaries.
            poc_src_dir: Path to poc-src/ directory (for staleness checks).
        """
        self._bin_dir = poc_bin_dir
        self._src_dir = poc_src_dir
        self._checksums_path = os.path.join(poc_bin_dir, _CHECKSUMS_FILE)
        self._checksums: Dict[str, Dict[str, Any]] = {}
        self._load_checksums()

    def _load_checksums(self):
        if os.path.isfile(self._checksums_path):
            try:
                with open(self._checksums_path, 'r', encoding='utf-8') as f:
                    self._checksums = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._checksums = {}

    def _save_checksums(self):
        os.makedirs(self._bin_dir, exist_ok=True)
        with open(self._checksums_path, 'w', encoding='utf-8') as f:
            json.dump(self._checksums, f, indent=2, ensure_ascii=False)

    def update_checksums(self) -> int:
        """Regenerate checksums.json from current binaries on disk.

        Returns:
            Number of binaries checksummed.
        """
        self._checksums = {}
        count = 0

        if not os.path.isdir(self._bin_dir):
            self._save_checksums()
            return 0

        for name in sorted(os.listdir(self._bin_dir)):
            if not name.endswith(".bin"):
                continue
            filepath = os.path.join(self._bin_dir, name)
            if not os.path.isfile(filepath):
                continue

            entry = {
                "sha256": sha256_file(filepath),
                "size": os.path.getsize(filepath),
            }

            # Check for matching source directory
            if self._src_dir:
                cve_name = name.replace(".bin", "")
                src_path = os.path.join(self._src_dir, cve_name)
                if os.path.isdir(src_path):
                    entry["source_hash"] = sha256_directory(src_path)

            self._checksums[name] = entry
            count += 1

        self._save_checksums()
        logger.info("Updated checksums for %d binaries", count)
        return count

    def verify_all(self) -> IntegrityReport:
        """Verify all binaries listed in checksums.json.

        Returns:
            IntegrityReport with per-binary status.
        """
        results = []

        if not self._checksums:
            return IntegrityReport(results)

        for name, expected in sorted(self._checksums.items()):
            filepath = os.path.join(self._bin_dir, name)

            if not os.path.isfile(filepath):
                results.append(BinaryCheckResult(
                    name, IntegrityStatus.MISSING,
                    "Binary file not found"))
                continue

            actual_hash = sha256_file(filepath)
            if actual_hash != expected.get("sha256"):
                results.append(BinaryCheckResult(
                    name, IntegrityStatus.CORRUPTED,
                    "SHA-256 mismatch (expected {}, got {})".format(
                        expected["sha256"][:12], actual_hash[:12])))
                continue

            # Check staleness against source
            if self._src_dir and "source_hash" in expected:
                cve_name = name.replace(".bin", "")
                src_path = os.path.join(self._src_dir, cve_name)
                if os.path.isdir(src_path):
                    current_src_hash = sha256_directory(src_path)
                    if current_src_hash != expected["source_hash"]:
                        results.append(BinaryCheckResult(
                            name, IntegrityStatus.STALE,
                            "Source updated but binary not recompiled"))
                        continue

            results.append(BinaryCheckResult(name, IntegrityStatus.OK))

        return IntegrityReport(results)

    def verify_single(self, binary_name: str) -> BinaryCheckResult:
        """Verify a single binary by name."""
        if binary_name not in self._checksums:
            return BinaryCheckResult(binary_name, IntegrityStatus.OK,
                                     "Not in checksums (untracked)")

        expected = self._checksums[binary_name]
        filepath = os.path.join(self._bin_dir, binary_name)

        if not os.path.isfile(filepath):
            return BinaryCheckResult(binary_name, IntegrityStatus.MISSING,
                                     "Binary file not found")

        actual_hash = sha256_file(filepath)
        if actual_hash != expected.get("sha256"):
            return BinaryCheckResult(binary_name, IntegrityStatus.CORRUPTED,
                                     "SHA-256 mismatch")

        return BinaryCheckResult(binary_name, IntegrityStatus.OK)

    def attempt_recovery(self, failed: List[BinaryCheckResult],
                         compiler: str = "gcc") -> Dict[str, bool]:
        """Attempt to recompile failed binaries from source.

        Args:
            failed: List of failed BinaryCheckResults.
            compiler: Compiler to use (default: gcc).

        Returns:
            Dict mapping binary name to recovery success.
        """
        results = {}

        if not self._src_dir:
            for f in failed:
                results[f.name] = False
            return results

        has_compiler = self._check_compiler(compiler)
        if not has_compiler:
            logger.warning("Compiler %s not found, cannot auto-recover", compiler)
            for f in failed:
                results[f.name] = False
            return results

        for check in failed:
            cve_name = check.name.replace(".bin", "")
            src_dir = os.path.join(self._src_dir, cve_name)
            output = os.path.join(self._bin_dir, check.name)

            if not os.path.isdir(src_dir):
                results[check.name] = False
                continue

            c_files = [f for f in os.listdir(src_dir)
                       if f.endswith(".c")]
            if not c_files:
                results[check.name] = False
                continue

            main_src = os.path.join(src_dir, c_files[0])
            try:
                subprocess.run(
                    [compiler, "-static", "-o", output, main_src],
                    check=True, capture_output=True, timeout=60)
                results[check.name] = True
                logger.info("Recovered %s via recompilation", check.name)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    OSError) as e:
                logger.warning("Failed to recompile %s: %s", check.name, e)
                results[check.name] = False

        return results

    @staticmethod
    def _check_compiler(compiler: str) -> bool:
        """Check if a compiler is available."""
        try:
            subprocess.run([compiler, "--version"],
                          capture_output=True, timeout=5)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False

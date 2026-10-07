"""
sec-kernel Main entry point

Linux Kernel CVE Vulnerability Detection Tool
- Plugin architecture, auto-discover CVE detectors
- Support PoC/Exp exploitability verification (fileless execution)
- Designed for Linux server environments only
"""
import argparse
import os
import sys
import logging
from pathlib import Path

SECURITY_BANNER = """
\u26a0\ufe0f  SECURITY DISCLAIMER / 安全声明
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
本工具仅限在已授权的隔离测试环境中使用。
This tool is only permitted for use in authorized isolated test environments.

严禁用于生产环境或未授权系统。违规使用需承担全部法律责任。
Production use or unauthorized testing is strictly prohibited.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


def _check_root_privilege(logger: logging.Logger) -> bool:
    """Check if the process is running as root.

    sec-kernel requires root to collect kernel info, load modules in the
    Prepare phase, and execute PoC binaries that may need privileged setup.
    If not running as root, log an actionable error and tell the caller to
    re-run with sudo, then exit with a non-zero status.
    """
    try:
        euid = os.geteuid()
    except AttributeError:
        # Non-POSIX platform (should not happen on Linux), treat as non-root
        euid = -1

    if euid != 0:
        # Best-effort rebuild of the original invocation for the hint
        argv = sys.argv if sys.argv else ["python3 -m scripts"]
        cmdline = " ".join(argv)
        logger.error(
            "sec-kernel requires root privileges to run (current euid=%s).",
            euid
        )
        logger.error(
            "Please re-run with sudo, e.g.: sudo %s", cmdline
        )
        return False
    return True


def parse_args():
    """Parse command line parameters"""
    parser = argparse.ArgumentParser(
        prog="sec-kernel",
        description="Linux Kernel CVE Vulnerability Detection Tool"
    )

    # Run Mode
    parser.add_argument(
        "--mode",
        choices=["host"],
        default="host",
        help="Detection run mode (default: host, designed for Linux servers only)"
    )

    # PoC Related (PoC verification is always enabled)
    parser.add_argument("--poc-output", default="./workspace", help="PoC evidence output directory")
    parser.add_argument("--poc-timeout", type=int, default=30, help="PoC execution timeout (seconds)")
    parser.add_argument("--no-prepare", action="store_true",
                        help="Skip Prepare phase")
    parser.add_argument("--no-post", action="store_true",
                        help="Skip Post phase")
    parser.add_argument("--poc-user", default="nobody",
                        help="Run phase execution user (default: nobody)")
    parser.add_argument("--no-force-demote", action="store_true",
                        help="Do not force demote to unprivileged user")
    
    # PoC compilation
    parser.add_argument("--compile-poc", action="store_true",
                        help="Auto-compile missing PoC binaries (plain mode only)")

    # Output
    parser.add_argument("--output-dir", default="./workspace", help="Report output directory")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report format")

    # Filter
    parser.add_argument("--cve-id", help="Only detect specified CVE")

    # Coverage analysis
    parser.add_argument("--coverage", action="store_true",
                        help="Run CVE coverage analysis for the current kernel")
    parser.add_argument("--coverage-version", default=None,
                        help="Override kernel version for coverage analysis (e.g. 5.10.134)")
    parser.add_argument("--coverage-priority", type=int, default=10,
                        help="Number of top priority CVEs to show (default: 10)")

    # PoC integrity
    parser.add_argument("--verify-poc", action="store_true",
                        help="Verify PoC binary integrity against checksums")
    parser.add_argument("--update-checksums", action="store_true",
                        help="Regenerate poc-bin/checksums.json from current binaries")

    # Scan history diff
    parser.add_argument("--diff", action="store_true",
                        help="Compare current results with previous scan")
    parser.add_argument("--baseline", default=None,
                        help="Baseline snapshot file for --diff comparison")
    parser.add_argument("--regression-check", action="store_true",
                        help="Check for CVE regressions across full history")

    # Configuration
    parser.add_argument("--config", default=None, help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--list-detectors", action="store_true", help="List all available detectors")

    return parser.parse_args()


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def _ensure_output_dir(path: str) -> None:
    """Ensure output directory exists and belongs to calling user (non-root)"""
    from .utils.output_dir import ensure_output_dir
    ensure_output_dir(path)


def _run_coverage_analysis(args, logger) -> int:
    """Execute coverage analysis and print report."""
    import platform
    from .coverage.cve_map import CoverageMap
    from .coverage.validity_checker import ValidityChecker
    from .coverage.priority_advisor import PriorityAdvisor
    from .coverage.trend_tracker import TrendTracker

    kernel_version = args.coverage_version or platform.release()
    logger.info(f"Running coverage analysis for kernel {kernel_version}")

    coverage_map = CoverageMap()
    validity = ValidityChecker()
    advisor = PriorityAdvisor()
    tracker = TrendTracker()

    print(coverage_map.format_report(kernel_version))
    print()
    print(validity.format_report(kernel_version))
    print()
    print(advisor.format_report(kernel_version, top_n=args.coverage_priority))
    print()

    tracker.record_snapshot(kernel_version)
    print(tracker.format_report(kernel_version))

    return 0


def main():
    """Main entry point"""
    args = parse_args()
    setup_logging(args.verbose)

    # Output security disclaimer banner
    print(SECURITY_BANNER, file=sys.stderr)

    logger = logging.getLogger("sec-kernel")
    logger.info("sec-kernel v1.4.1 - Linux Kernel CVE Detection (JSON-driven architecture)")

    # PoC integrity commands (no root needed)
    if getattr(args, 'verify_poc', False) or getattr(args, 'update_checksums', False):
        from .poc.integrity_checker import PoCIntegrityChecker
        abs_file = Path(__file__).resolve()
        project_root = abs_file.parent.parent
        poc_bin_dir = str(project_root / "poc-bin")
        poc_src_dir = str(project_root / "poc-src")
        checker = PoCIntegrityChecker(poc_bin_dir, poc_src_dir)

        if args.update_checksums:
            count = checker.update_checksums()
            print("Updated checksums for {} binaries.".format(count))
            return 0

        report = checker.verify_all()
        print(report.format_report())
        if not report.all_ok and args.compile_poc:
            recovery = checker.attempt_recovery(report.failed)
            recovered = sum(1 for v in recovery.values() if v)
            print("\nRecovery: {}/{} binaries recompiled.".format(
                recovered, len(recovery)))
            checker.update_checksums()
        return 0 if report.all_ok else 1

    # Enforce root privilege before doing anything that needs it.
    # --list-detectors and --coverage are read-only commands allowed without root.
    if args.coverage:
        return _run_coverage_analysis(args, logger)

    if not args.list_detectors and not _check_root_privilege(logger):
        return 1

    # Pre-create output directory and assign correct permissions (before root operation)
    _ensure_output_dir(args.output_dir)
    _ensure_output_dir(args.poc_output)

    # Check PoC binaries availability (PoC is always enabled)
    from .detector.registry import get_registry
    
    registry = get_registry()
    cve_ids_to_check = []
    
    if args.cve_id:
        cve_ids_to_check = [args.cve_id]
    else:
        # Check all PoC-enabled CVEs
        for d in registry.get_all():
            if d.has_poc:
                cve_ids_to_check.append(d.cve_id)
    
    # Check each PoC binary
    missing_pocs = []
    for cve_id in cve_ids_to_check:
        if not _check_and_compile_poc(cve_id, args.compile_poc):
            missing_pocs.append(cve_id)
    
    if missing_pocs:
        logger.error(
            f"\nMissing PoC binaries for: {', '.join(missing_pocs)}\n"
            f"Compile with: cd poc-src && bash build.sh <cve_id>\n"
            f"Or rebuild package: bash build.sh"
        )
        return 1

    if args.list_detectors:
        detectors = registry.get_all()
        print(f"Available detectors ({registry.count}):")
        for d in detectors:
            poc_flag = " [PoC]" if d.has_poc else ""
            print(f"  {d.cve_id} ({d.severity}, CVSS {d.cvss_score}){poc_flag}")
        return 0

    # Determine host path (always use local paths for Linux server mode)
    host_proc = "/proc"
    host_boot = "/boot"

    # Execute detection (PoC is always enabled for all enabled CVEs)
    from .core.orchestrator import DetectionOrchestrator
    orchestrator = DetectionOrchestrator()
    results = orchestrator.run(
        poc_output_dir=args.poc_output,
        cve_id_filter=args.cve_id,
        host_proc=host_proc,
        host_boot=host_boot,
        poc_user=args.poc_user,
        poc_enable_prepare=not args.no_prepare,
        poc_enable_post=not args.no_post,
        poc_force_demote=not args.no_force_demote,
    )

    # Retrieve PoC statistics from orchestrator
    stats = orchestrator.stats

    # Terminal output (delegated to ConsolePrinter)
    from .reporter.console_printer import ConsolePrinter
    printer = ConsolePrinter(verbose=args.verbose)
    printer.print_full_report(
        results=results,
        stats=stats,
        kernel_info=orchestrator.kernel_info,
        mode=args.mode,
        execution_time=orchestrator.execution_time,
        poc_output_dir=args.poc_output,
    )

    # Generate file report
    from .reporter.report_generator import ReportGenerator
    reporter = ReportGenerator(output_dir=args.output_dir, format=args.format)
    report_path = reporter.generate(
        results=results,
        kernel_info=orchestrator.kernel_info,
        execution_time=orchestrator.execution_time,
        poc_enabled=True,
    )
    print(f"\n  Report saved: {report_path}\n")

    # Save scan history snapshot
    from .core.scan_history import ScanSnapshot, ScanHistoryStore
    kernel_version = orchestrator.kernel_info.version
    snapshot = ScanSnapshot.from_results(results, kernel_version=kernel_version)
    history_store = ScanHistoryStore(args.output_dir)
    history_path = history_store.save(snapshot)
    logger.info(f"Scan history saved: {history_path}")

    # Handle --diff flag
    if args.diff:
        if args.baseline:
            baseline = history_store.load_file(args.baseline)
        else:
            snapshots = history_store.list_snapshots()
            baseline = None
            if len(snapshots) >= 2:
                baseline = history_store.load_file(snapshots[-2])
        if baseline:
            diff_result = history_store.diff(snapshot, baseline)
            print(diff_result.format_report())
        else:
            print("No baseline available for comparison. Run another scan first.")

    # Handle --regression-check flag
    if args.regression_check:
        regressions = history_store.detect_regressions(snapshot)
        if regressions:
            print(f"\n[CRITICAL] {len(regressions)} regression(s) detected:")
            for cve in regressions:
                print(f"  ! {cve} — was previously fixed, now vulnerable again")
        else:
            print("\nNo regressions detected.")

    return 0


def _check_and_compile_poc(cve_id: str, auto_compile: bool) -> bool:
    """
    Check if PoC binary exists, compile if missing and auto_compile enabled
    
    Args:
        cve_id: CVE identifier (e.g. "CVE-2016-5195")
        auto_compile: If True, attempt compilation automatically
    
    Returns:
        True if binary available, False otherwise
    """
    logger = logging.getLogger("sec-kernel")
    
    # Detect project root (plain or zipapp mode)
    abs_file = Path(__file__).resolve()
    
    if '.pyz' in str(abs_file):
        # Zipapp mode: __file__ is inside .pyz, need to go up 2 levels
        # Example: /path/sec-kernel/scripts/main.pyz → project_root = /path/sec-kernel
        pyz_path = str(abs_file).split('.pyz')[0] + '.pyz'
        project_root = Path(pyz_path).parent.parent  # scripts → sec-kernel
    else:
        # Plain mode: __file__ = scripts/main.py → go up 2 levels to sec-kernel/
        project_root = abs_file.parent.parent
    
    # Construct poc-bin path
    poc_bin_name = f"{cve_id.replace('-', '_').lower()}.bin"
    poc_bin_path = project_root / "poc-bin" / poc_bin_name
    
    if poc_bin_path.exists():
        logger.info(f"PoC binary found: {poc_bin_path}")
        return True
    
    logger.warning(f"PoC binary NOT found: {poc_bin_path}")
    
    # Check if poc-src exists (zipapp should NOT have poc-src)
    # In zipapp mode, project_root is already at sec-kernel/ level
    if '.pyz' in str(abs_file):
        logger.error(
            f"Zipapp package missing PoC binary: {poc_bin_name}\n"
            f"Rebuild package with: bash build.sh"
        )
        return False
    
    # Plain mode: check poc-src
    poc_src_dir = project_root / "poc-src"
    poc_cve_name = cve_id.replace('-', '_').lower()
    poc_cve_dir = poc_src_dir / poc_cve_name
    
    if not poc_cve_dir.exists():
        logger.error(f"PoC source NOT found: {poc_cve_dir}")
        return False
    
    if not auto_compile:
        logger.warning(
            f"PoC binary missing. Compile with:\n"
            f"  cd poc-src && bash build.sh {poc_cve_name}"
        )
        return False
    
    # Auto-compile
    logger.info(f"Auto-compiling PoC for {cve_id}...")
    
    try:
        import subprocess
        build_script = poc_src_dir / "build.sh"
        
        if not build_script.exists():
            logger.error(f"build.sh not found: {build_script}")
            return False
        
        result = subprocess.run(
            ["bash", str(build_script), poc_cve_name],
            cwd=str(poc_src_dir),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info(f"PoC compilation successful")
            return poc_bin_path.exists()
        else:
            logger.error(f"PoC compilation failed: {result.stderr}")
            return False
    
    except Exception as e:
        logger.error(f"Compilation error: {e}")
        return False


if __name__ == "__main__":
    sys.exit(main())
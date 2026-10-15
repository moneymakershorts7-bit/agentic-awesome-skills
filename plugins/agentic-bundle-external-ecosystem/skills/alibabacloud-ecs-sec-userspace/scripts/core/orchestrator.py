"""Scan orchestrator: main() entry point and all scan-phase helpers.

This module holds the main() function and all helpers that orchestrate
the collect → analyze → report pipeline. It delegates to core.engine
for execution and core.pipeline for data flow.
"""
import os
import sys
import json
import signal
import socket
import logging
import time
import threading
from datetime import date, datetime, timezone
from typing import Dict, Any

from ..utils import preflight, workspace, stream, throttle
from ..utils.perf.resource_monitor import ResourceMonitor
from ..utils.config_loader import get_logging_config
from ..utils.symlink_validator import SymlinkValidator

# Core modules
from . import (
    parse_args,
    setup_resource_limits,
    _get_cpu_limit,
    _get_scan_timeout,
    _calculate_throttle_target,
    COLLECTORS,
    _get_analyzers,
    run_collectors,
    run_analyzers,
    run_environment_profiling,
    get_partial_results,
    global_timeout_handler,
)

# ── Global state ─────────────────────────────────────────────────────


class ScanContext:
    """Encapsulates scan execution state to avoid module-level globals."""

    def __init__(self):
        self.partial_results: Dict[str, Any] = {}
        self.args = None
        self.stream = None
        self.start_time = None
        self.start_wall_time = None
        self.resource_monitor = None
        self.timeout_flag = False
        self.old_sigalrm_handler = None

    def reset(self):
        """Reset all state for a new scan session."""
        self.partial_results = {}
        self.args = None
        self.stream = None
        self.start_time = None
        self.start_wall_time = None
        self.resource_monitor = None
        self.timeout_flag = False
        self.old_sigalrm_handler = None


_context = ScanContext()


def _init_partial_results():
    """Initialize partial results from pipeline."""
    _context.partial_results = get_partial_results()


# ── Locale detection ─────────────────────────────────────────────────

def _detect_locale() -> str:
    """Detect system locale for report language selection."""
    import locale as _locale_module
    try:
        lang = _locale_module.getlocale()[0] or ''
        if lang.lower().startswith('zh'):
            return 'zh'
    except (_locale_module.Error, ValueError, OSError):
        pass
    lang_env = os.environ.get('LANG', '').lower()
    if 'zh' in lang_env:
        return 'zh'
    return 'en'


# ── Timeout handler ─────────────────────────────────────────────────

def _global_timeout_handler(signum, frame):
    """Global timeout signal handler."""
    _context.timeout_flag = True
    global_timeout_handler(signum, frame)


# ── Logging ──────────────────────────────────────────────────────────

def _setup_logging(output_dir: str, quiet: bool = False, log_level: str = "INFO") -> logging.Logger:
    """Configure logging."""
    logger = logging.getLogger("sec-userspace")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    log_date = date.today().isoformat()
    os.makedirs(os.path.join(output_dir, 'report'), exist_ok=True)
    log_file = os.path.join(output_dir, 'report', f'sec-userspace-log-{log_date}.log')

    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(file_handler)

    if not quiet:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.INFO)
        stderr_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(stderr_handler)

    return logger


# ── Health checks ────────────────────────────────────────────────────

def run_health_checks(args):
    """Execute health checks."""

    if not preflight.check_root():
        sys.exit(1)

    workspace_dir = workspace.create_workspace(args.output_dir)
    args.workspace_dir = workspace_dir
    workspace.get_or_create_venv(args.output_dir)

    from ..utils.cleanup import cleanup_old_reports, _format_size
    deleted, freed = cleanup_old_reports(args.output_dir, args.retention_days, dry_run=False)
    if deleted > 0:
        logging.getLogger(__name__).info(f"Cleaned up {deleted} old reports, freed {_format_size(freed)}")

    _log_level = "DEBUG"
    try:
        _logging_cfg_call = get_logging_config()
        _log_level = _logging_cfg_call.get('level', 'INFO')
    except (KeyError, AttributeError, OSError):
        pass

    logger = _setup_logging(args.output_dir, getattr(args, 'quiet', False), log_level=_log_level)

    ok, messages = preflight.preflight_check(force=args.force)
    for msg in messages:
        logger.info(msg)
    if not ok and not args.force:
        logger.error("System load check failed, use --force to skip")
        sys.exit(2)

    _context.old_sigalrm_handler = signal.signal(signal.SIGALRM, _global_timeout_handler)
    setup_resource_limits()

    scan_timeout = _get_scan_timeout()
    if scan_timeout > 0:
        signal.alarm(scan_timeout)
        logging.getLogger("sec-userspace").info(f"Scan timeout: {scan_timeout}s ({scan_timeout//60}min)")
    else:
        logging.getLogger("sec-userspace").info("Scan timeout: disabled (not recommended)")

    stream_out = stream.StreamOutput(quiet=getattr(args, 'quiet', False))
    _context.args = args
    _context.stream = stream_out
    stream_out.info(f"sec-userspace starting, target: {socket.gethostname()}")
    stream_out.info("Running privilege: root")
    stream_out.info(f"Output directory: {workspace_dir}/report/")
    stream_out.info(f"Detection format: {args.format}")

    # Auto-install skill
    try:
        from ..utils.skill_installer import install_skill_links
        install_result = install_skill_links()
        if install_result["installed"]:
            stream_out.info(f"Skill installed: {', '.join(install_result['installed'])}")
    except (ImportError, OSError):
        pass

    # Initialize whitelist
    try:
        from ..utils.whitelist import get_whitelist_manager, get_whitelist_stats, detect_environment
        env_context = getattr(args, 'env', 'auto')
        if env_context == 'auto':
            env_context = detect_environment()
        whitelist_mgr = get_whitelist_manager(workspace_dir, environment=env_context)
        _merge_default_whitelist(whitelist_mgr, workspace_dir)
        stats = get_whitelist_stats(workspace_dir)
        stream_out.info(f"Whitelist loaded: {stats['active']} active entries (env: {env_context})")
    except (ImportError, OSError, json.JSONDecodeError):
        pass

    cpu_limit = _get_cpu_limit()
    throttle_target = _calculate_throttle_target(cpu_limit)
    throttle_ctrl = throttle.Throttle(target_cpu_percent=throttle_target)

    logging.getLogger("sec-userspace").info(
        f"CPU limit: {cpu_limit}% (from config), throttle target: {throttle_target}%"
    )

    return logger, stream_out, workspace_dir, throttle_ctrl




# ── Symlink validation ───────────────────────────────────────────────

def run_symlink_validation(stream_out, logger):
    """Validate skill symlinks before scan."""
    try:
        validator = SymlinkValidator()
        is_valid, issues = validator.validate_all()
        if not is_valid:
            stream_out.info("[PRE-SCAN] Validating skill symlinks...")
            for issue in issues:
                stream_out.warn(f"Symlink issue: {issue}")
            logger.warning(f"Skill symlink validation found {len(issues)} issue(s)")
        else:
            logger.debug("Skill symlinks validation passed")
    except (OSError, ValueError) as e:
        logger.warning(f"Skill symlink validation failed: {e}")


# ── Whitelist maintenance ────────────────────────────────────────────

def _merge_default_whitelist(whitelist_mgr, workspace_dir: str) -> None:
    """Merge default whitelist to user whitelist."""
    import base64
    from ..utils.path_resolver import get_asset_path

    rules_path = get_asset_path("whitelist", "analyzer_rules.b64")
    if not os.path.exists(rules_path):
        logging.getLogger(__name__).debug("Default whitelist file not found: %s", rules_path)
        return

    try:
        existing_ids = {e.id for e in whitelist_mgr.entries}
        merged_count = 0

        with open(rules_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    decoded = base64.b64decode(line).decode('utf-8')
                    rule_data = json.loads(decoded)
                except ValueError:
                    continue

                rule_id = rule_data.get("id", "")
                if rule_id and rule_id not in existing_ids:
                    from ..utils.whitelist import WhitelistEntry
                    entry = WhitelistEntry(
                        id=rule_id, module=rule_data.get("module", ""),
                        pattern=rule_data.get("pattern", ""), reason=rule_data.get("reason", ""),
                        added_by=rule_data.get("added_by", "system"),
                        added_at=rule_data.get("added_at", ""),
                        expires=rule_data.get("expires"), environment=rule_data.get("environment"),
                        tags=rule_data.get("tags", []),
                    )
                    whitelist_mgr.entries.append(entry)
                    existing_ids.add(rule_id)
                    merged_count += 1

        if merged_count > 0:
            whitelist_mgr._save()
            logging.getLogger(__name__).debug("Merged %d default whitelist entries", merged_count)
    except (OSError, ValueError, KeyError) as e:
        logging.getLogger(__name__).debug("Whitelist merge failed: %s", e)


def run_whitelist_maintenance(workspace_dir: str, stream_out, logger, args=None) -> None:
    """Run whitelist maintenance before scan starts."""
    try:
        _auto_update_whitelist_if_needed(workspace_dir, stream_out, logger, update_days=30, delta_only=False)

        from ..utils.config.whitelist_config_loader import get_whitelist_config
        from ..utils.whitelist import WhitelistManager, detect_environment

        config = get_whitelist_config()
        if not config.is_whitelist_enabled():
            stream_out.info("Whitelist is disabled in configuration")
            return

        environment = detect_environment()
        whitelist_path = os.path.join(workspace_dir, "whitelist.json")
        manager = WhitelistManager(whitelist_path, environment)

        if config.should_auto_cleanup():
            cleaned_count = manager.cleanup_expired()
            if cleaned_count > 0:
                stream_out.info(f"Cleaned up {cleaned_count} expired whitelist entries")
    except (ImportError, OSError, ValueError, KeyError) as e:
        logger.warning(f"Whitelist maintenance failed (continuing scan): {e}")


def _auto_update_whitelist_if_needed(workspace_dir: str, stream_out, logger, update_days: int = 30, delta_only: bool = False) -> None:
    """Check and run whitelist auto-update if needed."""
    try:
        from ..analyzer.whitelist_auto_updater import WhitelistAutoUpdater
    except ImportError:
        logger.debug("whitelist_auto_updater module not available, skipping auto-update")
        return
    try:
        updater = WhitelistAutoUpdater(workspace_dir=workspace_dir, delta_only=delta_only)
        if not updater.should_auto_update(update_days):
            return

        mode_str = "delta" if delta_only else "full"
        stream_out.info(f"Checking whitelist updates ({mode_str} mode, interval={update_days} days)...")

        import queue
        result_queue = queue.Queue()

        def _run_update():
            try:
                from ..analyzer.whitelist_auto_updater import run_whitelist_auto_update_cli
                report = run_whitelist_auto_update_cli(workspace_dir=workspace_dir, update_days=update_days, limit=1000, fetch_metadata=False, delta_only=delta_only)
                result_queue.put(("success", report))
            except (ImportError, OSError, ValueError, KeyError, RuntimeError) as e:
                result_queue.put(("error", str(e)))

        update_thread = threading.Thread(target=_run_update, daemon=True)
        update_thread.start()
        update_thread.join(timeout=60)

        if update_thread.is_alive():
            logger.warning("Whitelist auto-update timed out (continuing scan)")
        elif not result_queue.empty():
            try:
                status, result = result_queue.get_nowait()
                if status == "success" and result:
                    added = result.get("packages_added", 0)
                    if added > 0:
                        stream_out.info(f"Whitelist updated: {added} new packages added")
            except queue.Empty:
                pass
    except (ImportError, OSError, ValueError, KeyError, RuntimeError) as e:
        logger.debug(f"Whitelist auto-update check failed (continuing scan): {e}")


# ── Subcommand handlers ──────────────────────────────────────────────

def run_standalone(args):
    """Run standalone mode."""
    from ..utils.standalone.main import main as standalone_main
    sys.argv = ["sec-userspace-standalone"]
    if getattr(args, "list_tools", False): sys.argv.append("--list-tools")
    if getattr(args, "configure", False): sys.argv.append("--configure")
    if getattr(args, "interactive", False): sys.argv.append("--interactive")
    if getattr(args, "prompt", None): sys.argv.extend(["--prompt", args.prompt])
    if getattr(args, "skip_detect", False): sys.argv.append("--skip-detect")
    if getattr(args, "no_auto_install", False): sys.argv.append("--no-auto-install")
    if getattr(args, "api_key", None): sys.argv.extend(["--api-key", args.api_key])
    if getattr(args, "provider", None): sys.argv.extend(["--provider", args.provider])
    if getattr(args, "model", None): sys.argv.extend(["--model", args.model])
    if getattr(args, "base_url", None): sys.argv.extend(["--base-url", args.base_url])
    return standalone_main()


def handle_scheduler_commands(args):
    """Handle scheduler-related CLI commands."""
    from ..utils.scheduler import SmartScheduler
    all_analyzers = _get_analyzers()
    scheduler = SmartScheduler(all_analyzers)
    analyzers = scheduler.list_analyzers()

    print("\n" + "=" * 80)
    print("sec-userspace Analyzers")
    print("=" * 80)
    print(f"{'Name':<40} {'Type':<12} {'Est. Time':<12} {'Timeout':<10}")
    print("-" * 80)

    total_time = 0.0
    for a in analyzers:
        print(f"{a['name']:<40} {a['type']:<12} {a['estimated_time']:<12.1f}s {a['timeout']:<10}s")
        total_time += a['estimated_time']

    print("-" * 80)
    print(f"{'TOTAL':<40} {'':<12} {total_time:<12.1f}s")
    print("=" * 80)

    stats = scheduler.get_analyzer_stats()
    print(f"\nTotal analyzers: {stats['total']}")
    print(f"Estimated total time: {stats['total_estimated_time']:.1f}s")
    print("\nBy type:")
    for atype, data in stats['by_type'].items():
        print(f"  {atype}: {data['count']} analyzers, {data['time']:.1f}s")
    print()


def handle_performance_commands(args):
    """Handle performance monitoring subcommands."""
    from ..utils.perf import PerformanceTracker, DashboardGenerator
    from pathlib import Path

    tracker = PerformanceTracker()

    if args.perf_command == "show":
        print("\n=== Performance Metrics ===\n")
        slowest = tracker.get_slowest_analyzers(days=7, limit=10)
        if slowest:
            print("Top 10 Slowest Analyzers (7-day average):")
            print(f"{'Analyzer':<45} {'Avg Duration':>12}")
            print("-" * 60)
            for name, avg_dur in slowest:
                from ..utils.perf.tracker import PERFORMANCE_BUDGETS
                budget = PERFORMANCE_BUDGETS.get(name, PERFORMANCE_BUDGETS["default"])
                status = "EXCEEDED" if avg_dur > budget else "OK"
                print(f"{name:<45} {avg_dur:>10.2f}s  [{status}]")
        else:
            print("No performance data available yet. Run a scan first.")
        print()
    elif args.perf_command == "dashboard":
        output_dir = Path("/tmp/sec-userspace-perf")
        output_dir.mkdir(parents=True, exist_ok=True)
        generator = DashboardGenerator(tracker)
        generator.generate(output_dir / "dashboard.html", days=30)
        print(f"\nPerformance dashboard generated: {output_dir / 'dashboard.html'}")
    elif args.perf_command == "check":
        workspace_p = Path("/data/sec-userspace/workspace")
        today = datetime.now().strftime("%Y-%m-%d")
        json_report = workspace_p / today / "report" / f"sec-report-{today}.json"
        if not json_report.exists():
            print(f"No report found for today. Run a scan first.")
            return
        with open(json_report, encoding='utf-8') as f:
            report_data = json.load(f)
        violations = tracker.check_budget_violations(report_data)
        if violations:
            print(f"\nFound {len(violations)} performance budget violation(s):\n")
            for v in violations:
                print(f"  {v['analyzer']}: {v['duration']:.2f}s / Budget: {v['budget']:.2f}s ({v['excess_percent']:.1f}% over)")
        else:
            print("\nAll analyzers within performance budgets\n")


def run_trend_analysis_if_enabled(args, stream_out, logger, module_stats=None, throttle_ctrl=None, report_summary=None):
    """Execute trend analysis."""
    workspace_dir = getattr(args, "workspace_dir", args.output_dir)
    report_dir = os.path.join(workspace_dir, "report")
    try:
        from ..reporter.trend import TrendAnalyzer
        trend_analyzer = TrendAnalyzer(base_dir=args.output_dir, days=7)
        trend_result = trend_analyzer.analyze()
        if trend_result.get("available"):
            md_content = trend_analyzer.generate_markdown(trend_result)
            trend_path = trend_analyzer.save_report(md_content, report_dir)
            stream_out.info(f"Patrol report: direction={trend_result['trend_direction']}, persistent={len(trend_result['persistent_issues'])}, new={len(trend_result['new_issues'])}, resolved={len(trend_result['resolved_issues'])}")
            stream_out.info(f"Patrol report output to {trend_path}")
    except (ImportError, OSError, ValueError, KeyError) as e:
        logger.debug(f"Patrol report generation failed: {e}")


# ── Error/timeout reports ────────────────────────────────────────────

def _generate_timeout_report(workspace_dir: str, args, stream_out) -> None:
    """Generate a minimal report when scan times out."""
    report_dir = os.path.join(workspace_dir, datetime.now().strftime("%Y-%m-%d"), "report")
    os.makedirs(report_dir, exist_ok=True)
    date_str = date.today().isoformat()
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"

    partial_evidences = len(_context.partial_results.get("evidences", []))
    partial_modules = sum(1 for m in _context.partial_results.get("module_stats", []) if m.get("status") != "skipped")
    total_modules = len(_context.partial_results.get("module_stats", []))

    timeout_md = (
        f"# Security Intrusion Detection Report (Timeout - Partial Results)\n\n"
        f"## Conclusion\n- **Mode**: Default (Timeout)\n- **Time**: {datetime.now(timezone.utc).isoformat()}\n"
        f"- **Host**: {hostname}\n- **Status**: Scan timed out\n\n"
        f"## Partial Results\n- **Evidence**: {partial_evidences}\n- **Modules**: {partial_modules}/{total_modules}\n\n"
        f"Use --force or retry during lower load.\n"
    )
    sec_report_path = os.path.join(report_dir, f"sec-report-{date_str}.md")
    with open(sec_report_path, "w", encoding="utf-8") as f:
        f.write(timeout_md)
    stream_out.info(f"Timeout report: {sec_report_path}")


def _generate_error_report(workspace_dir: str, args, error: Exception, stream_out) -> None:
    """Generate a minimal error report on fatal failure."""
    import traceback
    report_dir = os.path.join(workspace_dir, datetime.now().strftime("%Y-%m-%d"), "report")
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")

    partial_evidences = len(_context.partial_results.get("evidences", []))
    partial_modules = sum(1 for m in _context.partial_results.get("module_stats", []) if m.get("status") != "skipped")

    error_report = {
        "report_type": "fatal_error", "timestamp": timestamp,
        "error_type": type(error).__name__, "error_message": str(error),
        "traceback": traceback.format_exc(),
        "partial_results": {"evidences": partial_evidences, "modules": partial_modules},
    }
    report_path = os.path.join(report_dir, f"error-report-{timestamp}.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(error_report, f, indent=2, ensure_ascii=False)
    stream_out.warn(f"Error report: {report_path}")


# Report generation (now in reporter.report)
from ..reporter.report import generate_all_reports


# ── Main entry point ─────────────────────────────────────────────────

def _run_feedback_loop(workspace_dir: str, module_stats: list, evidences: list,
                       system_info: dict, stream_out, logger) -> None:
    """Record scan history and run self-evolution analysis."""
    try:
        from ..feedback.scan_history import ScanHistoryStore
        from ..feedback.confidence_adjuster import ConfidenceAdjuster
        from ..feedback.pattern_learner import PatternLearner
        from ..feedback.evolution_reporter import EvolutionReporter

        # Record this scan
        history_store = ScanHistoryStore(workspace_dir)
        entry = history_store.record(module_stats, evidences, system_info)
        env_fp = entry.get("env_fingerprint", "")

        # Update confidence scores
        adjuster = ConfidenceAdjuster(workspace_dir)
        confidence_actions = adjuster.update(env_fingerprint=env_fp)

        # Run pattern learning (every 10 scans)
        scan_count = len(history_store.load_history())
        pattern_analysis = {}
        if scan_count % 10 == 0 and scan_count >= 10:
            learner = PatternLearner(workspace_dir)
            pattern_analysis = learner.analyze()
            if pattern_analysis.get("candidate_iocs"):
                learner.save_candidate_iocs(pattern_analysis["candidate_iocs"])

        # Generate evolution summary
        reporter = EvolutionReporter(confidence_actions, pattern_analysis)
        summary = reporter.generate_summary()
        for line in summary.split("\n"):
            if line.strip():
                stream_out.info(line)

    except (ImportError, OSError, ValueError, KeyError) as e:
        logger.debug(f"Feedback loop execution skipped: {e}")


def main():
    """Main function — orchestrates the full scan pipeline."""
    _context.reset()
    _init_partial_results()
    _context.start_time = time.monotonic()
    _context.start_wall_time = time.time()
    _context.resource_monitor = ResourceMonitor()
    _context.timeout_flag = False

    args = parse_args()

    # Handle subcommands
    if args.subcommand == "standalone":
        return run_standalone(args)
    if args.list_analyzers:
        handle_scheduler_commands(args)
        return
    if hasattr(args, 'whitelist_command') and args.whitelist_command:
        from ..utils.whitelist_cli import handle_whitelist_commands
        handle_whitelist_commands(args)
        return
    if args.show_assets is not None:
        from ..utils.asset_manager import get_asset_manager
        mgr = get_asset_manager()
        if mgr.load():
            print(mgr.show(category=args.show_assets))
        else:
            print("Error: failed to load assets data", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    if hasattr(args, 'perf_command') and args.perf_command:
        handle_performance_commands(args)
        return
    if getattr(args, 'analyzer_health', False):
        from ..utils.analyzer_health import AnalyzerHealthTracker
        workspace_dir = args.output_dir
        tracker = AnalyzerHealthTracker(workspace_dir)
        print(tracker.format_report())
        return

    # FP tracker
    from ..utils.fp_tracker import get_tracker
    tracker = get_tracker(enable_suppression=not args.no_fp_suppression)

    from ..utils.fp_auto_learner import get_fp_auto_learner
    fp_auto_learner = get_fp_auto_learner(output_dir=getattr(args, 'output_dir', None))
    fp_learner_stats = fp_auto_learner.get_stats()
    logging.getLogger('sec-userspace').info(
        "FP auto-learner initialized: %d entries from %s",
        fp_learner_stats['enabled'], fp_learner_stats['file']
    )

    # Health check
    logger, stream_out, workspace_dir, throttle_ctrl = run_health_checks(args)

    exit_code = 0
    try:
        run_symlink_validation(stream_out, logger)
        run_whitelist_maintenance(workspace_dir, stream_out, logger, args)
        # Get load info
        load_ratio = None
        timeout_scaler = None
        try:
            from ..utils.preflight import get_preflight_load_info
            load_info = get_preflight_load_info()
            load_ratio = load_info.get('load_ratio')
            timeout_scaler = load_info.get('timeout_scaler')
            if args is not None:
                args.load_ratio = load_ratio
            if load_ratio is not None:
                logger.info(f"System load: {load_info.get('load5', 0):.1f} (ratio: {load_ratio:.1f}x)")
        except (ImportError, OSError, ValueError, AttributeError) as e:
            logger.debug(f"Failed to get load info: {e}")

        # Phase 1: Collection
        stream_out.info("=" * 40)
        stream_out.info("Phase One: Data Collection")
        collection_start = time.monotonic()

        try:
            collected_data = run_collectors(
                COLLECTORS(), stream_out, throttle_ctrl,
                workspace_dir=workspace_dir,
                timeout_scaler=timeout_scaler,
            )
            collection_elapsed = time.monotonic() - collection_start
            if collection_elapsed > 75.0:
                stream_out.warn("WARNING: Collection exceeded 75s timeout ({:.1f}s)".format(collection_elapsed))
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, AttributeError) as e:
            logger.error("Collection phase failed: %s", e)
            collected_data = _context.partial_results.get("collected_data", {})

        _context.partial_results["collected_data"] = collected_data
        _context.resource_monitor.snapshot()

        # Phase 1.5: Environment profiling
        stream_out.info("=" * 40)
        stream_out.info("Phase 1.5: Environment and Business Profiling")
        active_analyzers, server_profile, system_info = run_environment_profiling(args, collected_data, stream_out, logger)
        _context.partial_results["system_info"] = system_info

        # Phase 2: Analysis
        stream_out.info("=" * 40)
        stream_out.info("Phase Two: Analysis Detection")
        analysis_start = time.monotonic()

        try:
            evidences, module_stats, analyzer_instances = run_analyzers(
                active_analyzers, collected_data, stream_out, throttle_ctrl, workspace_dir, args
            )
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, AttributeError) as e:
            logger.error(f"Analysis phase failed: {e}")
            evidences, module_stats, analyzer_instances = [], [], {}

        _context.partial_results["evidences"] = evidences
        _context.partial_results["module_stats"] = module_stats
        _context.resource_monitor.snapshot()

        if _context.timeout_flag:
            logger.error("Global timeout triggered")
            stream_out.error("Scan timed out")
            raise SystemExit(3)

        if server_profile is not None:
            system_info["server_profile"] = server_profile.to_dict()

        # Phase 3: Report
        stream_out.info("=" * 40)
        stream_out.info("Phase Three: Comprehensive Judgment and Report Generation")
        generate_all_reports(
            args, evidences, system_info, module_stats, stream_out, logger,
            start_time=_context.start_time, start_wall_time=_context.start_wall_time,
            whitelist_metadata=None, throttle_ctrl=throttle_ctrl,
        )

        # Phase 4: Trend analysis
        run_trend_analysis_if_enabled(args, stream_out, logger, module_stats=module_stats, throttle_ctrl=throttle_ctrl)

        # Phase 5: Feedback loop — record history and run self-evolution
        _run_feedback_loop(workspace_dir, module_stats, evidences, system_info, stream_out, logger)

    except SystemExit as e:
        if _context.timeout_flag and _context.partial_results.get("evidences"):
            try:
                generate_all_reports(args, _context.partial_results["evidences"], _context.partial_results["system_info"], _context.partial_results["module_stats"], stream_out, logger,
                    start_time=_context.start_time, start_wall_time=_context.start_wall_time, throttle_ctrl=throttle_ctrl)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as _report_err:
                _generate_timeout_report(workspace_dir, args, stream_out)
        elif _context.timeout_flag:
            _generate_timeout_report(workspace_dir, args, stream_out)
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, AttributeError, ImportError) as e:
        logger.error(f"Execution abnormal: {e}", exc_info=True)
        try:
            _generate_error_report(workspace_dir, args, e, stream_out)
        except (OSError, ValueError, TypeError) as report_err:
            sys.stderr.write(f"[ERROR] Fatal error: {e}\n")
            sys.stderr.write(f"[ERROR] Failed to generate error report: {report_err}\n")
        exit_code = 4
    finally:
        signal.alarm(0)
        old_handler = getattr(_context, 'old_sigalrm_handler', signal.SIG_DFL)
        signal.signal(signal.SIGALRM, old_handler)
        try:
            workspace.cleanup_tmp(workspace_dir)
        except OSError as cleanup_err:
            logger.warning(f"Cleanup temporary files failed: {cleanup_err}")
        stream_out.info("Temporary files cleaned")

    if exit_code != 0:
        sys.exit(exit_code)

    elapsed = time.monotonic() - _context.start_time
    stream_out.info(f"sec-userspace execution complete, total time {elapsed:.1f}s")

    if _context.resource_monitor is not None:
        resource_summary = _context.resource_monitor.format_summary()
        stream_out.info(resource_summary)


__all__ = ['main']

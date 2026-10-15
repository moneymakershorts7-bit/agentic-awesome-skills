"""Scan engine: orchestration of collect → analyze → report pipeline (sequential)."""
import logging
import threading

from .constants import COLLECTOR_PREFERRED_ORDER
from ..collector.collector_registry import (
    get_available_collectors,
    load_collectors,
)
from ..collector.data_validator import CollectorValidator
from ..analyzer.analyzer_registry import (
    ANALYZER_REGISTRY,
    load_analyzer,
    ANALYZER_PRIORITY_ORDER,
)
from ..reporter.severity import Severity


# ── Collector list building ───────────────────────────────────────────

def _build_collector_list() -> list:
    """Build collector list from dynamically discovered collectors."""
    available = set(get_available_collectors())
    ordered_names = []

    for name in COLLECTOR_PREFERRED_ORDER:
        if name in available:
            ordered_names.append(name)
            available.discard(name)

    for name in sorted(available):
        ordered_names.append(name)

    return load_collectors(ordered_names)


class _CollectorsCallable:
    """Callable object that behaves like a list but loads on demand."""

    def __call__(self):
        return _build_collector_list()

    def __len__(self):
        return len(self())

    def __iter__(self):
        return iter(self())

    def __getitem__(self, idx):
        return self()[idx]


COLLECTORS = _CollectorsCallable()


# ── Analyzer list building ────────────────────────────────────────────

def _build_analyzers_list() -> list:
    """Build analyzer list from registry at runtime."""
    analyzer_names = list(ANALYZER_PRIORITY_ORDER)
    for name in ANALYZER_REGISTRY:
        if name not in analyzer_names:
            analyzer_names.append(name)

    analyzers = []
    for name in analyzer_names:
        if name in ANALYZER_REGISTRY:
            try:
                cls = load_analyzer(name)
                analyzers.append((name, cls))
            except (ImportError, AttributeError, KeyError) as e:
                logging.getLogger("sec-userspace").warning("Skipping analyzer %s: %s", name, e)

    return analyzers


_analyzers_cache = None
_analyzers_cache_lock = threading.Lock()


def _get_analyzers():
    """Get analyzers list, building on first call."""
    global _analyzers_cache
    if _analyzers_cache is None:
        with _analyzers_cache_lock:
            if _analyzers_cache is None:
                logger = logging.getLogger("sec-userspace")
                logger.debug("Loading analyzers")
                _analyzers_cache = _build_analyzers_list()
    return _analyzers_cache




# ── Collection phase (sequential) ────────────────────────────────────

def run_collectors(collectors, stream_out, throttle_ctrl, workspace_dir=None, **kwargs) -> dict:
    """Execute collectors sequentially.

    Args:
        collectors: List of (name, class) tuples
        stream_out: Stream output handler
        throttle_ctrl: Throttle controller
        workspace_dir: Workspace directory for collectors that need it
    """
    results = {}
    total = len(collectors)
    baseline_memory = throttle_ctrl.set_baseline_memory()

    for i, (name, cls) in enumerate(collectors, 1):
        try:
            import inspect
            sig = inspect.signature(cls.__init__)
            params = {}
            if 'workspace_dir' in sig.parameters:
                params['workspace_dir'] = workspace_dir
            collector = cls(**params) if params else cls()
        except (ValueError, TypeError):
            collector = cls()

        stream_out.progress(i, total, "Collect {}".format(collector.name), "Starting...")

        result = collector.safe_collect(baseline_memory_mb=baseline_memory)
        results[name] = result

        if result.status == "success":
            stream_out.progress(
                i, total, "Collect {}".format(collector.name),
                "Complete (collected {} items, {:.1f}s, memory delta: {:+.1f}MB)".format(
                    result.items_count, result.duration, result.memory_delta_mb
                )
            )
        else:
            stream_out.progress(
                i, total, "Collect {}".format(collector.name),
                "{}: {}".format(result.status, result.reason)
            )

        throttle_ctrl.throttle()

        if result.status == "success":
            mem_ok = throttle_ctrl.check_collector_memory_delta(
                collector.name, result.memory_before_mb, result.memory_after_mb
            )
            if not mem_ok:
                stream_out.progress(
                    i, total, "Collect {}".format(collector.name),
                    "Memory delta exceeded budget, GC attempted"
                )

    # Validate collected data quality and annotate results
    validator = CollectorValidator()
    quality_summary = validator.validate_collect_results(results)
    for name, vr in quality_summary["results"].items():
        if name in results:
            results[name].data_quality = vr.degradation.lower()
            results[name].data_quality_score = vr.quality
            results[name].degraded_fields = vr.warnings

    # Store quality summary as a sentinel key for downstream consumers
    results["_data_quality"] = quality_summary

    return results


# ── Analysis phase (sequential) ──────────────────────────────────────

def run_analyzers(analyzers_list, collected_data, stream_out, throttle_ctrl, workspace_dir=None, args=None):
    """Execute analyzers sequentially.

    Args:
        analyzers_list: Ignored (we rebuild internally)
        collected_data: Data from collection phase
        stream_out: Stream output handler
        throttle_ctrl: Throttle controller
        workspace_dir: Workspace directory
        args: CLI arguments
    """
    analyzers = _get_analyzers()
    all_evidences = []
    module_stats = []
    analyzer_instances = {}

    # Determine which analyzers to skip due to data quality degradation
    skip_analyzers = set()
    quality_summary = collected_data.get("_data_quality")
    if quality_summary and isinstance(quality_summary, dict):
        skip_analyzers = quality_summary.get("skip_analyzers", set())

    # Feedback loop: pre-load confidence adjustments
    _confidence_state = {}
    if workspace_dir:
        try:
            from ..feedback.confidence_adjuster import ConfidenceAdjuster
            _adj = ConfidenceAdjuster(workspace_dir)
            _confidence_state = _adj.get_all_adjustments()
        except (ImportError, OSError, ValueError):
            pass

    for name, cls in analyzers:
        if name in skip_analyzers:
            module_stats.append({
                "name": name,
                "status": "skipped",
                "findings": 0,
                "duration": 0,
                "skip_reason": "DATA_INCOMPLETE: dependent collector returned empty data",
                "execution_mode": "skipped",
            })
            continue
        try:
            try:
                analyzer = cls(workspace_dir=workspace_dir) if workspace_dir else cls()
            except TypeError:
                analyzer = cls()
        except (ImportError, AttributeError, KeyError) as e:
            logging.getLogger("sec-userspace").warning("Skipping analyzer %s: %s", name, e)
            module_stats.append({
                "name": name,
                "status": "failed",
                "findings": 0,
                "duration": 0,
                "skip_reason": "Load failed: {}".format(e),
                "execution_mode": "failed",
            })
            continue

        analyzer_instances[name] = analyzer

        # Feedback loop: inject confidence factor from pre-loaded state
        if name in _confidence_state:
            analyzer.confidence_factor = _confidence_state[name].get(
                "adjusted_confidence", 1.0)

        result = analyzer.safe_analyze(collected_data)

        if result.status == "success":
            all_evidences.extend(result.evidences)
            for ev in result.evidences:
                if ev.severity in (Severity.CRITICAL, Severity.HIGH):
                    stream_out.finding(ev.severity.value, "{}: {}".format(ev.title, ev.description[:80]))

        module_stats.append({
            "name": name,
            "status": result.status,
            "findings": len(result.evidences) if result.status == "success" else 0,
            "duration": result.duration,
            "skip_reason": result.reason if result.status == "skipped" else None,
            "execution_mode": "sequential",
        })

        if throttle_ctrl:
            throttle_ctrl.throttle()

    # Record health metrics
    if workspace_dir and module_stats:
        try:
            from ..utils.analyzer_health import AnalyzerHealthTracker
            health_tracker = AnalyzerHealthTracker(workspace_dir)
            health_tracker.record_batch(module_stats)
        except (ImportError, OSError):
            pass

    return all_evidences, module_stats, analyzer_instances


# ── Environment profiling ────────────────────────────────────────────

def run_environment_profiling(args, collected_data, stream_out, logger):
    """Execute environment profiling and analyzer dispatch."""
    server_profile = None
    system_info = {}

    if "system" in collected_data and collected_data["system"].status == "success":
        system_info = collected_data["system"].data

    stream_out.info("Running all analyzers (default mode)")
    active_analyzers = _get_analyzers()

    return active_analyzers, server_profile, system_info


# ── Exports ──────────────────────────────────────────────────────────

__all__ = [
    'COLLECTORS',
    '_get_analyzers',
    'run_collectors',
    'run_analyzers',
    'run_environment_profiling',
]

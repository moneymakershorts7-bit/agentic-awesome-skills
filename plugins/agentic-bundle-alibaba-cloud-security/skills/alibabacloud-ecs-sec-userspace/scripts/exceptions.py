"""Custom exception hierarchy for sec-userspace.

Provides a typed exception tree that enables precise exception handling
across collectors, analyzers, reporters, and configuration modules.

All custom exceptions derive from SecInspectError to allow catch-all
handling at system boundaries while preserving specificity internally.
"""


class SecInspectError(Exception):
    """Base exception for all sec-userspace errors.
    
    Attributes:
        message: Human-readable error description
        module: Module name where error occurred (optional)
    """
    
    def __init__(self, message: str, module: str = None) -> None:
        super().__init__(message)
        self.message = message
        self.module = module


# ── Collector exceptions ─────────────────────────────────────────────

class CollectorError(SecInspectError):
    """Base exception for collector failures."""


class CollectorTimeoutError(CollectorError):
    """Collector execution exceeded timeout."""


class CollectorDataValidationError(CollectorError):
    """Collector returned invalid or malformed data."""


class CollectorResourceError(CollectorError):
    """Insufficient system resources for collection."""


# ── Analyzer exceptions ──────────────────────────────────────────────

class AnalyzerError(SecInspectError):
    """Base exception for analyzer failures."""


class AnalyzerTimeoutError(AnalyzerError):
    """Analyzer execution exceeded timeout."""


class AnalyzerDataError(AnalyzerError):
    """Analyzer received invalid or incomplete input data."""


class AnalyzerSkippedError(AnalyzerError):
    """Analyzer was intentionally skipped (not a failure)."""


# ── Reporter exceptions ──────────────────────────────────────────────

class ReporterError(SecInspectError):
    """Base exception for reporter failures."""


class ReportGenerationError(ReporterError):
    """Failed to generate report output."""


class ReportValidationError(ReporterError):
    """Report content failed validation checks."""


# ── Configuration exceptions ─────────────────────────────────────────

class ConfigError(SecInspectError):
    """Base exception for configuration errors."""


class ConfigNotFoundError(ConfigError):
    """Configuration file or key not found."""


class ConfigValidationError(ConfigError):
    """Configuration content failed validation."""


# ── Resource exceptions ──────────────────────────────────────────────

class TimeoutError(SecInspectError):  # noqa: A001 — shadows builtin, intentional
    """Generic timeout error (distinct from concurrent.futures.TimeoutError)."""


class ResourceExhaustedError(SecInspectError):
    """System resources (memory, CPU, disk) exhausted."""


class MemoryExhaustedError(ResourceExhaustedError):
    """Memory budget exceeded."""

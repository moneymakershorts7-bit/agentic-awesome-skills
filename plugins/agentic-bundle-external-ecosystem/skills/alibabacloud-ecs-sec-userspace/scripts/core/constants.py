"""Core constants for sec-userspace scan pipeline."""

# Collector preferred execution order (volatility descending)
COLLECTOR_PREFERRED_ORDER = [
    "system", "process", "network", "user", "cron", "service",
    "filesystem", "log", "dns", "package_history",
]

# Development environment path indicators for FP detection
DEV_ENV_PATHS = frozenset([
    '.qoder_cli', '.cursor', '.vscode', '.idea', '.claude',
    '.git/hooks', '__pycache__', '.cache',
    'node_modules', '.npm', '.bun', '.yarn', '.cargo',
    '.venv', 'venv', 'virtualenv',
    'dev', 'staging', 'example', 'demo', 'sample',
    'template', 'fixture', 'mock', 'test', 'tests',
    'testing', 'sandbox', 'playground',
    'build', 'dist', 'out', 'target', 'bin', 'obj',
    'docs', 'documentation', 'examples', 'tutorials',
])

# AI tool directory indicators
AI_TOOL_DIRS = ['.qoder', '.cursor', '.claude', '.vscode', '.idea']

# Test/example keywords for FP detection
TEST_KEYWORDS = ['test', 'example', 'sample', 'demo', 'fixture', 'mock']

# Default scan timeout (seconds)
DEFAULT_SCAN_TIMEOUT = 300

# Default CPU limit percentage
DEFAULT_CPU_LIMIT = 40

# Default output directory
DEFAULT_OUTPUT_DIR = '/data/sec-userspace/workspace'

# Default report retention (days)
DEFAULT_RETENTION_DAYS = 180

# Throttle target percentages by CPU limit level
THROTTLE_TARGETS = {
    80: 5.0,   # >= 80%: default throttle
    40: 2.5,   # >= 40%: half throttle
    20: 1.0,   # >= 20%: strong throttle
    0: 0.5,    # < 20%: very strong throttle
}

# Worker count calculation by CPU limit level
WORKER_COUNTS = {
    80: lambda cpu_count: max(min(cpu_count // 2, 4), 2),  # >= 80%
    40: lambda cpu_count: max(min(cpu_count // 4, 2), 1),  # >= 40%
    20: lambda cpu_count: 1,                                # >= 20%
    0:  lambda cpu_count: 1,                                # < 20%
}

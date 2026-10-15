"""CLI argument parsing for sec-userspace."""
import argparse

from ..utils.config_loader import load_config, get_server_config, get_scan_config, get_logging_config


def _setup_performance_commands(subparsers):
    """Setup performance monitoring subcommands."""
    perf_parser = subparsers.add_parser(
        "perf",
        help="Performance monitoring and analysis"
    )
    perf_parser.add_argument(
        "perf_command",
        choices=["show", "dashboard", "check"],
        help="Performance command"
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.
    
    CLI parameters follow the precedence: CLI > config file > hardcoded defaults.
    
    Returns:
        Parsed argument namespace
    """
    file_config = load_config()
    server_cfg = get_server_config(file_config)
    scan_cfg = get_scan_config(file_config)
    logging_cfg = get_logging_config(file_config)

    parser = argparse.ArgumentParser(
        description="sec-userspace - Linux Server Security Intrusion Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    # Add subcommand for standalone runner
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")
    
    # Standalone runner subcommand
    standalone_parser = subparsers.add_parser(
        "standalone",
        help="Run sec-userspace in standalone mode (with built-in LLM client)"
    )
    standalone_parser.add_argument("--list-tools", action="store_true", help="List discovered AI tools")
    standalone_parser.add_argument("--configure", action="store_true", help="Run configuration wizard")
    standalone_parser.add_argument("--interactive", "-i", action="store_true", help="Start interactive chat session")
    standalone_parser.add_argument("--prompt", "-p", type=str, default=None, help="Custom detection prompt")
    standalone_parser.add_argument("--skip-detect", action="store_true", help="Skip AI tool detection, use built-in client directly")
    standalone_parser.add_argument("--no-auto-install", action="store_false", dest="auto_install", default=True, help="Disable automatic skill installation")
    standalone_parser.add_argument("--api-key", "-k", type=str, help="API key (overrides config file)")
    
    # Import and setup K8S commands
    try:
        from ..utils.k8s.deploy_commands import setup_k8s_commands
        setup_k8s_commands(subparsers)
    except ImportError:
        pass
    
    # Import and setup whitelist learning commands
    try:
        from ..utils.whitelist_cli import setup_whitelist_commands
        setup_whitelist_commands(subparsers)
    except ImportError:
        pass
    
    # Setup performance monitoring commands
    _setup_performance_commands(subparsers)
    
    standalone_parser.add_argument("--provider", type=str, choices=["bailian", "openai", "anthropic", "deepseek"], help="API provider")
    standalone_parser.add_argument("--model", "-m", type=str, help="Model name")
    standalone_parser.add_argument("--base-url", type=str, help="Custom API base URL")
    
    # Core parameters (user-facing)
    parser.add_argument('--output-dir', type=str, default=scan_cfg.get('output_dir', '/data/sec-userspace/workspace'),
                        help='Output root directory, date subdirectory auto-created (default: from config)')
    parser.add_argument('--format', type=str, choices=['markdown', 'json', 'both'], default=scan_cfg.get('format', 'both'),
                        help='Output format (default: both)')
    parser.add_argument('--quiet', action='store_true', default=logging_cfg.get('quiet', False),
                        help='Suppress stderr output (default: from config)')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Skip load protection checks')
    parser.add_argument('--list-analyzers', action='store_true', default=False,
                        help='List all analyzers with their estimated time and type')
    parser.add_argument('--show-assets', nargs='?', const='all',
                        choices=['all', 'ioc', 'whitelist'], default=None,
                        help='Show current assets data (decoded), options: all, ioc, whitelist (default: all)')
    parser.add_argument('--analyzer-health', action='store_true', default=False,
                        help='Display analyzer health dashboard (trigger rate, errors, staleness)')

    # Optional parameters (useful for ops)
    parser.add_argument('--no-fp-suppression', action='store_true', default=False,
                        help='Disable FP suppression (report all results, for audit)')
    parser.add_argument('--force-json', action='store_true', default=False,
                        help='Force JSON report generation')
    parser.add_argument('--full-report', action='store_true', default=False,
                        help='Enable all report features: timeline, attack chain, cross-correlation, coverage')
    parser.add_argument('--lang', type=str, choices=['auto', 'en', 'zh', 'both'],
                        default='auto',
                        help='Report language: auto (detect locale), en, zh, both (default: auto)')
    parser.add_argument('--env', type=str, choices=['auto', 'development', 'production', 'ci', 'container'],
                        default='auto',
                        help='Environment context: auto (detect), development, production, ci, container (default: auto)')
    parser.add_argument('--retention-days', type=int, default=180,
                        help='Report retention period in days (default: 180)')
    parser.add_argument('--dry-run', action='store_true', default=False,
                        help='Show what would be reported without sending')

    return parser.parse_args()

#!/usr/bin/env python3
"""sec-userspace - Linux Server Security Intrusion Detection Tool Entry

Minimal entry point that delegates to core modules.
Supports plain mode (direct execution) and zipapp mode (.pyz).
"""
from pathlib import Path


def main():
    """Main entry point - supports plain and zipapp modes."""

    main_dir = Path(__file__).parent
    pyz_path = main_dir / "main.pyz"

    if pyz_path.exists():
        from .core.zipapp_runtime import run_zipapp_mode
        run_zipapp_mode(main_dir)
    else:
        from .core.orchestrator import main as orchestrator_main
        orchestrator_main()


if __name__ == "__main__":
    main()

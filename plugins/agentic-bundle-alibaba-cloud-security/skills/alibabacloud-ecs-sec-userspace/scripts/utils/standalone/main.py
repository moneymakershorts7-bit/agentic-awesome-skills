#!/usr/bin/env python3
"""
sec-userspace standalone runner.

Provides a self-contained execution environment for sec-userspace,
supporting AI tool discovery and built-in interactive client.
"""

import argparse
import sys

from .discovery import discover_ai_tools, get_preferred_tool, run_with_installed_tool
from .config import load_config, is_configured
from .wizard import run_wizard, quick_configure
from .client import StandaloneClient, get_skill_path
from . import __version__


def print_banner():
    """Print welcome banner."""
    print()
    print("=" * 60)
    print("           sec-userspace - Linux Security Detection Tool")
    print(f"                    Standalone Runner v{__version__}")
    print("=" * 60)
    print()


def cmd_list_tools(args):
    """List discovered AI tools."""
    print("[INFO] Discovering AI tools...\n")

    tools = discover_ai_tools()

    if not tools:
        print("No AI tools found in your system.")
        print("\nSupported tools:")
        print("  - claude (Claude Code)")
        print("  - opencode (OpenCode)")
        print("  - qodercli (QoderCLI)")
        print("  - cursor (Cursor CLI)")
        print("  - windsurf (Windsurf CLI)")
    else:
        print(f"Found {len(tools)} AI tool(s):\n")
        for tool in tools:
            version_info = f" (v{tool.version})" if tool.version else ""
            print(f"  - {tool.name}: {tool.path}{version_info}")

    return 0


def cmd_configure(args):
    """Run configuration wizard."""
    print("[INFO] Starting configuration wizard...\n")

    config = run_wizard()

    # Test connection
    print("\n[INFO] Testing API connection...")
    try:
        client = StandaloneClient(config)
        if client.test_connection():
            print("[INFO] Connection successful!")
        else:
            print("[WARN] Connection test failed, please check your API key.")
    except (OSError, ValueError, RuntimeError) as e:
        print(f"[WARN] Connection test failed: {e}")

    return 0


def cmd_run(args):
    """Run security detection."""
    print_banner()

    # Discover AI tools
    if not args.skip_detect:
        print("[INFO] Discovering AI tools...")
        tools = discover_ai_tools()

        if tools:
            preferred = get_preferred_tool(tools)
            if preferred:
                print(f"[INFO] Found AI tool: {preferred.name}")

                if args.auto_install:
                    print(f"[INFO] Using {preferred.name} to execute sec-userspace...")
                    skill_path = get_skill_path()
                    prompt = "Run Linux security detection with sec-userspace"
                    return run_with_installed_tool(preferred.name, skill_path, prompt)

    # No AI tools found, use built-in client
    print("[INFO] No AI tools found, using built-in client...")

    # Load or create configuration
    config = load_config()

    if not is_configured() and not args.api_key:
        print("[INFO] First time running sec-userspace.")
        print("[INFO] Starting configuration wizard...\n")
        config = run_wizard()
    elif args.api_key:
        config = quick_configure(
            provider=args.provider,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url
        )

    # Create client
    try:
        client = StandaloneClient(config)
    except ValueError as e:
        print(f"[ERROR] Failed to initialize client: {e}")
        return 1

    # Test connection
    print("[INFO] Testing API connection...")
    if not client.test_connection():
        print("[ERROR] Failed to connect to LLM API.")
        return 1
    print("[INFO] Connection successful!")

    # Install/verify skill
    if args.auto_install:
        print("[INFO] Verifying skill installation...")
        if not client.install_skill():
            print("[ERROR] Skill verification failed.")
            return 1

    # Run detection
    if args.interactive:
        client.interactive_chat()
    else:
        result = client.run_detection(prompt=args.prompt)
        print("\n" + "=" * 60)
        print("Security Detection Report")
        print("=" * 60)
        print(result)

    return 0


def cmd_interactive(args):
    """Start interactive chat session."""
    print_banner()

    # Load configuration
    config = load_config()

    if not is_configured() and not args.api_key:
        print("[INFO] First time running sec-userspace.")
        print("[INFO] Starting configuration wizard...\n")
        config = run_wizard()
    elif args.api_key:
        config = quick_configure(
            provider=args.provider,
            model=args.model,
            api_key=args.api_key,
            base_url=args.base_url
        )

    # Create client
    try:
        client = StandaloneClient(config)
    except ValueError as e:
        print(f"[ERROR] Failed to initialize client: {e}")
        return 1

    # Test connection
    print("[INFO] Testing API connection...")
    if not client.test_connection():
        print("[ERROR] Failed to connect to LLM API.")
        return 1
    print("[INFO] Connection successful!")

    # Verify skill
    client.install_skill()

    # Start interactive session
    client.interactive_chat()

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="sec-userspace standalone runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run security detection
  %(prog)s --list-tools             # List discovered AI tools
  %(prog)s --configure              # Run configuration wizard
  %(prog)s --interactive            # Start interactive chat
  %(prog)s --api-key sk-xxx         # Run with API key
  %(prog)s --skip-detect            # Skip AI tool detection
        """
    )

    # Action options
    action_group = parser.add_argument_group("Actions")
    action_group.add_argument(
        "--list-tools",
        action="store_true",
        help="List discovered AI tools"
    )
    action_group.add_argument(
        "--configure",
        action="store_true",
        help="Run configuration wizard"
    )
    action_group.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Start interactive chat session"
    )

    # Detection options
    detect_group = parser.add_argument_group("Detection Options")
    detect_group.add_argument(
        "--prompt", "-p",
        type=str,
        default=None,
        help="Custom detection prompt"
    )
    detect_group.add_argument(
        "--skip-detect",
        action="store_true",
        help="Skip AI tool detection, use built-in client directly"
    )
    detect_group.add_argument(
        "--no-auto-install",
        action="store_false",
        dest="auto_install",
        default=True,
        help="Disable automatic skill installation"
    )

    # API options
    api_group = parser.add_argument_group("API Options")
    api_group.add_argument(
        "--api-key", "-k",
        type=str,
        help="API key (overrides config file)"
    )
    api_group.add_argument(
        "--provider",
        type=str,
        choices=["bailian", "openai", "anthropic", "deepseek"],
        help="API provider"
    )
    api_group.add_argument(
        "--model", "-m",
        type=str,
        help="Model name"
    )
    api_group.add_argument(
        "--base-url",
        type=str,
        help="Custom API base URL"
    )

    args = parser.parse_args()

    # Handle actions
    if args.list_tools:
        return cmd_list_tools(args)

    if args.configure:
        return cmd_configure(args)

    if args.interactive:
        return cmd_interactive(args)

    # Default: run detection
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())

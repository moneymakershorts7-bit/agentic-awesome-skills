#!/usr/bin/env python3
"""
Permission Setup Script for sec-userspace

Configures AI tool permissions for sec-userspace security scanning.
"""

import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Minimal permission set for sec-userspace
#
# Security Model:
#   - root (sudo): Required to read system info (/proc, /sys, logs, etc.)
#   - Read-only: All system information is collected in read-only mode, zero system modification
#   - Write: Only workspace/ directory needs write permission for saving logs and reports
MINIMAL_PERMISSIONS = {
    "permissions": {
        "allow": [
            "Bash(sudo:*)",
            "Bash(python3:*)",
            "Read(**)",
            "Write(/data/sec-userspace/workspace/**)",
            "Write(workspace/**)"
        ]
    }
}

# Tool configurations
TOOL_CONFIGS = {
    "claude": {
        "name": "Claude Code",
        "config_path": ".claude/settings.local.json",
        "priority": 1
    },
    "opencode": {
        "name": "OpenCode",
        "config_path": ".opencode/settings.json",
        "priority": 1
    },
    "qoder": {
        "name": "QoderCLI",
        "config_path": ".qoder/settings.json",
        "priority": 1
    },
    "windsurf": {
        "name": "Windsurf",
        "config_path": ".codeium/windsurf/settings.json",
        "priority": 2
    },
    "cursor": {
        "name": "Cursor",
        "config_path": ".cursor/settings.json",
        "priority": 2
    },
    "gemini": {
        "name": "Gemini CLI",
        "config_path": ".gemini/settings.json",
        "priority": 2
    },
    "trae": {
        "name": "Trae",
        "config_path": ".trae/settings.json",
        "priority": 2
    }
}


def get_home_dir() -> Path:
    """Get real user home directory (handles sudo)"""
    # Check SUDO_USER for real user
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(f"/home/{sudo_user}")

    # Fallback to HOME
    home = os.environ.get("HOME", "/root")
    return Path(home)


def backup_config(config_path: Path) -> Optional[Path]:
    """Backup existing config file"""
    if not config_path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f".json.bak.{timestamp}")
    shutil.copy2(config_path, backup_path)
    return backup_path


def merge_permissions(existing: Dict, new_perms: Dict) -> Dict:
    """Merge new permissions into existing config"""
    if "permissions" not in existing:
        existing["permissions"] = {}

    if "allow" not in existing["permissions"]:
        existing["permissions"]["allow"] = []

    # Add new permissions (deduplicated)
    existing_allow = set(existing["permissions"]["allow"])
    new_allow = set(new_perms["permissions"]["allow"])

    merged = existing_allow | new_allow
    existing["permissions"]["allow"] = sorted(list(merged))

    return existing


def setup_tool_permissions(tool_name: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Setup permissions for a specific tool

    Returns:
        (success, message)
    """
    if tool_name not in TOOL_CONFIGS:
        return False, f"Unknown tool: {tool_name}"

    config = TOOL_CONFIGS[tool_name]
    home = get_home_dir()
    config_path = home / config["config_path"]

    if dry_run:
        return True, f"[DRY-RUN] Would configure: {config_path}"

    # Ensure parent directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Backup existing config
    backup_path = None
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding='utf-8'))
            backup_path = backup_config(config_path)
        except (json.JSONDecodeError, OSError) as e:
            existing = {}
    else:
        existing = {}

    # Merge permissions
    merged = merge_permissions(existing, MINIMAL_PERMISSIONS)

    # Write config
    try:
        config_path.write_text(json.dumps(merged, indent=2) + "\n", encoding='utf-8')
    except OSError as e:
        return False, f"Failed to write config: {e}"

    msg = f"Configured {config['name']}: {config_path}"
    if backup_path:
        msg += f"\n  Backup: {backup_path}"

    return True, msg


def detect_installed_tools() -> list:
    """Auto-detect all installed AI tools on the system"""
    installed = []
    home = get_home_dir()
    tool_markers = {
        "claude": home / ".claude",
        "opencode": home / ".opencode",
        "qoder": home / ".qoder",
        "cursor": home / ".cursor",
        "windsurf": home / ".codeium",
        "gemini": home / ".gemini",
        "trae": home / ".trae"
    }

    for tool, marker in tool_markers.items():
        if marker.exists():
            installed.append(tool)

    return installed


def list_tools():
    """List all supported tools"""
    print("Supported AI Tools:\n")
    print(f"{'Tool':<15} {'Priority':<10} {'Config Path'}")
    print("-" * 60)

    for tool, config in sorted(TOOL_CONFIGS.items(), key=lambda x: x[1]["priority"]):
        priority = "Primary" if config["priority"] == 1 else "Secondary"
        print(f"{config['name']:<15} {priority:<10} ~/{config['config_path']}")


def show_current_permissions(tool_name: str):
    """Show current permissions for a tool"""
    if tool_name not in TOOL_CONFIGS:
        print(f"Unknown tool: {tool_name}")
        return

    config = TOOL_CONFIGS[tool_name]
    home = get_home_dir()
    config_path = home / config["config_path"]

    print(f"\n{config['name']} Permissions ({config_path}):\n")

    if not config_path.exists():
        print("  No config file found")
        return

    try:
        data = json.loads(config_path.read_text(encoding='utf-8'))
        allow = data.get("permissions", {}).get("allow", [])

        if not allow:
            print("  No permissions configured")
            return

        for perm in allow:
            print(f"  - {perm}")
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Error reading config: {e}")


def verify_permissions() -> List[Tuple[str, bool, str]]:
    """Execute after configuration to verify permissions are effective.

    Returns:
        List of (check_name, passed, detail) tuples
    """
    results = []

    # 1. Verify sudo permission (non-interactive)
    try:
        proc = subprocess.run(
            ['sudo', '-n', 'true'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5
        )
        passed = proc.returncode == 0
        detail = "NOPASSWD sudo available" if passed else "sudo requires password"
        results.append(('sudo', passed, detail))
    except (subprocess.TimeoutExpired, OSError) as e:
        results.append(('sudo', False, f"sudo check failed: {e}"))

    # 2. Verify read permissions on critical paths
    read_targets = [
        ('/proc/1/status', 'kernel process info'),
        ('/etc/passwd', 'user database'),
        ('/var/log/auth.log', 'auth log (Debian)'),
        ('/var/log/secure', 'auth log (RHEL)'),
    ]
    for filepath, desc in read_targets:
        try:
            readable = os.path.exists(filepath) and os.access(filepath, os.R_OK)
            if not os.path.exists(filepath):
                results.append((f'read:{filepath}', True, f'{desc} - not present (OK)'))
            else:
                results.append((f'read:{filepath}', readable, desc))
        except OSError as e:
            results.append((f'read:{filepath}', False, str(e)))

    # 3. Verify write permissions on workspace
    workspace_candidates = [
        '/data/sec-userspace/workspace',
        os.path.join(os.getcwd(), 'workspace'),
    ]
    for dirpath in workspace_candidates:
        try:
            if os.path.isdir(dirpath):
                writable = os.access(dirpath, os.W_OK)
                results.append((f'write:{dirpath}', writable, 'workspace dir'))
            else:
                results.append((f'write:{dirpath}', False, 'directory not found'))
        except OSError as e:
            results.append((f'write:{dirpath}', False, str(e)))

    # 4. Verify Python version
    import sys
    py_ok = sys.version_info >= (3, 11)
    results.append((
        'python_version',
        py_ok,
        f'Python {sys.version_info.major}.{sys.version_info.minor} ({">=3.11 OK" if py_ok else "<3.11 WARN"})'
    ))

    return results


def print_verify_results(results: List[Tuple[str, bool, str]]):
    """Pretty-print verification results"""
    print("\n" + "=" * 60)
    print("  Permission Verification Results")
    print("=" * 60 + "\n")

    passed_count = sum(1 for _, p, _ in results if p)
    total = len(results)

    for name, passed, detail in results:
        icon = "\u2714" if passed else "\u2718"
        status = "PASS" if passed else "FAIL"
        print(f"  {icon} [{status}] {name:<30} {detail}")

    print(f"\n  Summary: {passed_count}/{total} checks passed")

    if passed_count == total:
        print("  \u2714 All permissions verified successfully!")
    else:
        print("  \u26a0 Some checks failed. Run with sudo or configure permissions.")
    print()

    return passed_count == total


def main():
    parser = argparse.ArgumentParser(
        description="Configure AI tool permissions for sec-userspace"
    )

    parser.add_argument(
        "--tool", "-t",
        choices=list(TOOL_CONFIGS.keys()),
        help="AI tool to configure"
    )

    parser.add_argument(
        "--auto", "-a",
        action="store_true",
        help="Auto-detect tool from environment"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Configure all supported tools"
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List supported tools"
    )

    parser.add_argument(
        "--show",
        action="store_true",
        help="Show current permissions"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )

    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify current permissions are effective"
    )

    args = parser.parse_args()

    # Verify permissions
    if args.verify:
        results = verify_permissions()
        all_passed = print_verify_results(results)
        raise SystemExit(0 if all_passed else 1)

    # List tools
    if args.list:
        list_tools()
        return

    # Show current permissions
    if args.show:
        if args.tool:
            show_current_permissions(args.tool)
        else:
            for tool in TOOL_CONFIGS:
                show_current_permissions(tool)
        return

    # Determine which tools to configure
    tools_to_configure = []

    if args.all:
        tools_to_configure = list(TOOL_CONFIGS.keys())
    elif args.auto:
        detected = detect_installed_tools()
        if detected:
            tools_to_configure = detected
            names = [TOOL_CONFIGS[t]['name'] for t in detected]
            print(f"Detected {len(detected)} AI tool(s): {', '.join(names)}")
        else:
            print("No AI tools detected. Please specify with --tool")
            return
    elif args.tool:
        tools_to_configure = [args.tool]
    else:
        parser.print_help()
        return

    # Configure each tool
    print("\nConfiguring permissions...\n")

    success_count = 0
    for tool in tools_to_configure:
        success, message = setup_tool_permissions(tool, args.dry_run)
        print(f"{'[OK]' if success else '[FAIL]'} {message}")
        if success:
            success_count += 1

    print(f"\nConfigured {success_count}/{len(tools_to_configure)} tools")

    if success_count > 0 and not args.dry_run:
        print("\nPlease restart the AI tool or reload settings to apply changes.")


if __name__ == "__main__":
    main()

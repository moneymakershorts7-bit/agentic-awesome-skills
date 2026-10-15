"""Path resolution utility that works in both plain and zipapp modes.

In plain mode (python3 -m scripts.main):
  __file__ resolves normally, path_resolver uses __file__ to derive skill root.

In zipapp mode (python3 scripts/main.pyz):
  __file__ inside the archive points to virtual paths like
  /path/to/sec-userspace/scripts/main.pyz/scripts/main.py,
  which cannot be used with os.path operations.
  path_resolver detects this and derives skill root from the .pyz file location.

The key insight: main.pyz sits at scripts/main.pyz, the same position as
scripts/main.py in plain mode. So the parent directory of main.pyz is
always the scripts/ directory, and its parent is the skill root.
"""

import os
import sys
import threading

_skill_root = None
_skill_root_lock = threading.Lock()


def is_zipapp_mode():
    """Check if currently running inside a zipapp archive.

    Returns:
        True if running from a .pyz file, False otherwise.
    """
    main_file = getattr(sys.modules.get('__main__'), '__file__', '') or ''
    return '.pyz' in main_file


def get_skill_root():
    """Return the sec-userspace root directory containing assets/, configs/, etc.

    The result is cached after first call.

    Returns:
        Absolute path to the skill root directory.
    """
    global _skill_root
    if _skill_root is not None:
        return _skill_root

    with _skill_root_lock:
        if _skill_root is not None:
            return _skill_root

        if is_zipapp_mode():
            main_file = getattr(sys.modules.get('__main__'), '__file__', '')
            pyz_part = main_file.split('.pyz')[0] + '.pyz'
            scripts_dir = os.path.dirname(os.path.abspath(pyz_part))
            root = os.path.dirname(scripts_dir)
        else:
            root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )

        _skill_root = root

    return _skill_root


def get_scripts_dir():
    """Return the scripts/ directory.

    Returns:
        Absolute path to the scripts/ directory.
    """
    return os.path.join(get_skill_root(), "scripts")


def get_assets_dir():
    """Return the assets/ directory.

    Returns:
        Absolute path to the assets/ directory.
    """
    return os.path.join(get_skill_root(), "assets")


def get_configs_dir():
    """Return the configs/ directory.

    Returns:
        Absolute path to the configs/ directory.
    """
    return os.path.join(get_skill_root(), "configs")


def get_asset_path(*parts):
    """Return a sub-path under assets/.

    Args:
        *parts: Path components under assets/ (e.g., "ioc", "manifest.json")

    Returns:
        Absolute path to the specified asset.
    """
    return os.path.join(get_assets_dir(), *parts)


def get_config_version():
    """Read version string from VERSION file at skill root.

    Returns:
        Version string (e.g. "1.0.0"), or empty string if not found.
    """
    version_path = os.path.join(get_skill_root(), "VERSION")
    if os.path.isfile(version_path):
        try:
            with open(version_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except OSError:
            pass
    return ""


def verify_config_version(config_version: str, config_name: str = "config") -> None:
    """Verify a config file's version matches the VERSION file.

    Prints a warning via ``print(..., file=sys.stderr)`` when versions
    differ, so the message is visible even before logging is configured.

    Args:
        config_version: Version string read from the config YAML.
        config_name:  Human-readable config name for the warning message.
    """
    expected = get_config_version()
    if expected and config_version and config_version != expected:
        print(
            f"[WARN] {config_name} version ({config_version}) "
            f"does not match VERSION file ({expected})",
            file=sys.stderr,
        )

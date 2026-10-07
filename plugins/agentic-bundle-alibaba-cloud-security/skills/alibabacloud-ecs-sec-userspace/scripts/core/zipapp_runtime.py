"""Zipapp runtime detection and Python version management.

Handles zipapp mode detection, Python version matching, runtime extraction,
and venv setup for running .pyz files with compatible interpreters.
"""
import os
import re
import sys
import shutil
import subprocess
import zipfile
from pathlib import Path


def get_python_version_tuple(version_str: str) -> tuple:
    """Parse Python version string to tuple (major, minor)."""
    parts = version_str.split('.')
    if len(parts) >= 2:
        return (int(parts[0]), int(parts[1]))
    return (0, 0)


def get_zipapp_python_version(pyz_path: Path) -> tuple:
    """Extract Python version from zipapp shebang.

    Returns:
        Tuple of (major, minor) version, or (0, 0) if not found
    """
    try:
        with open(pyz_path, 'rb') as f:
            magic = f.read(2)
            if magic != b'#!':
                return (0, 0)
            f.seek(0)
            shebang = f.readline()
            shebang_str = shebang.decode('utf-8', errors='ignore')
            match = re.search(r'python(\d+\.\d+)', shebang_str)
            if match:
                return get_python_version_tuple(match.group(1))
            return (0, 0)
    except (OSError, ValueError) as e:
        print(f"[WARN] Failed to read zipapp shebang: {e}", file=sys.stderr)
        return (0, 0)


def check_python_version_match(pyz_path: Path) -> bool:
    """Check if current Python version matches zipapp requirement."""
    current_version = (sys.version_info.major, sys.version_info.minor)
    required_version = get_zipapp_python_version(pyz_path)

    if required_version == (0, 0):
        return True

    is_match = current_version == required_version
    if not is_match:
        print(f"[INFO] Python version mismatch:")
        print(f"  Current: {current_version[0]}.{current_version[1]}")
        print(f"  Required: {required_version[0]}.{required_version[1]}")
    return is_match


def extract_python_runtime(workspace_dir: Path, assets_origin_dir: Path) -> Path:
    """Extract minimal Python runtime from assets-origin/python/ to workspace/python/.

    Returns:
        Path to extracted Python interpreter
    """
    python_dir = workspace_dir / "python"

    if python_dir.is_dir():
        python_exe = python_dir / "bin" / "python3"
        if python_exe.exists():
            print(f"[INFO] Using existing Python runtime: {python_dir}")
            return python_exe

    python_assets_dir = assets_origin_dir / "python"
    if not python_assets_dir.is_dir():
        print(f"[ERROR] Python runtime not found: {python_assets_dir}", file=sys.stderr)
        print("Please package the skill with --include-python option", file=sys.stderr)
        sys.exit(1)

    python_zips = sorted(python_assets_dir.glob("python-*.zip"), reverse=True)
    if not python_zips:
        print(f"[ERROR] No Python runtime zip found in {python_assets_dir}", file=sys.stderr)
        sys.exit(1)

    python_zip = python_zips[0]
    print(f"[INFO] Extracting Python runtime from {python_zip.name}...")

    if python_dir.exists():
        shutil.rmtree(python_dir)
    python_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(python_zip, 'r') as zf:
        for member in zf.namelist():
            member_path = (python_dir / member).resolve()
            if not str(member_path).startswith(str(python_dir.resolve())):
                print(f"[ERROR] Zip member escapes target dir: {member}", file=sys.stderr)
                sys.exit(1)
        zf.extractall(python_dir)

    python_exe = python_dir / "bin" / "python3"
    if not python_exe.exists():
        python_exe = python_dir / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
        if not python_exe.exists():
            print(f"[ERROR] Python executable not found in {python_dir}", file=sys.stderr)
            sys.exit(1)

    print(f"[INFO] Python runtime extracted to: {python_dir}")
    return python_exe


def setup_venv(python_exe: Path, workspace_dir: Path) -> Path:
    """Setup .venv in workspace with extracted Python runtime.

    Returns:
        Path to venv Python interpreter
    """
    venv_dir = workspace_dir / ".venv"
    venv_python = venv_dir / "bin" / "python3"

    if venv_python.exists():
        print(f"[INFO] Using existing venv: {venv_dir}")
        return venv_python

    print(f"[INFO] Creating virtual environment at {venv_dir}...")
    try:
        result = subprocess.run(
            [str(python_exe), "-m", "venv", str(venv_dir)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=60
        )
    except subprocess.TimeoutExpired:
        print("[ERROR] Venv creation timed out (60s)", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"[ERROR] Failed to create venv: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Virtual environment created: {venv_dir}")
    return venv_python


def run_zipapp_with_local_python(pyz_path: Path, python_exe: Path):
    """Run zipapp with local Python interpreter."""
    print(f"[INFO] Running zipapp with local Python: {python_exe}")
    cmd = [str(python_exe), str(pyz_path)] + sys.argv[1:]
    env = os.environ.copy()
    env['PYTHONPATH'] = ''
    try:
        result = subprocess.run(cmd, env=env, timeout=900, stdin=subprocess.DEVNULL)
        sys.exit(result.returncode)
    except subprocess.TimeoutExpired:
        print("[ERROR] Zipapp execution timed out (900s)", file=sys.stderr)
        sys.exit(124)


def run_zipapp_mode(main_dir: Path):
    """Handle zipapp execution mode: version check and delegation.

    If version matches, imports and runs the orchestrator directly.
    If not, extracts a compatible Python runtime and re-executes.
    """
    pyz_path = main_dir / "main.pyz"
    print("[INFO] Detected zipapp mode (main.pyz exists)")

    if check_python_version_match(pyz_path):
        print("[INFO] Python version matches, running zipapp directly")
        from .orchestrator import main as orchestrator_main
        orchestrator_main()
    else:
        print("[INFO] Python version mismatch, switching to local Python runtime")
        workspace_dir = Path(os.environ.get('WORKSPACE', '/data/sec-userspace/workspace'))
        skill_root = main_dir.parent
        assets_origin_dir = skill_root / "assets-origin"

        if not assets_origin_dir.is_dir():
            assets_origin_dir = workspace_dir.parent / "assets-origin"

        python_exe = extract_python_runtime(workspace_dir, assets_origin_dir)
        venv_python = setup_venv(python_exe, workspace_dir)
        run_zipapp_with_local_python(pyz_path, venv_python)

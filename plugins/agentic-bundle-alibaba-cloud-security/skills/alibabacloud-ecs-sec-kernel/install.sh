#!/bin/bash
# ============================================================
# install.sh - sec-kernel installation script
# Detects Python magic number compatibility and installs
# bundled Python 3.11 runtime if needed.
#
# Usage: ./install.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR"

echo "============================================"
echo "  sec-kernel Installation"
echo "============================================"

# 1. Read zipapp compiled magic number
BUNDLED_MAGIC_FILE="$INSTALL_DIR/assets-origin/PYTHON_MAGIC"
if [ ! -f "$BUNDLED_MAGIC_FILE" ]; then
    echo "[ERROR] Missing PYTHON_MAGIC file in assets-origin/"
    echo "[ERROR] This package may be corrupted. Please re-download."
    exit 1
fi

BUNDLED_MAGIC=$(cat "$BUNDLED_MAGIC_FILE" | tr -d '[:space:]')
echo "[INFO] Zipapp compiled magic: $BUNDLED_MAGIC"

# 2. Detect system Python magic number
SYS_MAGIC=""
SYS_PY_PATH=""
SYS_PY_VER=""

for PY in python3.11 python3; do
    if command -v "$PY" &>/dev/null; then
        PY_PATH=$(which "$PY")
        MAGIC=$("$PY" -c "import importlib.util; print(importlib.util.MAGIC_NUMBER.hex())" 2>/dev/null || echo "")
        if [ -n "$MAGIC" ]; then
            SYS_PY_PATH="$PY_PATH"
            SYS_PY_VER=$("$PY" --version 2>&1)
            SYS_MAGIC="$MAGIC"
            echo "[INFO] Found $PY at $PY_PATH (magic: $MAGIC)"
            if [ "$SYS_MAGIC" = "$BUNDLED_MAGIC" ]; then
                echo "[INFO] System Python magic matches zipapp magic"
                break
            fi
        fi
    fi
done

# 3. Setup runtime directory
mkdir -p "$INSTALL_DIR/runtime"

if [ "$SYS_MAGIC" = "$BUNDLED_MAGIC" ]; then
    echo "[OK] System Python ($SYS_PY_VER) magic matches: $SYS_MAGIC"
    echo "[INFO] Using system Python runtime"
    ln -sf "$SYS_PY_PATH" "$INSTALL_DIR/runtime/python3"
    echo "[OK] Runtime symlink created: runtime/python3 -> $SYS_PY_PATH"
else
    if [ -n "$SYS_MAGIC" ]; then
        echo "[WARN] System Python magic ($SYS_MAGIC) != zipapp magic ($BUNDLED_MAGIC)"
    else
        echo "[WARN] No compatible system Python found"
    fi

    echo "[INFO] Installing bundled Python 3.11 runtime..."

    # Check for bundled tarball
    BUNDLED_TAR="$INSTALL_DIR/assets-origin/python311.tar.gz"
    if [ ! -f "$BUNDLED_TAR" ]; then
        echo "[ERROR] Bundled Python runtime not found: $BUNDLED_TAR"
        echo "[ERROR] Please ensure assets-origin/python311.tar.gz exists"
        exit 1
    fi

    # Extract bundled Python
    tar -xzf "$BUNDLED_TAR" -C "$INSTALL_DIR/runtime/"
    ln -sf "$INSTALL_DIR/runtime/bin/python3.11" "$INSTALL_DIR/runtime/python3"

    # Verify bundled Python magic
    if [ ! -x "$INSTALL_DIR/runtime/bin/python3.11" ]; then
        echo "[ERROR] Bundled Python binary not executable"
        exit 1
    fi

    BUNDLED_CHECK=$("$INSTALL_DIR/runtime/python3" -c "import importlib.util; print(importlib.util.MAGIC_NUMBER.hex())" 2>/dev/null || echo "")
    if [ "$BUNDLED_CHECK" != "$BUNDLED_MAGIC" ]; then
        echo "[ERROR] Bundled Python magic mismatch! Expected $BUNDLED_MAGIC, got $BUNDLED_CHECK"
        exit 1
    fi

    echo "[OK] Bundled Python 3.11 installed, magic verified: $BUNDLED_CHECK"
fi

# 4. Verify the runtime can load the zipapp
echo ""
echo "[INFO] Verifying runtime can load sec-kernel..."
PY_RUNTIME="$INSTALL_DIR/runtime/python3"
if [ ! -x "$PY_RUNTIME" ]; then
    # Handle symlink
    if [ -L "$PY_RUNTIME" ]; then
        REAL_PATH=$(readlink -f "$PY_RUNTIME")
        if [ ! -x "$REAL_PATH" ]; then
            echo "[ERROR] Python runtime not executable: $REAL_PATH"
            exit 1
        fi
    else
        echo "[ERROR] Python runtime not executable"
        exit 1
    fi
fi

# Quick verification
"$PY_RUNTIME" -c "import sys; print(f'Python runtime ready: {sys.version}')" 2>/dev/null || {
    echo "[WARN] Runtime verification failed, but installation may still work"
}

# 5. Set executable permissions
chmod +x "$INSTALL_DIR/scripts/main.pyz" 2>/dev/null || true
chmod +x "$INSTALL_DIR/run.sh" 2>/dev/null || true

echo ""
echo "============================================"
echo "  Installation Complete"
echo "============================================"
echo ""
echo "  Run sec-kernel with:  sudo ./run.sh --mode host --poc"
echo "  List detectors:       sudo ./run.sh --list-detectors"
echo ""

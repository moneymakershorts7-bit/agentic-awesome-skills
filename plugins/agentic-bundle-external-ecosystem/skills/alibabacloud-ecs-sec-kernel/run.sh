#!/bin/bash
# ============================================================
# run.sh - sec-kernel unified entry point
#
# Supports both development mode (source tree) and release mode (installed).
# Automatically compiles PoC binaries, enables PoC for vulnerable CVEs,
# and displays high-priority evidence at the end.
#
# Usage:
#   ./run.sh                          # Quick scan (auto-detect mode)
#   ./run.sh --poc                    # Scan + PoC for vulnerable CVEs
#   ./run.sh --mode host --poc -v     # Full scan with verbose output
#   ./run.sh --list-detectors         # List all available detectors
#   ./run.sh --cve-id CVE-2024-0193   # Check specific CVE only
#   ./run.sh --no-poc-build           # Skip PoC auto-compilation
#   ./run.sh --no-evidence            # Skip evidence summary
# ============================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Determine script directory (works with symlinks)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Flags
SKIP_POC_BUILD=false
SKIP_EVIDENCE=false
HAS_POC_FLAG=false

# Parse arguments to detect --poc and special flags
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-poc-build)
            SKIP_POC_BUILD=true
            ;;
        --no-evidence)
            SKIP_EVIDENCE=true
            ;;
        --poc)
            HAS_POC_FLAG=true
            ARGS+=("$arg")
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

# ============================================================
# Phase 0: Mode detection (dev vs release)
# ============================================================
detect_mode() {
    # Release mode: has runtime/python3 and scripts/main.pyz
    if [ -f "$SCRIPT_DIR/runtime/python3" ] && [ -f "$SCRIPT_DIR/scripts/main.pyz" ]; then
        echo "release"
        return
    fi

    # Development mode: has scripts/ directory with main.py
    if [ -f "$SCRIPT_DIR/scripts/main.py" ]; then
        echo "dev"
        return
    fi

    echo "unknown"
}

MODE=$(detect_mode)

if [ "$MODE" = "unknown" ]; then
    echo -e "${RED}[ERROR]${NC} sec-kernel not found in: $SCRIPT_DIR"
    echo "Expected either:"
    echo "  - Release mode: runtime/python3 + scripts/main.pyz"
    echo "  - Dev mode:    scripts/main.py"
    exit 1
fi

# ============================================================
# Phase 1: Auto-compile PoC binaries (dev mode only, unless skipped)
# ============================================================
if [ "$MODE" = "dev" ] && [ "$SKIP_POC_BUILD" = false ]; then
    POC_SRC_DIR="$SCRIPT_DIR/poc-src"
    POC_BIN_DIR="$SCRIPT_DIR/poc-bin"

    if [ -d "$POC_SRC_DIR" ] && [ -f "$POC_SRC_DIR/build.sh" ]; then
        # Check if PoC build is needed by comparing .c files to .bin files
        NEED_BUILD=false

        if [ ! -d "$POC_BIN_DIR" ] || [ -z "$(ls -A "$POC_BIN_DIR" 2>/dev/null)" ]; then
            NEED_BUILD=true
        else
            # Check if any source .c file is newer than corresponding .bin, or .bin is missing
            for src_dir in "$POC_SRC_DIR"/cve_*/; do
                if [ ! -d "$src_dir" ]; then
                    continue
                fi
                cve_id=$(basename "$src_dir")
                bin_file="$POC_BIN_DIR/${cve_id}.bin"

                if [ ! -f "$bin_file" ]; then
                    NEED_BUILD=true
                    break
                fi

                # Check if poc.c exists and is newer than .bin
                if [ -f "$src_dir/poc.c" ] && [ "$src_dir/poc.c" -nt "$bin_file" ]; then
                    NEED_BUILD=true
                    break
                fi
            done
        fi

        if [ "$NEED_BUILD" = true ]; then
            echo -e "${BLUE}[BUILD]${NC} PoC source changed or missing, compiling..."
            echo ""

            if bash "$POC_SRC_DIR/build.sh" 2>&1; then
                echo ""
                echo -e "${GREEN}[BUILD]${NC} PoC compilation successful."
            else
                echo ""
                echo -e "${YELLOW}[WARN]${NC} PoC compilation had errors. Using existing binaries."
            fi
            echo ""
        else
            echo -e "${GREEN}[INFO]${NC} PoC binaries are up-to-date."
            echo ""
        fi
    fi
fi

# ============================================================
# Phase 2: Workspace directory setup
# ============================================================
WORKSPACE_DIR="$SCRIPT_DIR/workspace"
mkdir -p "$WORKSPACE_DIR"

# Set default output dir if not specified
HAS_OUTPUT_DIR=false
for arg in "${ARGS[@]}"; do
    if [[ "$arg" == --output-dir* ]]; then
        HAS_OUTPUT_DIR=true
        break
    fi
done

if [ "$HAS_OUTPUT_DIR" = false ]; then
    ARGS+=(--output-dir "$WORKSPACE_DIR")
fi

# Set default poc-output if --poc is enabled
if [ "$HAS_POC_FLAG" = true ]; then
    HAS_POC_OUTPUT=false
    for arg in "${ARGS[@]}"; do
        if [[ "$arg" == --poc-output* ]]; then
            HAS_POC_OUTPUT=true
            break
        fi
    done
    if [ "$HAS_POC_OUTPUT" = false ]; then
        ARGS+=(--poc-output "$WORKSPACE_DIR/poc-evidence")
    fi
fi

# ============================================================
# Phase 3: Execute sec-kernel
# ============================================================
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  sec-kernel v$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo 'unknown')${NC}"
echo -e "${BOLD}  Mode: $MODE${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

if [ "$MODE" = "release" ]; then
    PYTHON="$SCRIPT_DIR/runtime/python3"
    PYZ="$SCRIPT_DIR/scripts/main.pyz"
    exec "$PYTHON" "$PYZ" "${ARGS[@]}"
else
    PYTHON_BIN="${PYTHON:-python3}"
    cd "$SCRIPT_DIR"
    exec "$PYTHON_BIN" -m scripts "${ARGS[@]}"
fi

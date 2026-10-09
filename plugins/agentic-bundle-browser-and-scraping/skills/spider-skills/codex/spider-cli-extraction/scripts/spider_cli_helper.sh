#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DEFAULT_REPO="$(cd -- "$SKILL_DIR/../../../spider" 2>/dev/null && pwd || true)"
SPIDER_REPO="${SPIDER_REPO:-$DEFAULT_REPO}"

run_cli() {
  if [[ -z "${SPIDER_REPO:-}" || ! -d "$SPIDER_REPO" ]]; then
    echo "Set SPIDER_REPO to your spider repo path." >&2
    exit 1
  fi
  (cd "$SPIDER_REPO" && cargo run -q -p spider_cli -- "$@")
}

run_cli_feature() {
  local feature="$1"
  shift
  (cd "$SPIDER_REPO" && cargo run -q -p spider_cli --features "$feature" -- "$@")
}

usage() {
  cat <<'USAGE'
Usage:
  spider_cli_helper.sh help
  spider_cli_helper.sh crawl <url> [extra spider args...]
  spider_cli_helper.sh scrape <url> [extra spider args...]
  spider_cli_helper.sh download <url> [extra spider args...]
  spider_cli_helper.sh verify-headless

Examples:
  spider_cli_helper.sh crawl https://example.com --limit 20 --depth 2
  spider_cli_helper.sh scrape https://example.com --output-html --output-links
USAGE
}

if [[ "${1:-}" == "" ]]; then
  usage
  exit 1
fi

cmd="$1"
shift

case "$cmd" in
  help)
    usage
    ;;
  crawl|scrape|download)
    if [[ "${1:-}" == "" ]]; then
      echo "Missing URL for $cmd" >&2
      exit 1
    fi
    url="$1"
    shift
    run_cli --url "$url" "$cmd" "$@"
    ;;
  verify-headless)
    echo "[1/2] Default CLI help (searching for --headless/--http flags)..."
    if run_cli --help | rg -n -- '--headless|headless' >/dev/null; then
      echo "Found runtime headless support in default build help."
    else
      echo "No runtime headless flag in default build help."
    fi

    if run_cli --help | rg -n -- '--http' >/dev/null; then
      echo "Found runtime HTTP mode flag in default build help."
    else
      echo "No runtime HTTP mode flag in default build help."
    fi

    echo "[2/2] Chrome-feature CLI help (searching for --headless flag)..."
    if run_cli_feature chrome --help | rg -n -- '--headless|headless' >/dev/null; then
      echo "Found runtime headless support in chrome feature build help."
    else
      echo "No runtime headless flag in chrome feature build help."
    fi
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac

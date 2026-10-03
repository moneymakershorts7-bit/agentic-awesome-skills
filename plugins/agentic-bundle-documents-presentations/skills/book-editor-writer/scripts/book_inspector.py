#!/usr/bin/env python3
"""
book_inspector.py — Manuscript and Editorial Quality Inspection Tool

Analyzes manuscript files (Markdown, plain text) to verify:
- Word and chapter metrics
- Heading hierarchy and chapter detection
- Footnotes and bibliographic references
- Unresolved editorial placeholders ([TODO], [CITAR], [VERIFICAR], ???, etc.)
- Blockquote callout formatting
"""

import sys
import os
import re
import json
import argparse
from typing import Dict, List, Any


PLACEHOLDER_PATTERNS = [
    r"\[TODO[^\]]*\]",
    r"\[CITAR[^\]]*\]",
    r"\[PENDIENTE[^\]]*\]",
    r"\[VERIFICAR[^\]]*\]",
    r"\[CHECK[^\]]*\]",
    r"\bTBD\b",
    r"\bFIXME\b",
    r"\?\?\?",
    r"\[\s*\.\.\.\s*\]"
]


def inspect_manuscript(filepath: str) -> Dict[str, Any]:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    lines = content.splitlines()
    word_count = len(content.split())
    char_count = len(content)
    reading_time_mins = round(word_count / 220, 1)

    # Detect headings
    headings = []
    chapters = []
    for idx, line in enumerate(lines, start=1):
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            item = {"line": idx, "level": level, "title": title}
            headings.append(item)
            if level in [1, 2] and re.search(r"\b(cap[ií]tulo|chapter|parte|part|secci[oó]n|pr[oó]logo|ep[ií]logo)\b", title, re.IGNORECASE):
                chapters.append(item)

    # Detect placeholders / flags
    unresolved_flags = []
    for idx, line in enumerate(lines, start=1):
        for pattern in PLACEHOLDER_PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                unresolved_flags.append({
                    "line": idx,
                    "matched": match.group(0),
                    "context": line.strip()
                })

    # Detect footnotes
    footnotes_inline = re.findall(r"\[\^([a-zA-Z0-9_\-]+)\](?!:)", content)
    footnotes_definitions = re.findall(r"^\[\^([a-zA-Z0-9_\-]+)\]:\s*", content, re.MULTILINE)

    # Detect callouts / blockquotes
    callouts_sacred = len(re.findall(r"^>\s*📖", content, re.MULTILINE))
    callouts_history = len(re.findall(r"^>\s*📜", content, re.MULTILINE))
    callouts_principle = len(re.findall(r"^>\s*💡", content, re.MULTILINE))
    standard_blockquotes = len(re.findall(r"^>\s+", content, re.MULTILINE))

    # Detect tables
    tables_count = len(re.findall(r"^\|.*\|.*\|$", content, re.MULTILINE))

    missing_definitions = set(footnotes_inline) - set(footnotes_definitions)
    orphan_definitions = set(footnotes_definitions) - set(footnotes_inline)

    readiness = "READY"
    if unresolved_flags or missing_definitions:
        readiness = "NEEDS_EDITORIAL_ATTENTION"

    return {
        "file": filepath,
        "metrics": {
            "words": word_count,
            "characters": char_count,
            "lines": len(lines),
            "estimated_reading_minutes": reading_time_mins,
            "total_headings": len(headings),
            "detected_chapters": len(chapters),
            "tables_rows": tables_count,
            "callouts": {
                "sacred_primary": callouts_sacred,
                "historical_records": callouts_history,
                "principles_takeaways": callouts_principle,
                "total_blockquotes": standard_blockquotes
            }
        },
        "footnotes": {
            "inline_citations": len(footnotes_inline),
            "definitions": len(footnotes_definitions),
            "missing_definitions": sorted(list(missing_definitions)),
            "orphan_definitions": sorted(list(orphan_definitions))
        },
        "chapters": chapters,
        "unresolved_flags_count": len(unresolved_flags),
        "unresolved_flags": unresolved_flags[:20],  # sample up to 20
        "readiness_status": readiness
    }


def main():
    parser = argparse.ArgumentParser(description="Inspect manuscript files for publication readiness.")
    parser.add_argument("file", help="Path to manuscript file (.md, .txt)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    try:
        report = inspect_manuscript(args.file)
    except Exception as e:
        print(f"Error inspecting file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print("=" * 60)
    print(f"📖 MANUSCRIPT EDITORIAL INSPECTION REPORT")
    print(f"File: {report['file']}")
    print(f"Status: {report['readiness_status']}")
    print("=" * 60)
    print(f"• Words: {report['metrics']['words']:,}")
    print(f"• Estimated Reading Time: {report['metrics']['estimated_reading_minutes']} min")
    print(f"• Lines: {report['metrics']['lines']:,}")
    print(f"• Detected Chapters/Key Sections: {report['metrics']['detected_chapters']}")
    print(f"• Footnotes: {report['footnotes']['inline_citations']} inline, {report['footnotes']['definitions']} defined")
    if report['footnotes']['missing_definitions']:
        print(f"  ⚠️ Missing definitions for footnotes: {report['footnotes']['missing_definitions']}")

    print(f"\n📑 Editorial Typography Callouts:")
    print(f"  - Primary Texts (> 📖): {report['metrics']['callouts']['sacred_primary']}")
    print(f"  - Historical Excerpts (> 📜): {report['metrics']['callouts']['historical_records']}")
    print(f"  - Key Principles (> 💡): {report['metrics']['callouts']['principles_takeaways']}")

    print(f"\n🔍 Unresolved Editorial Placeholders: {report['unresolved_flags_count']}")
    if report['unresolved_flags']:
        for item in report['unresolved_flags']:
            print(f"  - [Line {item['line']}] Matched '{item['matched']}': {item['context'][:70]}...")

    print("=" * 60)
    if report['readiness_status'] == "READY":
        print("✅ Ready for publishing or final compilation.")
    else:
        print("⚠️ Address unresolved flags and footnote gaps before final publishing.")
    print("=" * 60)


if __name__ == "__main__":
    main()

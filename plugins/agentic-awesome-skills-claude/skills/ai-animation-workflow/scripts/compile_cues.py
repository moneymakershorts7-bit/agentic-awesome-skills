#!/usr/bin/env python3
"""
Compile Markdown cue tables and Whisper transcript JSON into frame-accurate timeline.json
for Remotion / Web scene renderers.
"""

import argparse
import os
import sys
import json
import re

def parse_time_seconds(time_str: str) -> float:
    time_str = time_str.strip().replace("s", "")
    if ":" in time_str:
        parts = time_str.split(":")
        if len(parts) == 2:
            return float(parts[0]) * 60 + float(parts[1])
        elif len(parts) == 3:
            return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
    return float(time_str)

def compile_cues(project_path: str, fps: int = 30):
    cues_md_path = os.path.join(project_path, "03_cues", "cues.md")
    transcript_json_path = os.path.join(project_path, "02_transcript", "transcript.json")
    output_timeline_path = os.path.join(project_path, "03_cues", "timeline.json")

    if not os.path.exists(cues_md_path):
        print(f"Error: cues file not found at {cues_md_path}", file=sys.stderr)
        sys.exit(1)

    with open(cues_md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Parse markdown table lines
    lines = md_text.splitlines()
    table_rows = []
    in_table = False

    for line in lines:
        line_clean = line.strip()
        if line_clean.startswith("|") and line_clean.endswith("|"):
            parts = [p.strip() for p in line_clean.split("|")[1:-1]]
            if not parts:
                continue
            if any("---" in p for p in parts) or "Beat ID" in parts[0]:
                in_table = True
                continue
            if in_table:
                table_rows.append(parts)

    timeline_items = []

    for row in table_rows:
        if len(row) < 5:
            continue
        beat_id = row[0].replace("`", "").strip()
        try:
            start_sec = parse_time_seconds(row[1])
            end_sec = parse_time_seconds(row[2])
        except Exception:
            continue

        phrase = row[3].strip('"').strip("'")
        visual_action = row[4]
        focus_elem = row[5].replace("`", "").strip() if len(row) > 5 else ""

        start_frame = int(round(start_sec * fps))
        end_frame = int(round(end_sec * fps))
        duration_frames = max(1, end_frame - start_frame)

        timeline_items.append({
            "id": beat_id,
            "startSec": round(start_sec, 3),
            "endSec": round(end_sec, 3),
            "startFrame": start_frame,
            "endFrame": end_frame,
            "durationFrames": duration_frames,
            "phrase": phrase,
            "visualAction": visual_action,
            "focusTarget": focus_elem
        })

    # If transcript exists, attach word-level timings
    words_data = []
    if os.path.exists(transcript_json_path):
        try:
            with open(transcript_json_path, "r", encoding="utf-8") as tf:
                t_raw = json.load(tf)
                # handle whisper json variants
                if isinstance(t_raw, dict) and "segments" in t_raw:
                    for seg in t_raw["segments"]:
                        if "words" in seg:
                            for w in seg["words"]:
                                words_data.append({
                                    "word": w.get("word", "").strip(),
                                    "start": w.get("start", 0.0),
                                    "end": w.get("end", 0.0),
                                    "startFrame": int(round(w.get("start", 0.0) * fps)),
                                    "endFrame": int(round(w.get("end", 0.0) * fps))
                                })
        except Exception as e:
            print(f"Warning: Could not parse transcript.json: {e}", file=sys.stderr)

    total_duration_frames = max([item["endFrame"] for item in timeline_items], default=fps * 10)

    result = {
        "fps": fps,
        "totalDurationFrames": total_duration_frames,
        "totalDurationSec": round(total_duration_frames / fps, 2),
        "beats": timeline_items,
        "words": words_data
    }

    with open(output_timeline_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"Compiled {len(timeline_items)} beats into: {output_timeline_path}")
    print(f"Total Video Length: {result['totalDurationSec']}s ({total_duration_frames} frames @ {fps}fps)")

def main():
    parser = argparse.ArgumentParser(description="Compile visual cues into timeline.json")
    parser.add_argument("--project", required=True, help="Path to project directory")
    parser.add_argument("--fps", type=int, default=30, help="Frames per second (default: 30)")
    args = parser.parse_args()

    compile_cues(os.path.abspath(args.project), args.fps)

if __name__ == "__main__":
    main()

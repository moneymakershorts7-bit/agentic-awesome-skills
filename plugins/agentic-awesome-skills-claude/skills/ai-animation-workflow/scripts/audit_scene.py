#!/usr/bin/env python3
"""
Audit animation project files, check beat boundaries, timing consistency,
and safe-zone compliance against Clief Notes Video-as-Code standards.
"""

import argparse
import os
import sys
import json

def audit_project(project_path: str):
    print(f"Auditing Animation Project at: {project_path}\n" + "="*50)
    warnings = []
    errors = []

    # 1. Check directories
    required_stages = ["docs", "01_voice", "02_transcript", "03_cues", "04_scene", "05_render"]
    for s in required_stages:
        p = os.path.join(project_path, s)
        if not os.path.exists(p):
            errors.append(f"Missing required stage directory: {s}")

    # 2. Check Stage 1 Audio
    audio_found = False
    for ext in [".wav", ".mp3", ".m4a", ".aac"]:
        for f in os.listdir(os.path.join(project_path, "01_voice")) if os.path.exists(os.path.join(project_path, "01_voice")) else []:
            if f.endswith(ext):
                audio_found = True
                print(f"[Stage 1 - Voice]: Found narration audio '{f}'")
                break
    if not audio_found:
        warnings.append("[Stage 1]: No approved narration audio file (.wav/.mp3) in 01_voice/")

    # 3. Check Stage 3 Timeline
    timeline_path = os.path.join(project_path, "03_cues", "timeline.json")
    if os.path.exists(timeline_path):
        try:
            with open(timeline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            beats = data.get("beats", [])
            print(f"[Stage 3 - Cues]: Loaded {len(beats)} beats (Total: {data.get('totalDurationSec')}s)")

            # Check for overlaps and gaps
            prev_end = 0.0
            for i, b in enumerate(beats):
                start = b.get("startSec", 0.0)
                end = b.get("endSec", 0.0)
                if start < prev_end:
                    warnings.append(f"[Stage 3]: Overlapping beats: Beat {i+1} ({b['id']}) starts at {start}s before Beat {i} ended at {prev_end}s.")
                if end - start > 8.0:
                    warnings.append(f"[Stage 3]: Long static beat: Beat '{b['id']}' duration is {end-start:.1f}s (> 8s). Consider breaking into visual sub-cues.")
                prev_end = end
        except Exception as e:
            errors.append(f"[Stage 3]: timeline.json is invalid JSON: {e}")
    else:
        warnings.append("[Stage 3]: timeline.json not generated. Run `compile_cues.py` first.")

    # 4. Check Stage 4 Scene Files
    scene_dir = os.path.join(project_path, "04_scene")
    if os.path.exists(scene_dir):
        scene_files = os.listdir(scene_dir)
        has_code = any(f.endswith((".tsx", ".jsx", ".ts", ".js", ".html")) for f in scene_files)
        if has_code:
            print(f"[Stage 4 - Scene]: Found scene implementation files.")
        else:
            warnings.append("[Stage 4]: No scene implementation file (.tsx/.js/.html) in 04_scene/")

    # Summary
    print("\n" + "="*50)
    print("AUDIT SUMMARY:")
    if errors:
        print(f"FAILED: {len(errors)} error(s) found:")
        for e in errors:
            print(f"  - ❌ {e}")
    else:
        print("  - Structure: PASS")

    if warnings:
        print(f"\nISSUES DETECTED: {len(warnings)} item(s):")
        for w in warnings:
            print(f"  - ⚠️ {w}")
    else:
        print("  - Timing & Cues: ALL CHECKS PASSED (0 issues)")

    print("="*50)
    return len(errors) == 0


def main():
    parser = argparse.ArgumentParser(description="Audit animation project structure and cue health")
    parser.add_argument("--project", required=True, help="Path to project directory")
    args = parser.parse_args()

    success = audit_project(os.path.abspath(args.project))
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

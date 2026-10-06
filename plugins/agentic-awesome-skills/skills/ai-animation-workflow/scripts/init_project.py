#!/usr/bin/env python3
"""
Initialize a standardized 5-stage AI Explainer Animation project directory.
Clief Notes Video-as-Code pipeline structure.
"""

import argparse
import os
import sys
import json

def init_project(target_dir: str, name: str, topic: str):
    base_path = os.path.join(target_dir, name)
    stages = [
        "docs",
        "01_voice",
        "02_transcript",
        "03_cues",
        "04_scene/assets",
        "04_scene/components",
        "05_render"
    ]

    for s in stages:
        os.makedirs(os.path.join(base_path, s), exist_ok=True)

    # 1. docs/brief.md
    brief_content = f"""# Project Brief: {name}

## Objective
Explain "{topic}" clearly in 45–60 seconds for learners or clients.

## Target Audience
- General audience / technical practitioner needing a clear visual mental model.

## Core Message / Source Note
> [Insert exact source quote, note, or problem statement here]

## Key Elements to Emphasize
1. **Source Fact / Entity:** (e.g. Actor / Component)
2. **Action / Transformation:** (e.g. Process / Event)
3. **Outcome / Deliverable:** (e.g. Result / Deadline)

## Safe Margins & Framing
- 16:9 Landscape ($1920 \\times 1080$) master.
- Bottom 180px reserved for subtitles.
"""
    with open(os.path.join(base_path, "docs", "brief.md"), "w", encoding="utf-8") as f:
        f.write(brief_content)

    # 2. 01_voice/script.md
    script_content = f"""# Voiceover Script: {name}

[Beat 1: The Problem / Source Fact] (0.0s - 4.5s)
Take a look at this note: [insert statement].

[Beat 2: Breaking Down the Components] (4.5s - 12.0s)
First, identify who is responsible. Next, see what action needs to happen.

[Beat 3: The Result & Synthesis] (12.0s - 20.0s)
When we connect the action to the due date, everything stays clear and accountable.
"""
    with open(os.path.join(base_path, "01_voice", "script.md"), "w", encoding="utf-8") as f:
        f.write(script_content)

    # 3. 03_cues/cues.md
    cues_content = f"""# Visual Cue Storyboard: {name}

| Beat ID | Start (s) | End (s) | Spoken Phrase | Visual Action | Focus Element |
| :--- | :--- | :--- | :--- | :--- | :--- |
| beat_01 | 0.00 | 4.50 | "Take a look at this note..." | Fade in Source Card | `node_source_doc` |
| beat_02 | 4.50 | 12.00 | "First, identify who is responsible..." | Slide in Structured Action Card | `badge_owner` + `char_sam` |
| beat_03 | 12.00 | 20.00 | "When we connect the action..." | Paired highlight connector line | `arrow_connector_01` |
"""
    with open(os.path.join(base_path, "03_cues", "cues.md"), "w", encoding="utf-8") as f:
        f.write(cues_content)

    # 4. project.json manifest
    manifest = {
        "projectName": name,
        "topic": topic,
        "fps": 30,
        "width": 1920,
        "height": 1080,
        "stages": {
            "voice": "01_voice/narration.wav",
            "transcript": "02_transcript/transcript.json",
            "cues": "03_cues/cues.md",
            "timeline": "03_cues/timeline.json",
            "scene": "04_scene/Scene.tsx",
            "render": "05_render/master_1080p.mp4"
        }
    }
    with open(os.path.join(base_path, "project.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Initialized AI Animation project at: {base_path}")
    print("Next step: Edit docs/brief.md and record/generate audio into 01_voice/narration.wav")

def main():
    parser = argparse.ArgumentParser(description="Scaffold an AI Animation project directory")
    parser.add_argument("--name", required=True, help="Project name (slug format, e.g. git-rebase-explainer)")
    parser.add_argument("--topic", default="Explainer Animation", help="Core concept or topic")
    parser.add_argument("--dir", default=".", help="Target root directory (defaults to current dir)")
    args = parser.parse_args()

    init_project(os.path.abspath(args.dir), args.name, args.topic)

if __name__ == "__main__":
    main()

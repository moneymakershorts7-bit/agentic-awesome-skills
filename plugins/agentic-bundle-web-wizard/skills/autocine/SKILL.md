---
name: autocine
description: Autonomous, programmatic long-form AI video and film production engine for any genre (YouTube essays, documentaries, sci-fi, anime, true crime, dark fantasy). Implements multi-panel character reference sheets, mathematical pacing budgets (2.5 wps), story-state continuity ledgers, neural TTS, multi-engine dispatch (Google Flow, Seedance 2.5, Kling, Hailuo, ComfyUI), dynamic 2.5D/Ken Burns camera motion, and broadcast FFmpeg timeline assembly with EBU R128 (-14 LUFS) audio mastering.
---

# AutoCine

AutoCine is a comprehensive, production-grade engine for creating automated cinematic videos of any length (up to 60+ minutes) across any genre.

## Core Capabilities

1. **Universal Genre Intelligence**: Automatic cinematographic profiling (palettes, lighting keys, camera syntax, audio soundscapes, and negative exclusions) across 20+ genres.
2. **Mathematical Clip & Pacing Budgeting**:
   - Total Clips: $\lceil \text{Target Duration (sec)} / \text{Max Clip Length } L \rceil$
   - Dialogue Rhythm: 2.0–2.5 words/second maximum speech capacity.
   - Shot Density: 1–2 shots for $\le 5$s, 2–3 shots for 6–10s, 3–5 shots for 11–15s.
3. **Multi-Panel Reference Sheets**: Turnaround sheets (4 full-body angles, 6 facial expressions, 1 hero pose) and empty environment plates.
4. **Story-State Continuity Ledger**: Tracks wardrobe, injuries, held items, time of day, and emotional tension across consecutive clips.
5. **Multi-Engine Quota Routing**: Combines Google Flow (Veo 3.1), Seedance 2.5, Kling AI, Hailuo MiniMax, and ComfyUI.
6. **Programmatic FFmpeg Assembly**: Sidechain audio ducking (-18 dB on music during speech), EBU R128 loudness normalization (-14 LUFS), and dynamic animated subtitles.

## CLI Commands

```bash
# 1. Plan a complete production bible and prompt manifest
uv run --project /home/npirela/autocine python3 -m autocine.cli plan \
  --title "The Quantum Paradox" \
  --genre "Sci-Fi Documentary" \
  --topic "The emergence of quantum artificial intelligence" \
  --duration 5.0 \
  --max-clip 10 \
  --output ./quantum_doc

# 2. Check API key and provider configuration
uv run --project /home/npirela/autocine python3 -m autocine.cli config

# 3. Generate automated browser dispatcher for Google Flow / Kling
uv run --project /home/npirela/autocine python3 -m autocine.cli bridge \
  --bible ./quantum_doc/production_bible.json

# 4. Generate neural audio stems & motion video plates
uv run --project /home/npirela/autocine python3 -m autocine.cli generate \
  --bible ./quantum_doc/production_bible.json

# 5. Assemble final broadcast film with background music
uv run --project /home/npirela/autocine python3 -m autocine.cli assemble \
  --project-dir ./quantum_doc \
  --music /path/to/ambient_track.mp3

# 6. End-to-end all-in-one execution
uv run --project /home/npirela/autocine python3 -m autocine.cli run \
  --title "The Lost Archives" \
  --genre "Historical Documentary" \
  --topic "The hidden libraries of Alexandria" \
  --duration 2.0 \
  --output ./alexandria_doc
```

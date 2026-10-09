---
name: autoclip
description: Open-source, local-first AI video clipper and shorts generator. Ingests long videos / YouTube links, transcribes via Whisper, detects viral moments via LLMs, reframes to 9:16 with active speaker tracking, burns animated subtitles, and exports platform-ready MP4 clips.
allowed-tools:
  - run_command
  - view_file
  - write_to_file
---

# AutoClip: Local-First AI Video Clipper & Shorts Generator

AutoClip ingests full-length videos or YouTube URLs, transcribes audio, selects high-retention highlights via LLMs, performs speaker-tracking 9:16 reframing (MediaPipe/FFmpeg), burns animated captions with `libass`, and exports vertical shorts.

---

## 1. Core Pipeline Stages

```
[Long Video Ingest] ──> [Whisper Transcription] ──> [LLM Highlight Selection] ──> [Speaker Tracking Reframe (9:16)] ──> [Animated Subtitles Burn] ──> [Platform MP4 Export]
```

1. **Ingest:** Reads local MP4/MKV files or downloads YouTube streams via `yt-dlp`.
2. **Transcription:** Offline local Whisper or fast API transcription with word-level timestamps.
3. **Highlight Detection:** Evaluates transcript moments with retention scoring, hook density, and emotional punchiness.
4. **Speaker-Tracking 9:16 Crop:** Detects active speakers and smoothly tracks them horizontally across widescreen frames.
5. **Caption Burning:** Burns dynamic word-by-word highlighted subtitles with `libass` and FFmpeg.

---

## 2. CLI Usage

When run in an isolated virtual environment (`autoclip` CLI):
```bash
# Analyze a long video and extract top 3 viral shorts
autoclip clip --input podcast.mp4 --max-clips 3 --target-ratio 9:16 --output-dir ./shorts_output/

# Run web review UI
autoclip serve --port 8000
```

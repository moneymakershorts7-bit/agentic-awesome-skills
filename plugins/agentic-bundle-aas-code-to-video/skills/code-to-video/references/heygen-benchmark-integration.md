# Strategic Analysis & Integration: HeyGen's `code2video-public` Dataset

## 1. Executive Summary & Dataset Provenance
HeyGen publicly released the **Code2Video Benchmark (`heygen/code2video-public`)** on Kaggle Benchmarks (September 2026, CC BY 4.0).
It represents the frontier industry standard for evaluating AI coding agents on motion design tasks, featuring **50 structured public tasks** across 8 stratified categories:
- `Key_Feature` (36%)
- `Product_Intro` (18%)
- `Hook` (12%)
- `Benefits` (10%)
- `CTA` (8%)
- `Brand_Outro` (8%)
- `Problem` (4%)
- `Social_Proof` (4%)

Each task pairs:
1. `instruction.md`: A high-fidelity, designer-grade scene brief specifying camera movement, color hexes, easing curves, layout coordinates, typography, and timeline events.
2. `tests/golden.mp4`: Human-crafted ground-truth reference video rendered at 60fps.
3. `tests/grade.py`: Automated multi-axis VLM judging harness evaluating 5 semantic dimensions: `engagement`, `prompt_intent`, `composition`, `temporal_consistency`, and `craft`.
4. `scripts/generate_elo.py`: Bradley-Terry Elo tournament engine ranking models against the human golden standard (centered at Elo 1500).

---

## 2. Reverse Engineering the HeyGen Runtime vs Our Master Engine

| Dimension | HeyGen Benchmark (`heygen-com/hyperframes`) | Naive Screen Recorder (`nexu-io/html-video`) | Our `code-to-video` Master Engine |
| :--- | :--- | :--- | :--- |
| **Engine Runtime** | `hyperframes` CLI (`v0.8.x`) Node CLI wrapping Chromium | Plain Playwright `recordVideo` in wall-clock time | Injected Deterministic Clock (`window.__seekToFrame`) via CDP + Puppeteer |
| **Frame Determinism** | High (internal frame stepping) | **None** (drops frames on CPU SwiftShader) | **Absolute 100%** (freezes wall clock until frame paint finishes) |
| **Audio Pipeline** | None / External | Real-time audio record | Fractional sample-rate PTS sync + sidechain ducking (`edge-tts`) |
| **Format Target** | Single-file HTML5 + GSAP | ContentGraph DAG -> HTML | Hermetic HTML5 + CSS3 + Canvas + WebGL + Video elements |
| **Evaluation Model** | 5-axis pairwise VLM judge vs `golden.mp4` | Subjective visual review | Automated Bradley-Terry ELO + deterministic smoke checks |

---

## 3. Strategic Integration Roadmap for `code-to-video`

### Phase 1: Benchmark Compatibility Layer
- Map HeyGen's task specifications (`instruction.md`) directly into prompt templates in `~/.agents/skills/code-to-video/templates/`.
- Support rendering single-file HeyGen `index.html` compositions directly via:
  ```bash
  code-to-video render -i tasks/<case_id>/index.html -o output.mp4 -d <duration> -r 60
  ```

### Phase 2: Synthetic Prompt Generation & Zero-Shot ELO Testing
- Use the 50 instruction briefs as few-shot training context for agents generating motion graphics.
- Benchmark agent output against `tests/golden.mp4` using local or cloud VLM judges across the 5 semantic axes (`engagement`, `prompt_intent`, `composition`, `temporal_consistency`, `craft`).

### Phase 3: Self-Healing Motion Feedback Loop
- Capture lint failures and video frame analysis to automatically correct HTML/CSS easing and coordinate clipping before final export.

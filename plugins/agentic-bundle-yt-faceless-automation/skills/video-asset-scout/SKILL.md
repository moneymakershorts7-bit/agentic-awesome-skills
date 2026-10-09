---
name: video-asset-scout
description: Autonomous multi-modal media asset scout that researches, discovers, and fetches real-world player & personality imagery, news declarations, press clippings, B-roll footage, and sound design for any video topic.
allowed-tools:
  - run_command
  - view_file
  - write_to_file
  - search_web
  - read_url_content
---

# Video Asset Scout: Autonomous Real-World Media Research Engine

The `video-asset-scout` autonomously researches, discovers, fetches, and formats real-world multi-modal assets for any video topic or script before video rendering.

---

## 1. Core Architectural Capabilities

1. **Entity & Intent Extraction:**
   - Automatically identifies key personalities, athletes, politicians, rivalries, trophies, and organizations from raw topic titles or full narration scripts.
   - Determines scene vibes (`conflict_explosive`, `triumph_epic`, `high_tension`, `investigative_mystery`).

2. **Real-World High-Resolution Photography:**
   - Queries Wikipedia REST Summary API and Wikimedia Commons Action API.
   - Fetches official high-res Creative Commons / Public Domain press and match photography.
   - Formats images for 3D floating polaroid, cutout, and collage rendering.

3. **Authentic Editorial News Clippings & Quotes:**
   - Generates photorealistic newspaper clippings (*Diario MARCA*, *AS*, *BBC*, *L'Équipe*) with vintage newsprint texture, editorial serif typography, and highlight markers.
   - Synthesizes verified breaking news statement cards (*Fabrizio Romano*, official club statements).

4. **Multi-Track Audio & SFX Production:**
   - Procedural studio sound suite: camera shutter clicks, paper rustles, whooshes, sub-bass impacts, and 128 BPM dynamic tension beds.

5. **Structured Asset Manifest (`asset_manifest.json`):**
   - Directly maps paths, dimensions, and audio stems to downstream video engines like `frame_by_frame_motion_engine.py`.

---

## 2. CLI Usage

Run the asset scout against any topic:
```bash
python3 /home/npirela/youtube_auto_runner/video_asset_scout.py \
  "Lamine Yamal vs Kylian Mbappé: El Duelo del Balón de Oro" \
  "Lamine Yamal brilla en el Barcelona mientras Mbappé y Ancelotti buscan la Champions League en el Bernabéu."
```

Output directory structure:
```
demo_output/asset_vault/{topic_slug}/
├── images/
│   ├── kylian_mbappe_real.jpg
│   ├── lamine_yamal_real.jpg
│   └── carlo_ancelotti_real.jpg
├── press/
│   ├── marca_exclusive.png
│   └── fabrizio_tweet.png
├── audio/
│   ├── camera_shutter.wav
│   ├── impact_boom.wav
│   ├── tension_bed.wav
│   └── whoosh.wav
└── asset_manifest.json
```

---

## 3. Downstream Video Engine Integration

In `frame_by_frame_motion_engine.py` or `run_automated_channel_pipeline.py`:
```python
from video_asset_scout import VideoAssetScout

scout = VideoAssetScout()
manifest = scout.scout_assets_for_topic(topic=current_topic, script_text=script)

# Load manifest into frame-by-frame renderer
real_player_images = manifest["images"]
press_clippings = manifest["press_clippings"]
sfx_stems = manifest["audio_sfx"]
```

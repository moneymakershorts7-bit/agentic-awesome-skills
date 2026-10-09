# FFmpeg Universal Editor Toolkit 🧰⚡

Production-tested, high-performance FFmpeg recipes for multi-format video editing, timeline assembly, audio mixing, subtitle rendering, and aspect ratio adaptation.

---

## 1. Multi-Format Canvas & Scaling Recipes

### 16:9 Landscape to 9:16 Vertical Short (Smart Crop + Blurred Backdrop)
```bash
ffmpeg -i input_16x9.mp4 -filter_complex \
"[0:v]scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920,boxblur=20:5[bg]; \
 [0:v]scale=1080:608[fg]; \
 [bg][fg]overlay=0:(H-h)/2[v]" \
-map "[v]" -map 0:a -c:v libx264 -crf 18 -preset fast output_9x16.mp4
```

### 16:9 Standard to 2.39:1 Cinematic Letterbox
```bash
ffmpeg -i input_16x9.mp4 -vf "crop=in_w:in_w/2.39,scale=1920:800,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black" \
-c:v libx264 -crf 18 output_scope.mp4
```

---

## 2. Dynamic Ken Burns Effect on Still Images / Archival Stills

Smooth continuous zoom-in with cubic ease curve over 5 seconds (150 frames @ 30fps):
```bash
ffmpeg -loop 1 -i photo.jpg -vf \
"scale=8000:-1,zoompan=z='min(zoom+0.0015,1.25)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=150:s=1920x1080:fps=30" \
-t 5 -c:v libx264 -pix_fmt yuv420p output_kenburns.mp4
```

---

## 3. A-Roll / B-Roll Overlay with Picture-in-Picture & Lower-Thirds

```bash
ffmpeg -i aroll_speaker.mp4 -i broll_clip.mp4 -i lower_third.png -filter_complex \
"[1:v]scale=640:360,drawbox=x=0:y=0:w=iw:h=ih:color=white@0.8:t=4[broll_pip]; \
 [0:v][broll_pip]overlay=W-w-50:50:enable='between(t,3,9)'[v_pip]; \
 [v_pip][2:v]overlay=50:H-h-50:enable='between(t,1,6)'[v_out]" \
-map "[v_out]" -map 0:a -c:v libx264 -crf 18 output_assembled.mp4
```

---

## 4. Multi-Layer Audio Mix with Sidechain Ducking & -14 LUFS Loudness

```bash
ffmpeg -i voiceover.wav -i bg_music.wav -i sfx_whoosh.wav -filter_complex \
"[1:a][0:a]sidechaincompress=threshold=0.09:ratio=7:attack=100:release=800[ducked_music]; \
 [0:a]volume=1.0[voice]; \
 [ducked_music]volume=0.35[music]; \
 [2:a]volume=0.75,adelay=3000|3000[sfx]; \
 [voice][music][sfx]amix=inputs=3:duration=first[mixed_audio]; \
 [mixed_audio]loudnorm=I=-14:TP=-1.0:LRA=7[mastered_audio]" \
-map 0:v -map "[mastered_audio]" -c:v copy -c:a aac -b:a 192k output_mastered.mp4
```

---

## 5. Kinetic Word-Level Subtitles Overlay (ASS / SRT)

```bash
ffmpeg -i video.mp4 -vf "ass=subtitles.ass" -c:v libx264 -crf 18 -c:a copy output_subtitled.mp4
```

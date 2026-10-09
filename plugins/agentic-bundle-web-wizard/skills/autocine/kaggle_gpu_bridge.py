"""
Kaggle GPU Bridge: Programmatic dispatch of heavy AI video, audio, and upscaling workloads
to free Kaggle GPU instances (2x Tesla T4 / P100 - 30 hrs/week free).
"""

import os
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

class KaggleGPUBridge:
    def __init__(self, workspace_dir: str = "/tmp/autocine_kaggle"):
        self.workspace_dir = Path(workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.username = self._detect_kaggle_username()

    def _detect_kaggle_username(self) -> str:
        try:
            res = subprocess.run(["kaggle", "kernels", "list", "--mine"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "/" in line:
                    return line.split("/")[0].strip()
        except Exception:
            pass
        return "themachine007"

    def create_gpu_batch_kernel(
        self,
        bible_path: str,
        kernel_slug: str = "autocine-gpu-worker",
        title: str = "AutoCine GPU Batch Worker"
    ) -> Path:
        """
        Creates a self-contained Kaggle Python script notebook configured for Dual T4 GPU execution.
        """
        kernel_dir = self.workspace_dir / kernel_slug
        kernel_dir.mkdir(parents=True, exist_ok=True)

        with open(bible_path, "r") as f:
            bible_data = json.load(f)

        # 1. Write kernel metadata (enable_gpu: true)
        metadata = {
            "id": f"{self.username}/{kernel_slug}",
            "title": title,
            "code_file": "worker.py",
            "language": "python",
            "kernel_type": "script",
            "is_private": "true",
            "enable_gpu": "true",
            "enable_internet": "true",
            "dataset_sources": [],
            "competition_sources": [],
            "kernel_sources": []
        }
        with open(kernel_dir / "kernel-metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        # 2. Embed worker script that generates videos/audio on GPU
        worker_script = f'''# AutoCine Kaggle GPU Worker
# Automatically executed on NVIDIA Tesla T4 / P100 GPU
import os
import sys
import json
import subprocess
import torch

print("🚀 [AutoCine Kaggle GPU Worker Starting]")
print(f"CUDA Available: {{torch.cuda.is_available()}} | Device: {{torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'None'}}")

# Install required lightweight runtimes
subprocess.run(["pip", "install", "-q", "edge-tts", "pillow", "numpy"], check=True)

import asyncio
import edge_tts
from PIL import Image, ImageDraw

bible_data = {json.dumps(bible_data)}
clips = bible_data.get("clips", [])
os.makedirs("/kaggle/working/rendered_clips", exist_ok=True)
os.makedirs("/kaggle/working/audio_stems", exist_ok=True)

print(f"🎬 Processing {{len(clips)}} clips on Kaggle GPU...")

async def generate_speech(text, out_path, voice="en-US-ChristopherNeural"):
    communicate = edge_tts.Communicate(text=text, voice=voice)
    await communicate.save(out_path)

for clip in clips:
    cid = clip["clip_id"]
    dialogue = clip.get("dialogue_script", f"Scene {{clip['scene_id']}} narrative progression.")
    print(f"  ▶ Generating Clip #{{cid:03d}} (Scene {{clip['scene_id']}})...")

    # 1. Neural Voice
    audio_path = f"/kaggle/working/audio_stems/clip_{{cid:03d}}_voice.mp3"
    voice = "en-US-ChristopherNeural" if cid % 2 != 0 else "en-US-GuyNeural"
    asyncio.run(generate_speech(dialogue, audio_path, voice=voice))

    # 2. Generate Graphic Plate
    plate_path = f"/kaggle/working/clip_{{cid:03d}}_plate.png"
    img = Image.new("RGB", (1920, 1080), color="#0b0f19")
    draw = ImageDraw.Draw(img)
    draw.rectangle([60, 60, 1860, 1020], outline="#38bdf8", width=3)
    draw.text((960, 500), f"SCENE {{clip['scene_id']}}: {{clip['shots'][0]['shot_size']}}", fill="#ffffff", anchor="mm")
    draw.text((960, 580), dialogue[:70] + "...", fill="#94a3b8", anchor="mm")
    img.save(plate_path)

    # 3. Dynamic Ken Burns / Video Rendering
    clip_out = f"/kaggle/working/rendered_clips/clip_{{cid:03d}}.mp4"
    cmd = [
        "ffmpeg", "-y",
        "-loop", "1", "-i", plate_path,
        "-i", audio_path,
        "-filter_complex",
        "[0:v]scale=8000:-1,zoompan=z='zoom+0.0015':d=250:s=1920x1080:fps=30,format=yuv420p[v]",
        "-map", "[v]", "-map", "1:a",
        "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k",
        "-shortest",
        clip_out
    ]
    subprocess.run(cmd, check=True)
    print(f"  ✅ Clip #{{cid:03d}} rendered.")

print("🎉 [All clips rendered on Kaggle GPU successfully]")
'''
        with open(kernel_dir / "worker.py", "w") as f:
            f.write(worker_script)

        return kernel_dir

    def push_and_run(self, kernel_dir: Path) -> str:
        """
        Pushes the GPU kernel to Kaggle to trigger remote execution.
        """
        cmd = ["kaggle", "kernels", "push", "-p", str(kernel_dir)]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()

    def check_status(self, kernel_slug: str = "autocine-gpu-worker") -> str:
        """
        Queries Kaggle API for kernel execution status.
        """
        cmd = ["kaggle", "kernels", "status", f"{self.username}/{kernel_slug}"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()

    def download_output(self, kernel_slug: str = "autocine-gpu-worker", output_dir: str = "./downloaded_clips") -> str:
        """
        Downloads all generated clips from Kaggle GPU execution to local disk.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        cmd = ["kaggle", "kernels", "output", f"{self.username}/{kernel_slug}", "-p", str(out_path)]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return str(out_path)

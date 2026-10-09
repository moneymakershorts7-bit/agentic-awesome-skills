#!/usr/bin/env python3
"""
Edge-TTS Expressive Narrator Engine 🎙️
Synthesizes emotional, multi-beat neural voiceovers with acoustic cadence optimization and EBU R128 mastering.
"""

import argparse
import asyncio
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple

import edge_tts

# Canonical Emotion Prosody Matrix
PROSODY_PRESETS = {
    "HYPE": {"rate": "+14%", "pitch": "+5Hz", "volume": "+5%"},
    "CLIMAX": {"rate": "+16%", "pitch": "+6Hz", "volume": "+6%"},
    "SHOCK": {"rate": "+10%", "pitch": "+6Hz", "volume": "+6%"},
    "COLD_PLUNGE": {"rate": "+12%", "pitch": "+5Hz", "volume": "+6%"},
    "SUSPENSE": {"rate": "-10%", "pitch": "-3Hz", "volume": "-2%"},
    "MYSTERY": {"rate": "-12%", "pitch": "-4Hz", "volume": "-3%"},
    "STORYTELLING": {"rate": "+2%", "pitch": "+0Hz", "volume": "+0%"},
    "NEUTRAL": {"rate": "+0%", "pitch": "+0Hz", "volume": "+0%"},
    "EMPATHY": {"rate": "-6%", "pitch": "-2Hz", "volume": "-3%"},
    "SERIOUS": {"rate": "-4%", "pitch": "-2Hz", "volume": "-2%"},
    "CONTEMPLATIVE": {"rate": "-8%", "pitch": "-4Hz", "volume": "-4%"},
    "AGGRESSIVE_FAST": {"rate": "+18%", "pitch": "+4Hz", "volume": "+6%"},
    "CTA": {"rate": "+6%", "pitch": "+2Hz", "volume": "+4%"},
}

DEFAULT_VOICE = "es-MX-JorgeNeural"


def optimize_cadence_formatting(text: str) -> str:
    """Enhance text with Spanish acoustic punctuation priors for neural models."""
    cleaned = text.strip()
    
    # Ensure inverted Spanish question marks
    lines = cleaned.split("\n")
    processed_lines = []
    for line in lines:
        l = line.strip()
        if not l:
            continue
        # If line ends with ? and doesn't start with ¿ or bracket tag
        if l.endswith("?") and not l.startswith("¿") and not l.startswith("["):
            l = "¿" + l
        # If line ends with ! and doesn't start with ¡ or bracket tag
        if l.endswith("!") and not l.startswith("¡") and not l.startswith("["):
            l = "¡" + l
        # Standardize ellipses spacing
        l = re.sub(r"\s*\.\.\.\s*", "... ", l)
        processed_lines.append(l)
        
    return "\n".join(processed_lines)


def parse_emotional_script(script_content: str) -> List[Dict[str, Any]]:
    """Parse text with [EMOTION: PRESET] or [PAUSE: Xs] tags into actionable beats."""
    segments = []
    current_emotion = "STORYTELLING"
    
    # Split on tag boundaries
    pattern = r"\[(EMOTION|PAUSE|VOICE):\s*([^\]]+)\]"
    tokens = re.split(pattern, script_content, flags=re.IGNORECASE)
    
    i = 0
    while i < len(tokens):
        token = tokens[i].strip()
        if not token:
            i += 1
            continue
            
        token_upper = token.upper()
        if token_upper == "EMOTION":
            current_emotion = tokens[i + 1].strip().upper()
            i += 2
        elif token_upper == "PAUSE":
            pause_val = tokens[i + 1].strip().lower().replace("s", "")
            try:
                pause_sec = float(pause_val)
                segments.append({"type": "pause", "duration": pause_sec})
            except ValueError:
                pass
            i += 2
        else:
            # Spoken text
            text_chunk = token.strip()
            if text_chunk:
                segments.append({
                    "type": "speech",
                    "text": text_chunk,
                    "emotion": current_emotion,
                    "prosody": PROSODY_PRESETS.get(current_emotion, PROSODY_PRESETS["STORYTELLING"])
                })
            i += 1
            
    # Fallback if no tags found
    if not segments and script_content.strip():
        segments.append({
            "type": "speech",
            "text": script_content.strip(),
            "emotion": "STORYTELLING",
            "prosody": PROSODY_PRESETS["STORYTELLING"]
        })
        
    return segments


async def synthesize_segment(text: str, voice: str, prosody: Dict[str, str], output_file: Path) -> None:
    """Synthesize an individual speech segment via edge-tts with specific prosody."""
    comm = edge_tts.Communicate(
        text=text,
        voice=voice,
        rate=prosody.get("rate", "+0%"),
        pitch=prosody.get("pitch", "+0Hz"),
        volume=prosody.get("volume", "+0%")
    )
    await comm.save(str(output_file))


def generate_silence(duration: float, output_file: Path) -> None:
    """Generate precise silent audio chunk using ffmpeg."""
    cmd = [
        "ffmpeg", "-y", "-f", "lavfi",
        "-i", f"anullsrc=r=44100:cl=stereo",
        "-t", str(duration),
        "-c:a", "aac",
        str(output_file)
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def master_audio_loudness(input_file: Path, output_file: Path, target_lufs: float = -14.0) -> None:
    """Apply EBU R128 / YouTube standard loudness normalization via FFmpeg."""
    cmd = [
        "ffmpeg", "-y", "-i", str(input_file),
        "-filter:a", f"loudnorm=I={target_lufs}:TP=-1.5:LRA=11",
        "-c:a", "aac",
        "-b:a", "192k",
        str(output_file)
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


async def narrate_pipeline(
    script_text: str,
    output_path: Path,
    voice: str = DEFAULT_VOICE,
    default_emotion: str = "STORYTELLING",
    auto_format: bool = True,
    target_lufs: float = -14.0,
    inter_segment_pause: float = 0.15
) -> Path:
    """Execute end-to-end expressive narration synthesis."""
    if auto_format:
        script_text = optimize_cadence_formatting(script_text)
        
    segments = parse_emotional_script(script_text)
    if not segments:
        raise ValueError("Script contains no synthesizeable speech text.")
        
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        chunk_files: List[Path] = []
        
        for idx, seg in enumerate(segments):
            if seg["type"] == "speech":
                chunk_path = temp_dir / f"chunk_{idx:03d}.mp3"
                prosody = seg["prosody"]
                print(f"  🎙️ Synthesizing Beat {idx+1}/{len(segments)} [{seg['emotion']}] (rate={prosody['rate']}, pitch={prosody['pitch']}): \"{seg['text'][:40]}...\"")
                await synthesize_segment(seg["text"], voice, prosody, chunk_path)
                chunk_files.append(chunk_path)
                
                # Optional natural inter-segment pause
                if inter_segment_pause > 0 and idx < len(segments) - 1:
                    pause_path = temp_dir / f"pause_{idx:03d}.aac"
                    generate_silence(inter_segment_pause, pause_path)
                    chunk_files.append(pause_path)
                    
            elif seg["type"] == "pause":
                pause_path = temp_dir / f"pause_explicit_{idx:03d}.aac"
                generate_silence(seg["duration"], pause_path)
                chunk_files.append(pause_path)
                
        # Concat all audio chunks via FFmpeg
        concat_list = temp_dir / "concat_list.txt"
        with open(concat_list, "w", encoding="utf-8") as f:
            for c in chunk_files:
                f.write(f"file '{c.resolve()}'\n")
                
        raw_concat = temp_dir / "raw_concat.aac"
        cmd_concat = [
            "ffmpeg", "-y", "-f", "concat", "-safe", "0",
            "-i", str(concat_list),
            "-c:a", "aac",
            str(raw_concat)
        ]
        subprocess.run(cmd_concat, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        
        # Apply Loudness Normalization
        output_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"  🎛️ Mastering complete audio track to {target_lufs} LUFS broadcast standard...")
        master_audio_loudness(raw_concat, output_path, target_lufs)
        
    print(f"  ✅ Audio successfully produced: {output_path}")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Edge-TTS Expressive Narrator Engine")
    parser.add_argument("--input-script", "-i", type=str, help="Path to text script file or raw string")
    parser.add_argument("--output-audio", "-o", type=str, required=True, help="Path to output audio file (.aac, .mp3, .wav)")
    parser.add_argument("--voice", "-v", type=str, default=DEFAULT_VOICE, help=f"Neural voice name (default: {DEFAULT_VOICE})")
    parser.add_argument("--emotion", "-e", type=str, default="STORYTELLING", choices=list(PROSODY_PRESETS.keys()), help="Default emotion preset")
    parser.add_argument("--lufs", type=float, default=-14.0, help="Target broadcast LUFS (default: -14.0)")
    parser.add_argument("--no-auto-format", action="store_true", help="Disable acoustic punctuation auto-formatting")
    
    args = parser.parse_args()
    
    if args.input_script:
        p = Path(args.input_script)
        if p.exists() and p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                script_content = f.read()
        else:
            script_content = args.input_script
    else:
        print("Reading script from stdin...")
        script_content = sys.stdin.read()
        
    asyncio.run(narrate_pipeline(
        script_text=script_content,
        output_path=Path(args.output_audio),
        voice=args.voice,
        default_emotion=args.emotion,
        auto_format=not args.no_auto_format,
        target_lufs=args.lufs
    ))


if __name__ == "__main__":
    main()

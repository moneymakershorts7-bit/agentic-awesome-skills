#!/usr/bin/env python3
"""
audiobook_producer.py - Long-Form Audiobook Direction & Multi-Engine Synthesis Engine

Analyzes long manuscripts, books, and documents; splits into structured chapters;
applies narrative tension curves (exposition, rising action, climax, resolution);
differentiates narrator voice from character dialogue; and formats scripts
specifically tailored to the target TTS engine's capabilities.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORDS_PER_MINUTE = 140  # Standard professional audiobook speaking rate

MODEL_PROFILES = {
    "edge-tts": {
        "tier": "free",
        "max_chunk_chars": 1800,
        "format": "ssml",
        "supports_ssml": True,
        "supports_emotion_tags": True,
        "recommended_narrator_es": "es-ES-AlvaroNeural",
        "recommended_dialogue_es": "es-ES-ElviraNeural",
        "recommended_narrator_en": "en-US-GuyNeural",
        "recommended_dialogue_en": "en-US-JennyNeural",
        "cost_per_10k_chars": 0.0,
    },
    "kokoro": {
        "tier": "free",
        "max_chunk_chars": 1500,
        "format": "kokoro",
        "supports_ssml": False,
        "supports_emotion_tags": False,
        "recommended_narrator_es": "em_alex",
        "recommended_dialogue_es": "ef_dora",
        "recommended_narrator_en": "am_adam",
        "recommended_dialogue_en": "af_sarah",
        "cost_per_10k_chars": 0.0,
    },
    "chattts": {
        "tier": "free",
        "max_chunk_chars": 1000,
        "format": "chattts",
        "supports_ssml": False,
        "supports_emotion_tags": True,
        "cost_per_10k_chars": 0.0,
    },
    "elevenlabs": {
        "tier": "paid",
        "max_chunk_chars": 3000,
        "format": "elevenlabs",
        "supports_ssml": True,
        "supports_emotion_tags": True,
        "cost_per_10k_chars": 0.35,
    },
    "openai": {
        "tier": "paid",
        "max_chunk_chars": 2000,
        "format": "openai",
        "supports_ssml": False,
        "supports_emotion_tags": False,
        "recommended_narrator_en": "onyx",
        "recommended_dialogue_en": "nova",
        "cost_per_10k_chars": 0.30,
    }
}


def clean_citations_and_markdown(text: str) -> str:
    """Removes technical academic citation markers and formatting artifacts that disrupt speech flow."""
    # Remove footnote markers like [1], [12], [^1]
    text = re.sub(r'\[\^?\d+\]', '', text)
    # Remove markdown link formatting [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Remove markdown image tags ![caption](url)
    text = re.sub(r'!\[[^\]]*\]\([^)]+\)', '', text)
    # Remove bold/italic markers (* or _)
    text = re.sub(r'[*_]{1,3}([^*_]+)[*_]{1,3}', r'\1', text)
    # Clean HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Normalize excessive spaces
    text = re.sub(r'[ \t]+', ' ', text)
    return text.strip()


def parse_book_chapters(content: str) -> List[Dict[str, Any]]:
    """Splits a full document/book into structured chapters based on markdown headers or natural breaks."""
    # Split by level 1 or 2 headers (e.g. # Chapter 1 or ## Capítulo 2)
    header_pattern = re.compile(r'^(#{1,2}\s+[^\n]+)', re.MULTILINE)
    splits = header_pattern.split(content)
    
    chapters = []
    if len(splits) <= 1:
        # No markdown headers found; treat whole text as Chapter 1
        cleaned = clean_citations_and_markdown(content)
        if cleaned:
            chapters.append({
                "chapter_index": 1,
                "title": "Capítulo 1",
                "raw_text": cleaned,
                "word_count": len(cleaned.split()),
            })
        return chapters

    # Process header splits
    current_title = "Introducción / Prólogo"
    # If the first segment before the first header has content
    first_chunk = clean_citations_and_markdown(splits[0])
    if first_chunk:
        chapters.append({
            "chapter_index": 1,
            "title": current_title,
            "raw_text": first_chunk,
            "word_count": len(first_chunk.split()),
        })

    idx = len(chapters) + 1
    for i in range(1, len(splits), 2):
        header_text = re.sub(r'^#{1,2}\s*', '', splits[i]).strip()
        body_text = clean_citations_and_markdown(splits[i + 1]) if (i + 1 < len(splits)) else ""
        if body_text.strip():
            chapters.append({
                "chapter_index": idx,
                "title": header_text or f"Capítulo {idx}",
                "raw_text": body_text,
                "word_count": len(body_text.split()),
            })
            idx += 1

    return chapters


def analyze_scene_blocks(chapter_text: str) -> List[Dict[str, Any]]:
    """
    Breaks down a chapter into narrative blocks, classifying:
    - Type: 'narration' vs 'dialogue'
    - Tension/Arc: 'exposition', 'rising_action', 'dramatic', 'resolution'
    """
    paragraphs = [p.strip() for p in chapter_text.split("\n\n") if p.strip()]
    total_paragraphs = max(len(paragraphs), 1)
    
    blocks = []
    dialogue_regex = re.compile(r'^(?:["«—]|“)[^"»”\n]+(?:["»”—]|”)?')

    for i, para in enumerate(paragraphs):
        is_dialogue = bool(dialogue_regex.search(para))
        rel_pos = i / total_paragraphs

        # Dramatic arc determination
        if rel_pos < 0.20:
            arc = "exposition"
            narrator_rate = "-2%"
            narrator_pitch = "+0Hz"
            ssml_style = "calm"
        elif rel_pos < 0.65:
            arc = "rising_action"
            narrator_rate = "+4%"
            narrator_pitch = "+2Hz"
            ssml_style = "general"
        elif rel_pos < 0.85:
            arc = "dramatic"
            narrator_rate = "-6%"
            narrator_pitch = "-3Hz"
            ssml_style = "serious"
        else:
            arc = "resolution"
            narrator_rate = "-4%"
            narrator_pitch = "-2Hz"
            ssml_style = "empathetic"

        # Split sentences and inject micro-pauses
        sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', para) if s.strip()]
        
        blocks.append({
            "block_index": i + 1,
            "type": "dialogue" if is_dialogue else "narration",
            "arc": arc,
            "ssml_style": ssml_style,
            "suggested_rate": narrator_rate,
            "suggested_pitch": narrator_pitch,
            "sentences": sentences,
            "full_text": para,
            "word_count": len(para.split())
        })

    return blocks


def format_chapter_for_engine(blocks: List[Dict[str, Any]], engine: str, chapter_title: str) -> Dict[str, Any]:
    """Formats the analyzed chapter blocks according to the specific TTS engine capabilities."""
    profile = MODEL_PROFILES.get(engine, MODEL_PROFILES["edge-tts"])
    
    if engine == "edge-tts":
        ssml_parts = []
        ssml_parts.append('<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xmlns:mstts="https://www.w3.org/2001/mstts" xml:lang="es-ES">')
        ssml_parts.append(f'  <!-- Chapter Title: {chapter_title} -->')
        ssml_parts.append('  <voice name="es-ES-AlvaroNeural">')
        ssml_parts.append(f'    <mstts:express-as style="serious"><prosody rate="-8%">{chapter_title}</prosody></mstts:express-as>')
        ssml_parts.append('    <break time="1200ms"/>')
        
        for b in blocks:
            voice_name = "es-ES-ElviraNeural" if b["type"] == "dialogue" else "es-ES-AlvaroNeural"
            ssml_parts.append(f'    <voice name="{voice_name}">')
            ssml_parts.append(f'      <mstts:express-as style="{b["ssml_style"]}">' if b["ssml_style"] != "general" else '')
            ssml_parts.append(f'        <prosody rate="{b["suggested_rate"]}" pitch="{b["suggested_pitch"]}">' if b["suggested_rate"] != "+0%" else '')
            
            for sentence in b["sentences"]:
                ssml_parts.append(f'          {sentence} <break time="300ms"/>')
                
            if b["suggested_rate"] != "+0%":
                ssml_parts.append('        </prosody>')
            if b["ssml_style"] != "general":
                ssml_parts.append('      </mstts:express-as>')
            ssml_parts.append('    </voice>')
            ssml_parts.append('    <break time="600ms"/>')
            
        ssml_parts.append('    <!-- Chapter Outro Room Tone -->')
        ssml_parts.append('    <break time="2000ms"/>')
        ssml_parts.append('  </voice>')
        ssml_parts.append('</speak>')
        
        clean_ssml = "\n".join([line for line in ssml_parts if line.strip()])
        return {"engine": engine, "script": clean_ssml, "format": "xml"}

    elif engine == "elevenlabs":
        el_parts = []
        el_parts.append(f"## {chapter_title}\n\n<break time=\"1.5s\" />\n\n")
        for b in blocks:
            stability = "0.65 (Narrator)" if b["type"] == "narration" else "0.35 (Expressive Dialogue)"
            el_parts.append(f"<!-- [Arc: {b['arc'].upper()} | Stability: {stability}] -->")
            joined = " ... ".join(b["sentences"])
            el_parts.append(joined)
            el_parts.append("\n\n<break time=\"0.8s\" />\n\n")
        el_parts.append("<break time=\"2.5s\" />\n")
        return {"engine": engine, "script": "".join(el_parts), "format": "txt"}

    elif engine == "kokoro":
        kk_parts = []
        kk_parts.append(f"{chapter_title} ... \n\n")
        for b in blocks:
            for s in b["sentences"]:
                # Kokoro punctuation pauses
                spaced = re.sub(r'([.!?])', r'\1 ... ', s)
                kk_parts.append(spaced)
            kk_parts.append("\n\n")
        return {"engine": engine, "script": "".join(kk_parts), "format": "txt"}

    elif engine == "chattts":
        chat_parts = []
        chat_parts.append(f"{chapter_title} [break_7] ")
        for b in blocks:
            cue = "[oral_1] " if b["type"] == "dialogue" else ""
            chat_parts.append(cue + " [break_3] ".join(b["sentences"]) + " [break_5] \n\n")
        return {"engine": engine, "script": "".join(chat_parts), "format": "txt"}

    else:
        # Clean text
        clean_lines = [chapter_title + "\n"]
        for b in blocks:
            clean_lines.append(b["full_text"])
        return {"engine": engine, "script": "\n\n".join(clean_lines), "format": "txt"}


def cmd_direct(args):
    """Direct a full book into structured, engine-optimized chapter scripts."""
    input_path = Path(args.file).resolve()
    if not input_path.exists():
        print(f"Error: File '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    chapters = parse_book_chapters(content)
    if not chapters:
        print("Error: No readable text found in manuscript.", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output_dir or input_path.parent / "audiobook_production").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "title": input_path.stem.replace("_", " ").title(),
        "source_file": str(input_path),
        "target_engine": args.engine,
        "language": args.lang,
        "total_chapters": len(chapters),
        "total_words": sum(c["word_count"] for c in chapters),
        "estimated_duration_minutes": round(sum(c["word_count"] for c in chapters) / WORDS_PER_MINUTE, 1),
        "chapters": []
    }

    print(f"\n🎧 Directing Audiobook: '{manifest['title']}'")
    print(f"   Target Engine: {args.engine.upper()} | Language: {args.lang}")
    print(f"   Total Chapters: {len(chapters)} | Total Words: {manifest['total_words']:,}")
    print(f"   Estimated Runtime: {manifest['estimated_duration_minutes']:.1f} minutes (~{manifest['estimated_duration_minutes']/60:.2f} hours)\n")

    for ch in chapters:
        blocks = analyze_scene_blocks(ch["raw_text"])
        formatted = format_chapter_for_engine(blocks, args.engine, ch["title"])
        
        ext = formatted["format"]
        ch_file_name = f"chapter_{ch['chapter_index']:02d}_{re.sub(r'[^a-zA-Z0-9_]', '_', ch['title'])[:25]}.{ext}"
        ch_path = out_dir / ch_file_name
        
        with open(ch_path, "w", encoding="utf-8") as out_f:
            out_f.write(formatted["script"])

        dialogue_count = sum(1 for b in blocks if b["type"] == "dialogue")
        narration_count = sum(1 for b in blocks if b["type"] == "narration")

        ch_meta = {
            "chapter_index": ch["chapter_index"],
            "title": ch["title"],
            "script_file": ch_file_name,
            "word_count": ch["word_count"],
            "estimated_minutes": round(ch["word_count"] / WORDS_PER_MINUTE, 1),
            "narration_blocks": narration_count,
            "dialogue_blocks": dialogue_count,
        }
        manifest["chapters"].append(ch_meta)

        print(f"  ✓ [{ch['chapter_index']:02d}] {ch['title']:<35} ({ch['word_count']:>5} words | ~{ch_meta['estimated_minutes']:>4.1f} min) -> {ch_file_name}")

    # Write manifest
    manifest_path = out_dir / "production_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2, ensure_ascii=False)

    print(f"\n✅ Production Direction Complete! Artifacts stored in: {out_dir}")
    print(f"   Production Manifest: {manifest_path}\n")


def cmd_estimate(args):
    """Calculates word count, runtime, ACX standards, and cost estimates across engines."""
    input_path = Path(args.file).resolve()
    if not input_path.exists():
        print(f"Error: File '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    chapters = parse_book_chapters(content)
    total_words = sum(c["word_count"] for c in chapters)
    total_chars = sum(len(c["raw_text"]) for c in chapters)
    total_minutes = total_words / WORDS_PER_MINUTE
    total_hours = total_minutes / 60.0

    print(f"\n📊 --- AUDIOBOOK PRODUCTION ESTIMATION MATRIX ---")
    print(f"• Document: {input_path.name}")
    print(f"• Chapters Detected: {len(chapters)}")
    print(f"• Total Words: {total_words:,} words")
    print(f"• Total Characters: {total_chars:,} chars")
    print(f"• Estimated Spoken Runtime: {total_minutes:.1f} minutes ({total_hours:.2f} hours)")
    print(f"• Audible/ACX Standard Chunking: 0.75s Head Room | 2.5s Tail Room | -3dB Peak")
    print("\n💰 Cost Comparison Across Engines:")
    print("-" * 75)
    print(f"{'Engine / Platform':<25} | {'Tier':<10} | {'Estimated Cost':<15} | {'Feasibility'}")
    print("-" * 75)
    for eng_name, eng_meta in MODEL_PROFILES.items():
        cost = (total_chars / 10000.0) * eng_meta["cost_per_10k_chars"]
        feasibility = "Recommended (100% Free)" if eng_meta["tier"] == "free" else "Commercial API"
        print(f"{eng_name.capitalize():<25} | {eng_meta['tier'].upper():<10} | ${cost:>10.2f} USD | {feasibility}")
    print("-" * 75 + "\n")


def cmd_synthesize_chapter(args):
    """Synthesizes a full chapter script using Edge-TTS with seamless binary concatenation."""
    edge_tts_bin = shutil.which("edge-tts")
    if not edge_tts_bin:
        print("Error: 'edge-tts' not found. Install with: uv tool install edge-tts", file=sys.stderr)
        sys.exit(1)

    script_path = Path(args.script).resolve()
    if not script_path.exists():
        print(f"Error: Script file '{script_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(script_path, "r", encoding="utf-8") as f:
        script_content = f.read()

    output_audio = Path(args.output or script_path.with_suffix(".mp3")).resolve()
    output_audio.parent.mkdir(parents=True, exist_ok=True)

    # Chunk script if text exceeds 1800 chars to avoid socket drops
    chunks = []
    if script_content.strip().startswith("<speak"):
        # Synthesize SSML directly via --file flag
        cmd = [edge_tts_bin, "--file", str(script_path), "--write-media", str(output_audio)]
        print(f"🎙️ Synthesizing Chapter SSML -> {output_audio.name}...")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            size_mb = output_audio.stat().st_size / (1024 * 1024)
            print(f"✅ Chapter Audio Generated: {output_audio} ({size_mb:.2f} MB)\n")
            return
        except subprocess.CalledProcessError as e:
            print(f"SSML synthesis failed: {e.stderr}. Falling back to plain chunking...", file=sys.stderr)

    # Plain text chunking and synthesis
    paragraphs = [p.strip() for p in script_content.split("\n\n") if p.strip()]
    voice = args.voice or "es-ES-AlvaroNeural"
    temp_dir = output_audio.parent / f"_temp_{output_audio.stem}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    temp_files = []
    print(f"🎙️ Synthesizing {len(paragraphs)} audio segments for '{output_audio.name}'...")

    for i, para in enumerate(paragraphs):
        seg_file = temp_dir / f"seg_{i:04d}.mp3"
        cmd = [
            edge_tts_bin,
            "--voice", voice,
            "--text", para,
            "--write-media", str(seg_file)
        ]
        if args.rate:
            cmd.extend(["--rate", args.rate])
        if args.pitch:
            cmd.extend(["--pitch", args.pitch])

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            temp_files.append(seg_file)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed on segment {i}: {e.stderr}", file=sys.stderr)

    # Concatenate MP3 binary frames directly
    print(f"🔗 Concatenating {len(temp_files)} audio chunks into final master...")
    with open(output_audio, "wb") as master_f:
        for seg in temp_files:
            with open(seg, "rb") as sf:
                master_f.write(sf.read())

    # Cleanup temp
    shutil.rmtree(temp_dir, ignore_errors=True)
    size_mb = output_audio.stat().st_size / (1024 * 1024)
    print(f"✅ Success! Master Audiobook Chapter Audio: {output_audio} ({size_mb:.2f} MB)\n")


def main():
    parser = argparse.ArgumentParser(
        description="Audiobook Producer - Long-form narration direction and synthesis engine."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: direct
    p_dir = subparsers.add_parser("direct", help="Direct a manuscript into engine-tailored production scripts.")
    p_dir.add_argument("--file", "-f", required=True, help="Path to book / document (Markdown or text).")
    p_dir.add_argument("--engine", "-e", choices=list(MODEL_PROFILES.keys()), default="edge-tts", help="Target TTS model.")
    p_dir.add_argument("--lang", "-l", choices=["es", "en", "fr", "de", "it", "pt"], default="es", help="Language code.")
    p_dir.add_argument("--output-dir", "-o", help="Output directory for chapter scripts.")
    p_dir.set_defaults(func=cmd_direct)

    # Subcommand: estimate
    p_est = subparsers.add_parser("estimate", help="Estimate word count, audio runtime, and engine costs.")
    p_est.add_argument("--file", "-f", required=True, help="Path to book or document.")
    p_est.set_defaults(func=cmd_estimate)

    # Subcommand: synthesize-chapter
    p_syn = subparsers.add_parser("synthesize-chapter", help="Synthesize full chapter audio using Edge-TTS.")
    p_syn.add_argument("--script", "-s", required=True, help="Path to chapter script or SSML file.")
    p_syn.add_argument("--output", "-o", help="Path to destination .mp3 audio file.")
    p_syn.add_argument("--voice", "-v", help="Neural voice name.")
    p_syn.add_argument("--rate", type=str, help="Speed adjustment (e.g. -5%%).")
    p_syn.add_argument("--pitch", type=str, help="Pitch adjustment (e.g. -2Hz).")
    p_syn.set_defaults(func=cmd_synthesize_chapter)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
tts_studio.py - Script Crafting, Emotion Injection & Multi-Engine TTS Studio

CLI utility to:
1. Transform raw text into emotion-infused, human-cadence scripts tailored for TTS engines.
2. Support markup formats: SSML, ChatTTS brackets, Bark tags, ElevenLabs punctuation, Kokoro pacing.
3. Synthesize speech via free Edge-TTS neural voices (zero cost, no API keys).
4. List voices by language and gender.
5. Compare free vs paid TTS engines and models.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EMOTION_STYLES = {
    "cheerful": {
        "ssml_style": "cheerful",
        "chattts_cues": ["[laugh] ", "[speed_7] "],
        "bark_cues": ["[laughs] ", ""],
        "elevenlabs_tone": "Upbeat, smiling tone with higher pitch variation and brisk cadence.",
        "pitch": "+5Hz",
        "rate": "+10%",
        "pause_factor": 0.8,
    },
    "empathetic": {
        "ssml_style": "empathetic",
        "chattts_cues": ["[oral_2] ", "[break_4] "],
        "bark_cues": ["[sighs] ", ""],
        "elevenlabs_tone": "Warm, gentle tone with softened plosives and tender, measured pauses.",
        "pitch": "-2Hz",
        "rate": "-8%",
        "pause_factor": 1.2,
    },
    "dramatic": {
        "ssml_style": "serious",
        "chattts_cues": ["[break_6] ", "[speed_4] "],
        "bark_cues": ["... ", "— "],
        "elevenlabs_tone": "Intense, weighty cadence with prolonged pauses before pivotal words.",
        "pitch": "-5Hz",
        "rate": "-12%",
        "pause_factor": 1.5,
    },
    "suspenseful": {
        "ssml_style": "whispering",
        "chattts_cues": ["[break_7] ", "[speed_3] "],
        "bark_cues": ["[gasps] ", "... "],
        "elevenlabs_tone": "Hushed, breathy delivery with sudden micro-pauses building tension.",
        "pitch": "-3Hz",
        "rate": "-15%",
        "pause_factor": 1.4,
    },
    "authoritative": {
        "ssml_style": "calm",
        "chattts_cues": ["[speed_5] ", "[break_2] "],
        "bark_cues": ["", ""],
        "elevenlabs_tone": "Firm, crisp consonants, steady downward intonations at sentence ends.",
        "pitch": "-2Hz",
        "rate": "-2%",
        "pause_factor": 1.0,
    },
    "whisper": {
        "ssml_style": "whispering",
        "chattts_cues": ["[oral_0] ", "[break_5] "],
        "bark_cues": ["[whispers] ", ""],
        "elevenlabs_tone": "Soft breath-driven phonation, lower dynamic range, close microphone proximity.",
        "pitch": "-4Hz",
        "rate": "-10%",
        "pause_factor": 1.3,
    },
    "excited": {
        "ssml_style": "excited",
        "chattts_cues": ["[laugh] ", "[speed_8] "],
        "bark_cues": ["[laughs] ", "!"],
        "elevenlabs_tone": "High vocal energy, fast onset, bright pitch inflections.",
        "pitch": "+8Hz",
        "rate": "+18%",
        "pause_factor": 0.7,
    },
    "conversational": {
        "ssml_style": "chat",
        "chattts_cues": ["[oral_5] ", "[break_3] "],
        "bark_cues": ["", ""],
        "elevenlabs_tone": "Natural colloquial pacing, fluid transitions, subtle human hesitation marks.",
        "pitch": "+0Hz",
        "rate": "+0%",
        "pause_factor": 1.0,
    },
    "neutral": {
        "ssml_style": "general",
        "chattts_cues": ["", ""],
        "bark_cues": ["", ""],
        "elevenlabs_tone": "Balanced, objective informational delivery.",
        "pitch": "+0Hz",
        "rate": "+0%",
        "pause_factor": 1.0,
    }
}

RECOMMENDED_VOICES = {
    "es": [
        {"name": "es-ES-AlvaroNeural", "gender": "Male", "locale": "Spain", "description": "Clear, professional, rich narrative baritone."},
        {"name": "es-ES-ElviraNeural", "gender": "Female", "locale": "Spain", "description": "Expressive, warm, excellent for storytelling and education."},
        {"name": "es-MX-DaliaNeural", "gender": "Female", "locale": "Mexico", "description": "Friendly, approachable, modern Latin American Spanish."},
        {"name": "es-MX-JorgeNeural", "gender": "Male", "locale": "Mexico", "description": "Confident, deep, widely used in corporate and commercial voiceovers."},
        {"name": "es-US-AlonsoNeural", "gender": "Male", "locale": "US-Spanish", "description": "Bilingual natural delivery, balanced tone."}
    ],
    "en": [
        {"name": "en-US-JennyNeural", "gender": "Female", "locale": "US", "description": "Extremely versatile, natural conversational, supports multiple emotion styles."},
        {"name": "en-US-GuyNeural", "gender": "Male", "locale": "US", "description": "Classic male narrator, authoritative, warm, news and audiobooks."},
        {"name": "en-US-AriaNeural", "gender": "Female", "locale": "US", "description": "Dynamic, vibrant, expressive storytelling and assistant voice."},
        {"name": "en-US-ChristopherNeural", "gender": "Male", "locale": "US", "description": "Deep documentary narrator, calm, reflective."},
        {"name": "en-GB-SoniaNeural", "gender": "Female", "locale": "UK", "description": "Refined British RP accent, clear, elegant delivery."},
        {"name": "en-GB-RyanNeural", "gender": "Male", "locale": "UK", "description": "Approachable British narrator, conversational and friendly."}
    ]
}

ENGINE_COMPARISON = [
    {
        "Tier": "FREE / Open Source",
        "Engine": "Microsoft Edge TTS (edge-tts)",
        "Type": "Cloud API (No auth required)",
        "Pricing": "$0.00 (Unlimited fair-use)",
        "Key Strengths": "100+ languages, 400+ neural voices, pitch/rate control, zero setup, rock-solid reliability.",
        "Emotion Control": "Via SSML (prosody, rate, pitch, break time) and style-capable voices (e.g. Jenny, Aria).",
        "Best For": "Everyday voiceovers, video narration, quick drafts, headless Linux pipelines."
    },
    {
        "Tier": "FREE / Open Source",
        "Engine": "Kokoro-82M",
        "Type": "Local Model (82M parameters)",
        "Pricing": "$0.00 (Apache 2.0 open weights)",
        "Key Strengths": "Runs on CPU in real-time, exceptional audio quality rivaling 1B+ models, phoneme accuracy.",
        "Emotion Control": "Punctuation shaping, phoneme guides, voice mixing across blends.",
        "Best For": "Private local execution, embedded apps, offline voice synthesis, fast podcast production."
    },
    {
        "Tier": "FREE / Open Source",
        "Engine": "ChatTTS",
        "Type": "Local Model (Conversational)",
        "Pricing": "$0.00 (Open Source)",
        "Key Strengths": "Conversational realism, laughter insertion [laugh], breathing [oral], natural hesitations.",
        "Emotion Control": "Direct bracket prompt cues ([oral_1], [break_4], [laugh]), seed selection for personality.",
        "Best For": "Dialogue, podcast co-hosts, conversational voice bots, natural comedy or drama."
    },
    {
        "Tier": "FREE / Open Source",
        "Engine": "Piper TTS",
        "Type": "Local Neural Engine (C++ / ONNX)",
        "Pricing": "$0.00 (MIT / Open Source)",
        "Key Strengths": "Runs with near-zero RAM (<50MB) on Raspberry Pi/laptops, ultra low latency (<20ms).",
        "Emotion Control": "Phoneme length, speaking rate, noise scales.",
        "Best For": "Real-time robotics, home automation, lightweight IoT, screen readers."
    },
    {
        "Tier": "FREE / Open Source",
        "Engine": "Bark (Suno) / Parler-TTS",
        "Type": "Local Audio Diffusion/Transformer",
        "Pricing": "$0.00 (Open Source)",
        "Key Strengths": "Rich non-speech acoustics (crying, laughter, music generation, whispers), promptable timbre.",
        "Emotion Control": "Text description prompts ('A speaker who is breathless and terrified...') + audio cues.",
        "Best For": "Sound design, audio drama, extreme emotive acting, experimental voice styling."
    },
    {
        "Tier": "PAID / Hosted",
        "Engine": "ElevenLabs (Turbo v2.5 / Multilingual)",
        "Type": "Cloud API (Proprietary)",
        "Pricing": "~$0.30 - $0.50 / 10k chars",
        "Key Strengths": "Gold standard in vocal nuance, emotional range, realistic micro-breaths, instant voice cloning.",
        "Emotion Control": "Voice settings slider (Stability, Similarity, Style Exaggeration), SSML breaks, punctuation cues.",
        "Best For": "High-end commercial voiceovers, cinematic audiobooks, hero advertising, authentic voice cloning."
    },
    {
        "Tier": "PAID / Hosted",
        "Engine": "Cartesia Sonic",
        "Type": "Cloud API (State Space / Mamba)",
        "Pricing": "~$0.05 - $0.08 / 1k chars",
        "Key Strengths": "Ultra-low latency (~90-130ms first chunk), streaming real-time conversational agents.",
        "Emotion Control": "Controllable emotion tags (speed, emotion vector, pitch).",
        "Best For": "Real-time voice agents, telephonic AI, live customer interaction."
    },
    {
        "Tier": "PAID / Hosted",
        "Engine": "OpenAI Audio (tts-1 / tts-1-hd / gpt-4o-audio)",
        "Type": "Cloud API",
        "Pricing": "$0.015 - $0.030 / 1k chars",
        "Key Strengths": "Integrated into OpenAI ecosystem, consistent clean studio tone, seamless JSON responses.",
        "Emotion Control": "Driven by prompt text context and punctuation; limited granular SSML.",
        "Best For": "General assistant feedback, simple app narration, multi-modal GPT workflows."
    },
    {
        "Tier": "PAID / Hosted",
        "Engine": "Deepgram Aura",
        "Type": "Cloud API (High Throughput)",
        "Pricing": "$0.015 / 1k chars",
        "Key Strengths": "Tuned specifically for conversational agents paired with Deepgram Nova STT.",
        "Emotion Control": "Punctuation and cadence control.",
        "Best For": "Scalable call centers, agentic dialog loops."
    }
]


def humanize_text_cadence(text: str, emotion: str, target: str) -> str:
    """
    Analyzes raw text, adds breath points, breaks down stiff run-on sentences,
    and inserts emotion-specific prosody markers according to the target engine.
    """
    style = EMOTION_STYLES.get(emotion, EMOTION_STYLES["conversational"])
    
    # Clean whitespace
    text = re.sub(r'\s+', ' ', text.strip())
    
    # 1. Break long compound sentences with thoughtful punctuation (em-dashes, ellipses)
    # Stiff sentences with commas before conjunctions get converted into breath marks
    text = re.sub(r',\s+(pero|sin embargo|no obstante|porque|ya que)\b', r'... \1', text, flags=re.IGNORECASE)
    text = re.sub(r',\s+(but|however|because|although|yet)\b', r'... \1', text, flags=re.IGNORECASE)
    
    # Replace colons and semicolons with em-dashes for natural spoken suspense
    text = re.sub(r'\s*;\s*', ' — ', text)
    text = re.sub(r'\s*:\s*', ' — ', text)

    lines = [p.strip() for p in re.split(r'(?<=[.!?])\s+', text) if p.strip()]
    
    if target == "ssml":
        ssml_lines = []
        ssml_lines.append('<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xmlns:mstts="https://www.w3.org/2001/mstts" xml:lang="en-US">')
        ssml_lines.append(f'  <mstts:express-as style="{style["ssml_style"]}">' if style["ssml_style"] != "general" else '')
        ssml_lines.append(f'    <prosody rate="{style["rate"]}" pitch="{style["pitch"]}">' if style["rate"] != "+0%" or style["pitch"] != "+0Hz" else '')
        
        for i, line in enumerate(lines):
            # Add micro pause between distinct ideas
            if i > 0 and i % 2 == 0:
                ssml_lines.append(f'      {line} <break time="450ms"/>')
            else:
                ssml_lines.append(f'      {line} <break time="250ms"/>')
                
        if style["rate"] != "+0%" or style["pitch"] != "+0Hz":
            ssml_lines.append('    </prosody>')
        if style["ssml_style"] != "general":
            ssml_lines.append('  </mstts:express-as>')
        ssml_lines.append('</speak>')
        return "\n".join([line for line in ssml_lines if line])

    elif target == "chattts":
        cues = style["chattts_cues"]
        result = []
        result.append(cues[0]) # Initial emotion trigger
        for i, line in enumerate(lines):
            result.append(line)
            if i < len(lines) - 1:
                # Add natural conversational pause tag
                break_tag = "[break_4]" if (i % 2 == 0) else "[break_2]"
                result.append(f" {break_tag} ")
        return "".join(result).strip()

    elif target == "bark":
        bark_prefix = style["bark_cues"][0]
        bark_lines = []
        if bark_prefix:
            bark_lines.append(bark_prefix)
        for i, line in enumerate(lines):
            # Emphasis with caps or micro-pauses
            bark_lines.append(line)
            if i < len(lines) - 1:
                bark_lines.append("... ")
        return " ".join(bark_lines).strip()

    elif target == "elevenlabs":
        # ElevenLabs responds best to punctuation pacing (ellipses, commas, em-dashes, and occasional breath indicators)
        el_parts = []
        for i, line in enumerate(lines):
            el_parts.append(line)
            if i < len(lines) - 1:
                if emotion in ["dramatic", "suspenseful"]:
                    el_parts.append("\n\n<break time=\"1.0s\" />\n\n")
                elif emotion in ["empathetic", "conversational"]:
                    el_parts.append(" ... ")
                else:
                    el_parts.append("\n\n")
        return "".join(el_parts).strip()

    elif target == "kokoro":
        # Kokoro excels when clauses are separated by clear commas or ellipses to let the neural vocoder breathe
        kk_parts = []
        for line in lines:
            line_spaced = re.sub(r'([.!?])', r'\1 ', line)
            kk_parts.append(line_spaced.strip())
        return " ... ".join(kk_parts)

    else: # Default clean spoken format
        clean_parts = []
        for i, line in enumerate(lines):
            clean_parts.append(line)
            if i < len(lines) - 1:
                clean_parts.append(" ... ")
        return "".join(clean_parts)


def cmd_format_script(args):
    """Format raw text into an emotion-infused script."""
    input_text = ""
    if args.text:
        input_text = args.text
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            input_text = f.read()
    else:
        print("Error: Provide --text or --file.", file=sys.stderr)
        sys.exit(1)

    formatted = humanize_text_cadence(input_text, args.emotion, args.target)
    
    style_meta = EMOTION_STYLES.get(args.emotion, EMOTION_STYLES["conversational"])
    
    if args.json:
        out = {
            "target_engine": args.target,
            "emotion": args.emotion,
            "rate_adjustment": style_meta["rate"],
            "pitch_adjustment": style_meta["pitch"],
            "vocal_direction": style_meta["elevenlabs_tone"],
            "formatted_script": formatted
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"\n🎙️ --- VOCAL DIRECTION [{args.emotion.upper()}] ---")
        print(f"• Pacing / Rate: {style_meta['rate']} | Pitch: {style_meta['pitch']}")
        print(f"• Human Tone Guidance: {style_meta['elevenlabs_tone']}")
        print(f"• Target Markup: {args.target}")
        print("\n📝 --- FORMATTED SCRIPT ---")
        print(formatted)
        print("----------------------------\n")


def cmd_synthesize(args):
    """Synthesize speech using free Edge-TTS voices."""
    # Check if edge-tts is in PATH
    edge_tts_bin = shutil.which("edge-tts")
    if not edge_tts_bin:
        print("Error: 'edge-tts' executable not found in PATH.", file=sys.stderr)
        print("Install it with: uv tool install edge-tts", file=sys.stderr)
        sys.exit(1)

    text_to_speak = args.text
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text_to_speak = f.read()

    if not text_to_speak:
        print("Error: No text provided to synthesize.", file=sys.stderr)
        sys.exit(1)

    # Determine voice
    voice = args.voice
    if not voice:
        # Pick sensible default
        voice = "es-ES-AlvaroNeural" if args.lang == "es" else "en-US-JennyNeural"

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        edge_tts_bin,
        "--voice", voice,
        "--write-media", str(output_path)
    ]

    if args.rate:
        cmd.extend(["--rate", args.rate])
    if args.pitch:
        cmd.extend(["--pitch", args.pitch])
    if args.volume:
        cmd.extend(["--volume", args.volume])

    # If text is SSML, pass --ssml (if edge-tts supports file or raw text)
    if text_to_speak.strip().startswith("<speak"):
        cmd.extend(["--ssml", text_to_speak])
    else:
        cmd.extend(["--text", text_to_speak])

    print(f"🔊 Synthesizing with voice: {voice}...")
    print(f"   Rate: {args.rate or 'default'} | Pitch: {args.pitch or 'default'}")
    print(f"   Destination: {output_path}")

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        size_kb = output_path.stat().st_size / 1024
        print(f"✅ Success! Generated audio file: {output_path} ({size_kb:.1f} KB)")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to synthesize audio: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def cmd_list_voices(args):
    """List recommended or all available neural voices."""
    edge_tts_bin = shutil.which("edge-tts")
    
    if args.all and edge_tts_bin:
        cmd = [edge_tts_bin, "--list-voices"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        lines = res.stdout.splitlines()
        
        filtered = []
        for line in lines:
            if args.lang and not line.lower().startswith(args.lang.lower()):
                continue
            if args.gender and args.gender.lower() not in line.lower():
                continue
            filtered.append(line)
            
        print("\n".join(filtered[:args.limit]))
        return

    # Recommended curated voices
    print("\n🌟 --- CURATED HIGH-QUALITY NEURAL VOICES (100% FREE) ---\n")
    langs = [args.lang] if args.lang and args.lang in RECOMMENDED_VOICES else list(RECOMMENDED_VOICES.keys())
    
    for lang in langs:
        voices = RECOMMENDED_VOICES.get(lang, [])
        print(f"[{lang.upper()}] Recommended Voices:")
        for v in voices:
            if args.gender and v["gender"].lower() != args.gender.lower():
                continue
            print(f"  • {v['name']:<25} ({v['gender']}, {v['locale']}): {v['description']}")
        print()


def cmd_compare(args):
    """Output engine comparison table."""
    print("\n📊 --- COMPREHENSIVE TTS ENGINE & MODEL COMPARISON ---\n")
    print(f"{'Tier':<20} | {'Engine':<32} | {'Pricing':<24} | {'Best For':<30}")
    print("-" * 115)
    for row in ENGINE_COMPARISON:
        print(f"{row['Tier']:<20} | {row['Engine']:<32} | {row['Pricing']:<24} | {row['Best For']:<30}")
    print("\n💡 Key takeaway: Start with Edge-TTS or Kokoro-82M (0 cost, natural quality).")
    print("   Upgrade to ElevenLabs only when extreme voice cloning or actor nuance is required.\n")


def main():
    parser = argparse.ArgumentParser(
        description="TTS Voice Studio - Convert text to natural emotional voiceover scripts and synthesize audio."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: format-script
    p_format = subparsers.add_parser("format-script", help="Turn raw text into emotion-infused spoken script.")
    p_format.add_argument("--text", "-t", type=str, help="Text to convert.")
    p_format.add_argument("--file", "-f", type=str, help="Path to text file.")
    p_format.add_argument(
        "--target", choices=["ssml", "edge-tts", "chattts", "bark", "elevenlabs", "kokoro", "clean"],
        default="elevenlabs", help="Target markup format."
    )
    p_format.add_argument(
        "--emotion", choices=list(EMOTION_STYLES.keys()),
        default="conversational", help="Target emotion."
    )
    p_format.add_argument("--json", action="store_true", help="Output as JSON.")
    p_format.set_defaults(func=cmd_format_script)

    # Subcommand: synthesize
    p_synth = subparsers.add_parser("synthesize", help="Generate audio using free Edge-TTS neural voices.")
    p_synth.add_argument("--text", "-t", type=str, help="Text to speak.")
    p_synth.add_argument("--file", "-f", type=str, help="Path to text or SSML file.")
    p_synth.add_argument("--voice", "-v", type=str, help="Neural voice name (e.g. es-ES-AlvaroNeural).")
    p_synth.add_argument("--lang", choices=["es", "en"], default="es", help="Default language fallback.")
    p_synth.add_argument("--output", "-o", default="output.mp3", help="Output audio file path (.mp3).")
    p_synth.add_argument("--rate", type=str, help="Speed adjustment (e.g. +10%%, -15%%).")
    p_synth.add_argument("--pitch", type=str, help="Pitch adjustment (e.g. +5Hz, -5Hz).")
    p_synth.add_argument("--volume", type=str, help="Volume adjustment (e.g. +0%%, -10%%).")
    p_synth.set_defaults(func=cmd_synthesize)

    # Subcommand: list-voices
    p_voices = subparsers.add_parser("list-voices", help="List free neural voices.")
    p_voices.add_argument("--lang", type=str, help="Filter by language code (e.g. es, en, fr).")
    p_voices.add_argument("--gender", choices=["male", "female"], help="Filter by gender.")
    p_voices.add_argument("--all", action="store_true", help="Query all 400+ voices from Edge-TTS.")
    p_voices.add_argument("--limit", type=int, default=40, help="Max voices to display with --all.")
    p_voices.set_defaults(func=cmd_list_voices)

    # Subcommand: compare-engines
    p_comp = subparsers.add_parser("compare-engines", help="Compare free vs paid TTS engines.")
    p_comp.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

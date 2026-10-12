#!/usr/bin/env python3
"""
Locution & Diction Processor for Neural TTS (Edge-TTS, Kokoro, ElevenLabs, Gemini 3.8)
Transforms raw written text into broadcast-grade spoken scripts with phonetic normalization,
phonic breath chunking, acoustic punctuation, dynamic prosody curves, and multi-engine export.
"""

import re
import os
import sys
import json
import argparse
from typing import Dict, List, Any

# Number words mappings for Spanish and English
ES_ONES = {
    0: "cero", 1: "un", 2: "dos", 3: "tres", 4: "cuatro", 5: "cinco",
    6: "seis", 7: "siete", 8: "ocho", 9: "nueve", 10: "diez",
    11: "once", 12: "doce", 13: "trece", 14: "catorce", 15: "quince",
    16: "dieciséis", 17: "diecisiete", 18: "dieciocho", 19: "diecinueve",
    20: "veinte", 21: "veintiún", 22: "veintidós", 23: "veintitrés",
    24: "veinticuatro", 25: "veinticinco", 26: "veintiséis", 27: "veintisiete",
    28: "veintiocho", 29: "veintinueve"
}
ES_TENS = {
    30: "treinta", 40: "cuarenta", 50: "cincuenta", 60: "sesenta",
    70: "setenta", 80: "ochenta", 90: "noventa"
}

def number_to_words_es(n: int) -> str:
    """Converts integers up to 1,000,000 into spoken Spanish words."""
    if n in ES_ONES:
        return ES_ONES[n]
    if n < 100:
        ten = (n // 10) * 10
        rem = n % 10
        return f"{ES_TENS[ten]} y {ES_ONES[rem]}" if rem else ES_TENS[ten]
    if n == 100:
        return "cien"
    if n < 200:
        return f"ciento {number_to_words_es(n - 100)}"
    if n < 1000:
        hundreds = {
            2: "doscientos", 3: "trescientos", 4: "cuatrocientos",
            5: "quinientos", 6: "seiscientos", 7: "setecientos",
            8: "ochocientos", 9: "novecientos"
        }
        h = n // 100
        rem = n % 100
        return f"{hundreds[h]} {number_to_words_es(rem)}" if rem else hundreds[h]
    if n == 1000:
        return "mil"
    if n < 2000:
        return f"mil {number_to_words_es(n - 1000)}"
    if n < 1000000:
        thousands = n // 1000
        rem = n % 1000
        th_word = f"{number_to_words_es(thousands)} mil"
        return f"{th_word} {number_to_words_es(rem)}" if rem else th_word
    return str(n)


class LocutionDictionEngine:
    """Transforms written prose into acoustic locution scripts."""

    COMMON_ACRONYMS = ["FBI", "CIA", "NASA", "OTAN", "AI", "GPU", "CPU", "RAM", "NFT", "API", "USA"]

    ABBREVIATIONS_ES = {
        r"\bDr\.\b": "Doctor",
        r"\bDra\.\b": "Doctora",
        r"\bSr\.\b": "Señor",
        r"\bSra\.\b": "Señora",
        r"\bEE\.UU\.\b": "Estados Unidos",
        r"\betc\.\b": "etcétera",
        r"\bvs\.\b": "versus",
        r"\bpág\.\b": "página",
        r"\bej\.\b": "por ejemplo",
    }

    PROSODY_PRESETS = {
        "HYPE": {"rate": "+14%", "pitch": "+5Hz", "volume": "+5%", "style": "excited, energetic"},
        "SHOCK": {"rate": "+10%", "pitch": "+6Hz", "volume": "+6%", "style": "urgent, alarmed"},
        "SUSPENSE": {"rate": "-10%", "pitch": "-3Hz", "volume": "-2%", "style": "whispered, mysterious"},
        "STORYTELLING": {"rate": "+2%", "pitch": "+0Hz", "volume": "+0%", "style": "calm, narrative"},
        "EMPATHY": {"rate": "-6%", "pitch": "-2Hz", "volume": "-3%", "style": "warm, gentle"},
        "CTA": {"rate": "+6%", "pitch": "+2Hz", "volume": "+4%", "style": "authoritative, engaging"},
        "NEUTRAL": {"rate": "+0%", "pitch": "+0Hz", "volume": "+0%", "style": "natural, balanced"}
    }

    @classmethod
    def normalize_phonetics_es(cls, text: str) -> str:
        """Expands abbreviations, numbers, and currencies into natural spoken Spanish."""
        out = text

        # 1. Abbreviations
        for pattern, repl in cls.ABBREVIATIONS_ES.items():
            out = re.sub(pattern, repl, out, flags=re.IGNORECASE)

        # 2. Currencies (e.g. $1,500,000 -> un millón y medio de dólares, $500 -> 500 dólares)
        out = re.sub(r"\$(\d+)\s*millones", r"\1 millones de dólares", out)
        out = re.sub(r"\$(\d+)", r"\1 dólares", out)
        out = re.sub(r"€(\d+)", r"\1 euros", out)

        # 3. Percentages (e.g. 50% -> cincuenta por ciento)
        out = re.sub(r"(\d+)%", r"\1 por ciento", out)

        # 4. Units
        out = re.sub(r"(\d+)\s*km/h\b", r"\1 kilómetros por hora", out, flags=re.IGNORECASE)
        out = re.sub(r"(\d+)\s*km\b", r"\1 kilómetros", out, flags=re.IGNORECASE)
        out = re.sub(r"(\d+)\s*kg\b", r"\1 kilogramos", out, flags=re.IGNORECASE)

        # 5. Acronyms (Hyphenate spelling where needed)
        for acr in ["FBI", "CIA", "GPU", "CPU", "API", "NFT"]:
            out = re.sub(rf"\b{acr}\b", "-".join(list(acr)), out)

        # 6. Numbers into words (for single and double digit integers in prose)
        def replace_num(match):
            val = int(match.group(0))
            if val <= 100:
                return number_to_words_es(val)
            return match.group(0)

        out = re.sub(r"\b\d{1,2}\b", replace_num, out)
        return out

    @classmethod
    def apply_acoustic_punctuation_es(cls, text: str) -> str:
        """Applies phonic groups, suspense pauses, and inverted Hispanic punctuation."""
        lines = text.splitlines()
        processed_lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Ensure opening ¡ and ¿ for sentences ending in ! or ?
            if line.endswith("!") and not line.startswith("¡"):
                line = "¡" + line
            if line.endswith("?") and not line.startswith("¿"):
                line = "¿" + line

            # Convert weak parenthetical dashes into acoustic em-dashes
            line = re.sub(r"\s+-\s+", " — ", line)

            # Insert dramatic suspense ellipses before reveal connectors
            reveal_triggers = [
                r"\by el ganador fue\b",
                r"\by la respuesta es\b",
                r"\bpero detrás de todo\b",
                r"\bhasta que de pronto\b"
            ]
            for trig in reveal_triggers:
                line = re.sub(trig, r"... \g<0>", line, flags=re.IGNORECASE)

            processed_lines.append(line)

        return "\n".join(processed_lines)

    @classmethod
    def chunk_phonic_breath_groups(cls, text: str, max_words: int = 10) -> str:
        """Breaks run-on sentences into 5-10 word phonic breath units."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        result_chunks = []

        for sent in sentences:
            words = sent.split()
            if len(words) <= max_words:
                result_chunks.append(sent)
                continue

            # Split sentence at commas, semicolons, or conjunctions
            subparts = re.split(r"([,;]\s+|\s+(?:pero|sin embargo|aunque|porque)\s+)", sent)
            current_chunk = []
            for part in subparts:
                current_chunk.append(part)
                token_count = len(" ".join(current_chunk).split())
                if token_count >= max_words // 2:
                    result_chunks.append("".join(current_chunk).strip())
                    current_chunk = []
            if current_chunk:
                result_chunks.append("".join(current_chunk).strip())

        return " ".join(result_chunks)

    @classmethod
    def compile_for_engine(cls, text: str, engine: str, emotion: str = "HYPE", voice: str = "es-MX-JorgeNeural") -> Any:
        """Compiles humanized text into the target TTS engine's payload format."""
        emotion_cfg = cls.PROSODY_PRESETS.get(emotion.upper(), cls.PROSODY_PRESETS["NEUTRAL"])
        normalized = cls.normalize_phonetics_es(text)
        punctuated = cls.apply_acoustic_punctuation_es(normalized)
        chunked = cls.chunk_phonic_breath_groups(punctuated)

        if engine.lower() == "edge_tts":
            return {
                "engine": "edge_tts",
                "voice": voice,
                "rate": emotion_cfg["rate"],
                "pitch": emotion_cfg["pitch"],
                "volume": emotion_cfg["volume"],
                "tagged_script": f"[EMOTION: {emotion.upper()}]\n{chunked}"
            }

        elif engine.lower() == "gemini_tts":
            # Convert ellipses to <short pause> and format for Gemini Enterprise
            gemini_text = chunked.replace("...", "... <short pause> ")
            return {
                "engine": "gemini_tts",
                "contents": [{
                    "role": "user",
                    "parts": [{
                        "text": gemini_text,
                        "speechMetadata": {"style": emotion_cfg["style"]}
                    }]
                }],
                "generationConfig": {
                    "responseModalities": ["AUDIO"],
                    "speechConfig": {"voiceConfig": {"voice": "Kore"}}
                }
            }

        elif engine.lower() == "elevenlabs":
            eleven_text = chunked
            if emotion.upper() == "SUSPENSE":
                eleven_text = f"[whispers] {eleven_text}"
            elif emotion.upper() == "SHOCK":
                eleven_text = f"[gasps] {eleven_text}"
            return {
                "engine": "elevenlabs",
                "text": eleven_text,
                "voice_settings": {
                    "stability": 0.40 if emotion.upper() in ["HYPE", "SHOCK", "SUSPENSE"] else 0.75,
                    "similarity_boost": 0.85,
                    "style": 0.12,
                    "use_speaker_boost": True
                }
            }

        elif engine.lower() == "kokoro":
            return {
                "engine": "kokoro",
                "text": chunked,
                "speed": 0.95 if emotion.upper() == "SUSPENSE" else 1.05,
                "voice": "ef_dora" if voice.startswith("es") else "af_bella"
            }

        elif engine.lower() == "chattts":
            chat_text = chunked
            if emotion.upper() in ["HYPE", "CTA"]:
                chat_text = f"{chat_text} [laugh_1]"
            chat_text = chat_text.replace("...", " [break_3] ")
            return {
                "engine": "chattts",
                "text": chat_text,
                "refine_prompt": "[oral_2][laugh_0][break_2]"
            }

        return {"engine": "raw", "text": chunked}


def main():
    parser = argparse.ArgumentParser(description="Locution & Diction Processor for Neural TTS")
    parser.add_argument("--text", type=str, required=True, help="Input raw text to transform")
    parser.add_argument("--engine", type=str, choices=["edge_tts", "gemini_tts", "elevenlabs", "kokoro", "chattts"], default="edge_tts")
    parser.add_argument("--emotion", type=str, default="HYPE", choices=["HYPE", "SHOCK", "SUSPENSE", "STORYTELLING", "EMPATHY", "CTA", "NEUTRAL"])
    parser.add_argument("--voice", type=str, default="es-MX-JorgeNeural")
    args = parser.parse_args()

    result = LocutionDictionEngine.compile_for_engine(
        text=args.text,
        engine=args.engine,
        emotion=args.emotion,
        voice=args.voice
    )

    print("\n" + "=" * 70)
    print("🎙️ [Locution & Diction Processor Output]")
    print("=" * 70)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

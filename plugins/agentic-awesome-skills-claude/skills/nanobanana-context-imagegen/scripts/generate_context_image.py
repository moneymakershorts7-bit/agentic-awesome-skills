#!/usr/bin/env python3
"""Context-Driven Image Generation with Google Nano Banana & Imagen 3.

Analyzes narrative or technical text to derive spectacular visual concepts,
enforces a strict zero-guessing clarification gate when context is ambiguous,
and synthesizes 7-layer master prompts for Google Gemini media models
(Nano Banana Pro/Flash) and Imagen 3.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_MODEL = "gemini-3-pro-image"
FALLBACK_FLASH_MODEL = "gemini-3.1-flash-image"
IMAGEN_MODEL = "imagen-3.0-generate-002"

SUPPORTED_ASPECT_RATIOS = ["1:1", "3:4", "4:3", "9:16", "16:9", "21:9"]


def analyze_text_context(text: str) -> dict[str, Any]:
    """Analyze document excerpt to extract setting, entities, and assess ambiguity."""
    cleaned = text.strip()
    words = cleaned.split()
    word_count = len(words)

    # Heuristic checks for ambiguity
    has_explicit_style = bool(
        re.search(
            r"\b(oil painting|photograph|engraving|watercolor|digital art|3d render|sketch)\b",
            cleaned,
            re.IGNORECASE,
        )
    )
    has_explicit_ratio = bool(
        re.search(
            r"\b(16:9|3:4|4:3|1:1|2:3|widescreen|portrait|square|cover|banner)\b",
            cleaned,
            re.IGNORECASE,
        )
    )

    # Detect entity and scene density
    mentions_multiple_scenes = len(re.findall(r"\b(then|afterward|vision|meanwhile|next|later)\b", cleaned, re.IGNORECASE)) > 2

    is_ambiguous = (not has_explicit_style) or mentions_multiple_scenes

    # Derive sample clarification questions if ambiguous
    clarification_options = []
    if not has_explicit_style:
        clarification_options.append({
            "dimension": "Artistic Medium / Style",
            "question": "Which visual medium best complements this document's presentation?",
            "options": [
                "(Recommended) Classical Oil Painting (dramatic chiaroscuro, rich fine-art textures)",
                "Cinematic Photorealism (natural directional lighting, authentic period materials)",
                "Vintage Copperplate Engraving (monochrome line-art with cross-hatching for classic book plates)",
            ],
        })

    if not has_explicit_ratio:
        clarification_options.append({
            "dimension": "Asset Role & Framing",
            "question": "Where will this visual asset be placed within the document/book?",
            "options": [
                "(Recommended) Chapter Frontispiece / Plate (3:4 vertical page plate)",
                "Section Header Banner (16:9 widescreen panorama)",
                "Book Cover Art (2:3 vertical with generous negative space for title)",
            ],
        })

    return {
        "word_count": word_count,
        "is_ambiguous": is_ambiguous,
        "has_explicit_style": has_explicit_style,
        "has_explicit_ratio": has_explicit_ratio,
        "clarification_questions": clarification_options,
    }


def synthesize_master_prompt(
    subject: str,
    setting: str,
    lighting: str,
    medium: str,
    palette: str,
    aspect_ratio: str,
    avoid: str = "cartoonish or anime distortion, modern 21st-century garments, distorted anatomy, blurry faces, unprompted text or signatures",
) -> str:
    """Compose the 7-layer visual prompt specification."""
    return (
        f"Subject: {subject}\n"
        f"Setting/Environment: {setting}\n"
        f"Lighting & Atmosphere: {lighting}\n"
        f"Camera & Optics: 70mm lens, eye-level cinematic staging, shallow depth of field\n"
        f"Artistic Medium: {medium}\n"
        f"Color Palette: {palette}\n"
        f"Aspect Ratio: {aspect_ratio}\n"
        f"Constraints & Avoid: {avoid}"
    )


def generate_with_google_sdk(
    prompt: str,
    model: str = DEFAULT_MODEL,
    aspect_ratio: str = "16:9",
    image_size: str = "2K",
) -> bytes:
    """Invoke Google GenAI SDK if installed, or provide instructions for execution."""
    try:
        from google import genai
        from google.genai import types

        client = genai.Client()
        response = client.models.generate_content(
            model=model,
            contents=[prompt],
            config=types.GenerateContentConfig(
                response_modalities=["TEXT", "IMAGE"],
                image_config=types.ImageConfig(
                    aspect_ratio=aspect_ratio,
                    image_size=image_size,
                ),
            ),
        )
        for part in response.parts:
            if part.inline_data is not None:
                img = part.as_image()
                # Return bytes if image object
                import io
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                return buf.getvalue()
        raise RuntimeError("No image returned from Google GenAI model.")
    except ImportError:
        raise RuntimeError(
            "google-genai SDK not installed. Run 'uv pip install google-genai' or delegate "
            "the prompt to the 'image-generator' subagent."
        )


def write_sidecar_metadata(
    output_path: Path,
    metadata: dict[str, Any],
) -> Path:
    """Write JSON metadata sidecar documenting context, model, and prompt."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar_path = output_path.with_suffix(".json")
    metadata["saved_at"] = datetime.now(timezone.utc).isoformat()
    metadata["target_image"] = output_path.name

    with open(sidecar_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return sidecar_path


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Context-driven image generator with Google Nano Banana & Imagen 3.",
    )
    parser.add_argument("--context-file", "-f", type=Path, help="Path to text or markdown document")
    parser.add_argument("--context-text", "-t", type=str, help="Raw excerpt string to analyze")
    parser.add_argument("--analyze", "-a", action="store_true", help="Analyze context and check ambiguity gate")
    parser.add_argument("--prompt", "-p", type=str, help="Direct prompt override")
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL, help="Model ID (default: gemini-3-pro-image)")
    parser.add_argument("--aspect-ratio", "-r", default="16:9", choices=SUPPORTED_ASPECT_RATIOS, help="Aspect ratio")
    parser.add_argument("--output-dir", "-o", type=Path, default=Path("images"), help="Target output directory")
    parser.add_argument("--filename", type=str, default="generated_asset.png", help="Target filename")
    parser.add_argument("--dry-run", action="store_true", help="Print synthesized prompt and exit without API call")

    args = parser.parse_args()

    content = ""
    if args.context_file:
        if not args.context_file.exists():
            print(f"Error: Context file not found: {args.context_file}", file=sys.stderr)
            return 1
        content = args.context_file.read_text(encoding="utf-8")
    elif args.context_text:
        content = args.context_text

    if args.analyze or (content and not args.prompt):
        print("=== CONTEXT ANALYSIS & ZERO-GUESSING CLARIFICATION GATE ===")
        analysis = analyze_text_context(content)
        print(f"Word Count: {analysis['word_count']}")
        print(f"Explicit Style Detected: {analysis['has_explicit_style']}")
        print(f"Explicit Ratio Detected: {analysis['has_explicit_ratio']}")

        if analysis["is_ambiguous"]:
            print("\n[!] AMBIGUITY DETECTED: DO NOT GUESS. Ask the user before generating:")
            for i, q in enumerate(analysis["clarification_questions"], 1):
                print(f"\n{i}. Dimension: {q['dimension']}")
                print(f"   Question: {q['question']}")
                for opt in q["options"]:
                    print(f"   • {opt}")
            if not args.prompt and not args.dry_run:
                print("\nPlease provide explicit choices or specify --prompt to proceed.")
                return 0

    prompt = args.prompt
    if not prompt and content:
        # Default synthesized prompt based on text
        prompt = synthesize_master_prompt(
            subject=f"Key dramatic visual moment from excerpt: '{content[:120]}...'",
            setting="Authentic atmospheric historical environment grounded in the passage",
            lighting="Dramatic Caravaggio chiaroscuro with intense golden and celestial highlights",
            medium="Masterpiece oil on linen canvas, classical European baroque fine art",
            palette="Deep lapis lazuli blue, burnished bronze, ochre dust, ivory highlights",
            aspect_ratio=args.aspect_ratio,
        )

    if not prompt:
        print("Error: No context or prompt provided. Use --context-file, --context-text, or --prompt.", file=sys.stderr)
        return 1

    print("\n=== SYNTHESIZED 7-LAYER PROMPT ===")
    print(prompt)

    out_file = args.output_dir / args.filename
    sidecar_path = write_sidecar_metadata(
        output_path=out_file,
        metadata={
            "model": args.model,
            "aspect_ratio": args.aspect_ratio,
            "prompt": prompt,
            "context_source": str(args.context_file) if args.context_file else "direct_text",
        },
    )
    print(f"\n✓ Metadata sidecar prepared: {sidecar_path}")

    if args.dry_run:
        print("\n[Dry Run] Image generation skipped.")
        return 0

    print(f"\nReady to generate with Google media model '{args.model}' (Aspect: {args.aspect_ratio}).")
    try:
        img_bytes = generate_with_google_sdk(
            prompt=prompt,
            model=args.model,
            aspect_ratio=args.aspect_ratio,
        )
        out_file.write_bytes(img_bytes)
        print(f"✓ Image saved: {out_file}")
        return 0
    except Exception as e:
        print(f"\nNote: {e}", file=sys.stderr)
        print("The synthesized prompt and sidecar are saved and ready for invocation via the 'image-generator' subagent or REST API.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())

# Google Media Models Reference: Nano Banana & Imagen 3

> Technical reference for model IDs, aspect ratios, resolutions, REST payloads, and Python SDK integration.

---

## 1. Model Catalog

| Model Tier | Model ID | Primary Use Case | Output Resolutions |
| :--- | :--- | :--- | :--- |
| **Nano Banana Pro** | `gemini-3-pro-image` | High-complexity scenes, multi-character fusion, book covers, fine-art canvas. | `1K`, `2K`, `4K` |
| **Nano Banana 2** | `gemini-3.1-flash-image` | Rapid chapter illustrations, editorial web headers, spot art. | `1K` |
| **Google Imagen 3** | `imagen-3.0-generate-002` | State-of-the-art studio photorealism, textured oil painting, fine line engraving. | `1024x1024`, `1792x1024`, `1024x1792` |

---

## 2. Aspect Ratio Specifications

Google's Gemini and Imagen models support standard aspect ratios designed for publishing and digital media:

| Aspect Ratio | Dimension Shape | Recommended Document Role |
| :---: | :---: | :--- |
| **`1:1`** | Square | Spot illustrations, character profile icons, social vignettes. |
| **`3:4`** | Vertical Standard | Standard book plates, chapter frontispieces, portrait illustrations. |
| **`2:3`** | Vertical Book | Standard trade paperback and hardcover full-jacket covers. |
| **`4:3`** | Horizontal Standard | Classic horizontal landscape illustration, slide decks. |
| **`16:9`** | Widescreen | Chapter header banners, digital article hero visuals, cinematic panoramas. |
| **`21:9`** | Ultrawide | Panoramic landscape establishing shots, wide foldout plates. |

---

## 3. Python SDK (`google-genai`)

When using the unified Google GenAI SDK:

```python
import os
from google import genai
from google.genai import types

# 1. Initialize client with environment key (GEMINI_API_KEY)
client = genai.Client()

# 2. Call Nano Banana Pro (Gemini 3 Pro Image)
response = client.models.generate_content(
    model="gemini-3-pro-image",
    contents=["A dramatic classical oil painting of Daniel in Babylon..."],
    config=types.GenerateContentConfig(
        response_modalities=["TEXT", "IMAGE"],
        image_config=types.ImageConfig(
            aspect_ratio="16:9",   # "1:1", "3:4", "4:3", "9:16", "16:9"
            image_size="2K"        # "1K", "2K", "4K"
        )
    )
)

# 3. Save generated image
for part in response.parts:
    if part.inline_data is not None:
        image = part.as_image()
        image.save("output_image.png")
```

---

## 4. REST Endpoint Specification

For environments interacting via HTTP without the Python SDK:

- **Method**: `POST`
- **Path**: `/v1beta/models/{model}:generateContent`
- **Host**: `generativelanguage.googleapis.com`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <AUTH_TOKEN>`

### Request Body Schema:
```json
{
  "contents": [{
    "parts": [{
      "text": "7-layer synthesized prompt text..."
    }]
  }],
  "generationConfig": {
    "responseModalities": ["TEXT", "IMAGE"],
    "imageConfig": {
      "aspectRatio": "16:9",
      "imageSize": "2K"
    }
  }
}
```

---

## 5. Metadata Sidecar Schema (`<image_name>.json`)

Always write a JSON sidecar adjacent to every generated image file:

```json
{
  "source_document": "books/daniel_commentary/chapter_10.md",
  "model": "gemini-3-pro-image",
  "aspect_ratio": "16:9",
  "resolution": "2K",
  "prompt": "Full 7-layer synthesized prompt text...",
  "clarification_gate_asked": true,
  "user_selection": "Option A: Panoramic vision with celestial messenger",
  "created_at": "2026-10-03T18:30:00Z",
  "output_path": "images/daniel_ch10_vision.png"
}
```

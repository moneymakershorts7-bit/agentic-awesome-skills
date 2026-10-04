#!/usr/bin/env python3
"""
Book Designer & Typesetter CLI (book_typesetter.py)
Transforms Markdown manuscripts into publication-ready, beautifully typeset PDFs.
Supports custom typography pairings, color themes, book anatomy, and headless vector printing.
"""

import os
import sys
import re
import argparse
import subprocess
import shutil
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
TEMPLATES_DIR = SKILL_DIR / "templates"
THEMES_CSS_PATH = TEMPLATES_DIR / "themes.css"
BRAVE_PATH = Path("/opt/brave.com/brave/brave-browser")

PAGE_SIZES = {
    "A4": "210mm 297mm",
    "trade-6x9": "6in 9in",
    "letter": "8.5in 11in"
}

PAGE_MARGINS = {
    "A4": "24mm 18mm 24mm 18mm",
    "trade-6x9": "18mm 15mm 20mm 15mm",
    "letter": "22mm 18mm 22mm 18mm"
}


def convert_markdown_to_html(md_content: str) -> str:
    """Uses bun and marked to compile GFM Markdown into clean HTML."""
    bun_cmd = [
        "bun",
        "--eval",
        """
import { marked } from 'marked';
const input = await Bun.stdin.text();
console.log(marked.parse(input));
"""
    ]
    proc = subprocess.run(
        bun_cmd,
        shell=False,
        input=md_content,
        capture_output=True,
        text=True,
        check=True
    )
    return proc.stdout


def resolve_image_paths(md_content: str, base_dir: Path) -> str:
    """Replaces relative image paths in markdown with absolute file URLs."""
    def _replace_img(match):
        alt = match.group(1)
        src = match.group(2).strip()
        if src.startswith("http://") or src.startswith("https://") or src.startswith("file://"):
            return f"![{alt}]({src})"
        abs_path = (base_dir / src).resolve()
        if abs_path.exists():
            return f"![{alt}](file://{abs_path})"
        return match.group(0)

    return re.sub(r'!\[(.*?)\]\((.*?)\)', _replace_img, md_content)


def post_process_html(html: str) -> str:
    """Enriches HTML with book classes, callouts, figures, and page break helpers."""
    # 1. Enrich blockquotes based on leading emoji
    def _enrich_bq(match):
        content = match.group(1)
        if "📖" in content:
            return f'<blockquote class="callout callout-scripture">{content}</blockquote>'
        elif "📜" in content:
            return f'<blockquote class="callout callout-historical">{content}</blockquote>'
        elif "🏛️" in content or "Verificación Histórica" in content:
            return f'<blockquote class="callout callout-factcheck">{content}</blockquote>'
        elif "💡" in content:
            return f'<blockquote class="callout callout-insight">{content}</blockquote>'
        return f'<blockquote>{content}</blockquote>'

    html = re.sub(r'<blockquote>(.*?)</blockquote>', _enrich_bq, html, flags=re.DOTALL)

    # 2. Enrich standalone images followed by italic captions into proper <figure>
    # Pattern: <p><img src="(.*?)" alt="(.*?)"><br>\s*<em>(Figura \d+:.*?)</em></p>
    def _enrich_figure(match):
        src = match.group(1)
        alt = match.group(2)
        caption = match.group(3)
        return f'''<figure class="editorial-figure">
  <img src="{src}" alt="{alt}" class="book-illustration">
  <figcaption class="image-caption">{caption}</figcaption>
</figure>'''

    html = re.sub(
        r'<p>\s*<img\s+src="([^"]+)"\s+alt="([^"]*)"\s*>\s*(?:<br\s*/?>)?\s*<em>(Figura\s+\d+:.*?)</em>\s*</p>',
        _enrich_figure,
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # 3. Detect Bibliography section and wrap in bibliography-section div
    if '<h1 id="bibliografia-general">' in html or 'BIBLIOGRAFÍA HISTÓRICA' in html:
        html = re.sub(
            r'(<h1[^>]*>.*?BIBLIOGRAFÍA.*?</h1>)',
            r'<div class="bibliography-section">\1',
            html,
            count=1,
            flags=re.IGNORECASE
        )
        html += "</div>"

    return html


def build_full_document(
    body_html: str,
    title: str,
    subtitle: str,
    author: str,
    theme: str,
    page_size: str,
    cover_image_path: Path = None,
    css_content: str = ""
) -> str:
    """Assembles the complete HTML document including front matter and styles."""
    size_css = PAGE_SIZES.get(page_size, PAGE_SIZES["A4"])
    margin_css = PAGE_MARGINS.get(page_size, PAGE_MARGINS["A4"])

    # Front matter components
    front_matter_html = ""

    # Cover Page
    if cover_image_path and cover_image_path.exists():
        cover_abs_url = f"file://{cover_image_path.resolve()}"
        front_matter_html += f"""
<div class="cover-page">
  <img src="{cover_abs_url}" alt="Portada: {title}" class="cover-image">
</div>
"""

    # Title Page (Portada Interior)
    front_matter_html += f"""
<div class="title-page">
  <div class="title-page-top">
    <div class="title-ornament">✦ ✦ ✦</div>
    <h1 class="book-main-title">{title}</h1>
    {f'<div class="book-subtitle">{subtitle}</div>' if subtitle else ''}
  </div>
  <div class="title-page-center">
    <div class="title-ornament">❖ ❖ ❖</div>
  </div>
  <div class="title-page-bottom">
    <div class="book-author">{author}</div>
    <div class="book-credentials">Edición Bestseller Digital e Historiográfica</div>
    <div class="book-credentials">Verificación de Fuentes y Cánones Documentales</div>
  </div>
</div>
"""

    # Colophon Page (Página de Créditos)
    front_matter_html += f"""
<div class="colophon-page">
  <h4>CRÉDITOS Y REGISTRO EDITORIAL</h4>
  <p><strong>Obra:</strong> {title}</p>
  {f'<p><strong>Subtítulo:</strong> {subtitle}</p>' if subtitle else ''}
  <p><strong>Compilación e Investigación Exegética:</strong> {author}</p>
  <p><strong>Diseño Tipográfico y Maquetación:</strong> Skill <code>book-designer-typesetter</code></p>
  <p><strong>Tipografías Principales:</strong> Cinzel (Roman Imperial) y EB Garamond (Sixteenth-Century Classic)</p>
  <p><strong>Motor de Renderizado:</strong> Chromium Print Engine (Vector PDF)</p>
  <p><strong>Fecha de Edición:</strong> Octubre 2026</p>
  <hr style="width: 100%; margin: 1rem 0; border: 0; border-top: 1px solid #ccc;">
  <p style="font-size: 0.8rem; color: #777;">
    Edición académica y exegética preparada para estudio personal, pastoral, misionero e investigación histórica.
    Todos los textos y cronologías han sido cotejados con fuentes primarias y monografías académicas estándar.
  </p>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
@page {{
  size: {size_css};
  margin: {margin_css};
}}

{css_content}
</style>
</head>
<body class="theme-{theme}">
{front_matter_html}
<main class="book-body">
{body_html}
</main>
</body>
</html>
"""


def render_pdf(
    html_path: Path,
    pdf_path: Path,
    title: str,
    author: str
) -> None:
    """Executes Brave Headless to produce a high-resolution vector PDF."""
    if not BRAVE_PATH.exists():
        raise FileNotFoundError(f"Headless browser binary not found at: {BRAVE_PATH}")

    # Chromium header/footer templates
    header_template = f"""<div style="font-size: 7.5pt; font-family: 'Cinzel', Georgia, serif; width: 100%; text-align: center; color: #777; border-bottom: 0.5pt solid #ddd; padding-bottom: 3px; margin: 0 18mm; text-transform: uppercase; letter-spacing: 0.05em;">
  <span>{title}</span>
</div>"""

    footer_template = f"""<div style="font-size: 8pt; font-family: 'EB Garamond', Georgia, serif; width: 100%; text-align: center; color: #777; border-top: 0.5pt solid #ddd; padding-top: 3px; margin: 0 18mm;">
  <span class="pageNumber"></span>
</div>"""

    cmd = [
        str(BRAVE_PATH),
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=6000",
        "--display-header-footer",
        f"--header-template={header_template}",
        f"--footer-template={footer_template}",
        f"--print-to-pdf={pdf_path}",
        str(html_path.resolve())
    ]

    print(f"[*] Rendering vector PDF via Chromium Print Engine...")
    proc = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"Error during browser execution: {proc.stderr}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Book Designer & Typesetter: Transform Markdown into Publication-Quality PDFs."
    )
    parser.add_argument("-i", "--input", required=True, help="Input Markdown manuscript (.md)")
    parser.add_argument("-o", "--output", help="Output PDF file path")
    parser.add_argument("-t", "--theme", default="sacred-history",
                        choices=["sacred-history", "academic-oxford", "editorial-minimalist", "renaissance-earth"],
                        help="Book color and typography theme")
    parser.add_argument("-s", "--size", default="A4",
                        choices=["A4", "trade-6x9", "letter"],
                        help="Page trim size")
    parser.add_argument("--cover", help="Cover image path (PNG/JPG)")
    parser.add_argument("--title", help="Book title (default: extracted from manuscript)")
    parser.add_argument("--subtitle", help="Book subtitle")
    parser.add_argument("--author", default="Nolberto Pirela", help="Book author/compiler")
    parser.add_argument("--keep-html", action="store_true", help="Keep intermediate HTML file")

    args = parser.parse_args()

    input_file = Path(args.input).resolve()
    if not input_file.exists():
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    output_pdf = Path(args.output).resolve() if args.output else input_file.with_suffix(".pdf")
    temp_html = input_file.with_name(f"{input_file.stem}_typeset_temp.html")

    print("=" * 60)
    print("📖 BOOK DESIGNER & TYPESETTER")
    print(f"• Manuscript: {input_file.name}")
    print(f"• Theme:      {args.theme}")
    print(f"• Trim Size:  {args.size}")
    print(f"• Target PDF: {output_pdf.name}")
    print("=" * 60)

    # 1. Read Manuscript
    with open(input_file, "r", encoding="utf-8") as f:
        md_text = f.read()

    # 2. Extract or define Title
    title = args.title
    if not title:
        m_title = re.search(r'^#\s+(.+)$', md_text, re.MULTILINE)
        if m_title:
            title = m_title.group(1).replace("#", "").strip()
        else:
            title = input_file.stem.replace("_", " ").title()

    subtitle = args.subtitle or "Comentario Versículo a Versiculo con Verificación Historiográfica"

    # 3. Resolve Images
    print("[*] Resolving image assets to absolute URLs...")
    md_text_resolved = resolve_image_paths(md_text, input_file.parent)

    # 4. Convert Markdown to HTML via Bun + marked
    print("[*] Compiling Markdown to structured semantic HTML...")
    raw_html = convert_markdown_to_html(md_text_resolved)

    # 5. Post-process HTML (callouts, figures, bibliography)
    print("[*] Enriching layout with book callouts, figures, and typography...")
    body_html = post_process_html(raw_html)

    # 6. Read CSS Stylesheet
    with open(THEMES_CSS_PATH, "r", encoding="utf-8") as f:
        css_content = f.read()

    # 7. Assemble Full HTML Document
    cover_path = Path(args.cover).resolve() if args.cover else None
    full_html = build_full_document(
        body_html=body_html,
        title=title,
        subtitle=subtitle,
        author=args.author,
        theme=args.theme,
        page_size=args.size,
        cover_image_path=cover_path,
        css_content=css_content
    )

    with open(temp_html, "w", encoding="utf-8") as f:
        f.write(full_html)

    # 8. Render to PDF
    try:
        render_pdf(temp_html, output_pdf, title, args.author)
        pdf_size_mb = output_pdf.stat().st_size / (1024 * 1024)
        print("=" * 60)
        print("✅ BOOK TYPESETTING COMPLETED SUCCESSFULLY!")
        print(f"• PDF Generated: {output_pdf}")
        print(f"• File Size:     {pdf_size_mb:.2f} MB")
        print("=" * 60)
    finally:
        if not args.keep_html and temp_html.exists():
            temp_html.unlink()


if __name__ == "__main__":
    main()

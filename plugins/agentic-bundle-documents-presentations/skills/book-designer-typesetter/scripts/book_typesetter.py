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
    """Enriches HTML with book classes, callouts, figures, two-column editorial prose, and page break helpers."""
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

    # 2. Enrich standalone images followed by captions into proper <figure>
    def _enrich_figure_with_caption(match):
        src = match.group(1)
        alt = match.group(2)
        caption = match.group(3)
        return f'''<figure class="editorial-figure">
  <img src="{src}" alt="{alt}" class="book-illustration">
  <figcaption class="image-caption">{caption}</figcaption>
</figure>'''

    html = re.sub(
        r'<p>\s*<img\s+src="([^"]+)"\s+alt="([^"]*)"\s*>\s*(?:<br\s*/?>)?\s*<em>((?:Figura|Infografía|Carta)\s*.*?)</em>\s*</p>',
        _enrich_figure_with_caption,
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # 3. Enrich bare standalone images
    def _enrich_figure_bare(match):
        src = match.group(1)
        alt = match.group(2)
        return f'''<figure class="editorial-figure">
  <img src="{src}" alt="{alt}" class="book-illustration">
</figure>'''

    html = re.sub(
        r'<p>\s*<img\s+src="([^"]+)"\s+alt="([^"]*)"\s*>\s*</p>',
        _enrich_figure_bare,
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # 4. Wrap Table of Contents in 2-column container
    def _wrap_toc(match):
        heading = match.group(1)
        list_content = match.group(2)
        return f'{heading}\n<div class="table-of-contents">\n{list_content}\n</div>'

    html = re.sub(
        r'(<h2[^>]*>.*?Índice General.*?</h2>)\s*(<ul[^>]*>.*?</ul>)',
        _wrap_toc,
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # 5. Group consecutive commentary paragraphs and lists into .editorial-prose (2 columns)
    block_pattern = re.compile(
        r"(<h[1-6][^>]*>.*?</h[1-6]>|<blockquote[^>]*>.*?</blockquote>|<figure[^>]*>.*?</figure>|<table[^>]*>.*?</table>|<div[^>]*>.*?</div>|<hr/?>|<p[^>]*>.*?</p>|<ul[^>]*>.*?</ul>|<ol[^>]*>.*?</ol>)",
        re.DOTALL | re.IGNORECASE
    )

    parts = []
    prose_acc = []
    is_first_chapter_paragraph = False

    def flush_prose():
        nonlocal is_first_chapter_paragraph
        if prose_acc:
            joined = "\n".join(prose_acc)
            parts.append(f'<div class="editorial-prose">\n{joined}\n</div>')
            prose_acc.clear()

    last_end = 0
    for match in block_pattern.finditer(html):
        start, end = match.span()
        interstitial = html[last_end:start].strip()
        if interstitial:
            flush_prose()
            parts.append(interstitial)

        block = match.group(1)
        tag_match = re.match(r"<([a-zA-Z0-9]+)", block)
        tag_name = tag_match.group(1).lower() if tag_match else ""

        if tag_name == "h1":
            flush_prose()
            is_first_chapter_paragraph = True
            parts.append(block)
        elif tag_name in ("h2", "h3", "h4", "h5", "h6", "blockquote", "figure", "table", "div", "hr"):
            flush_prose()
            parts.append(block)
        elif tag_name in ("p", "ul", "ol"):
            if "<img" in block or "<figure" in block:
                flush_prose()
                parts.append(block)
            else:
                if is_first_chapter_paragraph and tag_name == "p":
                    block = re.sub(r"^<p([^>]*)>", r'<p\1 class="drop-cap">', block)
                    is_first_chapter_paragraph = False
                prose_acc.append(block)
        last_end = end

    flush_prose()
    if last_end < len(html):
        rem = html[last_end:].strip()
        if rem:
            parts.append(rem)

    html = "\n\n".join(parts)

    # 6. Wrap Bibliography section in bibliography-section div
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

    # Front matter components (Cover is rendered separately full-bleed by cdp_pdf_engine)
    front_matter_html = f"""
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
    <div class="book-credentials">Quinta Edición Editorial: Verificación Científica y Registro Internacional (ISBN / DOI / LCCN)</div>
    <div class="book-credentials">Teología Historicista, Fuentes Académicas Primarias y Espíritu de Profecía</div>
  </div>
</div>

<div class="colophon-page">
  <h4>CRÉDITOS Y REGISTRO EDITORIAL</h4>
  <p><strong>Obra:</strong> {title}</p>
  {f'<p><strong>Subtítulo:</strong> {subtitle}</p>' if subtitle else ''}
  <p><strong>Compilación e Investigación Exegética:</strong> {author}</p>
  <p><strong>Composición Tipográfica y Diseño Editorial:</strong> Edición Impresa Clásica en Dos Columnas</p>
  <p><strong>Tipografías Principales:</strong> Cinzel (Roman Imperial) y EB Garamond (Sixteenth-Century Classic)</p>
  <p><strong>Edición:</strong> Quinta Edición Revisada y Ampliada (Registro Bibliográfico Internacional ISBN / DOI / LCCN y Fuentes Académicas Primarias)</p>
  <p><strong>Fecha de Edición:</strong> Octubre 2026</p>
  <hr style="width: 100%; margin: 1rem 0; border: 0; border-top: 1px solid #ccc;">
  <p style="font-size: 0.8rem; color: #777;">
    Edición académica, pastoral y exegética preparada para estudio personal, pastoral, misionero e investigación teológica.
    Todos los textos proféticos, cronologías y citas han sido rigurosamente cotejados con las Sagradas Escrituras, el Espíritu de Profecía, ediciones críticas estándar y fuentes historiográficas documentadas con registro internacional ISBN / DOI / LCCN.
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
    author: str,
    page_size: str = "A4",
    cover_image_path: Path = None
) -> None:
    """Executes Bun CDP PDF Engine to produce a publication-ready vector PDF."""
    cdp_engine_path = SCRIPT_DIR / "cdp_pdf_engine.js"
    if not cdp_engine_path.exists():
        raise FileNotFoundError(f"CDP PDF engine script not found at: {cdp_engine_path}")

    size_css = PAGE_SIZES.get(page_size, PAGE_SIZES["A4"])

    if cover_image_path and cover_image_path.exists():
        # Render cover page separately
        cover_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@page {{ size: {size_css}; margin: 0; }}
html, body {{ margin: 0; padding: 0; width: 100vw; height: 100vh; overflow: hidden; background: #000; }}
.cover-wrap {{ width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; }}
.cover-wrap img {{ width: 100%; height: 100%; object-fit: cover; }}
</style>
</head>
<body>
<div class="cover-wrap">
  <img src="file://{cover_image_path.resolve()}">
</div>
</body>
</html>"""
        temp_cover_html = html_path.with_name(f"{html_path.stem}_cover.html")
        temp_cover_pdf = html_path.with_name(f"{html_path.stem}_cover.pdf")
        temp_body_pdf = html_path.with_name(f"{html_path.stem}_body.pdf")

        with open(temp_cover_html, "w", encoding="utf-8") as f:
            f.write(cover_html)

        try:
            print("[*] Rendering full-bleed cover page without headers/footers...")
            cover_cmd = [
                "bun", str(cdp_engine_path),
                "--input", str(temp_cover_html.resolve()),
                "--output", str(temp_cover_pdf.resolve()),
                "--size", page_size,
                "--is-cover"
            ]
            subprocess.run(cover_cmd, shell=False, check=True)

            print("[*] Rendering book interior with running headers & footers (zero URL leakage)...")
            body_cmd = [
                "bun", str(cdp_engine_path),
                "--input", str(html_path.resolve()),
                "--output", str(temp_body_pdf.resolve()),
                "--title", title,
                "--author", author,
                "--size", page_size
            ]
            subprocess.run(body_cmd, shell=False, check=True)

            print("[*] Uniting cover and interior via pdfunite...")
            subprocess.run(["/usr/bin/pdfunite", str(temp_cover_pdf), str(temp_body_pdf), str(pdf_path.resolve())], check=True)
        finally:
            for p in [temp_cover_html, temp_cover_pdf, temp_body_pdf]:
                if p.exists():
                    p.unlink()
    else:
        print("[*] Rendering book interior with running headers & footers (zero URL leakage)...")
        body_cmd = [
            "bun", str(cdp_engine_path),
            "--input", str(html_path.resolve()),
            "--output", str(pdf_path.resolve()),
            "--title", title,
            "--author", author,
            "--size", page_size
        ]
        subprocess.run(body_cmd, shell=False, check=True)


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

    # 2. Extract Title and Subtitle (checking YAML frontmatter first)
    title = args.title
    if not title:
        m_yaml = re.search(r'^title:\s*["\']?([^"\']+)["\']?', md_text, re.MULTILINE)
        if m_yaml:
            title = m_yaml.group(1).strip()
        else:
            m_title = re.search(r'^#\s+(.+)$', md_text, re.MULTILINE)
            if m_title:
                title = m_title.group(1).replace("#", "").strip()
            else:
                title = input_file.stem.replace("_", " ").title()

    subtitle = args.subtitle
    if not subtitle:
        m_sub = re.search(r'^subtitle:\s*["\']?([^"\']+)["\']?', md_text, re.MULTILINE)
        if m_sub:
            subtitle = m_sub.group(1).strip()
        else:
            subtitle = "Comentario Versículo a Versiculo con Verificación Historiográfica"

    # Strip YAML frontmatter and redundant cover/title header from manuscript body
    # (since build_full_document generates the elegant Title Page and Colophon)
    md_text_clean = re.sub(r'^---\s*\n.*?\n---\s*\n', '', md_text, flags=re.DOTALL)
    md_text_clean = re.sub(r'^\s*<div align="center">.*?</div>\s*', '', md_text_clean, flags=re.DOTALL)

    # 3. Resolve Images
    print("[*] Resolving image assets to absolute URLs...")
    md_text_resolved = resolve_image_paths(md_text_clean, input_file.parent)

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
        render_pdf(temp_html, output_pdf, title, args.author, page_size=args.size, cover_image_path=cover_path)
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

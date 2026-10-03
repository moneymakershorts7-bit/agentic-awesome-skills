#!/usr/bin/env python3
"""
vet_and_install_tool.py - Tool-First Discovery and Security Vetting Engine

Read-only, zero-subprocess inspection utility for agents to scout canonical tools
for deterministic tasks, audit provenance against typosquatting, and output
safe installation plans for human or supervisor review.
"""

import argparse
import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

# Curated catalog of vetted canonical tools for mechanical / deterministic tasks
VETTED_TOOLS = {
    # Documents
    "pandoc": {
        "category": "documents",
        "description": "Universal document format converter (Markdown, DOCX, PDF, HTML, EPUB, LaTeX)",
        "keywords": ["markdown", "docx", "pdf", "epub", "latex", "convert document", "md to docx", "docx to md"],
        "manager": "apt",
        "package": "pandoc",
        "binary": "pandoc",
        "offline_safe": True,
        "sample_cmd": "pandoc -s input.md -o output.docx",
        "install_cmd": "apt-get install -y --no-install-recommends pandoc",
        "risk_level": "SAFE",
    },
    "libreoffice": {
        "category": "documents",
        "description": "Headless office suite converter for DOCX, XLSX, PPTX to PDF/HTML",
        "keywords": ["office to pdf", "docx to pdf", "pptx to pdf", "xlsx to pdf", "convert word to pdf"],
        "manager": "apt",
        "package": "libreoffice-writer-nogui",
        "binary": "libreoffice",
        "offline_safe": True,
        "sample_cmd": "libreoffice --headless --convert-to pdf input.docx",
        "install_cmd": "apt-get install -y --no-install-recommends libreoffice-writer-nogui",
        "risk_level": "SAFE",
    },
    "pdftotext": {
        "category": "documents",
        "description": "High-fidelity text extractor from PDF documents",
        "keywords": ["pdf to text", "extract text from pdf", "pdf text", "read pdf"],
        "manager": "apt",
        "package": "poppler-utils",
        "binary": "pdftotext",
        "offline_safe": True,
        "sample_cmd": "pdftotext -layout input.pdf output.txt",
        "install_cmd": "apt-get install -y --no-install-recommends poppler-utils",
        "risk_level": "SAFE",
    },
    "pdftoppm": {
        "category": "documents",
        "description": "Rasterize PDF pages into PNG/JPEG images",
        "keywords": ["pdf to image", "pdf to png", "pdf to jpeg", "rasterize pdf", "render pdf"],
        "manager": "apt",
        "package": "poppler-utils",
        "binary": "pdftoppm",
        "offline_safe": True,
        "sample_cmd": "pdftoppm -png -r 150 input.pdf page",
        "install_cmd": "apt-get install -y --no-install-recommends poppler-utils",
        "risk_level": "SAFE",
    },
    "qpdf": {
        "category": "documents",
        "description": "Structural PDF transformation, encryption, decryption, and merging",
        "keywords": ["merge pdf", "split pdf", "combine pdf", "decrypt pdf", "pdf linearize"],
        "manager": "apt",
        "package": "qpdf",
        "binary": "qpdf",
        "offline_safe": True,
        "sample_cmd": "qpdf --empty --pages file1.pdf file2.pdf -- merged.pdf",
        "install_cmd": "apt-get install -y --no-install-recommends qpdf",
        "risk_level": "SAFE",
    },
    "typst": {
        "category": "documents",
        "description": "Modern, ultra-fast markup-based typesetting engine compiling to PDF",
        "keywords": ["typst", "typeset", "latex alternative", "fast pdf generation"],
        "manager": "cargo",
        "package": "typst-cli",
        "binary": "typst",
        "offline_safe": True,
        "sample_cmd": "typst compile document.typ output.pdf",
        "install_cmd": "cargo install typst-cli",
        "risk_level": "SAFE",
    },

    # Multimedia
    "ffmpeg": {
        "category": "multimedia",
        "description": "Universal audio/video transcoder, trimmer, scaler, and extractor",
        "keywords": ["video convert", "transcode", "extract audio", "mp4 to mp3", "compress video", "cut video", "audio convert"],
        "manager": "apt",
        "package": "ffmpeg",
        "binary": "ffmpeg",
        "offline_safe": True,
        "sample_cmd": "ffmpeg -i input.mp4 -vn -acodec libmp3lame -q:a 2 output.mp3",
        "install_cmd": "apt-get install -y --no-install-recommends ffmpeg",
        "risk_level": "SAFE",
    },
    "sox": {
        "category": "multimedia",
        "description": "Sound eXchange: command-line audio processing suite",
        "keywords": ["audio normalizer", "wav to mp3", "resample audio", "audio filter", "sox"],
        "manager": "apt",
        "package": "sox",
        "binary": "sox",
        "offline_safe": True,
        "sample_cmd": "sox input.wav output.mp3 norm -0.1",
        "install_cmd": "apt-get install -y --no-install-recommends sox libsox-fmt-all",
        "risk_level": "SAFE",
    },

    # Images
    "magick": {
        "category": "images",
        "description": "ImageMagick suite for image format conversion, scaling, batch operations",
        "keywords": ["image convert", "resize image", "crop image", "png to jpg", "jpg to png", "imagemagick"],
        "manager": "apt",
        "package": "imagemagick",
        "binary": "magick",
        "offline_safe": True,
        "sample_cmd": "magick input.jpg -resize 800x600 output.png",
        "install_cmd": "apt-get install -y --no-install-recommends imagemagick",
        "risk_level": "SAFE",
    },
    "optipng": {
        "category": "images",
        "description": "Advanced lossless PNG optimizer and compressor",
        "keywords": ["optimize png", "compress png", "png lossless", "reduce png size"],
        "manager": "apt",
        "package": "optipng",
        "binary": "optipng",
        "offline_safe": True,
        "sample_cmd": "optipng -o5 image.png",
        "install_cmd": "apt-get install -y --no-install-recommends optipng",
        "risk_level": "SAFE",
    },
    "cwebp": {
        "category": "images",
        "description": "High-efficiency WebP image encoder",
        "keywords": ["convert to webp", "png to webp", "jpg to webp", "webp encoder"],
        "manager": "apt",
        "package": "webp",
        "binary": "cwebp",
        "offline_safe": True,
        "sample_cmd": "cwebp -q 80 input.png -o output.webp",
        "install_cmd": "apt-get install -y --no-install-recommends webp",
        "risk_level": "SAFE",
    },
    "rsvg-convert": {
        "category": "images",
        "description": "High-speed SVG renderer to PNG/PDF without full browser overhead",
        "keywords": ["svg to png", "svg to pdf", "rasterize svg", "render svg"],
        "manager": "apt",
        "package": "librsvg2-bin",
        "binary": "rsvg-convert",
        "offline_safe": True,
        "sample_cmd": "rsvg-convert -w 1024 -h 1024 -f png input.svg -o output.png",
        "install_cmd": "apt-get install -y --no-install-recommends librsvg2-bin",
        "risk_level": "SAFE",
    },

    # Structured Data
    "jq": {
        "category": "data",
        "description": "Lightweight and flexible command-line JSON processor and query engine",
        "keywords": ["json parse", "query json", "filter json", "format json", "jq"],
        "manager": "apt",
        "package": "jq",
        "binary": "jq",
        "offline_safe": True,
        "sample_cmd": "jq '.data[] | {id, title}' input.json",
        "install_cmd": "apt-get install -y --no-install-recommends jq",
        "risk_level": "SAFE",
    },
    "yq": {
        "category": "data",
        "description": "Portable command-line YAML, JSON, and XML processor",
        "keywords": ["yaml parse", "yaml to json", "json to yaml", "query yaml", "yq"],
        "manager": "apt",
        "package": "yq",
        "binary": "yq",
        "offline_safe": True,
        "sample_cmd": "yq -p=yaml -o=json input.yaml > output.json",
        "install_cmd": "apt-get install -y --no-install-recommends yq",
        "risk_level": "SAFE",
    },
    "duckdb": {
        "category": "data",
        "description": "High-performance analytical in-process SQL database for CSV, Parquet, JSON",
        "keywords": ["csv to parquet", "parquet to csv", "sql on csv", "sql on json", "query parquet", "duckdb"],
        "manager": "uv",
        "package": "duckdb",
        "binary": "duckdb",
        "offline_safe": True,
        "sample_cmd": "duckdb -c \"COPY (SELECT * FROM 'data.csv') TO 'data.parquet' (FORMAT PARQUET);\"",
        "install_cmd": "uv tool install duckdb",
        "risk_level": "SAFE",
    },
    "csvkit": {
        "category": "data",
        "description": "Suite of command-line tools for converting to and working with CSV",
        "keywords": ["csv cut", "csv join", "csv to json", "csv clean", "csvkit"],
        "manager": "uv",
        "package": "csvkit",
        "binary": "csvcut",
        "offline_safe": True,
        "sample_cmd": "csvcut -c 1,3 data.csv > subset.csv",
        "install_cmd": "uv tool install csvkit",
        "risk_level": "SAFE",
    },

    # OCR
    "tesseract": {
        "category": "ocr",
        "description": "High-accuracy open-source Optical Character Recognition engine",
        "keywords": ["ocr", "image to text", "extract text from image", "scan to text", "tesseract"],
        "manager": "apt",
        "package": "tesseract-ocr",
        "binary": "tesseract",
        "offline_safe": True,
        "sample_cmd": "tesseract image.png output_text -l spa+eng",
        "install_cmd": "apt-get install -y --no-install-recommends tesseract-ocr",
        "risk_level": "SAFE",
    },

    # Compression
    "zstd": {
        "category": "compression",
        "description": "Zstandard real-time compression algorithm with high compression ratios",
        "keywords": ["compress fast", "zstd", "tar zstd", "compress files", "decompress zst"],
        "manager": "apt",
        "package": "zstd",
        "binary": "zstd",
        "offline_safe": True,
        "sample_cmd": "zstd -T0 -19 file.tar -o file.tar.zst",
        "install_cmd": "apt-get install -y --no-install-recommends zstd",
        "risk_level": "SAFE",
    },
    "7z": {
        "category": "compression",
        "description": "Multi-format high ratio file archiver (7z, zip, rar, tar)",
        "keywords": ["extract 7z", "compress 7z", "extract rar", "split archive", "7zip"],
        "manager": "apt",
        "package": "p7zip-full",
        "binary": "7z",
        "offline_safe": True,
        "sample_cmd": "7z x archive.7z -o/destination",
        "install_cmd": "apt-get install -y --no-install-recommends p7zip-full",
        "risk_level": "SAFE",
    },
}

# Known typosquatting or malicious packages
KNOWN_TYPOSQUATS = {
    "pypandoc-malicious", "pandoc-cli-tool", "pandoc-py",
    "ffmpeg-python-bin", "pyffmpeg-core", "ffmpeg-fast",
    "image-magick-tool", "imagemagick-cli",
    "duck-db", "duckdb-core-lib",
    "csv-kit", "csvtools-kit",
    "rip-grep", "ripgrep-bin-linux"
}


def find_tool_for_query(query: str) -> List[Dict[str, Any]]:
    """Match task keywords against vetted tool catalog."""
    query_lower = query.lower()
    matches = []
    
    for name, info in VETTED_TOOLS.items():
        score = 0
        if name in query_lower:
            score += 10
        if info["binary"] in query_lower:
            score += 8
        for kw in info["keywords"]:
            if kw in query_lower:
                score += 5
            elif any(word in query_lower for word in kw.split()):
                score += 1
                
        if score > 0:
            item = dict(info)
            item["tool_name"] = name
            item["match_score"] = score
            item["is_installed"] = shutil.which(info["binary"]) is not None
            matches.append(item)
            
    matches.sort(key=lambda x: x["match_score"], reverse=True)
    return matches


def check_tool_status(tool_name: str) -> Dict[str, Any]:
    """Check if tool binary is available in PATH via shutil.which."""
    info = VETTED_TOOLS.get(tool_name)
    binary = info["binary"] if info else tool_name
    path = shutil.which(binary)
    
    return {
        "tool_name": tool_name,
        "binary": binary,
        "installed": path is not None,
        "path": path,
        "category": info["category"] if info else "unknown",
        "install_cmd": info["install_cmd"] if info else f"Check package manager for '{binary}'",
        "sample_cmd": info["sample_cmd"] if info else None
    }


def audit_package_security(package_name: str, manager: str = "apt") -> Dict[str, Any]:
    """Audit candidate package against catalog, typosquatting, and offline policy."""
    findings = []
    
    # 1. Typosquat check
    if package_name.lower() in KNOWN_TYPOSQUATS:
        findings.append(f"CRITICAL: Package name '{package_name}' matches known typosquatting blacklist.")
        return {
            "package": package_name,
            "manager": manager,
            "risk_level": "CRITICAL",
            "safe_to_install": False,
            "findings": findings
        }
        
    # 2. Check if it is in our canonical catalog
    vetted_match = next((v for k, v in VETTED_TOOLS.items() if v["package"] == package_name or k == package_name), None)
    if vetted_match:
        findings.append(f"INFO: Recognized canonical tool in '{vetted_match['category']}' category.")
        findings.append(f"INFO: Offline execution safe: {vetted_match['offline_safe']}")
        return {
            "package": package_name,
            "manager": vetted_match["manager"],
            "risk_level": "SAFE",
            "safe_to_install": True,
            "offline_safe": vetted_match["offline_safe"],
            "recommended_binary": vetted_match["binary"],
            "sample_usage": vetted_match["sample_cmd"],
            "install_cmd": vetted_match["install_cmd"],
            "findings": findings
        }
        
    # 3. Third-party unverified package
    findings.append(f"WARN: Package '{package_name}' is not in the pre-vetted catalog.")
    findings.append("WARN: Human verification of package source and license required.")
    return {
        "package": package_name,
        "manager": manager,
        "risk_level": "WARN",
        "safe_to_install": False,
        "findings": findings
    }


def plan_installation(tool_name: str) -> Dict[str, Any]:
    """Generate safe, reviewed installation plan for human or agent execution."""
    audit = audit_package_security(tool_name)
    if not audit["safe_to_install"]:
        return {
            "success": False,
            "error": f"Tool '{tool_name}' failed security audit: Risk Level {audit['risk_level']}",
            "findings": audit["findings"]
        }
        
    status = check_tool_status(tool_name)
    if status["installed"]:
        return {
            "success": True,
            "already_installed": True,
            "binary_path": status["path"],
            "message": f"Tool '{tool_name}' is already installed at {status['path']}."
        }
        
    return {
        "success": True,
        "already_installed": False,
        "package": audit["package"],
        "manager": audit["manager"],
        "install_command": audit.get("install_cmd"),
        "verification_step": f"{audit.get('recommended_binary')} --version",
        "sample_usage": audit.get("sample_usage")
    }


def main():
    parser = argparse.ArgumentParser(description="Tool-First Discovery and Security Gate")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Subcommand: recommend
    p_rec = subparsers.add_parser("recommend", help="Recommend best tool for a task")
    p_rec.add_argument("query", help="Natural language description of the mechanical task")
    
    # Subcommand: check
    p_chk = subparsers.add_parser("check", help="Check if tool is installed in PATH")
    p_chk.add_argument("tool", help="Tool name or binary")
    
    # Subcommand: audit
    p_aud = subparsers.add_parser("audit", help="Audit package provenance and security")
    p_aud.add_argument("package", help="Package or tool name to audit")
    p_aud.add_argument("--manager", default="apt", choices=["apt", "uv", "bun", "cargo"], help="Target package manager")
    
    # Subcommand: plan
    p_pln = subparsers.add_parser("plan", help="Generate audited installation plan")
    p_pln.add_argument("tool", help="Tool name from vetted catalog")

    args = parser.parse_args()
    
    if args.command == "recommend":
        matches = find_tool_for_query(args.query)
        if args.json:
            print(json.dumps(matches, indent=2))
        else:
            if not matches:
                print(f"❌ No canonical tool match found for task: '{args.query}'")
                print("💡 Recommendation: Consult tool_matrix.md or search official repositories.")
            else:
                print(f"🎯 Recommended Tools for task: '{args.query}':\n")
                for m in matches[:3]:
                    status = "✅ INSTALLED" if m["is_installed"] else "⬇️  NEEDS INSTALL"
                    print(f"• Tool: {m['tool_name']} [{m['category'].upper()}] - {status}")
                    print(f"  Description: {m['description']}")
                    print(f"  Package: {m['package']} (via {m['manager']})")
                    print(f"  Install: {m['install_cmd']}")
                    print(f"  Sample: {m['sample_cmd']}\n")
                    
    elif args.command == "check":
        res = check_tool_status(args.tool)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            if res["installed"]:
                print(f"✅ Tool '{args.tool}' is INSTALLED at: {res['path']}")
                if res["sample_cmd"]:
                    print(f"   Usage: {res['sample_cmd']}")
            else:
                print(f"❌ Tool '{args.tool}' is NOT installed.")
                print(f"💡 Recommended installation: {res['install_cmd']}")

    elif args.command == "audit":
        audit = audit_package_security(args.package, args.manager)
        if args.json:
            print(json.dumps(audit, indent=2))
        else:
            print(f"🛡️  Security Pre-Flight Audit for '{args.package}' [{args.manager}]:")
            print(f"• Risk Level: {audit['risk_level']}")
            print(f"• Safe to Install: {'YES' if audit['safe_to_install'] else 'NO'}")
            print("• Findings:")
            for f in audit["findings"]:
                print(f"  - {f}")
                
    elif args.command == "plan":
        plan = plan_installation(args.tool)
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            if not plan["success"]:
                print(f"⛔ Security Warning: {plan['error']}")
                for f in plan.get("findings", []):
                    print(f"  - {f}")
                sys.exit(1)
            elif plan.get("already_installed"):
                print(f"✅ {plan['message']}")
            else:
                print(f"📋 Audited Installation Plan for '{args.tool}':")
                print(f"• Package: {plan['package']} (via {plan['manager']})")
                print(f"• Command: {plan['install_command']}")
                print(f"• Verify:  {plan['verification_step']}")
                print(f"• Sample:  {plan['sample_usage']}")


if __name__ == "__main__":
    main()

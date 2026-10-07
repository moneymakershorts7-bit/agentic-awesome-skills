"""
AST and Structural Code Declaration Extractor
Extracts functions, classes, signatures, docstrings, and imports
without flooding the context window with full raw files.
Supports Python (native AST) and regex-based AST extractors for TS/JS, Go, Rust.
"""

from __future__ import annotations
import ast
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class CodeDeclaration:
    """Represents an extracted structural declaration (function, class, type, or block)."""
    kind: str  # 'function', 'class', 'type', 'interface', 'method', 'constant'
    name: str
    signature: str
    docstring: Optional[str]
    start_line: int
    end_line: int
    file_path: str
    body_snippet: str
    calls: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    relevance_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "signature": self.signature,
            "docstring": self.docstring,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "file_path": self.file_path,
            "body_snippet": self.body_snippet,
            "calls": self.calls,
            "imports": self.imports,
            "relevance_score": self.relevance_score
        }


class CodebaseExtractor:
    """Extracts structural code units and relationship tokens across source languages."""

    @staticmethod
    def extract_declarations(file_path: str, content: str, max_lines_per_decl: int = 40) -> List[CodeDeclaration]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".py":
            return CodebaseExtractor._extract_python(file_path, content, max_lines_per_decl)
        elif ext in [".ts", ".tsx", ".js", ".jsx", ".mjs"]:
            return CodebaseExtractor._extract_js_ts(file_path, content, max_lines_per_decl)
        elif ext == ".go":
            return CodebaseExtractor._extract_go(file_path, content, max_lines_per_decl)
        elif ext == ".rs":
            return CodebaseExtractor._extract_rust(file_path, content, max_lines_per_decl)
        else:
            return CodebaseExtractor._extract_generic_chunks(file_path, content, max_lines_per_decl)

    @staticmethod
    def _extract_python(file_path: str, content: str, max_lines: int) -> List[CodeDeclaration]:
        declarations: List[CodeDeclaration] = []
        lines = content.splitlines()

        try:
            tree = ast.parse(content, filename=file_path)
        except Exception:
            # If invalid syntax or partial snippet, fallback to chunk extraction
            return CodebaseExtractor._extract_generic_chunks(file_path, content, max_lines)

        file_imports: List[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    file_imports.append(f"{mod}.{alias.name}")

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", start + len(node.body))
                doc = ast.get_docstring(node)
                
                # Extract calls inside function
                calls: List[str] = []
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Name):
                            calls.append(sub.func.id)
                        elif isinstance(sub.func, ast.Attribute):
                            calls.append(sub.func.attr)

                # Signature
                args = [a.arg for a in node.args.args]
                sig = f"def {node.name}({', '.join(args)})"
                if isinstance(node, ast.AsyncFunctionDef):
                    sig = "async " + sig

                body_lines = lines[start - 1: min(end, start - 1 + max_lines)]
                snippet = "\n".join(body_lines)

                declarations.append(CodeDeclaration(
                    kind="function",
                    name=node.name,
                    signature=sig,
                    docstring=doc,
                    start_line=start,
                    end_line=end,
                    file_path=file_path,
                    body_snippet=snippet,
                    calls=list(set(calls)),
                    imports=file_imports
                ))

            elif isinstance(node, ast.ClassDef):
                start = node.lineno
                end = getattr(node, "end_lineno", start + len(node.body))
                doc = ast.get_docstring(node)
                bases = [ast.unparse(b) if hasattr(ast, "unparse") else getattr(b, "id", "") for b in node.bases]
                sig = f"class {node.name}({', '.join(filter(None, bases))})"

                body_lines = lines[start - 1: min(end, start - 1 + max_lines)]
                snippet = "\n".join(body_lines)

                declarations.append(CodeDeclaration(
                    kind="class",
                    name=node.name,
                    signature=sig,
                    docstring=doc,
                    start_line=start,
                    end_line=end,
                    file_path=file_path,
                    body_snippet=snippet,
                    imports=file_imports
                ))

        return declarations

    @staticmethod
    def _extract_js_ts(file_path: str, content: str, max_lines: int) -> List[CodeDeclaration]:
        declarations: List[CodeDeclaration] = []
        lines = content.splitlines()

        # Extract top imports
        imports = re.findall(r'(?:import|from)\s+[\'"]([^\'"]+)[\'"]', content)

        # Regex for functions, methods, classes, interfaces
        decl_pattern = re.compile(
            r'^(?:export\s+)?(?:async\s+)?(?:function\*?|class|interface|type|const|let)\s+([A-Za-z0-9_$]+)',
            re.MULTILINE
        )

        for match in decl_pattern.finditer(content):
            name = match.group(1)
            char_idx = match.start()
            line_idx = content[:char_idx].count('\n') + 1
            start = line_idx
            end = min(len(lines), start + max_lines)

            body_lines = lines[start - 1: end]
            first_line = body_lines[0].strip() if body_lines else ""
            
            kind = "declaration"
            if "class" in first_line:
                kind = "class"
            elif "function" in first_line:
                kind = "function"
            elif "interface" in first_line:
                kind = "interface"
            elif "type" in first_line:
                kind = "type"

            declarations.append(CodeDeclaration(
                kind=kind,
                name=name,
                signature=first_line,
                docstring=None,
                start_line=start,
                end_line=end,
                file_path=file_path,
                body_snippet="\n".join(body_lines),
                imports=imports
            ))

        return declarations if declarations else CodebaseExtractor._extract_generic_chunks(file_path, content, max_lines)

    @staticmethod
    def _extract_go(file_path: str, content: str, max_lines: int) -> List[CodeDeclaration]:
        declarations: List[CodeDeclaration] = []
        lines = content.splitlines()
        decl_pattern = re.compile(r'^(?:func\s+(?:\([^)]+\)\s+)?([A-Za-z0-9_]+)|type\s+([A-Za-z0-9_]+)\s+struct)', re.MULTILINE)

        for match in decl_pattern.finditer(content):
            name = match.group(1) or match.group(2)
            char_idx = match.start()
            line_idx = content[:char_idx].count('\n') + 1
            start = line_idx
            end = min(len(lines), start + max_lines)

            body_lines = lines[start - 1: end]
            sig = body_lines[0].strip() if body_lines else ""
            kind = "function" if sig.startswith("func") else "struct"

            declarations.append(CodeDeclaration(
                kind=kind,
                name=name,
                signature=sig,
                docstring=None,
                start_line=start,
                end_line=end,
                file_path=file_path,
                body_snippet="\n".join(body_lines)
            ))

        return declarations if declarations else CodebaseExtractor._extract_generic_chunks(file_path, content, max_lines)

    @staticmethod
    def _extract_rust(file_path: str, content: str, max_lines: int) -> List[CodeDeclaration]:
        declarations: List[CodeDeclaration] = []
        lines = content.splitlines()
        decl_pattern = re.compile(r'^(?:pub\s+)?(?:async\s+)?(?:fn|struct|enum|trait|impl)\s+([A-Za-z0-9_]+)', re.MULTILINE)

        for match in decl_pattern.finditer(content):
            name = match.group(1)
            char_idx = match.start()
            line_idx = content[:char_idx].count('\n') + 1
            start = line_idx
            end = min(len(lines), start + max_lines)

            body_lines = lines[start - 1: end]
            sig = body_lines[0].strip() if body_lines else ""

            declarations.append(CodeDeclaration(
                kind="declaration",
                name=name,
                signature=sig,
                docstring=None,
                start_line=start,
                end_line=end,
                file_path=file_path,
                body_snippet="\n".join(body_lines)
            ))

        return declarations if declarations else CodebaseExtractor._extract_generic_chunks(file_path, content, max_lines)

    @staticmethod
    def _extract_generic_chunks(file_path: str, content: str, chunk_size: int = 50) -> List[CodeDeclaration]:
        lines = content.splitlines()
        if not lines:
            return []

        declarations: List[CodeDeclaration] = []
        for i in range(0, len(lines), chunk_size):
            chunk_lines = lines[i: i + chunk_size]
            start = i + 1
            end = i + len(chunk_lines)
            snippet = "\n".join(chunk_lines)
            declarations.append(CodeDeclaration(
                kind="chunk",
                name=f"lines_{start}_{end}",
                signature=f"{os.path.basename(file_path)}:L{start}-L{end}",
                docstring=None,
                start_line=start,
                end_line=end,
                file_path=file_path,
                body_snippet=snippet
            ))
        return declarations

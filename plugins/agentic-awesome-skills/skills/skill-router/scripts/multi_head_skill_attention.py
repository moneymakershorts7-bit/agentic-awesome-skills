#!/usr/bin/env python3
"""
multi_head_skill_attention.py
------------------------------
2-Stage Hierarchical Multi-Head Skill Attention Router.
Projects tasks into Domain, Action, and Runtime subspaces, applies MMR diversity,
and routes 3,366+ skills to top-k (k=5) high-relevance activations with zero prompt bloat.
"""

import os
import re
import math
import sys
from collections import Counter
from pathlib import Path

SKILLS_DIR = Path(os.path.expanduser("~/.agents/skills")).resolve()

HEAD_VOCABULARIES = {
    "domain": {
        "security": ["security", "vuln", "pentest", "cve", "auth", "sast", "dast", "audit", "hunt", "injection", "crypto"],
        "media": ["video", "audio", "tts", "ffmpeg", "remotion", "render", "animation", "narrator", "clip", "subtitles"],
        "frontend": ["react", "nextjs", "css", "tailwind", "ui", "ux", "component", "design", "dom", "html", "icons"],
        "devops": ["docker", "k8s", "kubernetes", "cloud", "aws", "cloudflare", "ci", "git", "github", "pipeline", "deploy"],
        "data_ml": ["model", "llm", "rag", "torch", "kaggle", "benchmark", "dataset", "agent", "inference", "eval"],
    },
    "action": {
        "audit": ["audit", "inspect", "scan", "check", "verify", "review", "evaluate", "lint"],
        "generate": ["generate", "build", "create", "scaffold", "synthesize", "produce", "author"],
        "optimize": ["optimize", "tune", "speed", "performance", "compress", "cache", "latency", "scale"],
        "refactor": ["refactor", "clean", "rewrite", "simplify", "reorganize", "migrate"],
        "reverse": ["reverse", "decompile", "disassemble", "intercept", "pcap", "unpack"],
    },
    "runtime": {
        "python": ["python", "uv", "pip", "pytest", "fastapi", "numpy", "pandas"],
        "node_bun": ["bun", "node", "typescript", "npm", "javascript", "vitest"],
        "headless_browser": ["playwright", "puppeteer", "browser", "brave", "chromium", "scrape"],
        "edge_worker": ["worker", "cloudflare", "wrangler", "kv", "d1", "r2"],
        "linux_cli": ["bash", "shell", "posix", "terminal", "systemd", "kernel"],
    }
}

def tokenize(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9_-]{2,}", text.lower())]

class MultiHeadSkillAttention:
    def __init__(self, skills_dir: Path = SKILLS_DIR):
        self.skills_dir = skills_dir
        self.skills = []
        self.index_skills()

    def index_skills(self):
        for s_dir in self.skills_dir.iterdir():
            if not s_dir.is_dir():
                continue
            skill_md = s_dir / "SKILL.md"
            if not skill_md.exists():
                continue
            
            s_name = s_dir.name
            parts = s_name.split("-")
            family = "-".join(parts[:2]) if len(parts) >= 2 else parts[0]
            
            header_sample = skill_md.read_text(encoding="utf-8", errors="ignore")[:600].lower()
            toks = tokenize(f"{s_name} {header_sample}")
            
            self.skills.append({
                "name": s_name,
                "family": family,
                "path": str(skill_md),
                "tokens": set(toks),
                "tok_counts": Counter(toks)
            })

    def project_subspace(self, q_toks: Counter, vocab_map: dict) -> str:
        best_cluster = None
        max_overlap = 0
        for cluster, words in vocab_map.items():
            overlap = sum(q_toks[w] for w in words if w in q_toks)
            if overlap > max_overlap:
                max_overlap = overlap
                best_cluster = cluster
        return best_cluster

    def route(self, query: str, top_k: int = 5, mmr_lambda: float = 0.70) -> list[dict]:
        q_toks = Counter(tokenize(query))
        if not q_toks:
            return []

        target_domain = self.project_subspace(q_toks, HEAD_VOCABULARIES["domain"])
        target_action = self.project_subspace(q_toks, HEAD_VOCABULARIES["action"])
        target_runtime = self.project_subspace(q_toks, HEAD_VOCABULARIES["runtime"])

        domain_bonus_terms = set(HEAD_VOCABULARIES["domain"].get(target_domain, [])) if target_domain else set()
        action_bonus_terms = set(HEAD_VOCABULARIES["action"].get(target_action, [])) if target_action else set()
        runtime_bonus_terms = set(HEAD_VOCABULARIES["runtime"].get(target_runtime, [])) if target_runtime else set()

        d_k = len(q_toks)
        sqrt_dk = math.sqrt(d_k) if d_k > 0 else 1.0

        candidates = []
        for s in self.skills:
            tc = s["tok_counts"]
            dot_product = sum(tc[qt] for qt in q_toks if qt in tc)
            if dot_product == 0:
                continue

            score = dot_product / sqrt_dk

            if s["tokens"] & domain_bonus_terms:
                score += 1.5
            if s["tokens"] & action_bonus_terms:
                score += 1.2
            if s["tokens"] & runtime_bonus_terms:
                score += 0.8
            if any(qt in s["name"] for qt in q_toks):
                score += 3.0

            candidates.append((score, s))

        candidates.sort(key=lambda x: x[0], reverse=True)
        top_candidates = candidates[:25]

        selected = []
        family_counts = Counter()
        for score, s in top_candidates:
            fam = s["family"]
            if family_counts[fam] >= 2:
                continue

            diversity_penalty = (1.0 - mmr_lambda) * (family_counts[fam] * 1.5)
            final_score = score - diversity_penalty

            family_counts[fam] += 1
            selected.append({
                "skill": s["name"],
                "family": fam,
                "attention_score": round(final_score, 2),
                "path": s["path"]
            })

            if len(selected) >= top_k:
                break

        return selected

if __name__ == "__main__":
    router = MultiHeadSkillAttention()
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "audit security vulnerabilities in container"
    results = router.route(query)
    print(f"Query: '{query}' -> Top-{len(results)} Skills Selected:")
    for r in results:
        print(f"  [{r['attention_score']}] {r['skill']} ({r['family']}) -> {r['path']}")

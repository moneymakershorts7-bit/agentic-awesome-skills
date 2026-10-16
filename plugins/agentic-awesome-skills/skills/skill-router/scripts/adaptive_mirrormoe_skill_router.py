#!/usr/bin/env python3
"""
adaptive_mirrormoe_skill_router.py
-----------------------------------
Adaptive MirrorMoE Skill Attention Router for Autonomous Agent Capability Routing.
Based on the theoretical principles of MirrorMoE (arXiv:2610.22353, Li et al., 2026):
  1. Stage 1: Fast Lexical Retrieval Beam (SQLite FTS5 + BM25, Top N=30).
  2. Stage 2: Dual-Head Multi-Representation Attention:
     - Domain, Functionality, and Context orthogonal projection heads.
     - Softmax exploitation distribution: xi_i = softmax(s_i / tau).
     - Mirrored exploration distribution: zeta_i = softmax(-s_i / tau) = (1/xi_i) / sum(1/xi_j).
     - Blended activation probability: p_i = (1 - rho) * xi_i + rho * zeta_i.
  3. Stage 3: Dynamic Effective Capacity (K_eff) & Token-Adaptive Suppression:
     - Candidate selection via blended p_i, but aggregation and ranking strictly via xi_i.
     - Exponential Shannon entropy: K_eff = exp(-sum xi_bar * ln xi_bar) in [1.0, top_k].
     - Dynamic threshold gate: Keep skill i iff xi_bar_i >= gamma / K_eff.
     - Trivial queries automatically collapse to 1 expert (80% token savings);
       complex multi-domain queries expand up to full capacity with zero clumping.

Dependencies: 100% Python Standard Library (sqlite3, math, re, collections, dataclasses). Zero external packages.
"""

import os
import re
import math
import time
import json
import sqlite3
import argparse
from pathlib import Path
from collections import Counter
from dataclasses import dataclass

SKILLS_DIR = Path(os.path.expanduser("~/.agents/skills")).resolve()
DB_PATH = Path(os.path.expanduser("~/.agents/memory/skills_fts.db")).resolve()

HEAD_VOCABULARIES = {
    "domain": {
        "security": ["security", "vuln", "vulnerabilities", "pentest", "penetration", "cve", "auth", "sast", "dast", "audit", "hunt", "injection", "crypto", "iam", "cloud", "reverse", "apk", "reentrancy", "semgrep", "trivy"],
        "media": ["video", "audio", "tts", "ffmpeg", "remotion", "render", "animation", "narrator", "clip", "subtitles", "captions", "transcode", "trim", "mp4"],
        "frontend": ["react", "nextjs", "css", "tailwind", "ui", "ux", "component", "design", "dom", "html", "icons", "scaffold", "dark", "threejs", "3d", "favicon"],
        "devops": ["docker", "k8s", "kubernetes", "cloud", "aws", "cloudflare", "ci", "git", "github", "pipeline", "deploy", "container", "hardening", "actions", "cd"],
        "data_ml": ["model", "llm", "rag", "torch", "kaggle", "benchmark", "dataset", "agent", "inference", "eval", "postgres", "postgresql", "database", "supabase", "drizzle", "sql"],
    },
    "functionality": {
        "audit": ["audit", "inspect", "scan", "check", "verify", "review", "evaluate", "lint", "testing", "pentest", "hunt"],
        "generate": ["generate", "build", "create", "scaffold", "synthesize", "produce", "author", "develop", "construct"],
        "optimize": ["optimize", "tune", "speed", "performance", "compress", "cache", "latency", "scale"],
        "refactor": ["refactor", "clean", "rewrite", "simplify", "reorganize", "migrate"],
        "reverse": ["reverse", "decompile", "disassemble", "intercept", "pcap", "unpack", "extract"],
    },
    "context": {
        "python": ["python", "uv", "pip", "pytest", "fastapi", "numpy", "pandas"],
        "node_bun": ["bun", "node", "typescript", "npm", "javascript", "vitest", "react", "expo", "threejs", "drizzle"],
        "headless_browser": ["playwright", "puppeteer", "browser", "brave", "chromium", "scrape"],
        "edge_worker": ["worker", "workers", "cloudflare", "wrangler", "kv", "d1", "r2"],
        "linux_cli": ["bash", "shell", "posix", "terminal", "systemd", "kernel", "cli", "gh", "defuddle", "git"],
        "mobile": ["expo", "react-native", "android", "ios", "apk"],
        "cloud": ["aws", "iam", "s3", "gcp", "azure", "k8s", "docker"]
    }
}

def tokenize(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9_-]{2,}", text.lower())]

@dataclass
class RoutedSkill:
    skill: str
    family: str
    path: str
    raw_score: float
    xi_bar: float
    is_suppressed: bool

class AdaptiveMirrorMoERouter:
    def __init__(self, skills_dir: Path = SKILLS_DIR, db_path: Path = DB_PATH):
        self.skills_dir = skills_dir
        self.db_path = db_path
        self.skills_meta = {}
        self.conn = None
        self.init_database()

    def init_database(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS skills_meta (
                name TEXT PRIMARY KEY,
                family TEXT NOT NULL,
                path TEXT NOT NULL,
                total_tokens INTEGER NOT NULL
            );
        """)
        cur.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS skills_fts USING fts5(
                name,
                family,
                content,
                tokenize = "porter unicode61"
            );
        """)
        self.conn.commit()
        
        cur.execute("SELECT count(*) FROM skills_meta;")
        count = cur.fetchone()[0]
        if count == 0:
            self.sync_index()
        else:
            self.load_metadata()

    def sync_index(self):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM skills_meta;")
        cur.execute("DELETE FROM skills_fts;")
        
        skills_loaded = 0
        for s_dir in self.skills_dir.iterdir():
            if not s_dir.is_dir():
                continue
            s_md = s_dir / "SKILL.md"
            if not s_md.exists():
                continue
            
            name = s_dir.name
            parts = name.split("-")
            family = "-".join(parts[:2]) if len(parts) >= 2 else parts[0]
            txt = s_md.read_text(encoding="utf-8", errors="ignore")[:800].lower()
            toks = tokenize(f"{name} {txt}")
            total_toks = max(len(toks), 10)

            cur.execute(
                "INSERT INTO skills_meta(name, family, path, total_tokens) VALUES (?, ?, ?, ?)",
                (name, family, str(s_md), total_toks)
            )
            cur.execute(
                "INSERT INTO skills_fts(name, family, content) VALUES (?, ?, ?)",
                (name, family, txt)
            )
            skills_loaded += 1

        self.conn.commit()
        self.load_metadata()

    def load_metadata(self):
        cur = self.conn.cursor()
        cur.execute("SELECT name, family, path, total_tokens FROM skills_meta;")
        for name, fam, p, tot in cur.fetchall():
            self.skills_meta[name] = {
                "name": name,
                "family": fam,
                "path": p,
                "name_tokens": set(name.split("-")),
                "total_tokens": tot
            }

    def project_subspace(self, q_toks: Counter, vocab_map: dict) -> tuple[str | None, int]:
        best = None
        max_overlap = 0
        for cluster, words in vocab_map.items():
            ov = sum(q_toks[w] for w in words if w in q_toks)
            if ov > max_overlap:
                max_overlap = ov
                best = cluster
        return best, max_overlap

    def route(
        self,
        query: str,
        tau: float = 2.5,
        rho: float = 0.04,
        gamma: float = 0.52,
        top_n: int = 30,
        top_k: int = 5,
        mmr_lambda: float = 0.75
    ) -> dict:
        q_raw = tokenize(query)
        q_toks = Counter(q_raw)
        if not q_toks:
            return {"query": query, "latency_ms": 0.0, "k_eff": 0.0, "t_prune": 0.0, "skills": []}

        t0 = time.perf_counter()

        # Step 1: Lexical Retrieval Beam (Stage 1)
        expanded = list(q_raw)
        for i in range(len(q_raw) - 1):
            expanded.append(f"{q_raw[i]}{q_raw[i+1]}")
        terms = [re.sub(r"[^a-zA-Z0-9]", "", w) for w in expanded if len(w) >= 3]
        fts_terms = [f"{t}*" for t in set(terms)]
        fts_q = " OR ".join(fts_terms)

        cur = self.conn.cursor()
        try:
            cur.execute(
                "SELECT name, family, bm25(skills_fts) FROM skills_fts WHERE skills_fts MATCH ? ORDER BY bm25(skills_fts) LIMIT ?;",
                (fts_q, top_n)
            )
            stage1_cands = cur.fetchall()
        except sqlite3.OperationalError:
            stage1_cands = []

        if not stage1_cands:
            return {"query": query, "latency_ms": 0.0, "k_eff": 0.0, "t_prune": 0.0, "skills": []}

        # Step 2: Multi-Head Subspace Attention (Stage 2)
        dom_target, _ = self.project_subspace(q_toks, HEAD_VOCABULARIES["domain"])
        func_target, _ = self.project_subspace(q_toks, HEAD_VOCABULARIES["functionality"])
        ctx_target, _ = self.project_subspace(q_toks, HEAD_VOCABULARIES["context"])

        dom_terms = set(HEAD_VOCABULARIES["domain"].get(dom_target, [])) if dom_target else set()
        func_terms = set(HEAD_VOCABULARIES["functionality"].get(func_target, [])) if func_target else set()
        ctx_terms = set(HEAD_VOCABULARIES["context"].get(ctx_target, [])) if ctx_target else set()

        sqrt_dq = math.sqrt(len(q_toks)) if q_toks else 1.0

        scored = []
        for name, fam, bm in stage1_cands:
            meta = self.skills_meta.get(name)
            if not meta:
                continue
            
            # Load tokens on-demand for candidate
            try:
                cand_text = Path(meta["path"]).read_text(encoding="utf-8", errors="ignore")[:800].lower()
                cand_toks = Counter(tokenize(f"{name} {cand_text}"))
            except Exception:
                cand_toks = Counter()

            dot = sum(cand_toks[qt] for qt in q_toks if qt in cand_toks)
            name_ov = len(set(expanded) & meta["name_tokens"])
            exact_match = 1.0 if name in q_raw or any(w == name for w in expanded) else 0.0

            # Length-normalized attention dot product
            norm_factor = sqrt_dq * math.sqrt(meta["total_tokens"])
            dot_norm = (dot / norm_factor) * 12.0

            score = dot_norm + (name_ov * 4.0) + (exact_match * 8.0) + (abs(bm) * 0.15)
            cand_tokens_set = set(cand_toks.keys())
            if cand_tokens_set & dom_terms:
                score += 2.0
            if cand_tokens_set & func_terms:
                score += 1.5
            if cand_tokens_set & ctx_terms:
                score += 1.0

            scored.append((name, fam, score, meta["path"]))

        # Softmax exploitation (xi) and Mirrored exploration (zeta)
        scores = [x[2] for x in scored]
        max_s = max(scores)
        exp_s = [math.exp((s - max_s) / tau) for s in scores]
        sum_exp_s = sum(exp_s)
        xi = [e / sum_exp_s for e in exp_s]

        min_s = min(scores)
        exp_neg = [math.exp((min_s - s) / tau) for s in scores]
        sum_exp_neg = sum(exp_neg)
        zeta = [e / sum_exp_neg for e in exp_neg]

        # Blended activation probability: p_i = (1 - rho) * xi_i + rho * zeta_i
        p = [(1.0 - rho) * xi[i] + rho * zeta[i] for i in range(len(xi))]

        # Step 3: Dynamic Effective Capacity & Token-Adaptive Suppression (Stage 3)
        cand_indices = sorted(range(len(p)), key=lambda i: p[i], reverse=True)[:top_k * 2]
        
        # Diversity gating (MMR)
        active_sorted = sorted(cand_indices, key=lambda i: xi[i], reverse=True)
        diverse_active = []
        fam_counts = Counter()
        for i in active_sorted:
            fam = scored[i][1]
            if fam_counts[fam] >= 2:
                continue
            fam_counts[fam] += 1
            diverse_active.append(i)
            if len(diverse_active) >= top_k:
                break

        # Normalized aggregation weights over active set
        active_xi = [xi[i] for i in diverse_active]
        sum_active_xi = sum(active_xi)
        xi_bar = [x / max(sum_active_xi, 1e-12) for x in active_xi]

        # Effective Experts K_eff (exponential Shannon entropy)
        entropy = -sum(xb * math.log(xb) for xb in xi_bar if xb > 0)
        k_eff = math.exp(entropy)

        # Dynamic Pruning Threshold
        t_prune = gamma * (1.0 / k_eff)

        survivors = []
        for idx, i in enumerate(diverse_active):
            xb = xi_bar[idx]
            name, fam, raw_sc, path = scored[i]
            is_pruned = xb < t_prune
            survivors.append(RoutedSkill(
                skill=name,
                family=fam,
                path=path,
                raw_score=round(raw_sc, 2),
                xi_bar=round(xb, 4),
                is_suppressed=is_pruned
            ))

        active_skills = [s for s in survivors if not s.is_suppressed]
        elapsed_ms = (time.perf_counter() - t0) * 1000

        total_cands = len(survivors)
        retained = len(active_skills)
        saved_pct = round(((total_cands - retained) / total_cands) * 100, 1) if total_cands > 0 else 0.0

        return {
            "query": query,
            "latency_ms": round(elapsed_ms, 2),
            "k_eff": round(k_eff, 2),
            "t_prune": round(t_prune, 4),
            "total_candidates": total_cands,
            "retained_count": retained,
            "tokens_saved_pct": saved_pct,
            "skills": [
                {
                    "skill": s.skill,
                    "family": s.family,
                    "path": s.path,
                    "weight": s.xi_bar,
                    "raw_score": s.raw_score
                }
                for s in active_skills
            ]
        }

def main():
    parser = argparse.ArgumentParser(description="Adaptive MirrorMoE Skill Attention Router")
    parser.add_argument("query", nargs="?", default="audit security vulnerabilities in container", help="User task or query")
    parser.add_argument("--sync", action="store_true", help="Sync/rebuild FTS5 database")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--top-k", type=int, default=5, help="Maximum number of active skills")
    parser.add_argument("--tau", type=float, default=2.5, help="Softmax temperature")
    parser.add_argument("--rho", type=float, default=0.04, help="Mirror routing exploration weight")
    parser.add_argument("--gamma", type=float, default=0.52, help="Dynamic pruning ratio")
    args = parser.parse_args()

    router = AdaptiveMirrorMoERouter()
    if args.sync:
        print("🔄 Syncing FTS5 index over skills directory...")
        t_sync = time.perf_counter()
        router.sync_index()
        print(f"✅ Sync complete in {round((time.perf_counter() - t_sync) * 1000, 1)} ms.")

    result = router.route(
        args.query,
        tau=args.tau,
        rho=args.rho,
        gamma=args.gamma,
        top_k=args.top_k
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("=" * 75)
        print(f"🎯 ADAPTIVE MIRROR-MOE ROUTER: '{result['query']}'")
        print(f"⚡ Latency: {result['latency_ms']} ms | K_eff: {result['k_eff']} | Retained: {result['retained_count']}/{result['total_candidates']} ({result['tokens_saved_pct']}% tokens saved)")
        print("=" * 75)
        for i, s in enumerate(result["skills"], 1):
            print(f"[{i}] {s['skill']} ({s['family']}) | Weight: {s['weight']} | Score: {s['raw_score']}")
            print(f"    Path: {s['path']}")
        print("=" * 75)

if __name__ == "__main__":
    main()

import os
import re
import json
import math
import time
from collections import defaultdict, Counter

DEFAULT_TREE_FILE = os.path.expanduser("~/.agents/skills/skill-router/data/index_tree.json")

MCP_SERVER_DOMAINS = {
    "kaggle": ("ai_ml_nvidia_ecosystem", "ml_data_science_models"),
    "playwright": ("automation_scraping_cli", "browser_web_automation"),
    "puppeteer": ("automation_scraping_cli", "browser_web_automation"),
    "agent-browser": ("automation_scraping_cli", "browser_web_automation"),
    "chrome-devtools": ("automation_scraping_cli", "browser_web_automation"),
    "davinci-resolve": ("media_creative_production", "video_editing_generation"),
    "youtube-safe-local": ("media_creative_production", "video_editing_generation"),
    "cloudflare": ("devops_cloud_infrastructure", "cloud_platforms_aws_azure_gcp"),
    "cloudflare-docs": ("devops_cloud_infrastructure", "cloud_platforms_aws_azure_gcp"),
    "github": ("devops_cloud_infrastructure", "ci_cd_gitops"),
    "skillspector": ("compliance_governance_devsecops", "sast_dast_scanning"),
    "memory": ("ai_ml_nvidia_ecosystem", "agent_frameworks_orchestration"),
    "claude-mem": ("ai_ml_nvidia_ecosystem", "agent_frameworks_orchestration"),
}

SYNONYMS = {
    "speed": ["performance", "optimization", "profiling", "fast", "latency", "benchmark"],
    "fast": ["performance", "speed", "optimization", "latency"],
    "slow": ["optimization", "performance", "profiling", "indexing", "leak"],
    "hack": ["pentest", "vulnerability", "exploit", "attack", "redteam", "security"],
    "hacking": ["pentest", "vulnerability", "exploit", "attack", "redteam", "security"],
    "crawl": ["scrape", "scraper", "crawling", "spider", "extraction", "playwright"],
    "crawling": ["scrape", "scraper", "crawl", "extraction", "playwright"],
    "scrape": ["crawl", "scraper", "playwright", "puppeteer", "extraction"],
    "scraping": ["crawl", "scraper", "playwright", "puppeteer", "extraction"],
    "subtitles": ["captions", "transcription", "remotion", "audio"],
    "captions": ["subtitles", "remotion", "transcription", "speech"],
    "k8s": ["kubernetes", "pod", "cluster", "helm", "kustomize", "container"],
    "pod": ["kubernetes", "k8s", "container", "docker"],
    "login": ["auth", "authentication", "session", "jwt", "oauth", "password", "mfa"],
    "db": ["database", "postgres", "mysql", "sql", "orm", "redis", "mongodb"],
    "database": ["db", "postgres", "mysql", "sql", "orm", "indexing"],
    "queries": ["query", "indexing", "sql", "postgres", "optimization"],
    "leak": ["leakage", "memory", "secret", "exposure", "security"],
    "ci": ["ci-cd", "github-actions", "gitlab-ci", "pipeline", "jenkins"],
    "cd": ["ci-cd", "deployment", "pipeline", "gitops", "argocd"],
    "iaas": ["infrastructure", "cloud", "aws", "azure", "gcp", "terraform"],
    "iac": ["terraform", "cloudformation", "pulumi", "sst", "infrastructure"],
    "helm": ["helm-charts", "helm-chart-scaffolding", "kubernetes", "k8s"],
    "charts": ["helm-charts", "helm-chart-scaffolding", "visualization"],
    "chart": ["helm-charts", "helm-chart-scaffolding", "visualization"]
}

STOPWORDS = set([
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "what",
    "which", "this", "that", "these", "those", "then", "just", "so", "than",
    "such", "both", "through", "about", "for", "is", "of", "while", "during",
    "to", "from", "in", "out", "on", "off", "again", "further", "then", "once",
    "here", "there", "when", "where", "why", "how", "all", "any", "each",
    "few", "more", "most", "other", "some", "no", "nor", "not", "only",
    "own", "same", "too", "very", "can", "will", "don", "should", "now",
    "using", "with", "into", "use", "make", "help", "want", "need", "build", "set"
])

def advanced_tokenize(text: str):
    raw_words = re.findall(r"[a-zA-Z0-9_#+.-]{1,}", text.lower())
    tokens = []
    for w in raw_words:
        if w in ["c", "r", "go", "k8s", "c++", "c#", "ui", "ux", "db", "ci", "cd"]:
            tokens.append(w)
            continue
        parts = re.split(r"[-_.]", w)
        for p in parts:
            if len(p) >= 2 and p not in STOPWORDS:
                tokens.append(p)
        if len(w) >= 2 and w not in STOPWORDS:
            tokens.append(w)
            
    expanded = list(tokens)
    for t in tokens:
        if t in SYNONYMS:
            expanded.extend(SYNONYMS[t])
    return expanded

class ProductionHierarchicalEngine:
    def __init__(self, tree_path=DEFAULT_TREE_FILE):
        self.tree_path = tree_path
        self.reload_tree()

    def reload_tree(self):
        if not os.path.exists(self.tree_path):
            raise FileNotFoundError(f"Tree index not found at {self.tree_path}")
        with open(self.tree_path, "r", encoding="utf-8") as f:
            self.tree = json.load(f)

        self.doc_freq = Counter()
        self.total_docs = 0
        self.items = []
        self.inverted_index = defaultdict(list)

        for d_k, d_v in self.tree["domains"].items():
            for sub_k, sub_v in d_v["subcategories"].items():
                for item in sub_v["skills"] + sub_v["tools"]:
                    item_id = item["id"]
                    item_type = item.get("type", "skill")
                    item_desc = item.get("description", "")
                    
                    parts = item_id.split("-")
                    family = "-".join(parts[:2]) if len(parts) >= 2 else parts[0]
                    if item_type == "mcp_tool":
                        srv = item.get("server", "mcp")
                        family = f"mcp_{srv}"

                    toks = advanced_tokenize(f"{item_id} {item_id} {d_k} {sub_k} {family} {item_desc}")
                    unique_toks = set(toks)
                    item_idx = len(self.items)

                    for t in unique_toks:
                        self.doc_freq[t] += 1
                        self.inverted_index[t].append(item_idx)
                        
                    self.items.append({
                        "id": item_id,
                        "type": item_type,
                        "family": family,
                        "domain": d_k,
                        "subcat": sub_k,
                        "tokens": toks,
                        "tok_counts": Counter(toks),
                        "desc": item_desc
                    })
                    self.total_docs += 1

    def idf(self, term: str) -> float:
        df = self.doc_freq.get(term, 0)
        return math.log(1.0 + (self.total_docs - df + 0.5) / (df + 0.5))

    def route(self, query: str, top_k: int = 10, diversity_limit: int = 2):
        q_tokens = advanced_tokenize(query)
        if not q_tokens:
            return {
                "primary_domain": "backend_systems_databases",
                "ranked_domains": [("backend_systems_databases", 1.0)],
                "active_domains": ["backend_systems_databases"],
                "recommendations": []
            }

        candidate_indices = set()
        for qt in q_tokens:
            if qt in self.inverted_index:
                candidate_indices.update(self.inverted_index[qt])

        domain_accum = Counter()
        item_scores = []

        for idx in candidate_indices:
            item = self.items[idx]
            tok_counts = item["tok_counts"]
            score = 0.0
            for qt in q_tokens:
                if qt in tok_counts:
                    tf = tok_counts[qt]
                    idf_val = self.idf(qt)
                    boost = 8.0 if qt in item["id"].lower() else 1.8
                    score += idf_val * (tf / (tf + 1.2)) * boost

            if score > 0:
                item_scores.append((score, item))
                domain_accum[item["domain"]] += score

        item_scores.sort(key=lambda x: x[0], reverse=True)
        ranked_domains = domain_accum.most_common(3)
        primary_domain = ranked_domains[0][0] if ranked_domains else "backend_systems_databases"

        multi_domain_union = False
        active_domains = [primary_domain]
        if len(ranked_domains) > 1:
            top_score = ranked_domains[0][1]
            sec_domain, sec_score = ranked_domains[1]
            if top_score > 0 and ((top_score - sec_score) / top_score) < 0.25:
                multi_domain_union = True
                active_domains.append(sec_domain)

        family_counts = Counter()
        mcp_server_counts = Counter()
        final_candidates = []

        for score, item in item_scores:
            fam = item["family"]
            itype = item["type"]
            
            if family_counts[fam] >= diversity_limit:
                continue
                
            if itype == "mcp_tool":
                srv = fam.replace("mcp_", "")
                if mcp_server_counts[srv] >= diversity_limit:
                    continue
                mcp_server_counts[srv] += 1

            family_counts[fam] += 1
            final_candidates.append({
                "id": item["id"],
                "type": itype,
                "domain": item["domain"],
                "subcat": item["subcat"],
                "family": fam,
                "score": round(score, 2),
                "description": item["desc"]
            })

            if len(final_candidates) >= top_k:
                break

        return {
            "query": query,
            "primary_domain": primary_domain,
            "ranked_domains": ranked_domains,
            "multi_domain_union_active": multi_domain_union,
            "active_domains": active_domains,
            "recommendations": final_candidates
        }

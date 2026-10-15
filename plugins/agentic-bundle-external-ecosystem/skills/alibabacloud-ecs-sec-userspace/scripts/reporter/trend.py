"""Trend Analysis Module: Analyzes historical reports to generate security trends."""
import json
import os
import logging
from datetime import date, timedelta
from typing import List

logger = logging.getLogger("sec-userspace")


class TrendAnalyzer:
    """Analyzes N days of historical JSON reports to generate security trends."""

    def __init__(self, base_dir: str = "/data/sec-userspace/workspace", days: int = 7):
        self.base_dir = base_dir
        self.days = days

    def analyze(self) -> dict:
        """Analyzes trends and returns structured results."""
        reports = self._load_history()
        if len(reports) < 2:
            return {
                "available": False,
                "reason": f"历史报告不足（需至少 2 天，当前{len(reports)}天）",
                "reports_found": len(reports),
            }

        scores = [(r["date"], r["total_score"]) for r in reports]
        trend_direction = self._calc_trend(scores)

        # Persistent issues: Evidence titles appearing 3+ consecutive days
        persistent = self._find_persistent_issues(reports)

        # New issues: Evidence titles in latest report but not in previous day
        new_issues = self._find_new_issues(reports)

        # Resolved issues: Evidence titles in previous day but not in latest report
        resolved = self._find_resolved_issues(reports)

        latest = reports[-1]
        return {
            "available": True,
            "period": f"{reports[0]['date']} ~ {reports[-1]['date']}",
            "reports_analyzed": len(reports),
            "trend_direction": trend_direction,
            "latest_score": latest["total_score"],
            "latest_conclusion": latest.get("conclusion", ""),
            "score_history": scores,
            "persistent_issues": persistent,
            "new_issues": new_issues,
            "resolved_issues": resolved,
        }

    def generate_markdown(self, trend: dict) -> str:
        """Generates trend report in Markdown format (Chinese output for users)."""
        if not trend.get("available"):
            return f"# 安全趋势报告\n\n{trend.get('reason', '数据不足')}\n"

        lines = [
            "# 安全趋势报告",
            "",
            f"- **分析周期**: {trend['period']}",
            f"- **报告数量**: {trend['reports_analyzed']} 份",
            f"- **趋势方向**: {trend['trend_direction']}",
            f"- **最新评分**: {trend['latest_score']}/100",
            f"- **最新结论**: {trend['latest_conclusion']}",
            "",
            "## 评分变化",
            "",
            "| 日期 | 风险评分 |",
            "|------|---------|",
        ]
        for d, s in trend["score_history"]:
            lines.append(f"| {d} | {s} |")

        if trend["persistent_issues"]:
            lines.extend(["", "## 持续存在的问题", ""])
            for issue in trend["persistent_issues"]:
                lines.append(
                    f"- **{issue['title']}** (持续 {issue['days']} 天，"
                    f"最高严重度：{issue['max_severity']})"
                )

        if trend["new_issues"]:
            lines.extend(["", "## 新增问题", ""])
            for title in trend["new_issues"]:
                lines.append(f"- {title}")

        if trend["resolved_issues"]:
            lines.extend(["", "## 已解决问题", ""])
            for title in trend["resolved_issues"]:
                lines.append(f"- ~~{title}~~")

        lines.append("")
        return "\n".join(lines)

    def save_report(self, content: str, output_dir: str) -> str:
        """Saves trend report to file."""
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, f"sec-trend-{date.today().isoformat()}.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def _load_history(self) -> List[dict]:
        """Loads JSON reports from last N days, sorted by date ascending."""
        reports = []
        cutoff = date.today() - timedelta(days=self.days)

        if not os.path.isdir(self.base_dir):
            return reports

        for entry_name in sorted(os.listdir(self.base_dir)):
            try:
                entry_date = date.fromisoformat(entry_name)
            except ValueError:
                continue
            if entry_date < cutoff:
                continue

            json_path = os.path.join(
                self.base_dir, entry_name, "report",
                f"sec-report-{entry_name}.json"
            )
            if not os.path.isfile(json_path):
                continue

            try:
                with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                reports.append({
                    "date": entry_name,
                    "total_score": data.get("total_score", 0),
                    "conclusion": data.get("conclusion", ""),
                    "result_code": data.get("result_code", ""),
                    "severity_counts": data.get("severity_counts", {}),
                    "evidence_titles": [
                        {
                            "title": e.get("title", ""),
                            "severity": e.get("severity", "INFO"),
                        }
                        for e in data.get("evidences", [])
                    ],
                })
            except (json.JSONDecodeError, OSError) as e:
                logger.debug(f"Failed to load historical report {json_path}: {e}")
                continue

        return reports

    def _calc_trend(self, scores: list) -> str:
        """Calculates trend direction."""
        if len(scores) < 2:
            return "数据不足"
        first_score = scores[0][1]
        last_score = scores[-1][1]
        diff = last_score - first_score

        if diff > 5:
            return "恶化 ↑"
        elif diff < -5:
            return "改善 ↓"
        else:
            return "稳定 →"

    def _find_persistent_issues(self, reports: List[dict]) -> List[dict]:
        """Finds issues appearing 3+ consecutive days."""
        if len(reports) < 3:
            return []

        title_days = {}
        title_severity = {}
        for r in reports:
            for ev in r["evidence_titles"]:
                title = ev["title"]
                title_days.setdefault(title, 0)
                title_days[title] += 1
                existing = title_severity.get(title, "INFO")
                if self._sev_rank(ev["severity"]) > self._sev_rank(existing):
                    title_severity[title] = ev["severity"]

        persistent = []
        for title, days in title_days.items():
            if days >= 3:
                persistent.append({
                    "title": title,
                    "days": days,
                    "max_severity": title_severity.get(title, "INFO"),
                })
        persistent.sort(key=lambda x: -self._sev_rank(x["max_severity"]))
        return persistent

    def _find_new_issues(self, reports: List[dict]) -> List[str]:
        """Finds new issues in latest report."""
        if len(reports) < 2:
            return []
        prev_titles = {e["title"] for e in reports[-2]["evidence_titles"]}
        curr_titles = {e["title"] for e in reports[-1]["evidence_titles"]}
        return sorted(curr_titles - prev_titles)

    def _find_resolved_issues(self, reports: List[dict]) -> List[str]:
        """Finds resolved issues."""
        if len(reports) < 2:
            return []
        prev_titles = {e["title"] for e in reports[-2]["evidence_titles"]}
        curr_titles = {e["title"] for e in reports[-1]["evidence_titles"]}
        return sorted(prev_titles - curr_titles)

    @staticmethod
    def _sev_rank(severity: str) -> int:
        ranks = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return ranks.get(severity, 0)

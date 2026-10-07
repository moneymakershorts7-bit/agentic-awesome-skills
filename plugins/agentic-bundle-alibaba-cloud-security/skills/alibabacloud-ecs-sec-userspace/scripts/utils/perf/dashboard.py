"""Performance dashboard generator for sec-userspace

Generates HTML reports with Chart.js visualizations showing analyzer
performance trends and budget violations.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .tracker import PerformanceTracker

logger = logging.getLogger("sec-userspace")

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sec-userspace Performance Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .subtitle {{
            opacity: 0.9;
            font-size: 0.95em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}
        .stat-card h3 {{
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-value.warning {{
            color: #f59e0b;
        }}
        .stat-value.critical {{
            color: #ef4444;
        }}
        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }}
        .chart-container h2 {{
            font-size: 1.3em;
            margin-bottom: 20px;
            color: #333;
        }}
        .chart-wrapper {{
            position: relative;
            height: 300px;
        }}
        .violations-list {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }}
        .violations-list h2 {{
            font-size: 1.3em;
            margin-bottom: 20px;
        }}
        .violation-item {{
            padding: 15px;
            border-left: 4px solid #f59e0b;
            background: #fef3c7;
            margin-bottom: 10px;
            border-radius: 4px;
        }}
        .violation-item.critical {{
            border-left-color: #ef4444;
            background: #fee2e2;
        }}
        .violation-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }}
        .violation-name {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        .violation-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-warning {{
            background: #f59e0b;
            color: white;
        }}
        .badge-critical {{
            background: #ef4444;
            color: white;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background: #f9fafb;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75em;
            color: #666;
        }}
        tr:hover {{
            background: #f9fafb;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>sec-userspace Performance Dashboard</h1>
            <p class="subtitle">Generated at {generated_at}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Scans (7 days)</h3>
                <div class="stat-value">{total_scans}</div>
            </div>
            <div class="stat-card">
                <h3>Avg Scan Duration</h3>
                <div class="stat-value {duration_class}">{avg_duration:.1f}s</div>
            </div>
            <div class="stat-card">
                <h3>Budget Violations</h3>
                <div class="stat-value {violations_class}">{violation_count}</div>
            </div>
            <div class="stat-card">
                <h3>Slowest Analyzer</h3>
                <div class="stat-value" style="font-size: 1.2em;">{slowest_name}</div>
                <div style="color: #666; font-size: 0.9em;">{slowest_duration:.2f}s avg</div>
            </div>
        </div>

        {violations_section}

        <div class="chart-container">
            <h2>Top 10 Slowest Analyzers (7-day average)</h2>
            <div class="chart-wrapper">
                <canvas id="slowestChart"></canvas>
            </div>
        </div>

        <div class="chart-container">
            <h2>Performance Trends (Last 30 Days)</h2>
            <div class="chart-wrapper">
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <div class="chart-container">
            <h2>Analyzer Performance Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Analyzer</th>
                        <th>Avg Duration</th>
                        <th>Max Duration</th>
                        <th>Min Duration</th>
                        <th>Budget</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {analyzer_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>sec-userspace Performance Monitoring | Data from {db_path}</p>
        </div>
    </div>

    <script>
        // Slowest analyzers chart
        const slowestCtx = document.getElementById('slowestChart').getContext('2d');
        new Chart(slowestCtx, {{
            type: 'bar',
            data: {{
                labels: {slowest_labels},
                datasets: [{{
                    label: 'Average Duration (seconds)',
                    data: {slowest_data},
                    backgroundColor: 'rgba(102, 126, 234, 0.6)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Duration (seconds)'
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});

        // Trend chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: {trend_labels},
                datasets: {trend_datasets}
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Duration (seconds)'
                        }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        position: 'top',
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""


class DashboardGenerator:
    """Generate HTML performance dashboards"""

    def __init__(self, tracker: PerformanceTracker):
        """Initialize dashboard generator

        Args:
            tracker: PerformanceTracker instance
        """
        self.tracker = tracker

    def generate(
        self,
        output_path: Path,
        report_data: Optional[Dict] = None,
        days: int = 7,
    ):
        """Generate HTML dashboard

        Args:
            output_path: Path to write HTML file
            report_data: Optional current scan report for immediate feedback
            days: Number of days of historical data to include
        """
        try:
            # Gather metrics
            total_scans = self._get_total_scans(days)
            avg_duration = self._get_avg_scan_duration(days)
            slowest = self.tracker.get_slowest_analyzers(days, limit=1)

            # Check for violations in current report if provided
            violations = []
            if report_data:
                violations = self.tracker.check_budget_violations(report_data)

            # Get top 10 slowest analyzers
            slowest_analyzers = self.tracker.get_slowest_analyzers(days, limit=10)

            # Get performance trends for top 3 slowest
            trend_data = []
            for name, _ in slowest_analyzers[:3]:
                trend = self.tracker.get_performance_trend(name, days=30)
                if trend:
                    trend_data.append({"name": name, "data": trend})

            # Generate HTML
            html = self._render_html(
                total_scans=total_scans,
                avg_duration=avg_duration,
                violations=violations,
                slowest_analyzers=slowest_analyzers,
                trend_data=trend_data,
                slowest_name=slowest[0][0] if slowest else "N/A",
                slowest_duration=slowest[0][1] if slowest else 0.0,
            )

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html, encoding='utf-8')

            logger.info(f"Performance dashboard generated: {output_path}")

        except (OSError, ValueError, TypeError, KeyError) as e:
            logger.error(f"Failed to generate dashboard: {e}")
            raise

    def _get_total_scans(self, days: int) -> int:
        """Get total number of scans in last N days"""
        # This would need a method in tracker - simplified for now
        return 0  # Placeholder

    def _get_avg_scan_duration(self, days: int) -> float:
        """Get average scan duration in last N days"""
        # This would need a method in tracker - simplified for now
        return 0.0  # Placeholder

    def _render_html(
        self,
        total_scans: int,
        avg_duration: float,
        violations: List[Dict],
        slowest_analyzers: List[tuple],
        trend_data: List[Dict],
        slowest_name: str,
        slowest_duration: float,
    ) -> str:
        """Render HTML dashboard"""
        # Determine status classes
        duration_class = ""
        if avg_duration > 120:
            duration_class = "critical"
        elif avg_duration > 90:
            duration_class = "warning"

        violations_class = "critical" if violations else ""

        # Generate violations section
        if violations:
            violations_html = '<div class="violations-list"><h2>Performance Budget Violations</h2>'
            for v in violations:
                severity_class = "critical" if v["severity"] == "critical" else ""
                badge_class = f'badge-{v["severity"]}'
                violations_html += f"""
                <div class="violation-item {severity_class}">
                    <div class="violation-header">
                        <span class="violation-name">{v['analyzer']}</span>
                        <span class="violation-badge {badge_class}">{v['severity']}</span>
                    </div>
                    <div>Duration: {v['duration']:.2f}s / Budget: {v['budget']:.2f}s</div>
                    <div>Excess: {v['excess_percent']:.1f}%</div>
                </div>
                """
            violations_html += "</div>"
        else:
            violations_html = ""

        # Generate analyzer table rows
        analyzer_rows = ""
        for name, avg_dur in slowest_analyzers:
            from .tracker import PERFORMANCE_BUDGETS

            budget = PERFORMANCE_BUDGETS.get(name, PERFORMANCE_BUDGETS["default"])
            status = (
                '<span style="color: #ef4444;">EXCEEDED</span>'
                if avg_dur > budget
                else '<span style="color: #10b981;">OK</span>'
            )
            analyzer_rows += f"""
            <tr>
                <td>{name}</td>
                <td>{avg_dur:.2f}s</td>
                <td>-</td>
                <td>-</td>
                <td>{budget:.2f}s</td>
                <td>{status}</td>
            </tr>
            """

        # Prepare chart data
        slowest_labels = json.dumps([name for name, _ in slowest_analyzers])
        slowest_data = json.dumps([dur for _, dur in slowest_analyzers])

        # Prepare trend data
        trend_labels = json.dumps([])
        trend_datasets = json.dumps([])
        if trend_data:
            # Use first analyzer's dates
            trend_labels = json.dumps(
                [d["date"] for d in trend_data[0]["data"]]
            )

            colors = [
                "rgba(102, 126, 234, 1)",
                "rgba(245, 158, 11, 1)",
                "rgba(239, 68, 68, 1)",
            ]
            datasets = []
            for i, td in enumerate(trend_data):
                color = colors[i % len(colors)]
                datasets.append({
                    "label": td["name"],
                    "data": [d["avg_duration"] for d in td["data"]],
                    "borderColor": color,
                    "backgroundColor": color.replace("1)", "0.2)"),
                    "tension": 0.4,
                })
            trend_datasets = json.dumps(datasets)

        html = DASHBOARD_TEMPLATE.format(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_scans=total_scans,
            avg_duration=avg_duration,
            duration_class=duration_class,
            violation_count=len(violations),
            violations_class=violations_class,
            slowest_name=slowest_name,
            slowest_duration=slowest_duration,
            violations_section=violations_html,
            analyzer_rows=analyzer_rows,
            slowest_labels=slowest_labels,
            slowest_data=slowest_data,
            trend_labels=trend_labels,
            trend_datasets=trend_datasets,
            db_path=str(self.tracker.db_path),
        )

        return html

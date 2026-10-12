# Unified Test Report JSON Schema Specification

This schema standardizes test reporting across disparate engines (pytest, unittest, Vitest, Jest, Playwright, Cypress, k6, axe-core) into a single machine-readable contract consumed by CI/CD quality gates, PR comment generators, and DevSecOps dashboards.

---

## JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "UnifiedQAReport",
  "type": "object",
  "required": ["version", "run_id", "timestamp", "summary", "suites", "verdict"],
  "properties": {
    "version": { "type": "string", "const": "1.0.0" },
    "run_id": { "type": "string" },
    "timestamp": { "type": "string", "format": "date-time" },
    "project_path": { "type": "string" },
    "commit_sha": { "type": "string" },
    "branch": { "type": "string" },
    "verdict": {
      "type": "string",
      "enum": ["PASSED", "FAILED", "QUARANTINED", "BLOCKED"]
    },
    "summary": {
      "type": "object",
      "required": ["total", "passed", "failed", "skipped", "flaky", "duration_seconds", "pass_rate"],
      "properties": {
        "total": { "type": "integer", "minimum": 0 },
        "passed": { "type": "integer", "minimum": 0 },
        "failed": { "type": "integer", "minimum": 0 },
        "skipped": { "type": "integer", "minimum": 0 },
        "flaky": { "type": "integer", "minimum": 0 },
        "duration_seconds": { "type": "number", "minimum": 0 },
        "pass_rate": { "type": "number", "minimum": 0, "maximum": 100 }
      }
    },
    "quality_metrics": {
      "type": "object",
      "properties": {
        "mutation_score_index": { "type": "number", "minimum": 0, "maximum": 100 },
        "line_coverage_pct": { "type": "number", "minimum": 0, "maximum": 100 },
        "accessibility_violations_critical": { "type": "integer", "minimum": 0 },
        "perf_p95_latency_ms": { "type": "number", "minimum": 0 }
      }
    },
    "suites": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "framework", "tests"],
        "properties": {
          "name": { "type": "string" },
          "framework": { "type": "string" },
          "duration_seconds": { "type": "number" },
          "tests": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["name", "status", "duration_seconds"],
              "properties": {
                "name": { "type": "string" },
                "status": { "type": "string", "enum": ["PASSED", "FAILED", "SKIPPED", "FLAKY"] },
                "duration_seconds": { "type": "number" },
                "error_message": { "type": ["string", "null"] },
                "stack_trace": { "type": ["string", "null"] },
                "artifacts": {
                  "type": "object",
                  "properties": {
                    "trace_uri": { "type": "string" },
                    "video_uri": { "type": "string" },
                    "screenshot_uri": { "type": "string" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

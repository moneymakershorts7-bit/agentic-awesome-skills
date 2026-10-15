# Blameless Post-Mortem Writing Guide, Templates & MTTR Reduction

---

## Executive Overview & Operational Principles

### 1.1 Blameless Culture & Systems Theory

**Core Principle**: Human error is a symptom of system design, not the root cause. Blameless post-mortems focus on *systemic conditions* that enabled the error, not the individual who triggered it.

**Psychological Safety Requirements**:
- No disciplinary action for honest mistakes during incident response
- Focus on "What happened?" and "How did our systems allow this?" not "Who caused this?"
- Leadership must model vulnerability by sharing their own failures
- Retrospective facilitator must be neutral (not the incident commander)

**Systems Theory Application**:
- **Normalization of Deviance**: Track drift from intended procedures (Vaughan, 1996)
- **Swiss Cheese Model**: Identify aligned holes in defense layers (Reason, 1990)
- **STAMP/STPA**: Model control structure failures, not component failures (Leveson, 2011)

### 1.2 Incident Severity Classification (Production Standard)

| Severity | Definition | Response SLA | Communication | Post-Mortem Required |
|----------|------------|--------------|---------------|---------------------|
| **SEV-0** | Complete service outage, data loss, security breach | 5 min acknowledge, 15 min engage | Status page + customer notification + executive alert | Mandatory (48h draft) |
| **SEV-1** | Major feature down, >10% users affected, revenue impact | 10 min acknowledge, 30 min engage | Status page + stakeholder notification | Mandatory (48h draft) |
| **SEV-2** | Degraded performance, <10% users affected, workaround exists | 30 min acknowledge, 2h engage | Internal Slack + status page optional | Recommended (5 business days) |
| **SEV-3** | Minor issue, no user impact, cosmetic/non-critical | Next business day | Internal tracking only | Optional (learning review) |

### 1.3 MTTR Reduction Target Matrix

| Metric | Definition | Current Baseline | Target (6mo) | Target (12mo) | Optimization Lever |
|--------|------------|------------------|--------------|---------------|-------------------|
| **MTTA** | Mean Time to Acknowledge | 12 min | 5 min | 2 min | Escalation policy tuning, on-call tooling |
| **MTTD** | Mean Time to Detect | 8 min | 3 min | 1 min | Observability coverage, alert quality |
| **MTTI** | Mean Time to Identify | 25 min | 10 min | 5 min | Runbook linkage, distributed tracing |
| **MTTR** | Mean Time to Resolve | 65 min | 30 min | 15 min | Automation, feature flags, rollback capability |
| **MTBF** | Mean Time Between Failures | 14 days | 30 days | 60 days | Chaos engineering, capacity planning |

---

## Architecture & Concrete Configurations / Code Recipes

### 2.1 Complete Blameless Post-Mortem Markdown Template

```markdown
<!-- 
  BLAMELESS POST-MORTEM TEMPLATE v3.2
  Classification: INTERNAL - CONFIDENTIAL
  Retention: 7 years (compliance)
  Review Cycle: Quarterly by SRE Leadership
-->

# Post-Mortem: {{INCIDENT_ID}} - {{SHORT_DESCRIPTION}}

**Document Status**: `DRAFT` | `REVIEW` | `APPROVED` | `ARCHIVED`
**Incident ID**: `{{INCIDENT_ID}}` (e.g., INC-2024-001234)
**Severity**: `SEV-{{0|1|2|3}}`
**Status**: `RESOLVED` | `MITIGATED` | `MONITORING`
**Date**: `{{YYYY-MM-DD}}`
**Author**: `{{AUTHOR_NAME}}` (@{{SLACK_HANDLE}})
**Facilitator**: `{{FACILITATOR_NAME}}` (@{{SLACK_HANDLE}})
**Reviewers**: `{{REVIEWER_1}}, {{REVIEWER_2}}, {{REVIEWER_3}}`
**Approval**: `{{APPROVER_NAME}}` (@{{SLACK_HANDLE}}) on `{{APPROVAL_DATE}}`

---

## 1. Executive Summary

> **TL;DR**: One paragraph (3-5 sentences) summarizing: what happened, customer impact, root cause category, and top 3 preventive actions. Written for executive consumption.

{{EXECUTIVE_SUMMARY}}

**Key Metrics at a Glance**:
- **Total Downtime**: `{{TOTAL_DOWNTIME_MINUTES}}` minutes
- **Customers Affected**: `{{CUSTOMERS_AFFECTED_COUNT}}` ({{CUSTOMERS_AFFECTED_PERCENTAGE}}% of active)
- **Revenue Impact**: `${{REVENUE_IMPACT_USD}}` (estimated)
- **Data Loss**: `{{DATA_LOSS_STATUS}}` (None / Partial / Full - {{DETAILS}})
- **MTTR**: `{{MTTR_MINUTES}}` minutes (Target: {{MTTR_TARGET_MINUTES}} min)

---

## 2. Incident Overview

### 2.1 Classification

| Field | Value |
|-------|-------|
| **Incident ID** | `{{INCIDENT_ID}}` |
| **Severity** | `SEV-{{SEVERITY}}` |
| **Type** | `{{INCIDENT_TYPE}}` (Outage / Degradation / Data Loss / Security / False Positive) |
| **Services Affected** | `{{SERVICE_LIST}}` (comma-separated, link to service catalog) |
| **Teams Involved** | `{{TEAM_LIST}}` |
| **Detection Method** | `{{DETECTION_METHOD}}` (Alert / Customer Report / Synthetic Monitor / Internal Discovery) |
| **Alert Name** | `{{ALERT_NAME}}` (link to alert definition) |
| **On-Call Engineer** | `{{ONCALL_ENGINEER}}` (@{{SLACK_HANDLE}}) |

### 2.2 Impact Metrics

```yaml
impact_metrics:
  downtime:
    start_utc: "{{DOWNTIME_START_UTC}}"  # ISO 8601: 2024-01-15T14:23:00Z
    end_utc: "{{DOWNTIME_END_UTC}}"
    duration_minutes: {{DURATION_MINUTES}}
    availability_impact_percentage: {{AVAILABILITY_IMPACT_PCT}}
  
  customers:
    total_active_during_incident: {{TOTAL_ACTIVE_CUSTOMERS}}
    affected_count: {{AFFECTED_CUSTOMER_COUNT}}
    affected_percentage: {{AFFECTED_PERCENTAGE}}
    segments:
      - segment: "Enterprise"
        affected: {{ENTERPRISE_AFFECTED}}
        total: {{ENTERPRISE_TOTAL}}
      - segment: "SMB"
        affected: {{SMB_AFFECTED}}
        total: {{SMB_TOTAL}}
      - segment: "Free Tier"
        affected: {{FREE_AFFECTED}}
        total: {{FREE_TOTAL}}
  
  revenue:
    estimated_loss_usd: {{REVENUE_LOSS_USD}}
    calculation_method: "{{REVENUE_CALC_METHOD}}"  # e.g., "ARR * (downtime_minutes / 525600) * affected_percentage"
    contracts_at_risk: {{CONTRACTS_AT_RISK_COUNT}}
    sla_breaches: {{SLA_BREACH_COUNT}}
  
  technical:
    error_rate_peak: {{ERROR_RATE_PEAK_PCT}}%
    latency_p99_peak_ms: {{LATENCY_P99_PEAK_MS}}
    throughput_drop_percentage: {{THROUGHPUT_DROP_PCT}}%
    data_integrity_impact: "{{DATA_INTEGRITY_STATUS}}"
```

---

## 3. Chronological Detailed Timeline (UTC)

> **Requirement**: All timestamps in UTC. Include timezone offset in parentheses for local context. Minimum granularity: 1 minute during active incident.

```markdown
| Timestamp (UTC) | Local Time | Phase | Actor | Action / Observation | Evidence Link |
|-----------------|------------|-------|-------|---------------------|---------------|
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Detection | {{SYSTEM/PERSON}} | {{DESCRIPTION}} | {{LINK_TO_GRAFANA/DATADOG/PAGERDUTY}} |
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Acknowledgment | {{ONCALL_ENGINEER}} | Acknowledged alert in PagerDuty | {{PD_INCIDENT_LINK}} |
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Triage | {{ONCALL_ENGINEER}} | Started investigation; checked dashboard {{DASHBOARD_LINK}} | {{SLACK_THREAD_LINK}} |
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Escalation | {{ONCALL_ENGINEER}} | Escalated to {{TEAM/ENGINEER}} via {{METHOD}} | {{ESCALATION_LOG}} |
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Diagnosis | {{ENGINEER}} | Identified root cause: {{ROOT_CAUSE_SUMMARY}} | {{QUERY/LOG_LINK}} |
| {{YYYY-MM-DDTHH:MM:SSZ}} | {{LOCAL_TIME}} | Mitigation | {{ENGINEER}} | Applied mitigation: {{MITIGATION_ACTION}} | {{DEPLOYMENT

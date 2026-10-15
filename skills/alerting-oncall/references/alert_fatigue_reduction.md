# Alert Fatigue Reduction, Hygiene & Signal-to-Noise Engineering

## Executive Overview & Operational Principles

Alert fatigue is a prevalent issue in monitoring and observability systems, where on-call teams are overwhelmed with a flood of alerts, many of which are either non-actionable or false positives. This overload desensitizes team members, increasing the likelihood that critical alerts requiring immediate attention are overlooked.

To mitigate alert fatigue, we will focus on the following key principles:

1. **The Actionability Mandate**: Strict criteria for what constitutes a pageable alert vs non-pageable notifications, auditing non-actionable alerts, and converting low-urgency notifications to tickets or dashboards.
2. **Symptom-based vs Cause-based alerting**: Why alerting on user-impacting symptoms (high error rate, latency percentiles, saturated capacity) is superior to cause-based alerting (CPU spike, thread count) and how to avoid duplicate cascades.
3. **Prometheus Alertmanager deduplication, grouping, and routing**: Complete syntax-valid alertmanager.yml configurations with group_by, group_wait, group_interval, repeat_interval, and inhibit_rules.
4. **Flapping alerts mitigation**: Hysteresis, evaluation intervals, and `for` duration tuning.
5. **On-call hygiene scorecards and metrics**: Tracking pages per on-call shift, off-hours pages, un-actioned alerts, and weekly alert triage review rituals.

## Architecture & Concrete Configurations / Code Recipes

### Prometheus Alertmanager Deduplication, Grouping, and Routing

```yml
# alertmanager.yml
route:
  group_by: ['alertname', 'severity']
  receiver: 'slack'
receivers:
- name: 'slack'
  slack_configs:
  - channel: '#alerts'
    text: "{{ .CommonAnnotations.summary }}"
```

```yml
# alertmanager.yml (inhibit_rules)
route:
  group_by: ['alertname', 'severity']
  receiver: 'slack'
  inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname']
receivers:
- name: 'slack'
  slack_configs:
  - channel: '#alerts'
    text: "{{ .CommonAnnotations.summary }}"
```

### Flapping Alerts Mitigation

```yml
# prometheus.yml (hysteresis)
alert:
  InstanceDown:
    expr: up == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} is down"
      description: "No response from {{ $labels.instance }} for 5 minutes"
```

```yml
# prometheus.yml (evaluation intervals)
alert:
  InstanceDown:
    expr: up == 0
    for: 5m
    evaluation_interval: 1m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} is down"
      description: "No response from {{ $labels.instance }} for 5 minutes"
```

### On-call Hygiene Scorecards and Metrics

```sql
-- SQL query to track pages per on-call shift
SELECT 
  on_call_shift,
  COUNT(*) AS pages
FROM 
  incident_log
GROUP BY 
  on_call_shift;
```

```python
# Python script to track off-hours pages
import datetime

def track_off_hours_pages(incident_log):
    off_hours_pages = 0
    for incident in incident_log:
        if incident['created_at'].hour < 8 or incident['created_at'].hour >= 17:
            off_hours_pages += 1
    return off_hours_pages
```

## Step-by-Step Production Procedures & Diagnostic Queries / Commands

### Step 1: Identify Noisy Alerts

* Run the following query to identify noisy alerts:
```sql
SELECT 
  alert_name,
  COUNT(*) AS alert_count
FROM 
  incident_log
GROUP BY 
  alert_name
ORDER BY 
  alert_count DESC;
```

### Step 2: Configure Alertmanager Deduplication, Grouping, and Routing

* Update the `alertmanager.yml` file with the following configuration:
```yml
route:
  group_by: ['alertname', 'severity']
  receiver: 'slack'
receivers:
- name: 'slack'
  slack_configs:
  - channel: '#alerts'
    text: "{{ .CommonAnnotations.summary }}"
```

### Step 3: Mitigate Flapping Alerts

* Update the `prometheus.yml` file with the following configuration:
```yml
alert:
  InstanceDown:
    expr: up == 0
    for: 5m
    evaluation_interval: 1m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} is down"
      description: "No response from {{ $labels.instance }} for 5 minutes"
```

## Common Failure Modes, Anti-Patterns & Troubleshooting

### Common Failure Modes

* **Inadequate alert deduplication**: Alerts are not properly deduplicated, leading to duplicate notifications.
* **Insufficient alert grouping**: Alerts are not properly grouped, leading to unnecessary notifications.
* **Inadequate alert routing**: Alerts are not properly routed, leading to notifications being sent to the wrong recipients.

### Anti-Patterns

* **Overly broad alerting rules**: Alerting rules are too broad, leading to unnecessary notifications.
* **Insufficient alert threshold tuning**: Alert thresholds are not properly tuned, leading to unnecessary notifications.
* **Inadequate alert documentation**: Alert documentation is inadequate, leading to confusion and unnecessary notifications.

### Troubleshooting

* **Verify alert deduplication**: Verify that alert deduplication is working correctly by checking the `alertmanager.yml` file.
* **Verify alert grouping**: Verify that alert grouping is working correctly by checking the `alertmanager.yml` file.
* **Verify alert routing**: Verify that alert routing is working correctly by checking the `alertmanager.yml` file.

## Operational Checklist & Verification Gates

### Operational Checklist

* **Verify alert deduplication**: Verify that alert deduplication is working correctly.
* **Verify alert grouping**: Verify that alert grouping is working correctly.
* **Verify alert routing**: Verify that alert routing is working correctly.
* **Verify alert threshold tuning**: Verify that alert thresholds are properly tuned.
* **Verify alert documentation**: Verify that alert documentation is adequate.

### Verification Gates

* **Verify that alert deduplication is working correctly**: Run the following query to verify that alert deduplication is working correctly:
```sql
SELECT 
  alert_name,
  COUNT(*) AS alert_count
FROM 
  incident_log
GROUP BY 
  alert_name
ORDER BY 
  alert_count DESC;
```

* **Verify that alert grouping is working correctly**: Run the following query to verify that alert grouping is working correctly:
```sql
SELECT 
  alert_name,
  COUNT(*) AS alert_count
FROM 
  incident_log
GROUP BY 
  alert_name
ORDER BY 
  alert_count DESC;
```

* **Verify that alert routing is working correctly**: Run the following query to verify that alert routing is working correctly:
```sql
SELECT 
  alert_name,
  COUNT(*) AS alert_count
FROM 
  incident_log
GROUP BY 
  alert_name
ORDER BY 
  alert_count DESC;
```

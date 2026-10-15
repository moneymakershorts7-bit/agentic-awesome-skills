# Grafana Dashboard Provisioning, Templating & Visualization

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        GRAFANA OBSERVABILITY STACK                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐  │
│  │  Workloads   │───▶│ Node Exporter│───▶│  Prometheus  │───▶│ Grafana  │  │
│  │  (K8s/VM)    │    │   :9100      │    │   :9090      │    │  :3000   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘    └──────────┘  │
│         │                   │                   │                ▲         │
│         │                   │                   │                │         │
│         ▼                   ▼                   ▼                │         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    PROVISIONING LAYER (GitOps)                       │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
│  │  │ datasources/    │  │ dashboards/     │  │ dashboards/*.json   │  │   │
│  │  │ prometheus.yaml │  │ dashboards.yaml │  │ (version controlled)│  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    HELM DEPLOYMENT (values.yaml)                     │   │
│  │  • grafana.ini overrides    • Dashboard providers                    │   │
│  │  • Datasource secrets       • Plugin management                      │   │
│  │  • Resource limits          • Ingress/TLS config                     │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Component Matrix**
| Component | Port | Protocol | Purpose |
|-----------|------|----------|---------|
| Grafana | 3000 | HTTP/HTTPS | Visualization UI & API |
| Prometheus | 9090 | HTTP | Metrics storage & query |
| Node Exporter | 9100 | HTTP | Host metrics collection |
| Alertmanager | 9093 | HTTP | Alert routing & deduplication |
| Loki | 3100 | HTTP | Log aggregation |
| Promtail | 9080 | HTTP | Log shipping |
| Vector | 8686/9000 | HTTP/gRPC | Unified observability pipeline |

---

## Concrete Configs / Code Recipes

### 1. Declarative Datasource Provisioning

**File:** `provisioning/datasources/prometheus.yaml`
```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    uid: prometheus-primary
    access: proxy
    url: http://prometheus.monitoring.svc.cluster.local:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
      queryTimeout: "60s"
      httpMethod: POST
      exemplarTraceIdDestinations:
        - name: traceID
          datasourceUid: tempo-distributed
      customQueryParameters: "timeout=30s"
    secureJsonData:
      httpHeaderValue1: ""
    version: 1
    readOnly: false

  - name: Loki
    type: loki
    uid: loki-primary
    access: proxy
    url: http://loki.monitoring.svc.cluster.local:3100
    editable: false
    jsonData:
      maxLines: 1000
      timeout: 60
      derivedFields:
        - name: traceID
          matcherRegex: "trace[=:]([a-f0-9]+)"
          url: "${__value.raw}"
          datasourceUid: tempo-distributed
    version: 1

  - name: Tempo
    type: tempo
    uid: tempo-distributed
    access: proxy
    url: http://tempo.monitoring.svc.cluster.local:3200
    editable: false
    jsonData:
      tracesToLogs:
        datasourceUid: loki-primary
        tags: ["job", "instance", "pod", "namespace"]
        spanStartTimeShift: "-1h"
        spanEndTimeShift: "1h"
      tracesToMetrics:
        datasourceUid: prometheus-primary
        tags: ["job", "instance", "pod", "namespace"]
    version: 1
```

### 2. Declarative Dashboard Provisioning

**File:** `provisioning/dashboards/dashboards.yaml`
```yaml
apiVersion: 1

providers:
  - name: "Infrastructure Dashboards"
    orgId: 1
    folder: "Infrastructure"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards/infrastructure
      foldersFromFilesStructure: true

  - name: "Application Dashboards"
    orgId: 1
    folder: "Applications"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards/applications
      foldersFromFilesStructure: true

  - name: "Kubernetes Dashboards"
    orgId: 1
    folder: "Kubernetes"
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards/kubernetes
      foldersFromFilesStructure: true

  - name: "System Dashboards (Read-Only)"
    orgId: 1
    folder: "System"
    type: file
    disableDeletion: true
    updateIntervalSeconds: 10
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards/system
```

### 3. Dashboard JSON Model Structure (Complete)

**File:** `dashboards/infrastructure/node-exporter-full.json`
```json
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 1,
  "id": null,
  "iteration": 1678901234,
  "links": [],
  "liveNow": false,
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus-primary"
      },
      "fieldConfig": {
        "defaults": {
          "color": {"mode": "palette-classic"},
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {"tooltip": false, "viz": false, "legend": false},
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {"type": "linear"},
            "showPoints": "never",
            "spanNulls": true
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {"color": "green", "value": null},
              {"color": "orange", "value": 70},
              {"color": "red", "value": 90}
            ]
          },
          "unit": "percentunit"
        },
        "overrides": [
          {
            "matcher": {"id": "byName", "options": "iowait"},
            "properties": [
              {"id": "unit", "value": "percentunit"},
              {"id": "custom.lineWidth", "value": 2},
              {"id": "color.mode", "value": "fixed"},
              {"id": "color.fixedColor", "value": "#FF6B6B"}
            ]
          }
        ]
      },
      "gridPos": {"h": 8, "w": 12, "x":

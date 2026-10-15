# Fluent Bit Configuration, Parsing & Loki Forwarding

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FLUENT BIT LOG PIPELINE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────┐ │
│  │  INPUT   │───▶│  PARSER  │───▶│  FILTER  │───▶│  BUFFER  │───▶│OUTPUT│ │
│  │ (tail,   │    │ (regex,  │    │ (k8s,    │    │ (mem/    │    │(Loki)│ │
│  │  stdin,  │    │  json,   │    │  modify, │    │  fs,     │    │      │ │
│  │  syslog) │    │  cri)    │    │  grep,   │    │  chunk)  │    │      │ │
│  └──────────┘    └──────────┘    │  rewrite)│    └──────────┘    └──────┘ │
│                                  └──────────┘                              │
│                                                                             │
│  Backpressure: mem_buf_limit → filesystem storage → pause input             │
│  HA: Multiple outputs + retry + standby replicas                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Component Matrix**

| Layer | Plugins | Purpose |
|-------|---------|---------|
| Service | `flush`, `grace`, `storage.path` | Engine tuning, persistence |
| Input | `tail`, `systemd`, `forward`, `tcp` | Source ingestion |
| Parser | `regex`, `json`, `cri`, `logfmt` | Structured extraction |
| Filter | `kubernetes`, `record_modifier`, `grep`, `rewrite_tag`, `multiline` | Enrichment, routing, cleanup |
| Output | `loki`, `grafana-loki`, `stdout`, `null` | Destination delivery |

---

## Concrete Configs / Code Recipes

### 1. Production `fluent-bit.yaml` (Service + Storage + Input + Parser + Filter + Output)

```yaml
# fluent-bit.yaml
service:
  flush: 5
  grace: 30
  log_level: info
  daemon: false
  parsers_file: parsers.conf
  plugins_file: plugins.conf
  storage:
    path: /var/lib/fluent-bit/storage
    sync: normal
    checkpoint: 'on'
    max_chunks_up: 128
  http_server:
    enabled: true
    listen: 0.0.0.0
    port: 2020
  health_check:
    enabled: true
    port: 2021

# ─────────────────────────────────────────────────────────────────────────────
# INPUT: Tail container logs with CRI parser, rotation DB, backpressure limits
# ─────────────────────────────────────────────────────────────────────────────
input:
  - name: tail
    alias: container-logs
    tag: kube.*
    path: /var/log/containers/*.log
    parser: cri
    db: /var/lib/fluent-bit/tail.db
    db.sync: normal
    mem_buf_limit: 50MB
    skip_long_lines: true
    refresh_interval: 10
    rotate_wait: 5
    storage.type: filesystem
    buffer_max_size: 2MB
    buffer_chunk_size: 512KB

  - name: tail
    alias: host-logs
    tag: host.*
    path: /var/log/*.log
    parser: syslog-rfc3164
    db: /var/lib/fluent-bit/host-tail.db
    mem_buf_limit: 20MB
    skip_long_lines: true

# ─────────────────────────────────────────────────────────────────────────────
# FILTER: Kubernetes enrichment, label normalization, sensitive field removal
# ─────────────────────────────────────────────────────────────────────────────
filter:
  - name: kubernetes
    match: kube.*
    kube_url: https://kubernetes.default.svc:443
    kube_ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    kube_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    merge_log: true
    merge_log_key: log_processed
    k8s_logging_parser: true
    k8s_logging_exclude: "true"
    labels: true
    annotations: false
    use_kubelet: false

  - name: record_modifier
    match: kube.*
    record:
      cluster: "prod-east-1"
      environment: "production"
      # Remove PII / high-cardinality fields
      remove_keys: "emailAddress,ssn,password,token,authorization,cookie,session"

  - name: grep
    match: kube.*
    regex:
      log: "^(?!.*healthz).*$"          # Drop kube-probe noise
      kubernetes_container_name: "^(?!istio-proxy).*"  # Drop sidecar logs if needed

  - name: rewrite_tag
    match: kube.*
    rule: $log ^(?<level>error|fatal|panic)  kube.$TAG.error true
    rule: $log ^(?<level>warn|warning)       kube.$TAG.warn  true
    emitter_name: re-tagged
    emitter_storage.type: memory

  - name: multiline
    match: kube.*
    parser: multiline-java
    flush_timeout: 1000

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT: Loki with auto Kubernetes labels, batching, retries, TLS
# ─────────────────────────────────────────────────────────────────────────────
output:
  - name: loki
    match: kube.*
    url: https://loki-gateway.observability.svc.cluster.local:3100/loki/api/v1/push
    tenant_id: ""
    labels: "{job=\"fluent-bit\", cluster=\"prod-east-1\"}"
    auto_kubernetes_labels: true
    kubernetes_label_selector: "app,component,tier,version"
    remove_keys: "log,kubernetes,stream,time,cluster,environment"
    label_keys: "kubernetes_namespace_name,kubernetes_pod_name,kubernetes_container_name,kubernetes_host"
    line_format: json
    batch_wait: 1
    batch_size: 10240
    retries: 5
    min_backoff: 2
    max_backoff: 30
    tls:
      enabled: true
      ca_file: /etc/fluent-bit/certs/ca.crt
      verify: true
    network:
      connect_timeout: 10
      keepalive: 30
      keepalive_idle: 60
      keepalive_interval: 10
      keepalive_count: 3
    buffer:
      storage.type: filesystem
      path: /var/lib/fluent-bit/loki-buffer
      max_chunks_up: 256
      chunk_size: 2MB
      sync: normal
```

---

### 2. Parsers (`parsers.conf`)

```ini
# parsers.conf
[PARSER]
    Name        cri
    Format      regex
    Regex       ^(?<time>[^ ]+) (?<stream>stdout|stderr) (?<logtag>[^ ]*) (?<log>.*)$
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L%z

[PARSER]
    Name        docker
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L
    Time_Keep   On
    Decode_Field_As   escaped_utf8

[PARSER]
    Name        json
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L
    Time_Keep   On

[PARSER]
    Name        logfmt
    Format      regex
    Regex       ^(?<time>[^ ]* [^ ]*) (?<level>\w+) (?<msg>.*)$
    Time_Key    time
    Time_Format %Y-%m-%d %H:%M:%S

[PARSER]
    Name        syslog-rfc3164
    Format      regex
    Regex       ^<(?<pri>[0-9]+)>(?<time>[^ ]* [^ ]* [^ ]*) (?<host>[^ ]*) (?<ident>[^:]*):?(?<message>.*)$
    Time_Key    time
    Time_Format %b %d %H:%M:%S

[PARSER]
    Name        multiline-java
    Format      regex
    Regex       ^(?

# OpenTelemetry Collector Architecture & Production Pipelines

## Architecture Overview

The OpenTelemetry Collector is a core element of the OpenTelemetry observability framework, acting as a neutral intermediary for collecting, processing, and forwarding telemetry signals (traces, metrics, and logs) to an observability backend.

## Concrete Configs / Code Recipes

### otelcol.yaml Configuration

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
  prometheus:
    config:
      scrape_configs:
        - job_name: 'api-service'
          scrape_interval: 10s
          static_configs:
            - targets: ['api-service:8080']
        - job_name: 'kubernetes-pods'
          kubernetes_sd_configs:
            - role: pod
          relabel_configs:
            - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
              action: keep
              regex: true
  filelog:
    include:
      - /var/log/pods/*/*/*.log
    exclude:
      - /var/log/pods/debug*.log
    operators:
      - type: regex_parser
        regex: '^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<severity>[A-Z]+) (?P<message>.*?)$'

processors:
  batch:
    send_batch_size: 10000
    timeout: 5s
  k8sattributes:
    auth_type: serviceAccount
    extract:
      - k8s.pod.name
      - k8s.pod.uid
      - k8s.deployment.name
      - k8s.namespace.name
      - k8s.node.name
      - k8s.pod.start_time
  filter:
    metrics:
      include:
        match_type: regexp
        metric_names: ['^(system|application).*']
    spans:
      exclude:
        match_type: strict
        attributes:
          - key: http.route
            value: /health
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      - name: error-policy
        type: status_code
        status_code: ERROR
      - name: latency-policy
        type: latency
        latency_threshold_ms: 500

exporters:
  otlp:
    endpoint: backend.example.com:4317
    tls:
      insecure: false
      cert_file: /certs/client.crt
      key_file: /certs/client.key

pipelines:
  traces:
    receivers: [otlp]
    processors: [k8sattributes, batch]
    exporters: [otlp]
  metrics:
    receivers: [otlp, prometheus, kubeletstats]
    processors: [k8sattributes, filter, batch]
    exporters: [otlp]
  logs:
    receivers: [otlp, filelog]
    processors: [k8sattributes, batch]
    exporters: [otlp]
```

### Docker Compose Configuration

```yaml
version: '3'
services:
  otel-collector:
    image: otel/opentelemetry-collector:latest
    volumes:
      - ./otelcol.yaml:/etc/otelcol/config.yaml
    ports:
      - "4318:4318"
    command: ["--config=/etc/otelcol/config.yaml"]
```

### Kubernetes Deployment Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
      - name: otel-collector
        image: otel/opentelemetry-collector:latest
        volumeMounts:
        - name: config
          mountPath: /etc/otelcol
        ports:
        - containerPort: 4318
        command: ["--config=/etc/otelcol/config.yaml"]
      volumes:
      - name: config
        configMap:
          name: otel-collector-config
```

## Operational Runbook / Failure Modes

### Runbook

1. Check the collector logs for any errors or warnings.
2. Verify that the collector is receiving data from the specified receivers.
3. Check the exporter logs to ensure that data is being sent to the desired backend.
4. Use the collector's built-in health checks to verify that it is functioning correctly.

### Failure Modes

1. **Receiver failure**: If a receiver fails, the collector will not receive data from that source.
2. **Processor failure**: If a processor fails, the collector may not be able to process data correctly.
3. **Exporter failure**: If an exporter fails, the collector will not be able to send data to the desired backend.
4. **Network failure**: If the network connection between the collector and the backend fails, data will not be sent.

### Troubleshooting

1. Check the collector logs for any errors or warnings.
2. Verify that the collector is receiving data from the specified receivers.
3. Check the exporter logs to ensure that data is being sent to the desired backend.
4. Use the collector's built-in health checks to verify that it is functioning correctly.

### Monitoring

1. Use the collector's built-in metrics to monitor its performance.
2. Use the collector's built-in logs to monitor its activity.
3. Use external monitoring tools to monitor the collector's performance and activity.

### Alerting

1. Set up alerts based on the collector's metrics and logs.
2. Use external alerting tools to send notifications when the collector experiences issues.

### Logging

1. Use the collector's built-in logs to monitor its activity.
2. Use external logging tools to collect and store the collector's logs.

### Security

1. Use secure communication protocols (e.g. TLS) to protect data in transit.
2. Use secure storage solutions to protect data at rest.
3. Use access controls to restrict access to the collector and its data.

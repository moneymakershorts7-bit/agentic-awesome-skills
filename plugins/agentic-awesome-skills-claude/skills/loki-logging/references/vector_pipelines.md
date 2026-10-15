# Vector Observability Pipelines & Loki Ingestion
## Architecture Overview

Vector is a robust open-source log aggregator developed by Datadog. It empowers you to build observability pipelines by seamlessly fetching logs from many sources, transforming the data as needed, and routing it to your preferred destination.

### High-Level Components

*   **Sources**: Vector can collect logs from various sources, including file, journald, docker, kubernetes_logs, and socket.
*   **Transforms**: Vector uses VRL (Vector Remap Language) for log transformation. It supports various operations, such as parse_json, coerce, field rename, secret redaction, drop conditions, and route transforms.
*   **Sinks**: Vector supports various sinks, including Loki, Elasticsearch, S3, and file.
*   **Buffer Configurations**: Vector provides buffer configurations for disk and memory, with options for max_bytes and when_full (block or drop_newest).
*   **Health Checks**: Vector provides health checks to monitor its performance and detect any issues.
*   **High-Throughput Topology Patterns**: Vector supports high-throughput topology patterns for efficient log processing.

## Concrete Configs / Code Recipes

### Vector Configuration File (vector.yaml)

```yml
version: 3

sources:
  - name: file_source
    type: file
    path: /var/log/app.log
    encoding: json

  - name: journald_source
    type: journald
    match: systemd.*

transforms:
  - name: parse_json
    type: parse_json
    fields:
      - name: message
        json_path: $.message

  - name: rename_fields
    type: rename_fields
    fields:
      - from: message
        to: log_message

sinks:
  - name: loki_sink
    type: loki
    url: http://localhost:3100/loki/api/v1/push
    labels:
      - app: my_app
      - env: prod
    auth:
      username: my_user
      password: my_password
    encoding: json
    compression: gzip

buffer:
  type: disk
  max_bytes: 100MB
  when_full: block
```

### Loki Configuration File (loki.yaml)

```yml
server:
  http_listen_port: 3100

ingester:
  lifecycler:
    ring:
      kvstore:
        store: inmemory
  wal:
    enabled: true

store:
  boltdb:
    path: /var/lib/loki/boltdb
```

### Vector Docker Compose File (docker-compose.yaml)

```yml
version: '3'

services:
  vector:
    image: vectordev/vector
    volumes:
      - ./vector.yaml:/etc/vector/vector.yaml
    ports:
      - "8686:8686"
    depends_on:
      - loki

  loki:
    image: grafana/loki:latest
    volumes:
      - ./loki.yaml:/etc/loki/loki.yaml
    ports:
      - "3100:3100"
```

## Operational Runbook / Failure Modes

### Vector Runbook

1.  **Start Vector**: Start the Vector service using the `vector` command.
2.  **Check Vector Logs**: Check the Vector logs for any errors or issues.
3.  **Check Loki Logs**: Check the Loki logs for any errors or issues.
4.  **Check Buffer**: Check the buffer configuration to ensure it is working correctly.

### Loki Runbook

1.  **Start Loki**: Start the Loki service using the `loki` command.
2.  **Check Loki Logs**: Check the Loki logs for any errors or issues.
3.  **Check Store**: Check the store configuration to ensure it is working correctly.

### Failure Modes

*   **Vector Failure**: If Vector fails, Loki will not receive any logs.
*   **Loki Failure**: If Loki fails, logs will not be stored.
*   **Buffer Failure**: If the buffer fails, logs may be lost.

### Troubleshooting

*   **Check Vector Logs**: Check the Vector logs for any errors or issues.
*   **Check Loki Logs**: Check the Loki logs for any errors or issues.
*   **Check Buffer**: Check the buffer configuration to ensure it is working correctly.

### Monitoring

*   **Monitor Vector**: Monitor Vector for any issues or errors.
*   **Monitor Loki**: Monitor Loki for any issues or errors.
*   **Monitor Buffer**: Monitor the buffer configuration to ensure it is working correctly.

### Alerting

*   **Alert on Vector Failure**: Alert on Vector failure to ensure logs are being processed.
*   **Alert on Loki Failure**: Alert on Loki failure to ensure logs are being stored.
*   **Alert on Buffer Failure**: Alert on buffer failure to ensure logs are not being lost.

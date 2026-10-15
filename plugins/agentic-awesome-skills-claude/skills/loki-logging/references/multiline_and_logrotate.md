# Multi-Line Stack Traces & Linux Logrotate Automation
## Architecture Overview

This document outlines the recipes for parsing multi-line stack traces and managing log rotation using various tools and technologies.

### Tools and Technologies

* Promtail: A log collector for Loki that can parse multi-line log entries.
* Fluent Bit: A log processor that can parse multi-line log entries.
* Logrotate: A Linux utility for managing log files and rotating them when they reach a certain size.
* Loki: A logging and monitoring system that can store and query log data.
* Vector: A log processing and forwarding system that can parse multi-line log entries.

## Concrete Configs / Code Recipes

### Java Stack Traces in Promtail

To parse Java stack traces in Promtail, you can use the following configuration:
```yaml
scrape_configs:
  - job_name: java
    static_configs:
      - targets: ["localhost:9080"]
    pipeline_stages:
      - parser:
          type: multiline
          multiline:
            max_lines: 100
            max_bytes: 100000
            contains: "at "
            keep_empty: false
          parser:
            type: json
            json:
              message_key: message
      - json:
          message_key: message
```
### Python Stack Traces in Promtail

To parse Python stack traces in Promtail, you can use the following configuration:
```yaml
scrape_configs:
  - job_name: python
    static_configs:
      - targets: ["localhost:9080"]
    pipeline_stages:
      - parser:
          type: multiline
          multiline:
            max_lines: 100
            max_bytes: 100000
            contains: "File "
            keep_empty: false
          parser:
            type: json
            json:
              message_key: message
      - json:
          message_key: message
```
### Go Stack Traces in Promtail

To parse Go stack traces in Promtail, you can use the following configuration:
```yaml
scrape_configs:
  - job_name: go
    static_configs:
      - targets: ["localhost:9080"]
    pipeline_stages:
      - parser:
          type: multiline
          multiline:
            max_lines: 100
            max_bytes: 100000
            contains: "goroutine "
            keep_empty: false
          parser:
            type: json
            json:
              message_key: message
      - json:
          message_key: message
```
### Node.js Stack Traces in Promtail

To parse Node.js stack traces in Promtail, you can use the following configuration:
```yaml
scrape_configs:
  - job_name: node
    static_configs:
      - targets: ["localhost:9080"]
    pipeline_stages:
      - parser:
          type: multiline
          multiline:
            max_lines: 100
            max_bytes: 100000
            contains: "at "
            keep_empty: false
          parser:
            type: json
            json:
              message_key: message
      - json:
          message_key: message
```
### Fluent Bit Multi-Line Parser

To parse multi-line log entries in Fluent Bit, you can use the following configuration:
```bash
[INPUT]
  Name tail
  Tag log
  Path /var/log/app.log
  Format json
  Multiline
    Max_Lines 100
    Max_Buf_Siz 100000
    Contains "at "
    Keep_Empty false

[OUTPUT]
  Name loki
  Host localhost
  Port 3100
  Tag log
```
### Logrotate Configuration

To configure Logrotate to rotate log files daily, you can use the following configuration:
```bash
/var/log/app.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  create 0644 root root
  postrotate
    kill -HUP `cat /var/run/syslogd.pid 2>/dev/null` 2>/dev/null || true
  endscript
}
```
### Vector Multi-Line Parser

To parse multi-line log entries in Vector, you can use the following configuration:
```toml
[inputs.file]
  enabled = true
  path = "/var/log/app.log"
  format = "json"
  multiline = true
  multiline_max_lines = 100
  multiline_max_bytes = 100000
  multiline_contains = "at "
  multiline_keep_empty = false

[outputs.loki]
  enabled = true
  host = "localhost"
  port = 3100
  tag = "log"
```
## Operational Runbook / Failure Modes

### Log File Growth

* Monitor log file growth to prevent disk space exhaustion.
* Implement log rotation to manage log file size.
* Use Logrotate to rotate log files daily.

### Log File Corruption

* Monitor log file corruption to prevent data loss.
* Implement log file checksums to detect corruption.
* Use Logrotate to rotate log files daily.

### Log File Rotation Failure

* Monitor Logrotate failure to prevent log file growth.
* Implement Logrotate retry mechanism to handle failure.
* Use Logrotate to rotate log files daily.

### Log File Compression Failure

* Monitor log file compression failure to prevent data loss.
* Implement log file compression retry mechanism to handle failure.
* Use Logrotate to rotate log files daily.

### Log File Encryption Failure

* Monitor log file encryption failure to prevent data loss.
* Implement log file encryption retry mechanism to handle failure.
* Use Logrotate to rotate log files daily.

### Log File Access Control Failure

* Monitor log file access control failure to prevent unauthorized access.
* Implement log file access control retry mechanism to handle failure.
* Use Logrotate to rotate log files daily.

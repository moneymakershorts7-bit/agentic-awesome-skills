# PromQL Production Cheat Sheet & Query Recipes
## Architecture Overview
Prometheus Query Language (PromQL) is a powerful and flexible language used to query and manipulate time-series metrics in Prometheus. It forms the backbone of extracting insights from your metrics data.

### Prerequisites
- Prior knowledge of Prometheus metrics concepts
- A recent version of Docker and Docker Compose installed on your machine

### Setting up a local Prometheus sandbox
To experiment with PromQL queries, you need a monitoring service set up with Prometheus and a data source, such as Node Exporter, to collect system metrics.

```yml
# docker-compose.yml
version: '3'
services:
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - --path.procfs=/host/proc
      - --path.rootfs=/rootfs
      - --path.sysfs=/host/sys
      - --collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)
    networks:
      - monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./alerts.yml:/etc/prometheus/alerts.yml
      - prometheus_data:/prometheus
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.path=/prometheus
      - --web.console.libraries=/etc/prometheus/console_libraries
      - --web.console.templates=/etc/prometheus/consoles
      - --web.enable-lifecycle
    expose:
      - 9090
    ports:
      - 9090:9090
    networks:
      - monitoring
networks:
  monitoring:
    driver: bridge
volumes:
  prometheus_data:
```

```yml
# prometheus.yml
global:
  scrape_interval: 10s
  scrape_configs:
    - job_name: prometheus
      static_configs:
        - targets:
            - localhost:9090
    - job_name: node-exporter
      static_configs:
        - targets:
            - node-exporter:9100
```

### Concrete Configs / Code Recipes
#### Instant Vectors
Instant vectors are used to query the current value of a metric.

```promql
# Get the current CPU usage
cpu_usage_seconds_total
```

#### Range Vectors
Range vectors are used to query the values of a metric over a specified time range.

```promql
# Get the CPU usage over the last 5 minutes
cpu_usage_seconds_total[5m]
```

#### Rate() vs irate() vs increase()
Rate, irate, and increase are used to calculate the rate of change of a metric.

```promql
# Calculate the rate of change of the CPU usage
rate(cpu_usage_seconds_total[1m])
irate(cpu_usage_seconds_total[1m])
increase(cpu_usage_seconds_total[1m])
```

#### Aggregation Operators
Aggregation operators are used to perform calculations on multiple metrics.

```promql
# Calculate the average CPU usage
avg(cpu_usage_seconds_total)
# Calculate the sum of the CPU usage
sum(cpu_usage_seconds_total)
# Calculate the minimum CPU usage
min(cpu_usage_seconds_total)
# Calculate the maximum CPU usage
max(cpu_usage_seconds_total)
# Get the top 5 CPU usage values
topk(5, cpu_usage_seconds_total)
# Get the bottom 5 CPU usage values
bottomk(5, cpu_usage_seconds_total)
# Count the number of CPU usage values
count(cpu_usage_seconds_total)
# Count the number of unique CPU usage values
count_values(cpu_usage_seconds_total)
```

#### Histogram Quantile Calculation Rules
Histogram quantile calculation rules are used to calculate the quantiles of a histogram.

```promql
# Calculate the 95th percentile of the CPU usage
histogram_quantile(0.95, cpu_usage_seconds_total)
```

#### Bucket Configuration
Bucket configuration is used to configure the buckets of a histogram.

```promql
# Configure the buckets of the CPU usage histogram
histogram_quantile(0.95, cpu_usage_seconds_total, buckets=[0.1, 0.5, 0.9])
```

#### Subqueries
Subqueries are used to query a metric within another query.

```promql
# Get the CPU usage where the node is not busy
cpu_usage_seconds_total{node!="busy"}
```

#### Binary Vector Matching
Binary vector matching is used to match a binary vector against a metric.

```promql
# Get the CPU usage where the node is busy
cpu_usage_seconds_total{node="busy"}
```

#### RED Method (Rate, Errors, Duration) Queries
RED method queries are used to measure the experience of users and service consumers.

```promql
# Calculate the rate of errors
rate(errors_total[1m])
# Calculate the rate of successful requests
rate(successful_requests_total[1m])
# Calculate the average duration of requests
avg(duration_seconds_total)
```

#### USE Method (Utilization, Saturation, Errors) Queries
USE method queries are used to measure the utilization, saturation, and errors of a system.

```promql
# Calculate the utilization of the system
rate(system_utilization[1m])
# Calculate the saturation of the system
rate(system_saturation[1m])
# Calculate the rate of errors
rate(errors_total[1m])
```

#### Performance Optimization for Slow Queries
Performance optimization for slow queries involves optimizing the query itself, the data storage, and the data retrieval.

```promql
# Optimize the query by using a smaller time range
cpu_usage_seconds_total[1m]
# Optimize the data storage by using a more efficient data structure
cpu_usage_seconds_total{node="busy"}
# Optimize the data retrieval by using a more efficient data retrieval method
cpu_usage_seconds_total{node="busy"}[1m]
```

## Operational Runbook / Failure Modes
### Failure Modes
- Query timeout: The query takes too long to execute, resulting in a timeout.
- Data not found: The data is not available or is missing.
- Data corruption: The data is corrupted or invalid.
- Query syntax error: The query has a syntax error.

### Runbook
- Query timeout:
  - Check the query syntax and optimize it if necessary.
  - Check the data storage and optimize it if necessary.
  - Check the data retrieval method and optimize it if necessary.
- Data not found:
  - Check the data storage and ensure that the data is available.
  - Check the query syntax and ensure that it is correct.
- Data corruption:
  - Check the data storage and ensure that the data is valid.
  - Check the query syntax and ensure that it is correct.
- Query syntax error:
  - Check the query syntax and correct it if necessary.
  - Check the data storage and ensure that the data is available.

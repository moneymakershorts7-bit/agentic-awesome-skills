# PostgreSQL Slow Query Logging, pg_stat_statements & Prometheus Alerting
## Executive Overview & Operational Principles

PostgreSQL slow query logging, statistical observability, and alerting are critical components of a production-ready database monitoring strategy. This runbook provides a comprehensive guide to configuring PostgreSQL slow query logging, utilizing the pg_stat_statements extension for statistical observability, and setting up Prometheus alerting rules using the postgres_exporter.

### Architecture & Concrete Configurations / Code Recipes

#### PostgreSQL Configuration

To enable slow query logging, modify the `postgresql.conf` file to include the following settings:

```sql
# Enable logging collector
logging_collector = on

# Set log destination
log_destination = 'syslog'

# Set log directory
log_directory = 'pg_log'

# Set log filename
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'

# Set log statement to 'all' to log all queries
log_statement = 'all'

# Set log min duration statement to 1000ms to log slow queries
log_min_duration_statement = 1000

# Set log line prefix format
log_line_prefix = '%m [%p] %q%u@%d %a %h'

# Set log checkpoints
log_checkpoints = on

# Set log lock waits
log_lock_waits = on

# Set log temp files
log_temp_files = on

# Set log autovacuum min duration
log_autovacuum_min_duration = 1000
```

#### Auto_explain Configuration

To capture query execution plans, install and configure the `auto_explain` module:

```sql
# Install auto_explain extension
CREATE EXTENSION IF NOT EXISTS auto_explain;

# Set auto_explain log min duration
auto_explain.log_min_duration = 1000;

# Set auto_explain log analyze to 'on' to analyze query execution plans
auto_explain.log_analyze = on;

# Set auto_explain log buffers to 'on' to log buffer usage
auto_explain.log_buffers = on;

# Set auto_explain log format to 'json' for JSON output
auto_explain.log_format = 'json';
```

#### pg_stat_statements Configuration

To enable statistical observability, install and configure the `pg_stat_statements` extension:

```sql
# Install pg_stat_statements extension
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

# Set pg_stat_statements log min duration
pg_stat_statements.log_min_duration = 1000;

# Set pg_stat_statements log buffer size
pg_stat_statements.log_buffer_size = 1000000;
```

#### Prometheus Alerting Rules

To set up Prometheus alerting rules using the `postgres_exporter`, create a YAML file with the following content:

```yml
groups:
  - name: postgres
    rules:
      - alert: HighConnectionPoolUtilization
        expr: postgres_connections > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High Connection Pool Utilization
      - alert: SlowQueryRateAnomaly
        expr: rate(postgres_slow_query_count[1m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Slow Query Rate Anomaly
      - alert: DeadlockDetected
        expr: postgres_deadlocks > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: Deadlock Detected
      - alert: TransactionWraparoundApproaching
        expr: postgres_xact_commit + postgres_xact_rollback > 100000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Transaction Wraparound Approaching
      - alert: ReplicationLag
        expr: postgres_replication_lag > 1s
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Replication Lag
```

### Step-by-Step Production Procedures & Diagnostic Queries / Commands

1.  Configure PostgreSQL slow query logging by modifying the `postgresql.conf` file.
2.  Install and configure the `auto_explain` module to capture query execution plans.
3.  Install and configure the `pg_stat_statements` extension for statistical observability.
4.  Set up Prometheus alerting rules using the `postgres_exporter`.
5.  Monitor PostgreSQL logs for slow queries and other issues.
6.  Use diagnostic queries and commands to troubleshoot issues.

### Common Failure Modes, Anti-Patterns & Troubleshooting

*   **Slow query logging not enabled**: Check the `postgresql.conf` file to ensure that slow query logging is enabled.
*   **Auto_explain not installed or configured**: Check if the `auto_explain` module is installed and configured correctly.
*   **pg_stat_statements not installed or configured**: Check if the `pg_stat_statements` extension is installed and configured correctly.
*   **Prometheus alerting rules not set up**: Check if the Prometheus alerting rules are set up correctly.
*   **PostgreSQL logs not being written**: Check the PostgreSQL logs for errors or issues that may be preventing logs from being written.

### Operational Checklist & Verification Gates

1.  Verify that slow query logging is enabled.
2.  Verify that the `auto_explain` module is installed and configured correctly.
3.  Verify that the `pg_stat_statements` extension is installed and configured correctly.
4.  Verify that Prometheus alerting rules are set up correctly.
5.  Verify that PostgreSQL logs are being written correctly.

By following this runbook, you can ensure that your PostgreSQL database is properly configured for slow query logging, statistical observability, and alerting, and that you are able to monitor and troubleshoot issues effectively.

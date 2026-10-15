# PostgreSQL VACUUM, Autovacuum Tuning & Table Bloat Management

## Executive Overview & Operational Principles

PostgreSQL is a powerful, open-source relational database that supports both SQL and JSON querying. However, as data accumulates, dead tuples can lead to table bloat, impacting performance. Autovacuum is a critical feature that helps maintain database health, but it requires tuning to ensure optimal performance.

### Key Principles

*   **MVCC (Multi-Version Concurrency Control)**: PostgreSQL uses MVCC to manage concurrent access to data, allowing for efficient handling of transactions and minimizing lock contention.
*   **Dead Tuples Accumulation**: Dead tuples are rows that have been deleted or updated, but not yet removed from the database. Over time, these tuples can accumulate, leading to table bloat and performance issues.
*   **Autovacuum**: Autovacuum is a PostgreSQL feature that automatically runs VACUUM operations to remove dead tuples and maintain database health.
*   **Tuning Autovacuum**: Autovacuum requires tuning to ensure optimal performance. This includes adjusting parameters such as `autovacuum_vacuum_scale_factor`, `autovacuum_vacuum_threshold`, and `autovacuum_vacuum_cost_limit`.

## Architecture & Concrete Configurations / Code Recipes

### Global Autovacuum Configuration

To enable autovacuum globally, add the following configuration to your `postgresql.conf` file:

```sql
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = 1min
autovacuum_vacuum_threshold = 50
autovacuum_vacuum_scale_factor = 0.2
autovacuum_vacuum_cost_limit = -1
autovacuum_vacuum_cost_delay = 10ms
```

### Per-Table Autovacuum Overrides

To override autovacuum settings for specific tables, use the following SQL command:

```sql
ALTER TABLE table_name SET (autovacuum_vacuum_scale_factor = 0.02, autovacuum_vacuum_threshold = 100, autovacuum_vacuum_cost_limit = -1);
```

### Asynchronous I/O Configuration

To enable asynchronous I/O, add the following configuration to your `postgresql.conf` file:

```sql
async_commit = on
async_rollback = on
```

## Step-by-Step Production Procedures & Diagnostic Queries / Commands

### VACUUM Operation

To run a VACUUM operation, use the following SQL command:

```sql
VACUUM table_name;
```

### Autovacuum Queue Inspection

To inspect the autovacuum queue, use the following SQL command:

```sql
SELECT * FROM pg_stat_activity WHERE state = 'autovacuum';
```

### Table Bloat Diagnosis

To diagnose table bloat, use the following SQL command:

```sql
SELECT schemaname, relname, pg_relation_size(relname) AS size, pg_total_relation_size(relname) AS total_size FROM pg_class WHERE relkind = 'r';
```

### Dead Tuple Ratio Calculation

To calculate the dead tuple ratio, use the following SQL command:

```sql
SELECT schemaname, relname, dead_tuple_count / live_tuple_count AS dead_tuple_ratio FROM pg_class WHERE relkind = 'r';
```

## Common Failure Modes, Anti-Patterns & Troubleshooting

### Transaction ID (XID) Wraparound Risk

To mitigate the XID wraparound risk, monitor the `pg_xact` table and run VACUUM operations regularly.

### Autovacuum Freeze Max Age

To prevent autovacuum freeze, monitor the `pg_autovacuum` table and adjust the `autovacuum_freeze_max_age` parameter as needed.

### Lock Contention on Long-Running Transactions

To mitigate lock contention, monitor the `pg_locks` table and adjust the `lock_timeout` parameter as needed.

### Manual Maintenance Procedures

To perform manual maintenance procedures, use the following SQL commands:

```sql
VACUUM ANALYZE table_name;
pg_repack -d database_name -t table_name;
VACUUM FULL table_name;
```

## Operational Checklist & Verification Gates

### Autovacuum Configuration Verification

*   Verify that autovacuum is enabled globally.
*   Verify that autovacuum settings are correctly overridden for specific tables.
*   Verify that asynchronous I/O is enabled.

### Table Bloat Diagnosis Verification

*   Verify that table bloat is diagnosed correctly using the provided SQL command.
*   Verify that dead tuple ratios are calculated correctly using the provided SQL command.

### Autovacuum Queue Inspection Verification

*   Verify that the autovacuum queue is inspected correctly using the provided SQL command.

### Lock Contention Verification

*   Verify that lock contention is mitigated correctly using the provided SQL command.

### Manual Maintenance Procedures Verification

*   Verify that manual maintenance procedures are performed correctly using the provided SQL commands.

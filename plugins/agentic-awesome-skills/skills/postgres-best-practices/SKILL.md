---
name: postgres-best-practices
description: "Postgres performance optimization and best practices from Supabase. Use this skill when writing, reviewing, or optimizing Postgres queries, schema designs, or database configurations."
risk: safe
source: community
date_added: "2026-02-27"
---

# Supabase Postgres Best Practices

Comprehensive performance optimization guide for Postgres, maintained by Supabase. Contains rules across 8 categories, prioritized by impact to guide automated query optimization and schema design.

## When to Use
Reference these guidelines when:
- Writing SQL queries or designing schemas
- Implementing indexes or query optimization
- Reviewing database performance issues
- Configuring connection pooling or scaling
- Optimizing for Postgres-specific features
- Working with Row-Level Security (RLS)

## Rule Categories by Priority

| Priority | Category | Impact | Prefix |
|----------|----------|--------|--------|
| 1 | Query Performance | CRITICAL | `query-` |
| 2 | Connection Management | CRITICAL | `conn-` |
| 3 | Security & RLS | CRITICAL | `security-` |
| 4 | Schema Design | HIGH | `schema-` |
| 5 | Concurrency & Locking | MEDIUM-HIGH | `lock-` |
| 6 | Data Access Patterns | MEDIUM | `data-` |
| 7 | Monitoring & Diagnostics | LOW-MEDIUM | `monitor-` |
| 8 | Advanced Features | LOW | `advanced-` |

## How to Use

Read individual rule files for detailed explanations and SQL examples:

```
rules/query-missing-indexes.md
rules/schema-partial-indexes.md
rules/_sections.md
```

Each rule file contains:
- Brief explanation of why it matters
- Incorrect SQL example with explanation
- Correct SQL example with explanation
- Optional EXPLAIN output or metrics
- Additional context and references
- Supabase-specific notes (when applicable)

## Full Compiled Document

For the complete guide with all rules expanded: `AGENTS.md`

## Progressive Disclosure & Production Reference Runbooks

Consult detailed production runbooks for specific deep-dive operational scenarios:
- **Query Tuning & Indexing**: [`references/query_tuning_and_indexing.md`](file:///home/npirela/.agents/skills/postgres-best-practices/references/query_tuning_and_indexing.md) - Deep EXPLAIN (ANALYZE, BUFFERS) inspection, scan node diagnosis, index architectures (B-tree, GIN, GiST, partial, covering), skip-scan emulation, and bloat detection.
- **PgBouncer Connection Pooling**: [`references/pgbouncer_pooling.md`](file:///home/npirela/.agents/skills/postgres-best-practices/references/pgbouncer_pooling.md) - Session vs transaction vs statement pooling modes, `pgbouncer.ini` production config, prepared statement handling, TLS, and administrative console management.
- **VACUUM & Autovacuum Tuning**: [`references/autovacuum_maintenance.md`](file:///home/npirela/.agents/skills/postgres-best-practices/references/autovacuum_maintenance.md) - MVCC tuple lifecycle, global autovacuum tuning in `postgresql.conf`, aggressive per-table autovacuum overrides, XID wraparound safety, and table bloat monitoring.
- **Slow Query Logging & Alerting**: [`references/slow_query_logging_and_alerting.md`](file:///home/npirela/.agents/skills/postgres-best-practices/references/slow_query_logging_and_alerting.md) - Production logging configuration, `auto_explain` module, `pg_stat_statements` top-consuming query diagnostics, and Prometheus Alertmanager rules.

### When to Use
This skill is applicable to execute the workflow or actions described in the overview.



## Production Runbooks & Architecture References

Detailed engineering runbooks distilled from production guides (Better Stack Community):
- [PostgreSQL Query Optimization, EXPLAIN ANALYZE & Indexing Strategies](references/query_tuning_and_indexing.md)
- [PgBouncer Connection Pooling, Systemd Service & Sizing](references/pgbouncer_pooling.md)
- [PostgreSQL VACUUM, Autovacuum Tuning & Table Bloat Management](references/autovacuum_maintenance.md)
- [Slow Query Logging, auto_explain, pg_stat_statements & Alerting Rules](references/slow_query_logging_and_alerting.md)

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.

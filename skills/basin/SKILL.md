---
name: basin
description: "Build and troubleshoot Cloudflare Basin analytics workflows with Basin Pipelines, Basin Catalog, and Basin SQL. Use for streaming data into R2 Iceberg tables, managing catalogs, or querying tables (formerly Data Platform, Pipelines, R2 Data Catalog, or R2 SQL)."
risk: safe
source: official
source_repo: cloudflare/skills
source_type: official
date_added: "2026-10-03"
---


## When to Use
Use this skill when building, querying, or troubleshooting Cloudflare Basin analytics pipelines, Iceberg tables in R2, or Basin SQL workflows.

# Cloudflare Basin

Basin ingests and transforms events, manages Apache Iceberg tables in R2, and queries them with distributed SQL. Start with the [Basin overview](https://developers.cloudflare.com/basin/index.md) and retrieve the relevant current docs before implementing changes, especially for limits, pricing, permissions, and CLI syntax. While PR #33850 remains open, use the proposed pages in that PR if the new URLs have not been published.

## Rebrand

Cloudflare Data Platform is now **Basin**. Cloudflare Pipelines, R2 Data Catalog, and R2 SQL are now **Basin Pipelines**, **Basin Catalog**, and **Basin SQL**. Existing resources and configurations continue to work. The prior Wrangler command families also continue to work: `wrangler pipelines`, `wrangler r2 bucket catalog`, and `wrangler r2 sql`. Use the new Basin commands and documentation URLs in new guidance. Legacy API identifiers and metrics names may still use the old terms; check the current docs for deprecation details. The migration is documented in [cloudflare-docs PR #33850](https://github.com/cloudflare/cloudflare-docs/pull/33850).

## Choose the workflow

| Need | Product | Reference | Current docs |
|------|---------|-----------|--------------|
| Receive events, transform rows, and deliver to R2 | Basin Pipelines | [Pipelines guide](references/pipelines/README.md) | [Basin Pipelines](https://developers.cloudflare.com/basin-pipelines/index.md) |
| Manage Iceberg metadata, table maintenance, and engine access | Basin Catalog | [Catalog guide](references/catalog/README.md) | [Basin Catalog](https://developers.cloudflare.com/basin-catalog/index.md) |
| Query Iceberg tables with analytical SQL | Basin SQL | [SQL guide](references/sql/README.md) | [Basin SQL](https://developers.cloudflare.com/basin-sql/index.md) |

Typical flow: Basin Pipelines → Basin Catalog tables in R2 → Basin SQL or a compatible external engine. Begin with the [Basin getting started guide](https://developers.cloudflare.com/basin/get-started/guide/index.md) for an end-to-end setup.

The proposed Wrangler command families are `wrangler basin pipelines`, `wrangler basin catalog`, and `wrangler basin sql`. Basin SQL uses `WRANGLER_BASIN_SQL_AUTH_TOKEN`; its REST query path is `/basin-sql/query/{BUCKET}`. Check the installed Wrangler version and current reference pages before running commands because the migration is ongoing.

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.

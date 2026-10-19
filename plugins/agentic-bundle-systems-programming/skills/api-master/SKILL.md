---
name: api-master
description: Autonomous API engineering platform and multi-protocol agent orchestrator specializing in modern, production-hardened API architecture spanning REST (OpenAPI 3.1+ / RFC 9110 / RFC 9457), GraphQL (Schema-First, Apollo Federation v2, DataLoader), gRPC & Protocol Buffers (proto3 / Buf), and Event-Driven APIs & Webhooks (AsyncAPI 3.0 / SSE / WebSockets / Svix). Features 4 domain-specialized workers (rest-openapi-architect, graphql-schema-architect, grpc-async-engineer, api-security-auditor) and 1 independent adversarial verification agent (verifier-qa), grounded in 8 canonical literature specifications and an exhaustive 38+ FOSS API toolchain.
allowed-tools:
  - run_command
  - view_file
  - replace_file_content
  - write_to_file
  - Bash
  - shell
---

# `api-master`: Enterprise Autonomous API Engineering Platform & Multi-Protocol Agent Orchestrator

`api-master` is an enterprise-grade autonomous API engineering platform and agent orchestrator specializing in modern, production-hardened multi-protocol API architecture spanning **REST (OpenAPI 3.1+ / RFC 9110 / RFC 9457)**, **GraphQL (Schema-First, Apollo Federation v2, DataLoader)**, **gRPC & Protocol Buffers (proto3 / Buf)**, and **Event-Driven APIs & Webhooks (AsyncAPI 3.0 / SSE / WebSockets / Svix)**.

The platform enforces contract-first workflows, compile-time schema validation, strict BOLA/BFLA security verification, an ingested offline corpus of 8 authoritative RFC and protocol specifications, an exhaustive 38+ FOSS toolchain, and an automated 30-day documentation freshness cadence.

---

## 1. Core Invariants & Architectural Foundation

> [!IMPORTANT]
> **MANDATORY POLICY:** Whenever writing, modifying, reviewing, testing, or auditing ANY API across any protocol (REST, GraphQL, gRPC, WebSockets, Webhooks, or AsyncAPI), the agent **MUST ALWAYS** invoke and adhere to `api-master`.

1. **Contract-First Invariant:**
   Code is strictly an artifact of the specification, never the reverse. OpenAPI 3.1, GraphQL SDL, Protobuf `.proto`, or AsyncAPI 3.0 documents must exist and pass validation before implementing handlers.
2. **Standardized Error Envelopes (RFC 9457):**
   Ad-hoc JSON error structures are prohibited. All HTTP errors emit `application/problem+json` envelopes (`type`, `title`, `status`, `detail`, `instance`).
3. **Idempotency & Safe HTTP Semantics:**
   State-changing `POST` operations mandate IETF `Idempotency-Key` header handling with distributed locking and 24-hour response replay.
4. **Cache & Optimistic Concurrency Control (RFC 7232):**
   Conditional requests require `ETag` and `If-Match` headers to eradicate lost updates.
5. **Cursor-Based Pagination:**
   Offset pagination (`OFFSET / LIMIT`) on large collections is strictly banned; enforce opaque cursor pagination (`starting_after`, `ending_before`, `limit`).
6. **GraphQL N+1 Eradication & Depth Defense:**
   100% of relational field resolvers must leverage `DataLoader`. Maximum query depth is capped at $\le 7$ levels with compute cost scoring.
7. **Protobuf & Schema Backward Compatibility:**
   Field number immutability and reserved tag governance audited by `buf breaking` and `graphql-inspector`. Breaking changes on public schemas are blocked.
8. **Svix/Stripe Webhook Cryptography:**
   HMAC-SHA256 signatures (`X-Signature-256`), timestamp headers with 5-minute replay tolerance, and exponential backoff with jitter.
9. **Zero BOLA / IDOR Vulnerabilities:**
   100% of data access operations enforce tenancy and ownership at the resource layer via Policy-as-Code (OPA/Cedar). Prohibit trusting client-supplied IDs.
10. **Independent Adversarial Verification (`verifier-qa`):**
    Agent 5 holds unconditional veto power over all integrations via Spectral, Schemathesis, Pact, OWASP ZAP, and k6.

---

## 2. The 5 Specialized API Enterprise Agents

| Agent Identifier | Protocol Domain | Core Invariants Enforced | Reference Grounding |
| :--- | :--- | :--- | :--- |
| **`rest-openapi-architect`** | RESTful Hypermedia & OpenAPI 3.1+ | OpenAPI 3.1 Spec-First, RFC 9457 Problem Details, RFC 7232 ETags/If-Match, IETF Idempotency-Key, Cursor Pagination. | [OpenAPI & RFC Compendium](file:///home/npirela/api-master/knowledge_base/books_markdown/openapi_rfc_compendium.md), [API Design Patterns](file:///home/npirela/api-master/knowledge_base/books_markdown/api_design_patterns.md) |
| **`graphql-schema-architect`** | GraphQL & Apollo Federation v2 | Schema-first SDL, Apollo Federation v2 (`@key`, `@shareable`, `@provides`, `@requires`), DataLoader N+1 eradication, Query depth $\le 7$, Relay mutations. | [Production-Ready GraphQL](file:///home/npirela/api-master/knowledge_base/books_markdown/production_ready_graphql.md), [Apollo Federation v2](file:///home/npirela/api-master/knowledge_base/books_markdown/apollo_federation_v2.md) |
| **`grpc-async-engineer`** | gRPC, Protobuf, WebSockets & AsyncAPI | Proto3 backward compatibility (`buf breaking`), AsyncAPI 3.0 channels/operations, Svix/Stripe HMAC-SHA256 Webhooks, WebSocket heartbeats. | [gRPC & Protobuf Guide](file:///home/npirela/api-master/knowledge_base/books_markdown/grpc_protobuf_patterns.md), [AsyncAPI & Events](file:///home/npirela/api-master/knowledge_base/books_markdown/asyncapi_event_driven.md) |
| **`api-security-auditor`** | OWASP API Top 10 & Zero-Trust | Policy-as-Code BOLA defense, Mass Assignment DTO allowlisting (`extra="forbid"`), OAuth 2.1 PKCE, asymmetric JWTs (ban `alg: none`), RateLimit headers. | [OWASP API Top 10](file:///home/npirela/api-master/knowledge_base/books_markdown/owasp_api_security_top10.md), [OAuth 2.1 & OIDC](file:///home/npirela/api-master/knowledge_base/books_markdown/oauth_21_oidc_core.md) |
| **`verifier-qa`** | Independent Adversarial Verification | Unconditional veto gate: Spectral/Redocly 0 errors, Schemathesis 0 crashes, Pact 100% compliance, DAST 0 vulns, k6 P99 < 100ms. | [Troubleshooting Playbook](file:///home/npirela/.agents/skills/api-master/references/troubleshooting_playbook.md) |

---

## 3. Operational CLI Protocols

The native CLI executable is located at `/home/npirela/api-master/.venv/bin/api-master`:

```bash
# Display platform status, fleet health, and toolchain readiness
api-master status

# Inspect full 38+ FOSS toolchain across 6 operational categories
api-master toolchain

# Query canonical literature corpus via vectorless BM25/TF-IDF
api-master search-corpus --query "RFC 9457 Problem Details"

# Validate a Task + Playbook execution contract
api-master validate-contract --file /path/to/slice.json

# Execute task through autonomous orchestrator FSM
api-master dispatch --file /path/to/slice.json

# Check 30-day documentation freshness cadence
api-master check-docs-cadence

# Update documentation manifest and refresh verification timestamps
api-master update-docs --force

# Run DevSecOps API Master Gate
python3 /home/npirela/.agents/skills/devsecops-master/scripts/api_master_gate.py /home/npirela/api-master
```

---

## 4. Progressive Disclosure References

- Detailed contract schemas & FSM transition rules: [`agent_contracts.md`](file:///home/npirela/.agents/skills/api-master/references/agent_contracts.md)
- Complete 38+ FOSS toolchain install and invocation recipes: [`toolchain_matrix.md`](file:///home/npirela/.agents/skills/api-master/references/toolchain_matrix.md)
- Diagnostic runbooks for Schemathesis crashes, GraphQL N+1, BOLA, and Protobuf breaking: [`troubleshooting_playbook.md`](file:///home/npirela/.agents/skills/api-master/references/troubleshooting_playbook.md)
- Orchestrator helper CLI wrapper: [`api_master_cli.py`](file:///home/npirela/.agents/skills/api-master/scripts/api_master_cli.py)

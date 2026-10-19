# API Master Troubleshooting & Diagnostic Runbook

This playbook provides actionable diagnostic procedures and remediation recipes for common API failures encountered during automated verification and production operation.

---

## 1. Schemathesis Property-Based Fuzzing Crashes

### Symptom:
`Schemathesis: 500 Internal Server Error on unexpected payload`
`Check: not_a_server_error [FAILED]`

### Root Cause:
The server crashed with an unhandled exception (e.g., `TypeError`, `KeyError`, or unhandled `None`) when receiving an edge-case payload (empty string, boundary integer, unexpected unicode, null field).

### Diagnostic Recipe:
1. Locate the exact reproducer payload emitted in the Schemathesis report.
2. Ensure strict schema validation middleware (Zod, Pydantic, or JSON Schema) intercepts requests *before* route handlers.
3. Catch deserialization and semantic validation errors and convert them to `422 Unprocessable Content` responses formatted as RFC 9457 `application/problem+json` envelopes.
4. Verify that no raw 500 Internal Server Error escapes to the client.

---

## 2. GraphQL N+1 Database Query Leaks

### Symptom:
`GraphQL Profiler: Excessive database queries detected (1 + N queries)`
`Resolver execution time scales linearly with collection size`

### Root Cause:
Nested field resolvers execute discrete database queries in a loop rather than batching.

### Diagnostic Recipe:
1. Wrap relational database access functions inside `DataLoader`.
2. Ensure DataLoader instances are created **per request** (scoped inside GraphQL context) to prevent cross-request cache pollution and memory leaks.
3. Verify that the batch function preserves input key ordering and returns an array of identical length:
   ```javascript
   const authorLoader = new DataLoader(async (authorIds) => {
     const authors = await db.authors.findMany({ where: { id: { in: authorIds } } });
     const authorMap = new Map(authors.map(a => [a.id, a]));
     return authorIds.map(id => authorMap.get(id) || null);
   });
   ```

---

## 3. Broken Object Level Authorization (BOLA / IDOR)

### Symptom:
`BOLA Gate: User A succeeded in retrieving or mutating resource belonging to Tenant B`
`Status 200 OK returned instead of 403 Forbidden`

### Root Cause:
The route handler accepted an object ID directly from the path or query parameter (`/v1/invoices/{id}`) and queried the database without filtering by authenticated tenant/user claims.

### Diagnostic Recipe:
1. Never execute un-scoped queries like `SELECT * FROM invoices WHERE id = :id`.
2. Extract the authenticated `tenant_id` and `user_id` strictly from cryptographically verified token claims (JWT context).
3. Evaluate Policy-as-Code (OPA/Cedar) or inject mandatory tenant filters into database queries:
   ```sql
   SELECT * FROM invoices WHERE id = :id AND tenant_id = :authenticated_tenant_id;
   ```
4. Return `404 Not Found` or `403 Forbidden` wrapped in an RFC 9457 Problem Details envelope when resource ownership does not match.

---

## 4. Protobuf Breaking Changes & Tag Collisions

### Symptom:
`buf breaking: Field "X" with tag N changed type from TYPE_A to TYPE_B`
`buf breaking: Previously used tag N was removed without reserved keyword`

### Root Cause:
A Protobuf message was updated in a manner that breaks binary wire compatibility with older clients.

### Diagnostic Recipe:
1. Never change the type of an existing field tag.
2. If a field is obsolete, mark its field number and name as `reserved`:
   ```protobuf
   message CustomerAccount {
     reserved 5, 8;
     reserved "tax_id", "ssn";
   }
   ```
3. Add new fields with brand-new incremented tag numbers.
4. Run `buf breaking --against '.git#branch=main'` locally before committing.

---

## 5. Webhook Signature Verification Failures

### Symptom:
`WebhookVerificationError: Webhook HMAC signature mismatch or timestamp expired`

### Root Cause:
1. Payload encoding mismatch (signed bytes did not match the raw body received).
2. Clock skew between emitter and receiver exceeding the 300-second replay window tolerance.

### Diagnostic Recipe:
1. Verify signature using raw bytes directly from the request stream before any JSON parsing.
2. Format signature string strictly: `f"{msg_id}.{timestamp}.{raw_body_bytes}"`.
3. Check NTP server synchronization on host systems to eliminate clock drift.

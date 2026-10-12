# Playbook 02: 60-Minute Threat Modeling Sprint

This playbook provides a lightweight, agile ceremony for engineering teams to evaluate architectural changes without stalling sprint velocity.

---

## When to Trigger
Run this session during sprint planning whenever a user story touches:
1. Authentication or authorization mechanics (JWT, OAuth, sessions, RBAC/ABAC).
2. Data storage involving PII, financial transactions, or cryptographic secrets.
3. New public HTTP/gRPC endpoints or external webhook listeners.
4. Changes to multi-tenant isolation boundaries.

---

## The 60-Minute Schedule

### Minute 00–15: Diagram the Data Flow (What are we building?)
1. Sketch a minimal Data Flow Diagram (DFD) on a whiteboard or virtual canvas:
   - Identify external actors (browser, mobile app, external third-party webhook).
   - Identify trust boundaries (internet boundary, DMZ, VPC, private database subnet).
   - Identify processes and datastores.

### Minute 15–35: Elicit Threats (What can go wrong?)
Walk through each DFD element using STRIDE-per-element:
1. **Spoofing:** Can an attacker forge identities or tokens?
2. **Tampering:** Can payload parameters or database records be modified without detection?
3. **Repudiation:** Can an actor deny performing a high-value transaction?
4. **Information Disclosure:** Are error messages, logs, or responses leaking confidential data?
5. **Denial of Service:** Can expensive database queries or unauthenticated endpoints exhaust system resources?
6. **Elevation of Privilege:** Can an ordinary tenant execute administrative actions?

### Minute 35–50: Define Mitigations (What are we going to do about it?)
For each identified threat, select an engineering countermeasure:
- Choose standard framework controls (e.g., ORM parameterized queries, standard JWT validator) over custom logic.
- Convert mitigations into concrete backlog acceptance criteria.

### Minute 50–60: Review & Acceptance Criteria (Did we do a good job?)
1. Draft 1–2 Evil User Stories with failing test scenarios:
   - Example: *"Ensure unauthorized requests to `/v1/payments/{id}` return HTTP 403 and write an audit event."*
2. Commit the threat model markdown document into `docs/security/threat-models/<feature-name>.md`.

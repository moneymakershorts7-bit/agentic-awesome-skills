# Exhaustive 38+ FOSS API Enterprise Toolchain Matrix

This document provides operational instructions, package manager recipes, and execution commands for the canonical 38+ FOSS API toolchain.

---

## 1. Specification, Design & Documentation Linters

### `spectral`
- **Purpose**: JSON/YAML linter for OpenAPI 3.x, AsyncAPI, and JSON Schema.
- **Install**: `npm install -g @stoplight/spectral-cli`
- **Invocation**: `spectral lint openapi.yaml --ruleset .spectral.yaml`
- **Key Flags**: `--fail-severity=warn` (strict enforcement).

### `redocly-cli`
- **Purpose**: OpenAPI bundler, multi-file resolver, and documentation generator.
- **Install**: `npm install -g @redocly/cli`
- **Invocation**: `redocly lint openapi.yaml && redocly bundle openapi.yaml -o dist/openapi.json`

### `asyncapi-cli`
- **Purpose**: Validate and generate AsyncAPI 3.0 event contracts.
- **Install**: `npm install -g @asyncapi/cli`
- **Invocation**: `asyncapi validate asyncapi.yaml`

### `buf`
- **Purpose**: Protobuf proto3 linter, code generator, and breaking change detector.
- **Install**: `brew install bufbuild/buf/buf`
- **Invocation**: `buf lint && buf breaking --against '.git#branch=main'`

### `swagger-cli`
- **Purpose**: OpenAPI multi-file validator and resolver.
- **Install**: `npm install -g @apidevtools/swagger-cli`
- **Invocation**: `swagger-cli validate openapi.yaml`

### `json-schema-validator`
- **Purpose**: Validate payloads against JSON Schema Draft 2020-12.
- **Install**: `npm install -g ajv-cli`
- **Invocation**: `ajv test -s schema.json -d payload.json --spec=draft2020`

---

## 2. GraphQL Tooling, Federation & Schema Governance

### `graphql-inspector`
- **Purpose**: Compare schemas, detect breaking changes, validate documents.
- **Install**: `npm install -g @graphql-inspector/cli`
- **Invocation**: `graphql-inspector diff old-schema.graphql new-schema.graphql`

### `rover`
- **Purpose**: Apollo Federation CLI for subgraph composition and linting.
- **Install**: `npm install -g @apollo/rover`
- **Invocation**: `rover supergraph compose --config supergraph.yaml`

### `graphql-code-generator`
- **Purpose**: Generate TypeScript/Rust/Go types from GraphQL SDL.
- **Install**: `npm install -D @graphql-codegen/cli`
- **Invocation**: `graphql-codegen --config codegen.yml`

### `graphql-armor`
- **Purpose**: Security middleware blocking deep queries, cost spikes, and aliases.
- **Install**: `npm install @escape.tech/graphql-armor`
- **Usage**: Integrate with Apollo Server or Envelop plugins.

### `dataloader`
- **Purpose**: Batching and caching utility to eliminate N+1 queries.
- **Install**: `npm install dataloader`
- **Pattern**: Scoped per HTTP request frame.

### `graphiql`
- **Purpose**: In-browser GraphQL IDE for schema inspection.
- **Install**: `npm install graphiql`

---

## 3. Contract, Consumer-Driven & Property-Based Testing

### `schemathesis`
- **Purpose**: Property-based contract testing and autonomous fuzzing.
- **Install**: `pip install schemathesis`
- **Invocation**: `schemathesis run openapi.yaml --base-url http://localhost:8080 --checks all`

### `pact-cli`
- **Purpose**: Consumer-driven contract verification across provider endpoints.
- **Install**: `gem install pact-provider-verifier`
- **Invocation**: `pact-provider-verifier --provider-base-url=http://localhost:8080 --pact-urls=pacts/contract.json`

### `dredd`
- **Purpose**: HTTP API testing against OpenAPI specifications.
- **Install**: `npm install -g dredd`
- **Invocation**: `dredd openapi.yaml http://localhost:8080`

### `prism`
- **Purpose**: Realistic mock HTTP server with schema validation.
- **Install**: `npm install -g @stoplight/prism-cli`
- **Invocation**: `prism mock openapi.yaml -p 4010`

### `hurl`
- **Purpose**: Plain text HTTP testing and assertion runner.
- **Install**: `cargo install hurl`
- **Invocation**: `hurl --test test.hurl`

### `newman`
- **Purpose**: Command-line runner for Postman collections.
- **Install**: `npm install -g newman`
- **Invocation**: `newman run collection.json -e environment.json`

---

## 4. Security, DAST & Vulnerability Scanning

### `zap-api-scan`
- **Purpose**: OWASP ZAP dynamic application security testing for REST/OpenAPI.
- **Install**: `apt-get install zaproxy`
- **Invocation**: `zap-api-scan.py -t openapi.yaml -f openapi -u http://localhost:8080`

### `cherrybomb`
- **Purpose**: OpenAPI specification validation and vulnerability scanning.
- **Install**: `cargo install cherrybomb`
- **Invocation**: `cherrybomb --file openapi.yaml`

### `trivy`
- **Purpose**: Secret detection, container image and IaC misconfiguration scanning.
- **Install**: `apt-get install trivy`
- **Invocation**: `trivy fs --security-checks vuln,config,secret .`

### `gitleaks`
- **Purpose**: High-performance secret scanner for git repositories.
- **Install**: `apt-get install gitleaks`
- **Invocation**: `gitleaks detect --source=. -v`

### `checkov`
- **Purpose**: Static analysis for API gateway and infrastructure manifests.
- **Install**: `pip install checkov`
- **Invocation**: `checkov -d ./infra --framework openapi,terraform`

### `semgrep`
- **Purpose**: Static analysis identifying API security anti-patterns.
- **Install**: `pip install semgrep`
- **Invocation**: `semgrep --config p/owasp-top-ten .`

---

## 5. Performance, Load Testing & Resilience Engineering

### `k6`
- **Purpose**: Developer-centric scriptable load testing for HTTP, gRPC, and WebSockets.
- **Install**: `apt-get install k6`
- **Invocation**: `k6 run load_test.js`

### `gatling`
- **Purpose**: High-throughput distributed load testing.
- **Install**: `apt-get install gatling`
- **Invocation**: `gatling.sh -s Simulation`

### `hey`
- **Purpose**: Fast HTTP load generator with live terminal statistics.
- **Install**: `go install github.com/rakyll/hey@latest`
- **Invocation**: `hey -n 1000 -c 50 http://localhost:8080/v1/health`

### `vegeta`
- **Purpose**: Constant-rate HTTP load testing tool.
- **Install**: `go install github.com/tsenart/vegeta@latest`
- **Invocation**: `echo 'GET http://localhost:8080/v1/health' | vegeta attack -rate=50 -duration=10s | vegeta report`

### `ghz`
- **Purpose**: High-performance gRPC benchmarking and load generator.
- **Install**: `go install github.com/bojand/ghz/cmd/ghz@latest`
- **Invocation**: `ghz --insecure --proto=service.proto --call=Service.Method -n 1000 localhost:50051`

### `toxiproxy`
- **Purpose**: TCP proxy simulating latency, jitter, bandwidth limits, and outages.
- **Install**: `apt-get install toxiproxy`
- **Invocation**: `toxiproxy-cli create proxy --listen 0.0.0.0:8443 --upstream backend.internal:443`

---

## 6. Gateways, Observability & Protocol Debugging

### `envoy`
- **Purpose**: High-performance edge and service mesh proxy.
- **Install**: `apt-get install envoy`
- **Invocation**: `envoy -c envoy.yaml`

### `traefik`
- **Purpose**: Modern reverse proxy and load balancer.
- **Install**: `apt-get install traefik`
- **Invocation**: `traefik --configFile=traefik.yml`

### `grpcurl`
- **Purpose**: Command-line tool for interacting with gRPC servers.
- **Install**: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
- **Invocation**: `grpcurl -plaintext localhost:50051 list`

### `websocat`
- **Purpose**: CLI client for WebSockets.
- **Install**: `cargo install websocat`
- **Invocation**: `websocat ws://localhost:8080/events`

### `otelcol`
- **Purpose**: OpenTelemetry Collector for distributed tracing and metrics.
- **Install**: `apt-get install otelcol`
- **Invocation**: `otelcol --config=otel-config.yaml`

### `jaeger`
- **Purpose**: End-to-end distributed tracing.
- **Install**: `apt-get install jaeger`
- **Invocation**: `jaeger-all-in-one`

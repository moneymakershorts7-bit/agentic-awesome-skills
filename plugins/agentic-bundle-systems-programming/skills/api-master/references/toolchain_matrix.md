# Exhaustive 48+ FOSS API Enterprise Toolchain Matrix

This document provides operational instructions, package manager recipes, and execution commands for the canonical 48+ FOSS API toolchain.

---

## 1. Specification, Design & Documentation Linters & Swagger Tooling

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
- **Install**: `brew install bufbuild/buf/buf || npm install -g @bufbuild/buf`
- **Invocation**: `buf lint && buf breaking --against '.git#branch=main'`

### `swagger-cli`
- **Purpose**: OpenAPI and Swagger multi-file validator and dereferencer.
- **Install**: `npm install -g @apidevtools/swagger-cli`
- **Invocation**: `swagger-cli validate openapi.yaml`

### `swagger-ui`
- **Purpose**: Interactive API documentation UI bundle for OpenAPI and Swagger specifications.
- **Install**: `npm install -g swagger-ui-dist`
- **Invocation**: `api-master generate-swagger-ui --spec openapi.json --output index.html`

### `swagger-editor`
- **Purpose**: Browser-based designer and editor for OpenAPI and Swagger definitions.
- **Install**: `npm install -g swagger-editor-dist`
- **Invocation**: `swagger-editor-dist`

### `openapi-generator-cli`
- **Purpose**: Generate clients, server stubs, configs, and docs across 50+ languages from OpenAPI.
- **Install**: `npm install -g @openapitools/openapi-generator-cli`
- **Invocation**: `openapi-generator-cli generate -i openapi.yaml -g typescript-fetch -o ./sdk`

### `swagger-codegen-cli`
- **Purpose**: Official Swagger Codegen CLI for generating client SDKs and server stubs.
- **Install**: `npm install -g swagger-codegen-cli`
- **Invocation**: `swagger-codegen generate -i swagger.json -l java -o ./sdk`

### `swagger-parser`
- **Purpose**: Swagger 2.0 and OpenAPI 3.x parser, dereferencer, and validator.
- **Install**: `npm install -g @apidevtools/swagger-parser`
- **Invocation**: `swagger-parser validate openapi.yaml`

### `openapi-typescript`
- **Purpose**: Generate TypeScript types directly from OpenAPI 3.0 & 3.1 schemas with zero runtime overhead.
- **Install**: `npm install -D openapi-typescript`
- **Invocation**: `openapi-typescript openapi.yaml -o schema.d.ts`

### `oasdiff`
- **Purpose**: Diff, breaking change detector, and changelog generator for OpenAPI specifications.
- **Install**: `brew install oasdiff || go install github.com/tufin/oasdiff@latest`
- **Invocation**: `oasdiff breaking base.yaml revision.yaml`

### `vacuum`
- **Purpose**: Ultra-fast OpenAPI 3 and Swagger linter written in Go.
- **Install**: `brew install vacuum || go install github.com/daveshanley/vacuum@latest`
- **Invocation**: `vacuum lint openapi.yaml`

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
- **Invocation**: Configured inside GraphQL server gateway.

### `dataloader`
- **Purpose**: Batching and caching utility to eliminate N+1 relational database lookups.
- **Install**: `npm install dataloader`
- **Invocation**: Wrapped around batched database fetchers.

### `graphiql`
- **Purpose**: In-browser IDE for exploring GraphQL endpoints.
- **Install**: `npm install -g graphiql-app`
- **Invocation**: `graphiql --endpoint http://localhost:8080/graphql`

### `gqlgen`
- **Purpose**: Go library and CLI for building type-safe GraphQL servers.
- **Install**: `go install github.com/99designs/gqlgen@latest`
- **Invocation**: `gqlgen generate`

### `altair`
- **Purpose**: Feature-rich desktop and web GraphQL client IDE.
- **Install**: `npm install -g altair`
- **Invocation**: `altair`

---

## 3. Contract, Consumer-Driven & Property-Based Testing

### `schemathesis`
- **Purpose**: Property-based contract testing and fuzzing for OpenAPI and GraphQL.
- **Install**: `pip install schemathesis`
- **Invocation**: `schemathesis run openapi.yaml --base-url http://localhost:8080 --checks all`

### `pact-cli`
- **Purpose**: Consumer-driven contract testing verifier.
- **Install**: `gem install pact-provider-verifier`
- **Invocation**: `pact-provider-verifier --provider-base-url=http://localhost:8080 --pact-urls=pacts/contract.json`

### `dredd`
- **Purpose**: Validate backend responses against OpenAPI descriptions.
- **Install**: `npm install -g dredd`
- **Invocation**: `dredd openapi.yaml http://localhost:8080`

### `prism`
- **Purpose**: Realistic mock HTTP server and API proxy with validation.
- **Install**: `npm install -g @stoplight/prism-cli`
- **Invocation**: `prism mock openapi.yaml -p 4010`

### `mockoon-cli`
- **Purpose**: Lightweight CLI for running Mockoon mock APIs locally and in CI/CD.
- **Install**: `npm install -g @mockoon/cli`
- **Invocation**: `mockoon-cli start --data ./mock-env.json --port 3000`

### `wiremock`
- **Purpose**: Flexible mock server for HTTP-based APIs with fault and latency injection.
- **Install**: `brew install wiremock || apt-get install wiremock`
- **Invocation**: `wiremock --port 8080 --root-dir ./wiremock`

### `hurl`
- **Purpose**: Plain-text HTTP testing utility for CI/CD pipelines.
- **Install**: `apt-get install hurl || brew install hurl`
- **Invocation**: `hurl --test test.hurl`

### `newman`
- **Purpose**: Postman collection CLI test runner.
- **Install**: `npm install -g newman`
- **Invocation**: `newman run collection.json -e environment.json`

### `mitmproxy`
- **Purpose**: Interactive SSL-capable man-in-the-middle HTTP/WebSocket inspection proxy.
- **Install**: `pip install mitmproxy || brew install mitmproxy`
- **Invocation**: `mitmweb --web-port 8081`

---

## 4. Security, DAST & Vulnerability Scanning

### `zap-api-scan`
- **Purpose**: OWASP ZAP dynamic application security testing against OpenAPI.
- **Install**: `apt-get install zaproxy`
- **Invocation**: `zap-api-scan.py -t openapi.yaml -f openapi -u http://localhost:8080`

### `cherrybomb`
- **Purpose**: CLI that validates OpenAPI specifications and verifies endpoint security controls.
- **Install**: `cargo install cherrybomb`
- **Invocation**: `cherrybomb --file openapi.yaml`

### `trivy`
- **Purpose**: Vulnerability and secret scanner for containers and infrastructure.
- **Install**: `apt-get install trivy || brew install trivy`
- **Invocation**: `trivy fs --security-checks vuln,config,secret .`

### `gitleaks`
- **Purpose**: Secret detection for exposed API keys, tokens, and private credentials.
- **Install**: `brew install gitleaks || apt-get install gitleaks`
- **Invocation**: `gitleaks detect --source=. -v`

### `checkov`
- **Purpose**: Static analysis for API gateways, Terraform, and Kubernetes manifests.
- **Install**: `pip install checkov`
- **Invocation**: `checkov -d ./infra --framework openapi,terraform`

### `semgrep`
- **Purpose**: Static analysis for API security anti-patterns in backend code.
- **Install**: `pip install semgrep`
- **Invocation**: `semgrep --config p/owasp-top-ten .`

### `nuclei`
- **Purpose**: Fast template-based vulnerability scanner for API endpoints.
- **Install**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **Invocation**: `nuclei -u http://localhost:8080 -t http/misconfiguration/`

### `restler-fuzzer`
- **Purpose**: Stateful REST API grammar-based fuzzer developed by Microsoft Research.
- **Install**: `pip install restler`
- **Invocation**: `restler compile --api_spec openapi.json`

---

## 5. Performance, Load Testing & Resilience Engineering

### `k6`
- **Purpose**: Scriptable load testing tool for HTTP/1.1, HTTP/2, gRPC, and WebSockets.
- **Install**: `apt-get install k6 || brew install k6`
- **Invocation**: `k6 run load_test.js`

### `gatling`
- **Purpose**: High-throughput load testing engine.
- **Install**: `apt-get install gatling || brew install gatling`
- **Invocation**: `gatling.sh -s SimulationClass`

### `hey`
- **Purpose**: Tiny HTTP load generator with terminal statistics.
- **Install**: `go install github.com/rakyll/hey@latest`
- **Invocation**: `hey -n 1000 -c 50 http://localhost:8080/v1/health`

### `vegeta`
- **Purpose**: HTTP load testing tool with constant request rate generation.
- **Install**: `go install github.com/tsenart/vegeta@latest`
- **Invocation**: `echo "GET http://localhost:8080/v1/health" | vegeta attack -duration=5s | vegeta report`

### `ghz`
- **Purpose**: gRPC benchmarking and load testing CLI.
- **Install**: `go install github.com/bojand/ghz/cmd/ghz@latest`
- **Invocation**: `ghz --insecure --proto=service.proto --call=Service.Method -n 1000 localhost:50051`

### `toxiproxy`
- **Purpose**: TCP proxy simulating latency, jitter, and network partitioning.
- **Install**: `brew install toxiproxy || apt-get install toxiproxy`
- **Invocation**: `toxiproxy-cli create payment_gateway --listen localhost:8443 --upstream api.stripe.com:443`

### `wrk`
- **Purpose**: Modern HTTP benchmarking tool capable of generating significant load.
- **Install**: `apt-get install wrk || brew install wrk`
- **Invocation**: `wrk -t12 -c400 -d30s http://localhost:8080/v1/health`

### `autocannon`
- **Purpose**: Fast HTTP/1.1 benchmarking tool written in Node.js.
- **Install**: `npm install -g autocannon`
- **Invocation**: `autocannon -c 100 -d 10 http://localhost:8080/v1/health`

---

## 6. Gateways, Observability & Protocol Debugging

### `envoy`
- **Purpose**: High-performance L7 proxy and communication bus for microservices.
- **Install**: `apt-get install envoy || brew install envoy`
- **Invocation**: `envoy -c envoy.yaml`

### `traefik`
- **Purpose**: Modern HTTP reverse proxy and ingress controller.
- **Install**: `apt-get install traefik || brew install traefik`
- **Invocation**: `traefik --configFile=traefik.yml`

### `grpcurl`
- **Purpose**: CLI for interacting with gRPC servers with reflection support.
- **Install**: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
- **Invocation**: `grpcurl -plaintext localhost:50051 list`

### `websocat`
- **Purpose**: CLI utility for connecting to and testing WebSocket streams.
- **Install**: `cargo install websocat || brew install websocat`
- **Invocation**: `websocat ws://localhost:8080/events`

### `otelcol`
- **Purpose**: OpenTelemetry Collector for tracing and metrics aggregation.
- **Install**: `apt-get install otelcol || brew install opentelemetry-collector`
- **Invocation**: `otelcol --config=otel-config.yaml`

### `jaeger`
- **Purpose**: Distributed tracing visualization and root-cause analysis.
- **Install**: `apt-get install jaeger || brew install jaeger`
- **Invocation**: `jaeger-all-in-one`

### `curl`
- **Purpose**: Standard HTTP client with support for all protocols.
- **Install**: `apt-get install curl`
- **Invocation**: `curl -i -H "Accept: application/problem+json" http://localhost:8080/v1/health`

### `httpie`
- **Purpose**: User-friendly command-line HTTP client with JSON formatting and syntax coloring.
- **Install**: `pip install httpie || apt-get install httpie`
- **Invocation**: `http GET localhost:8080/v1/health Accept:application/problem+json`

### `insomnia-cli`
- **Purpose**: Inso CLI for running Insomnia API test suites and linting specs in CI/CD pipelines.
- **Install**: `npm install -g insomnia-inso`
- **Invocation**: `inso run test spc_12345`

### `jq`
- **Purpose**: JSON filter and query processor for piping API payloads.
- **Install**: `apt-get install jq`
- **Invocation**: `curl -s http://localhost:8080/v1/health | jq .`

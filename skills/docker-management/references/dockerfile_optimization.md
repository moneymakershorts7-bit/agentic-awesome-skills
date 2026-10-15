# Advanced Dockerfile Optimization, Multi-Stage Builds & Image Minimization

## High-Level Architecture & Core Concepts

### Build Pipeline Topology
```mermaid
graph TD
    A[Source Context] --> B(.dockerignore Filter)
    B --> C[BuildKit Frontend]
    C --> D{Build Stage(s)}
    D -->|Compilers, SDKs, DevDeps| E[Build Environment]
    E --> F[Artifact Generation]
    F --> G[Runtime Stage]
    G -->|Distroless/Alpine/Scratch| H[Minimal Runtime]
    H --> I[Image Manifest]
    I --> J[Registry Push]
    J --> K[Trivy Scan / SBOM Gen]
    K --> L[Policy Gate]
    L --> M[Deploy]
```

### Core Principles
1.  **Build-Time vs Runtime Separation**: Build toolchains (gcc, node-gyp, maven, cargo, pip dev deps) **never** ship to production.
2.  **Layer Determinism**: Every `RUN` creates a layer. Cache invalidation occurs on file content change (COPY/ADD) or command string change.
3.  **BuildKit as Default**: Enable `DOCKER_BUILDKIT=1` or `# syntax=docker/dockerfile:1.7+` for cache mounts, secret mounts, heredocs, and parallel stage execution.
4.  **Immutable Base Pinning**: Reference base images by `sha256` digest, not mutable tags (`latest`, `22`, `slim`).
5.  **Attack Surface Minimization**: Zero package managers, shells, or debug tooling in final image. Prefer `gcr.io/distroless/*` or `scratch` for static binaries.

---

## Diagnostics & Analysis Commands

### Layer Forensics & Waste Identification
```bash
# 1. Layer history with size attribution (Human readable)
docker history --human --no-trunc <image>:<tag>

# 2. Interactive layer exploration (dive) - CI/CD gate for max layer waste
# Install: https://github.com/wagoodman/dive
dive <image>:<tag>
# CI Mode (fail if wasted space > 10MB or efficiency < 95%)
dive --ci --lowestEfficiency=95 --highestWastedBytes=10485760 <image>:<tag>

# 3. BuildKit cache inspection
docker buildx du
docker buildx prune --keep-storage=20GB --filter=until=72h
```

### Vulnerability Triage & SBOM Generation (Trivy)
```bash
# 1. High/Critical only, exit code 1 on findings (CI Gate)
trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed <image>:<tag>

# 2. Full SBOM generation (SPDX JSON / CycloneDX)
trivy image --format spdx-json --output sbom.spdx.json <image>:<tag>
trivy image --format cyclonedx --output sbom.cdx.json <image>:<tag>

# 3. Scan local Dockerfile for misconfigurations (IaC scan)
trivy config --severity HIGH,CRITICAL .

# 4. Verify base image digest pinning matches registry
docker buildx imagetools inspect <image>@sha256:<digest>
```

### Build Performance Profiling
```bash
# Build with BuildKit trace for flamegraph analysis
BUILDKIT_TRACE=1 docker build --progress=plain -t test . 2> build.trace
# Convert trace to speedscope/perfetto format (requires gotraceui or similar tooling)
```

---

## Production Configuration Recipes & Hardening Files

### 1. Universal Multi-Stage Template (BuildKit Native)
**Features**: Syntax directive, Cache mounts (apt, pip, npm, cargo, go), Secret mounts, Heredocs, Distroless final stage, Digest pinning.

```dockerfile
# syntax=docker/dockerfile:1.7

# ============================================================
# GLOBAL ARGS & BASE PINNING (Renovate/Dependabot compatible)
# ============================================================
ARG BUILDER_IMAGE=docker.io/library/golang@sha256:8f9b3a5b8c5d... # Pin specific digest
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12@sha256:f5b3a2c1d4e... # Non-root, no shell
ARG TARGETARCH
ARG TARGETOS

# ============================================================
# STAGE 1: DEPENDENCY RESOLUTION (CACHED INDEPENDENTLY)
# ============================================================
FROM ${BUILDER_IMAGE} AS deps
WORKDIR /src

# Cache Go module downloads
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download -x

# ============================================================
# STAGE 2: BUILD / COMPILATION
# ============================================================
FROM ${BUILDER_IMAGE} AS builder
WORKDIR /src

# Reuse module cache from deps stage
COPY --from=deps /go/pkg/mod /go/pkg/mod
COPY . .

# Build with cache mount for build cache (go build cache)
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -extldflags '-static'" -o /app/bin/main .

# ============================================================
# STAGE 3: RUNTIME (DISTROLESS / SCRATCH)
# ============================================================
FROM ${RUNTIME_IMAGE} AS runtime
# Non-root user defined in distroless base (nonroot:nonroot 65532:65532)
USER 65532:65532

# Copy only the static binary
COPY --from=builder --chown=65532:65532 /app/bin/main /main

# Runtime configuration via ENV (Immutable config)
ENV GIN_MODE=release \
    PORT=8080

EXPOSE 8080
ENTRYPOINT ["/main"]
```

### 2. Node.js / Python / Java Specific Cache Mount Patterns

#### Node.js (npm/ci + Build)
```dockerfile
# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=docker.io/library/node@sha256:3a1b2c4d5e6f... # 22-alpine or 22-slim digest
ARG BASE_RUNTIME=gcr.io/distroless/nodejs22-debian12@sha256:...

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
# Cache npm store globally
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    npm ci --prefer-offline --no-audit --progress=false

FROM ${NODE_IMAGE} AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Cache build output (e.g. .next, dist)
RUN --mount=type=cache,target=/app/.next/cache \
    npm run build

FROM ${BASE_RUNTIME} AS runtime
WORKDIR /app
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /app/dist ./dist
CO

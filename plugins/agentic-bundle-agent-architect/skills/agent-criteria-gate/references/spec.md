# System One Wire Specification & Criteria Primitives

## 1. Overview
The `/v1/systemone` wire protocol standardizes fast, discriminative, non-autoregressive decision models (such as TypeSafe AI's Jev and Jared Palmer's Kev). Unlike conversational endpoints (`/v1/chat/completions`), `/v1/systemone` evaluates multiple typed questions over an application `state` simultaneously in a single forward pass.

## 2. Question Types

### `noul` (Boolean / Binary Classification)
- Evaluates the probability $P(\text{true}) \in [0.0, 1.0]$.
- Does not return a separate `confidence` field because uncertainty is naturally represented by the probability value ($0.50$ = maximum uncertainty, $0.0$/$1.0$ = high certainty).
- **Request Format:**
  ```json
  {
    "type": "noul",
    "instructions": "Is this action dangerous or destructive?"
  }
  ```
- **Response Format:**
  ```json
  {
    "noul": 0.942
  }
  ```

### `choice` (Categorical Multi-Choice Routing)
- Selects the most probable option among up to 255 discrete choices.
- Returns the selected `choice`, full probability distribution, and aggregate `confidence`.
- **Request Format:**
  ```json
  {
    "type": "choice",
    "instructions": "Route to the best support tier",
    "options": {
      "tier1": "General FAQ and password resets",
      "tier2": "Technical debugging and code bugs",
      "escalation": "Hostile messages, legal notices, or severe outages"
    }
  }
  ```
- **Response Format:**
  ```json
  {
    "choice": "tier2",
    "confidence": 0.885,
    "probabilities": {
      "tier1": 0.082,
      "tier2": 0.885,
      "escalation": 0.033
    }
  }
  ```

### `score` (Ordinal Scale & Continuous Rubric)
- Evaluates a ranked list of 2 to 10 qualitative levels.
- Returns an expected continuous rating (e.g. `2.84` on a 1–3 scale) and probability distribution.
- **Request Format:**
  ```json
  {
    "type": "score",
    "instructions": "Rate urgency from low to critical",
    "levels": [
      "Level 1: Low urgency / informational",
      "Level 2: Moderate urgency / same-day reply",
      "Level 3: Critical emergency / immediate response"
    ]
  }
  ```
- **Response Format:**
  ```json
  {
    "score": 2.84,
    "confidence": 0.871,
    "probabilities": [0.03, 0.10, 0.87]
  }
  ```

## 3. Hierarchical Codebase Discovery & AST Gating

The `CodebaseDiscoveryGate` uses multi-stage System One evaluation:

### Stage 1: Directory Pruning Gate
Evaluates top-level directory names and path semantics before recursing into children. Unrelated modules are pruned without inspecting individual files.

### Stage 2: File Preview Gating & Byte Budget
Under a configurable byte navigation budget (default 256KB), reads preview headers (first ~30 lines) and scores file relevance.

### Stage 3: AST Declaration Slicing
Extracts only relevant AST declaration units (functions, classes, interfaces, signatures, docstrings, call graphs) instead of dumping full raw files.

### Stage 4: Dynamic Evidence Retraction
When stronger cross-file evidence is established, isolated or false-positive matches are dynamically retracted to preserve context headroom.

### Stage 5: Untrusted Data Envelope
Retrieved code is encapsulated as data with `role: "data_payload"` and security notices, preventing indirect prompt injection attacks from codebase files.

## 4. Server Deployment Options

### Local Kev Server (`kev-0.8b`)
- Open-source (Apache 2.0) by Jared Palmer.
- Can be run locally via CLI on CPU or Apple Silicon:
  ```bash
  kev run jaredpalmer/kev-0.8b --threads 2 --port 8000
  ```
- Connect via `SystemOneClient(base_url="http://127.0.0.1:8000")`.

### Hosted Cloud Jev
- Proprietary hosted API by TypeSafe AI.
- Connect via `SystemOneClient(base_url="https://api.typesafe.ai", api_key="YOUR_KEY", model="jev-latest")`.

### Embedded Local Fallback Engine
- Zero dependencies, pure Python in-process engine for instant $(<1\text{ms})$ offline evaluation.
- Automatically used when `fallback_local=True` and remote server is unreachable.

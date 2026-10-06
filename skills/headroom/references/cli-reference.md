# Headroom Reference Guide

## MCP Tools Integration

Headroom exposes the following MCP tools when integrated as a server:

1. `headroom_compress`:
   - `input_text`: The raw text or payload to compress.
   - `compression_level`: Standard (`fast`), Deep (`kompress-v2`), or Lossless Code (`ast`).
2. `headroom_retrieve`:
   - `ccr_key`: Retrieve cached original full-text chunks by token hash.
3. `headroom_stats`:
   - Returns session metrics: input tokens saved, output tokens trimmed, latency delta, cache hit rate.

## Configuration File (`~/.headroom/config.toml`)

```toml
[proxy]
port = 8787
cache_dir = "~/.headroom/cache"
max_cache_gb = 5.0

[compression]
default_ratio = 0.45
preserve_keywords = ["ERROR", "FATAL", "CRITICAL", "PANIC", "FAILED"]
code_mode = "ast_prune"

[agents]
auto_wrap = ["claude", "cursor"]
```

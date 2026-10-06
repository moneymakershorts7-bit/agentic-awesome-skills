# Claude-Mem Architecture & Schemas

## SQLite Schema Overview

The default SQLite store is located at `~/.claude-mem/memory.db`.

```sql
CREATE TABLE IF NOT EXISTS memory_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    project TEXT NOT NULL,
    category TEXT NOT NULL, -- 'fix', 'decision', 'architecture', 'convention'
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    raw_payload TEXT,
    tokens INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
    title, summary, project, category, content=memory_nodes, content_rowid=id
);
```

## MCP Tools Integration

- `mem_search(query, project, category, limit)`: Fast BM25/vector search returning high-level index cards.
- `mem_fetch(ids, detail)`: Retrieves structured metadata for targeted IDs.
- `mem_record(title, summary, category, payload)`: Adds new episodic memory entry.

# Anthropic Tool Calling Security Reference

## Secure Tool Definition
```json
{
  "name": "execute_query",
  "description": "Execute a read-only SQL query against the analytics database.",
  "input_schema": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "A SELECT query. Mutation commands (INSERT, UPDATE, DELETE, DROP) are strictly forbidden."
      }
    },
    "required": ["query"]
  }
}
```
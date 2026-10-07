# NeMo Guardrails Configuration Reference

## `config.yml` Example
```yaml
models:
  - type: main
    engine: openai
    model: gpt-4o

rails:
  input:
    flows:
      - check jailbreak
      - check toxic language
  output:
    flows:
      - self check facts
      - check sensitive data
```

## `rails.co` Example
```colang
define flow check jailbreak
  user prompt injection
  bot refuse to comply
  stop
```
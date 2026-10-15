# OpenAI Evals Adversarial Test Suite

## Eval YAML Definition
```yaml
prompt-injection-defense-eval:
  id: prompt-injection-defense-eval.v1
  description: Evaluates whether the system resists user prompt injection attempts.
  metrics: [accuracy]

prompt-injection-defense-eval.v1:
  class: evals.elsuite.basic.match:Match
  args:
    samples_jsonl: evals/registry/data/prompt_injection_samples.jsonl
```
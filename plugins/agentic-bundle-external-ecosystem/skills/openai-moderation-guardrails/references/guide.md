# OpenAI Moderation Integration Reference

## Python Implementation
```python
import openai

client = openai.OpenAI()

def check_content_moderation(text: str) -> dict:
    response = client.moderations.create(
        model="omni-moderation-latest",
        input=text
    )
    result = response.results[0]
    return {
        "flagged": result.flagged,
        "categories": {k: v for k, v in result.categories.model_dump().items() if v},
        "scores": result.category_scores.model_dump()
    }
```
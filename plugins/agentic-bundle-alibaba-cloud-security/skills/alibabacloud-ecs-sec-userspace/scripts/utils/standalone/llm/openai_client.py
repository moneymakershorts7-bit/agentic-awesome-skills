"""OpenAI Compatible LLM Client."""

import json
import urllib.request
import urllib.error
from typing import Iterator, List, Dict, Tuple
from .base import LLMClient, LLMResponse


class OpenAIClient(LLMClient):
    """OpenAI API compatible client."""

    DEFAULT_BASE_URL = "https://api.openai.com/v1"

    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = ""):
        super().__init__(
            api_key=api_key,
            model=model or "gpt-4o",
            base_url=base_url or self.DEFAULT_BASE_URL
        )

    def _make_request(
        self, payload: dict, stream: bool = False
    ) -> Tuple[Dict, Iterator]:
        """Make HTTP request to OpenAI API."""
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        if stream:
            headers["Accept"] = "text/event-stream"
            payload["stream"] = True

        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers)

        try:
            response = urllib.request.urlopen(req, timeout=60)
            if stream:
                return {}, self._parse_stream(response)
            else:
                with response:
                    body = response.read().decode("utf-8")
                return json.loads(body), iter([])
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            raise RuntimeError(f"OpenAI API error: {e.code} - {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"OpenAI API connection error: {e.reason}")

    def _parse_stream(self, response) -> Iterator[str]:
        """Parse SSE stream response."""
        with response:
            for line in response:
                line = line.decode("utf-8").strip()
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                        content = (
                            chunk.get("choices", [{}])[0]
                            .get("delta", {})
                            .get("content", "")
                        )
                        if content:
                            yield content
                    except json.JSONDecodeError:
                        pass

    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        """Send chat completion request."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 2048),
        }

        response_data, _ = self._make_request(payload, stream=False)

        choice = response_data.get("choices", [{}])[0]
        usage = response_data.get("usage", {})

        return LLMResponse(
            content=choice.get("message", {}).get("content", ""),
            model=response_data.get("model", self.model),
            usage=usage,
            raw_response=response_data,
        )

    def stream_chat(
        self, messages: List[Dict], **kwargs
    ) -> Iterator[str]:
        """Send streaming chat completion request."""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 2048),
        }

        _, stream = self._make_request(payload, stream=True)
        yield from stream

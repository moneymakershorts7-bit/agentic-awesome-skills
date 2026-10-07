"""Anthropic Claude LLM Client."""

import json
import urllib.request
import urllib.error
from typing import Iterator, List, Dict, Tuple
from .base import LLMClient, LLMResponse


class AnthropicClient(LLMClient):
    """Anthropic Claude API client."""

    DEFAULT_BASE_URL = "https://api.anthropic.com"
    API_VERSION = "2023-06-01"

    def __init__(
        self, api_key: str, model: str = "claude-3-sonnet-20240229", base_url: str = ""
    ):
        super().__init__(
            api_key=api_key,
            model=model or "claude-3-sonnet-20240229",
            base_url=base_url or self.DEFAULT_BASE_URL
        )

    def _make_request(
        self, payload: dict, stream: bool = False
    ) -> Tuple[Dict, Iterator]:
        """Make HTTP request to Anthropic API."""
        url = f"{self.base_url}/v1/messages"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "anthropic-version": self.API_VERSION,
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
            raise RuntimeError(f"Anthropic API error: {e.code} - {error_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Anthropic API connection error: {e.reason}")

    def _parse_stream(self, response) -> Iterator[str]:
        """Parse SSE stream response."""
        with response:
            for line in response:
                line = line.decode("utf-8").strip()
                if line.startswith("data: "):
                    data = line[6:]
                    try:
                        event = json.loads(data)
                        if event.get("type") == "content_block_delta":
                            content = event.get("delta", {}).get("text", "")
                            if content:
                                yield content
                        elif event.get("type") == "message_stop":
                            break
                    except json.JSONDecodeError:
                        pass

    def _convert_messages(self, messages: List[Dict]) -> Tuple[str, List[Dict]]:
        """Convert OpenAI format messages to Anthropic format."""
        system_prompt = ""
        anthropic_messages = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "system":
                system_prompt = content
            elif role == "user":
                anthropic_messages.append({
                    "role": "user",
                    "content": content
                })
            elif role == "assistant":
                anthropic_messages.append({
                    "role": "assistant",
                    "content": content
                })

        return system_prompt, anthropic_messages

    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        """Send chat completion request."""
        system_prompt, anthropic_messages = self._convert_messages(messages)

        payload = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": kwargs.get("max_tokens", 2048),
        }

        if system_prompt:
            payload["system"] = system_prompt

        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]

        response_data, _ = self._make_request(payload, stream=False)

        content = ""
        for block in response_data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        usage = response_data.get("usage", {})

        return LLMResponse(
            content=content,
            model=response_data.get("model", self.model),
            usage=usage,
            raw_response=response_data,
        )

    def stream_chat(
        self, messages: List[Dict], **kwargs
    ) -> Iterator[str]:
        """Send streaming chat completion request."""
        system_prompt, anthropic_messages = self._convert_messages(messages)

        payload = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": kwargs.get("max_tokens", 2048),
        }

        if system_prompt:
            payload["system"] = system_prompt

        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]

        _, stream = self._make_request(payload, stream=True)
        yield from stream

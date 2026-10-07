"""Base LLM Client."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Iterator, List, Dict


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    model: str
    usage: dict
    raw_response: Optional[dict] = None

    def __str__(self) -> str:
        return self.content


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, api_key: str, model: str, base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @abstractmethod
    def chat(self, messages: List[Dict], **kwargs) -> LLMResponse:
        """
        Send chat completion request.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            **kwargs: Additional parameters like temperature, max_tokens.

        Returns:
            LLMResponse object.
        """

    @abstractmethod
    def stream_chat(
        self, messages: List[Dict], **kwargs
    ) -> Iterator[str]:
        """
        Send streaming chat completion request.

        Args:
            messages: List of message dicts with 'role' and 'content'.
            **kwargs: Additional parameters.

        Yields:
            Chunks of response content.
        """

    def build_messages(
        self, system_prompt: str = "", user_prompt: str = ""
    ) -> List[Dict]:
        """Build messages list for chat."""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if user_prompt:
            messages.append({"role": "user", "content": user_prompt})

        return messages

    def simple_chat(self, prompt: str, **kwargs) -> str:
        """Simple chat with just a user prompt."""
        messages = self.build_messages(user_prompt=prompt)
        response = self.chat(messages, **kwargs)
        return response.content

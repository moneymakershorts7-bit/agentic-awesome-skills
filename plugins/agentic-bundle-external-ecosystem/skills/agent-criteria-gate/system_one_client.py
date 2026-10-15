"""
System One Decision Layer Client
Wire-compatible with TypeSafe AI's Jev and Jared Palmer's Kev (/v1/systemone)
Supports Noul, Choice, and Score question primitives with calibrated probabilities.
"""

from __future__ import annotations
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class NoulQuestion:
    """Binary / Boolean criteria question evaluating calibrated probability P(true)."""
    instructions: str
    type: str = "noul"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "instructions": self.instructions
        }


@dataclass
class ChoiceQuestion:
    """Categorical routing / multi-choice question evaluating probability distribution."""
    instructions: str
    options: Union[Dict[str, str], List[Dict[str, str]]]
    type: str = "choice"

    def to_dict(self) -> Dict[str, Any]:
        formatted_options: List[Dict[str, str]] = []
        if isinstance(self.options, dict):
            for name, desc in self.options.items():
                formatted_options.append({"name": name, "description": desc})
        elif isinstance(self.options, list):
            formatted_options = self.options
        return {
            "type": self.type,
            "instructions": self.instructions,
            "options": formatted_options
        }


@dataclass
class ScoreQuestion:
    """Ordinal rubric / continuous rating question evaluating probability across scale levels."""
    instructions: str
    levels: List[str]
    type: str = "score"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "instructions": self.instructions,
            "levels": self.levels
        }


QuestionType = Union[NoulQuestion, ChoiceQuestion, ScoreQuestion, Dict[str, Any]]


class SystemOneClient:
    """
    HTTP client for System One decision endpoints (/v1/systemone).
    Compatible with Jared Palmer's Kev (local) and TypeSafe AI's Jev (cloud).
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: Optional[str] = None,
        model: str = "kev-latest",
        timeout: float = 5.0,
        fallback_local: bool = True
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.fallback_local = fallback_local
        self._local_engine = None

    def _get_local_engine(self):
        if self._local_engine is None:
            from local_engine import LocalDecisionEngine
            self._local_engine = LocalDecisionEngine()
        return self._local_engine

    def evaluate(self, state: str, questions: Dict[str, QuestionType]) -> Dict[str, Any]:
        """
        Executes a single forward-pass decision evaluation on the given state.
        Falls back to in-process deterministic local engine if remote endpoint is offline and fallback_local=True.
        """
        payload = {
            "model": self.model,
            "state": state,
            "questions": {
                qid: q.to_dict() if hasattr(q, "to_dict") else q
                for qid, q in questions.items()
            }
        }

        endpoint = f"{self.base_url}/v1/systemone"
        data_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "agent-criteria-gate/1.0"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(endpoint, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    resp_json = json.loads(response.read().decode("utf-8"))
                    return resp_json.get("answers", {})
                else:
                    raise RuntimeError(f"System One returned status {response.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionRefusedError, OSError) as e:
            if self.fallback_local:
                engine = self._get_local_engine()
                return engine.evaluate(state, payload["questions"])
            raise RuntimeError(f"Failed to connect to System One server at {endpoint}: {e}") from e

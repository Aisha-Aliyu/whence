"""Answers from Cloudflare Workers AI, streamed as the model writes them.

Llama 3.3 70B costs 26,668 Neurons per million input tokens and 204,805 per
million output tokens. An answer that reads 2,500 tokens and writes 300 uses
about 130 of the 10,000 free Neurons a day. Free plan and data terms: see
workers_ai.py.
"""

import json
import logging
import time
from collections.abc import Callable, Iterator
from typing import Protocol

import httpx

from app.workers_ai import WorkersAI, WorkersAIError

log = logging.getLogger(__name__)

MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
MAX_TOKENS = 600  # a few sentences with citations
NEURONS_IN, NEURONS_OUT = 26_668 / 1e6, 204_805 / 1e6  # per token

Message = dict[str, str]


class ChatModel(Protocol):
    def stream(self, messages: list[Message]) -> Iterator[str]: ...


class CloudflareChat:
    def __init__(
        self,
        account_id: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        attempts: int = 3,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.ai = WorkersAI(
            account_id,
            api_token,
            timeout=timeout,
            attempts=attempts,
            transport=transport,
            sleep=sleep,
        )

    def close(self) -> None:
        self.ai.close()

    def stream(self, messages: list[Message]) -> Iterator[str]:
        """Yields the answer in pieces. Workers AI sends Server-Sent Events:
        data: {"response": "..."} lines, then data: [DONE]."""
        started = time.monotonic()
        body = {
            "messages": messages,
            "max_tokens": MAX_TOKENS,
            "temperature": 0.2,
            "stream": True,
        }
        response = self.ai.run(MODEL, body, stream=True)
        written, finished = 0, False
        usage: dict[str, int] = {}
        try:
            if response.status_code != 200:
                raise WorkersAIError(f"Workers AI answered HTTP {response.status_code}")
            for line in response.iter_lines():
                data = line.removeprefix("data:").strip()
                if not line.startswith("data:") or not data:
                    continue
                if data == "[DONE]":
                    finished = True
                    break
                event = json.loads(data)
                if isinstance(event, dict):
                    usage = event.get("usage") or usage
                    if text := event.get("response"):
                        written += len(text)
                        yield str(text)
            if not finished:  # the connection closed before the answer did
                raise WorkersAIError("The answer stream ended early")
        except (httpx.HTTPError, ValueError) as error:  # a broken stream or bad JSON
            raise WorkersAIError("The answer stream broke off") from error
        finally:
            response.close()
        estimate = sum(len(message["content"]) for message in messages) // 4
        read = int(usage.get("prompt_tokens", estimate))
        wrote = int(usage.get("completion_tokens", written // 4))
        log.info(
            "Answered with %s in %.1fs: %d tokens in, %d out, about %.0f Neurons",
            MODEL,
            time.monotonic() - started,
            read,
            wrote,
            read * NEURONS_IN + wrote * NEURONS_OUT,
        )

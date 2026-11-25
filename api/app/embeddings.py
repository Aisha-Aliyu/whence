"""Embeddings from Cloudflare Workers AI.

The free plan includes 10,000 neurons a day, about 5 million tokens with this
model, and calls fail with an error past that until 00:00 UTC. Cloudflare does
not train on what we send or keep it after the request:
https://developers.cloudflare.com/workers-ai/platform/privacy/
"""

import logging
import random
import time
from collections.abc import Callable, Sequence
from typing import Protocol

import httpx

log = logging.getLogger(__name__)

MODEL = "@cf/baai/bge-small-en-v1.5"
DIMENSIONS = 384
POOLING = "cls"  # documents and questions must use the same pooling
BATCH_SIZE = 50
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class EmbeddingError(Exception):
    """The provider could not embed the texts."""


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class CloudflareEmbedder:
    def __init__(
        self,
        account_id: str,
        api_token: str,
        *,
        timeout: float = 15.0,
        attempts: int = 4,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not account_id or not api_token:
            raise ValueError("Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN.")
        self.attempts = max(1, attempts)
        self.sleep = sleep
        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/"
        self.client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), BATCH_SIZE):
            vectors += self.embed_batch(texts[start : start + BATCH_SIZE])
        return vectors

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        started = time.monotonic()
        response = self.post({"text": list(texts), "pooling": POOLING})
        if response.status_code != 200:
            raise EmbeddingError(f"Workers AI answered HTTP {response.status_code}")
        try:
            vectors = [[float(x) for x in v] for v in response.json()["result"]["data"]]
        except (ValueError, KeyError, TypeError) as error:
            raise EmbeddingError("Workers AI sent an unexpected response") from error
        if len(vectors) != len(texts) or any(len(v) != DIMENSIONS for v in vectors):
            raise EmbeddingError("Workers AI sent vectors of the wrong shape")
        # The free plan costs nothing; the log shows how much of it we use.
        log.info(
            "Embedded %d passages with %s in %.1fs, about %d tokens",
            len(texts),
            MODEL,
            time.monotonic() - started,
            sum(len(text) for text in texts) // 4,
        )
        return vectors

    def post(self, body: dict[str, object]) -> httpx.Response:
        """Retries timeouts, rate limits and server errors with backoff and jitter."""
        attempt = 1
        while True:
            try:
                response = self.client.post(MODEL, json=body)
                if response.status_code not in RETRY_STATUSES:
                    return response
                problem = f"HTTP {response.status_code}"
            except httpx.TransportError as error:  # includes timeouts
                problem = type(error).__name__
            if attempt == self.attempts:
                raise EmbeddingError(f"Gave up after {attempt} attempts: {problem}")
            # Exponential backoff with full jitter. Not security, so random is fine.
            delay = random.uniform(0, 0.5 * 2**attempt)  # noqa: S311
            log.warning("Workers AI failed (%s), retrying in %.1fs", problem, delay)
            self.sleep(delay)
            attempt += 1

"""Embeddings from Cloudflare Workers AI (bge-small-en-v1.5).

This model costs 1,841 Neurons per million tokens, so the free 10,000 Neurons a
day cover about 5 million tokens. Free plan and data terms: see workers_ai.py.
"""

import json
import logging
import time
from collections.abc import Callable, Sequence
from typing import Protocol

import httpx

from app.workers_ai import WorkersAI, WorkersAIError

log = logging.getLogger(__name__)

MODEL = "@cf/baai/bge-small-en-v1.5"
DIMENSIONS = 384
POOLING = "cls"  # documents and questions must use the same pooling
BATCH_SIZE = 50
# BGE models find passages best when the question carries this instruction.
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

EmbeddingError = WorkersAIError


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


def as_vector(vector: list[float]) -> str:
    """pgvector's text format, [1.5,2,3], sent as a query parameter."""
    return json.dumps(vector, separators=(",", ":"))


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

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for start in range(0, len(texts), BATCH_SIZE):
            vectors += self.embed_batch(texts[start : start + BATCH_SIZE])
        return vectors

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        started = time.monotonic()
        response = self.ai.run(MODEL, {"text": list(texts), "pooling": POOLING})
        if response.status_code != 200:
            raise EmbeddingError(f"Workers AI answered HTTP {response.status_code}")
        try:
            data = response.json()["result"]["data"]
            vectors = [[float(x) for x in vector] for vector in data]
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

"""The Workers AI client: batches, retries with backoff, and response checks.

Requests go to a fake transport, so these tests never reach Cloudflare.
"""

import json
from collections.abc import Callable

import httpx
import pytest

from app.embeddings import DIMENSIONS, MODEL, CloudflareEmbedder, EmbeddingError

Handler = Callable[[httpx.Request], httpx.Response]


def answer(request: httpx.Request) -> httpx.Response:
    texts = json.loads(request.content)["text"]
    data = [[0.5] * DIMENSIONS for _ in texts]
    return httpx.Response(200, json={"success": True, "result": {"data": data}})


def make(handler: Handler, sleeps: list[float] | None = None) -> CloudflareEmbedder:
    waits = [] if sleeps is None else sleeps
    return CloudflareEmbedder(
        "account", "token", transport=httpx.MockTransport(handler), sleep=waits.append
    )


def test_texts_go_out_in_batches_with_the_token() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answer(request)

    vectors = make(handler).embed([f"passage {i}" for i in range(120)])
    assert len(vectors) == 120 and all(len(v) == DIMENSIONS for v in vectors)
    assert [len(json.loads(r.content)["text"]) for r in sent] == [50, 50, 20]
    assert sent[0].headers["authorization"] == "Bearer token"
    assert sent[0].url.path == f"/client/v4/accounts/account/ai/run/{MODEL}"


def test_timeouts_and_server_errors_are_retried_with_backoff() -> None:
    attempts: list[httpx.Request] = []

    def flaky(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        if len(attempts) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        if len(attempts) == 2:
            return httpx.Response(503)
        return answer(request)

    sleeps: list[float] = []
    assert len(make(flaky, sleeps).embed(["a"])) == 1
    assert len(attempts) == 3
    assert len(sleeps) == 2 and 0 <= sleeps[0] <= 1 and 0 <= sleeps[1] <= 2


def test_it_gives_up_after_the_last_attempt() -> None:
    attempts: list[httpx.Request] = []

    def busy(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        return httpx.Response(429)

    with pytest.raises(EmbeddingError):
        make(busy).embed(["a"])
    assert len(attempts) == 4


def test_a_refused_request_is_not_retried() -> None:
    attempts: list[httpx.Request] = []

    def refuse(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        return httpx.Response(401)

    with pytest.raises(EmbeddingError):
        make(refuse).embed(["a"])
    assert len(attempts) == 1


def test_a_reply_with_the_wrong_number_of_vectors_is_an_error() -> None:
    def one_short(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": {"data": [[0.5] * DIMENSIONS]}})

    with pytest.raises(EmbeddingError):
        make(one_short).embed(["a", "b"])


def test_missing_settings_stop_the_api_from_starting() -> None:
    with pytest.raises(ValueError, match="CLOUDFLARE"):
        CloudflareEmbedder("", "")

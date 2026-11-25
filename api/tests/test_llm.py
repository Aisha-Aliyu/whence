"""The Workers AI chat client: a streamed answer, retries and broken streams.

Requests go to a fake transport, so these tests never reach Cloudflare.
"""

import json
from collections.abc import Callable

import httpx
import pytest

from app.llm import MAX_TOKENS, MODEL, CloudflareChat
from app.workers_ai import WorkersAIError

MESSAGES = [{"role": "user", "content": "How long do refunds take?"}]


def stream(*events: object) -> httpx.Response:
    body = "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
    return httpx.Response(200, content=body.encode())


def make(handler: Callable[[httpx.Request], httpx.Response]) -> CloudflareChat:
    return CloudflareChat(
        "account", "token", transport=httpx.MockTransport(handler), sleep=lambda _: None
    )


def test_the_answer_arrives_in_pieces() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        usage = {"prompt_tokens": 12, "completion_tokens": 5}
        return stream(
            {"response": "Refunds take "},
            {"response": "five days."},
            {"response": "", "usage": usage},
        )

    assert list(make(handler).stream(MESSAGES)) == ["Refunds take ", "five days."]
    body = json.loads(sent[0].content)
    assert (body["stream"], body["max_tokens"], body["messages"]) == (
        True,
        MAX_TOKENS,
        MESSAGES,
    )
    assert sent[0].url.path.endswith(MODEL)


def test_a_busy_model_is_retried_before_the_answer_starts() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503) if len(calls) == 1 else stream({"response": "Hi."})

    assert list(make(handler).stream(MESSAGES)) == ["Hi."]
    assert len(calls) == 2


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(400),  # refused
        httpx.Response(200, content=b"data: {not json\n\n"),  # garbled
        httpx.Response(200, content=b'data: {"response": "Refunds"}\n\n'),  # cut off
    ],
)
def test_a_refused_garbled_or_cut_off_answer_is_an_error(
    response: httpx.Response,
) -> None:
    with pytest.raises(WorkersAIError):
        list(make(lambda request: response).stream(MESSAGES))

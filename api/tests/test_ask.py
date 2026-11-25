"""Asking through the API: the event stream, membership, outages and limits."""

import json
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.errors import ApiError
from app.ratelimit import RateLimiter
from tests.conftest import FakeChat, Headers, make_client
from tests.test_documents import upload
from tests.test_search import HANDBOOK
from tests.test_workspaces import create


def ask(
    client: TestClient,
    auth: Headers,
    user: UUID,
    workspace: str,
    body: dict[str, Any] | None = None,
) -> Any:  # TestClient's response type depends on the httpx package it finds
    return client.post(
        f"/v1/workspaces/{workspace}/ask",
        json=body or {"question": "How long do refunds take?"},
        headers=auth(user),
    )


def events(response: Any) -> list[tuple[str, Any]]:
    parsed = []
    for block in response.text.strip().split("\n\n"):
        name, data = block.split("\n", 1)
        parsed.append((name.removeprefix("event: "), json.loads(data[6:])))
    return parsed


def test_an_answer_streams_with_citations_from_this_workspace(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], chat: FakeChat
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    document = upload(client, auth, alice, workspace, HANDBOOK, "handbook.md").json()
    chat.reply = ["Refunds take ", "five days [P1]."]
    response = ask(client, auth, alice, workspace)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    stream = events(response)
    assert [name for name, _ in stream] == ["token", "token", "done"]
    done = stream[-1][1]
    assert (done["covered"], done["verified"]) == (True, True)
    assert done["citations"][0]["document_id"] == document["id"]
    assert done["citations"][0]["section"] == "Refunds"
    assert '<passage id="P1">' in chat.prompts[0][1]["content"]


def test_people_outside_the_workspace_get_404_before_any_model_runs(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], chat: FakeChat
) -> None:
    alice, bob = users
    workspace = create(client, auth, alice)
    upload(client, auth, alice, workspace, HANDBOOK, "handbook.md")
    assert ask(client, auth, bob, workspace).status_code == 404
    assert chat.prompts == []


def test_a_model_outage_ends_the_stream_with_an_error_event(
    client: TestClient, auth: Headers, users: tuple[UUID, UUID], chat: FakeChat
) -> None:
    alice, _ = users
    workspace = create(client, auth, alice)
    upload(client, auth, alice, workspace, HANDBOOK, "handbook.md")
    chat.fail = True
    assert [name for name, _ in events(ask(client, auth, alice, workspace))] == [
        "error"
    ]


def test_questions_are_checked_and_limited_per_user(
    database_url: str, auth: Headers, users: tuple[UUID, UUID]
) -> None:
    alice, bob = users
    with make_client(database_url, questions_per_hour=2) as app:
        workspace = create(app, auth, alice)
        bad = {"question": "How long?", "workspace_id": "another"}
        assert ask(app, auth, alice, workspace, bad).status_code == 422
        statuses = [ask(app, auth, alice, workspace).status_code for _ in range(3)]
        assert statuses == [200, 200, 429]
        assert int(ask(app, auth, alice, workspace).headers["retry-after"]) > 0
        assert ask(app, auth, bob, workspace).status_code == 404  # his own count


def test_a_limit_window_starts_over_after_an_hour() -> None:
    now = [0.0]
    limiter = RateLimiter(1, 3600, "questions", clock=lambda: now[0])
    limiter.hit("alice")
    with pytest.raises(ApiError) as caught:
        limiter.hit("alice")
    assert caught.value.headers["Retry-After"] == "3601"
    now[0] = 3600.0
    limiter.hit("alice")

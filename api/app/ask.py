"""Asking: POST /v1/workspaces/{id}/ask streams the answer as Server-Sent Events.

Events: "token" with {"text": ...} while the model writes, then one "done" with
the outcome (answer, citations, closest passages), or one "error". Every event's
data is JSON, so model text can never break the event framing.
"""

import json
import logging
from collections.abc import Iterator
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.agent import Agent, build
from app.auth import CurrentUser
from app.db import DbPool, as_user
from app.search import searcher
from app.workspaces import find

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/workspaces/{workspace_id}", tags=["asking"])


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    question: str = Field(min_length=3, max_length=1000)


@router.post("/ask", response_class=StreamingResponse)
def ask(
    workspace_id: UUID,
    body: Question,
    request: Request,
    user: CurrentUser,
    pool: DbPool,
) -> StreamingResponse:
    """Any member can ask. Non-members get 404 before any model runs."""
    request.app.state.question_limiter.hit(str(user))
    with as_user(pool, user) as conn:
        find(conn, workspace_id, user)
    search = searcher(pool, user, workspace_id, request.app.state.embedder)
    agent = build(search, request.app.state.chat)
    return StreamingResponse(
        events(agent, body.question),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )


def events(agent: Agent, question: str) -> Iterator[str]:
    try:
        outcome = None
        for mode, chunk in agent.stream(
            {"question": question}, stream_mode=["custom", "values"]
        ):
            if mode == "custom":
                yield event("token", {"text": chunk})
            elif "outcome" in chunk:
                outcome = chunk["outcome"]
        if outcome is None:
            raise RuntimeError("the agent finished without an outcome")
        yield event("done", outcome.model_dump(mode="json"))
    except Exception:
        log.exception("Could not answer a question")
        yield event(
            "error",
            {
                "code": "answer_failed",
                "message": "Whence could not answer just now. Try again in a minute.",
            },
        )


def event(name: str, data: object) -> str:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n"

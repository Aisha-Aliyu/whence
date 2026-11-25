"""Runs the evaluation set against the real models and prints a scorecard.

From api/, on a database the migrations have run on:

    DATABASE_URL=... SUPABASE_URL=... CLOUDFLARE_ACCOUNT_ID=... \\
    CLOUDFLARE_API_TOKEN=... uv run python -m evals.run

It makes a throwaway workspace, uploads handbook.md, asks every question in
questions.json, prints the results and deletes the workspace. A run uses about
1,600 of the 10,000 free Neurons a day.
"""

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.agent import Outcome, build
from app.db import as_user, open_pool
from app.documents import embed_document, fetch, save
from app.embeddings import CloudflareEmbedder
from app.llm import CloudflareChat
from app.search import Hit, searcher
from app.settings import Settings

HERE = Path(__file__).parent


def score(
    case: dict[str, Any], passages: list[Hit], outcome: Outcome
) -> dict[str, Any]:
    """found: the right passage was retrieved. correct: the answer holds an
    expected phrase, or says the documents do not cover it when they do not.
    cited: every sentence cites a passage from this search."""
    if case["answer"] is None:
        return {
            "question": case["question"],
            "found": None,
            "correct": not outcome.covered,
            "cited": None,
        }
    answer = outcome.answer.lower()
    return {
        "question": case["question"],
        "found": any(hit.section == case["section"] for hit in passages),
        "correct": outcome.covered
        and any(phrase.lower() in answer for phrase in case["answer"]),
        "cited": outcome.covered and outcome.verified,
    }


def table(rows: list[dict[str, Any]]) -> str:
    mark = {True: "yes", False: "no", None: "-"}
    lines = [
        "| Question | Passage found | Correct | Cited |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        cells = [mark[row[key]] for key in ("found", "correct", "cited")]
        lines.append(f"| {row['question']} | {' | '.join(cells)} |")
    lines.append("")
    for key in ("found", "correct", "cited"):
        scored = [row[key] for row in rows if row[key] is not None]
        lines.append(f"{key}: {sum(scored)} of {len(scored)}")
    return "\n".join(lines)


def main() -> None:
    settings = Settings()
    account = settings.cloudflare_account_id
    token = settings.cloudflare_api_token.get_secret_value()
    embedder, chat = CloudflareEmbedder(account, token), CloudflareChat(account, token)
    cases = json.loads((HERE / "questions.json").read_text(encoding="utf-8"))
    user = uuid4()  # a made-up user who owns only the throwaway workspace
    with open_pool(settings.database_url.get_secret_value(), 2, 10) as pool:
        with as_user(pool, user) as conn:
            row = conn.execute(
                "INSERT INTO whence.workspaces (name, created_by)"
                " VALUES ('Evaluation', %s) RETURNING id",
                (user,),
            ).fetchone()
            assert row is not None
            workspace = row["id"]
            conn.execute(
                "INSERT INTO whence.memberships (workspace_id, user_id, role)"
                " VALUES (%s, %s, 'owner')",
                (workspace, user),
            )
        try:
            data = (HERE / "handbook.md").read_bytes()
            document, _ = save(pool, user, workspace, "handbook.md", data, len(data))
            embed_document(pool, embedder, user, document.id)
            with as_user(pool, user) as conn:
                if fetch(conn, workspace, document.id).status != "ready":
                    raise SystemExit("Embedding failed. The log above says why.")
            agent = build(searcher(pool, user, workspace, embedder), chat)
            rows = []
            for case in cases:
                state = agent.invoke({"question": case["question"]})
                rows.append(score(case, state["passages"], state["outcome"]))
            print(table(rows))
        finally:
            with as_user(pool, user) as conn:
                conn.execute(
                    "DELETE FROM whence.workspaces WHERE id = %s", (workspace,)
                )
            embedder.close()
            chat.close()


if __name__ == "__main__":
    main()

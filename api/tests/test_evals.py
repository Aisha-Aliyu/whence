"""Scoring for the evaluation set. The run itself needs the real models."""

import json
from pathlib import Path
from uuid import uuid4

from app.agent import NOT_COVERED, verify
from app.extract import extract
from app.search import Hit
from evals.run import score, table

EVALS = Path(__file__).parent.parent / "evals"


def hit(section: str) -> Hit:
    return Hit(
        id=uuid4(),
        document_id=uuid4(),
        document="handbook.md",
        page=None,
        section=section,
        text="Full-time staff get 25 days of paid leave each year.",
        score=0.5,
    )


def test_every_question_points_at_a_real_section() -> None:
    handbook = extract((EVALS / "handbook.md").read_bytes(), "handbook.md")
    sections = {p.section for p in handbook.passages}
    cases = json.loads((EVALS / "questions.json").read_text(encoding="utf-8"))
    assert {c["section"] for c in cases if c["section"]} <= sections
    assert any(c["answer"] is None for c in cases)  # some must not be covered


def test_scores_count_retrieval_answers_and_citations() -> None:
    case = {"question": "Leave?", "section": "Paid leave", "answer": ["25 days"]}
    passages = [hit("Paid leave")]
    good = score(case, passages, verify("You get 25 days [P1].", passages))
    assert (good["found"], good["correct"], good["cited"]) == (True, True, True)
    wrong = score(case, [hit("Expenses")], verify("You get 20 days.", passages))
    assert (wrong["found"], wrong["correct"], wrong["cited"]) == (False, False, False)
    outside = {"question": "Wi-Fi?", "section": None, "answer": None}
    assert score(outside, passages, verify(NOT_COVERED, passages))["correct"]
    assert "found: 1 of 2" in table([good, wrong])
    # Finding nothing for a question the handbook covers earns no citation credit.
    missed = score(case, [], verify(NOT_COVERED, []))
    assert (missed["found"], missed["correct"], missed["cited"]) == (
        False,
        False,
        False,
    )

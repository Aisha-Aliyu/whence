"""Reading uploads: types checked by content, page numbers and passages."""

import pytest

from app import extract as extract_module
from app.errors import ApiError
from app.extract import PASSAGE_CHARS, extract, split
from tests.conftest import make_pdf


def test_a_pdf_keeps_its_page_numbers() -> None:
    extracted = extract(
        make_pdf(["Refunds take five days.", "Shipping is free."]), "policy.pdf"
    )
    assert (extracted.kind, extracted.pages) == ("pdf", 2)
    assert [(p.page, p.text) for p in extracted.passages] == [
        (1, "Refunds take five days."),
        (2, "Shipping is free."),
    ]


def test_markdown_passages_keep_their_section() -> None:
    text = (
        "# Leave\nTake 20 days a year.\n\n## Sick leave\nTell your manager.\n"
        "## Sick leave\nBring a note after three days.\n"
    )
    passages = extract(text.encode(), "handbook.md").passages
    assert [(p.section, p.text) for p in passages] == [
        ("Leave", "Take 20 days a year."),
        ("Sick leave", "Tell your manager."),
        ("Sick leave", "Bring a note after three days."),  # same name, new section
    ]


def test_a_paragraph_with_no_spaces_is_cut_at_the_limit() -> None:
    passages = split("x" * (PASSAGE_CHARS * 2 + 5), None)
    assert [len(p.text) for p in passages] == [PASSAGE_CHARS, PASSAGE_CHARS, 5]


def test_reading_stops_once_a_file_has_too_much_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extract_module, "MAX_PASSAGES", 2)
    for data, name in (
        (make_pdf(["One.", "Two.", "Three."]), "long.pdf"),
        (b"One.\n\n" + b"x" * PASSAGE_CHARS * 2, "long.txt"),
    ):
        with pytest.raises(ApiError) as caught:
            extract(data, name)
        assert caught.value.code == "too_much_text"


def test_long_text_becomes_passages_under_the_limit_with_nothing_lost() -> None:
    paragraph = " ".join(f"word{i}" for i in range(1000))
    passages = split(f"{paragraph}\n\nThe end.", None)
    assert len(passages) > 1
    assert all(len(p.text) <= PASSAGE_CHARS for p in passages)
    assert " ".join(p.text for p in passages).split() == f"{paragraph} The end.".split()


@pytest.mark.parametrize(
    ("data", "name", "status"),
    [
        (b"\x89PNG\r\n\x1a\n", "photo.png", 415),  # not an allowed type
        (b"Plain words", "report.pdf", 415),  # the name says PDF, the content does not
        (b"\xff\xfe\x00h\x00i", "notes.txt", 415),  # not UTF-8
        (b"text\x00\x01\x02", "notes.txt", 415),  # binary content
        (b"%PDF-1.7 damaged", "broken.pdf", 422),
        (make_pdf([""]), "scan.pdf", 422),  # no text layer, like a scan
        (b"  \n\n  ", "empty.md", 422),
    ],
)
def test_files_that_fail_a_check_are_refused(
    data: bytes, name: str, status: int
) -> None:
    with pytest.raises(ApiError) as caught:
        extract(data, name)
    assert caught.value.status == status

"""Reading uploads: check the type from the content, pull out the text with page
numbers, and split it into passages small enough to embed and cite.

Document text is untrusted data. It is stored and shown as plain text only.
"""

import io
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from pypdf import PdfReader

from app.errors import ApiError

Kind = Literal["pdf", "markdown", "text"]

EXTENSIONS: dict[str, Kind] = {
    ".pdf": "pdf",
    ".md": "markdown",
    ".markdown": "markdown",
    ".txt": "text",
}
MAX_PAGES = 500
MAX_PASSAGES = 2000
# About 300 tokens, well inside the embedding model's 512-token limit.
PASSAGE_CHARS = 1200
HEADING = re.compile(r"#{1,6}\s+(.+)")


@dataclass(frozen=True)
class Passage:
    page: int | None
    section: str | None
    text: str


@dataclass(frozen=True)
class Extracted:
    kind: Kind
    pages: int | None
    passages: list[Passage]


def kind_of(name: str) -> Kind:
    """The type a file name claims. extract() then checks the content agrees."""
    kind = EXTENSIONS.get(name[name.rfind(".") :].lower()) if "." in name else None
    if kind is None:
        raise ApiError(415, "unsupported_type", "Upload a PDF, Markdown or text file.")
    return kind


def extract(data: bytes, name: str) -> Extracted:
    kind = kind_of(name)
    if kind == "pdf":
        extracted = read_pdf(data)
    else:
        text = decode(data)
        extracted = Extracted(kind, None, split(text, None, kind == "markdown"))
    if not extracted.passages:
        raise ApiError(
            422,
            "no_text",
            "We found no text in this file. Scanned PDFs are not supported yet.",
        )
    return extracted


def too_much_text() -> ApiError:
    return ApiError(
        413, "too_much_text", "This file has too much text. Split it into parts."
    )


def read_pdf(data: bytes) -> Extracted:
    if not data.startswith(b"%PDF-"):
        raise ApiError(415, "unsupported_type", "This file is not a PDF.")
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            raise ApiError(
                422, "unreadable_file", "Password-protected PDFs are not supported."
            )
        if len(reader.pages) > MAX_PAGES:
            raise ApiError(
                413, "too_many_pages", f"PDFs can have up to {MAX_PAGES} pages."
            )
        passages: list[Passage] = []
        for number, page in enumerate(reader.pages, start=1):
            passages += split(page.extract_text(), number)
            if len(passages) > MAX_PASSAGES:  # stop now: text can dwarf the file
                raise too_much_text()
        return Extracted("pdf", len(reader.pages), passages)
    except ApiError:
        raise
    except Exception as error:  # a damaged PDF can fail in many ways
        raise ApiError(422, "unreadable_file", "We could not read this PDF.") from error


def decode(data: bytes) -> str:
    try:
        text = data.removeprefix(b"\xef\xbb\xbf").decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None or "\0" in text:  # binary content with a text file's name
        raise ApiError(415, "unsupported_type", "This file is not UTF-8 text.")
    return text


def split(text: str, page: int | None, markdown: bool = False) -> list[Passage]:
    """Groups paragraphs into passages of up to PASSAGE_CHARS characters.

    A passage never spans two pages or two Markdown sections, so every
    citation points at one place.
    """
    passages: list[Passage] = []
    parts: list[str] = []
    size = 0
    current, heading = -1, None
    for section, title, paragraph in paragraphs(text, markdown):
        for piece in pieces(paragraph):
            if parts and (section != current or size + len(piece) > PASSAGE_CHARS):
                passages.append(Passage(page, heading, "\n\n".join(parts)))
                if len(passages) > MAX_PASSAGES:
                    raise too_much_text()
                parts, size = [], 0
            current, heading = section, title
            parts.append(piece)
            size += len(piece) + 2
    if parts:
        passages.append(Passage(page, heading, "\n\n".join(parts)))
    if len(passages) > MAX_PASSAGES:
        raise too_much_text()
    return passages


def paragraphs(text: str, markdown: bool) -> Iterator[tuple[int, str | None, str]]:
    """Yields (section number, heading, paragraph). Blank lines end a paragraph,
    and every Markdown heading starts a new section, even a repeated one."""
    section, heading = 0, None
    lines: list[str] = []
    for line in [*text.splitlines(), ""]:
        stripped = line.strip()
        match = HEADING.fullmatch(stripped) if markdown else None
        if stripped and not match:
            lines.append(stripped)
            continue
        if lines:
            yield section, heading, "\n".join(lines)
            lines = []
        if match:
            section, heading = section + 1, match.group(1)[:200]


def pieces(paragraph: str) -> Iterator[str]:
    """Cuts a long paragraph at spaces into pieces of up to PASSAGE_CHARS.

    It moves an offset instead of copying the rest each time, so a huge
    paragraph costs time in proportion to its length.
    """
    start, end = 0, len(paragraph)
    while end - start > PASSAGE_CHARS:
        limit = start + PASSAGE_CHARS
        cut = max(
            paragraph.rfind(" ", start, limit), paragraph.rfind("\n", start, limit)
        )
        if cut <= start:
            cut = limit
        if piece := paragraph[start:cut].strip():
            yield piece
        start = cut
        while start < end and paragraph[start].isspace():
            start += 1
    if rest := paragraph[start:].strip():
        yield rest

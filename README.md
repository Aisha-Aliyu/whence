# Whence

Whence answers questions from your team's own documents and cites the passage behind every claim. When the documents do not contain the answer, it says so instead of guessing.

Status: in development since November 2026. Not ready for use yet.

## What it will do

- Answer questions about uploaded PDFs, Word files, Markdown, plain text and HTML.
- Attach a citation to every claim. Each citation opens the exact passage, with its page or section.
- Show the closest passages and say plainly when the documents do not cover a question.
- Keep each workspace's documents private to its members, enforced in the API and again in the database.

## How it works

A Next.js web app talks to a Python API built with FastAPI. The API runs a LangGraph agent that searches documents stored in Postgres with pgvector, using vector and keyword search together, and writes answers that cite their sources. Every service it uses runs on a free plan. Diagrams, data flow and trade-offs are in [docs/architecture.md](docs/architecture.md).

## Docs

- [Product spec](docs/product-spec.md): the problem, the users, the scope and the quality targets
- [Architecture](docs/architecture.md): components, data flow, the security model and the decisions behind them
- [Engineering concepts](docs/engineering-concepts.md): how Whence deals with rate limits, retries, backups and other production concerns
- [Roadmap](docs/roadmap.md): the build plan, day by day
- [How we work](docs/workflow.md): branches, reviews and the definition of done

## Security

Found a vulnerability? Please report it privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## License

[MIT](LICENSE)

# Roadmap

Whence is a portfolio project, so the plan aims at a working demo in nine days. A day is a milestone, not a calendar day, and each one ends with something you can see working.

## How each day works

1. Give Claude Code the day's task. Claude Code works on its own branch and opens a pull request.
2. Checks run and CodeRabbit reviews once. Claude Code fixes what matters and explains what it skips.
3. Read the changes. Ask about anything you could not explain in an interview.
4. Squash and merge, then tick the day off below.

## Plan and design

- [x] Day 1, plan and guardrails. Name, product spec, architecture, roadmap, working rules. Protected main branch, CodeRabbit, secret scanning, Dependabot, CLAUDE.md. Concepts: SDLC, branch protection, secrets management, CI/CD.
- [x] Day 2, development environment and AI guardrails. A dev container for Codespaces, a Claude Code hook that checks every package before it installs, a read-only review agent, verified commits. Concepts: supply chain attacks, slopsquatting.
- [ ] Day 3, design system. Color tokens, type, spacing, our own SVG logo, favicon and icons, component rules, and wireframes of the main screens. Concepts: design tokens, contrast ratios, WCAG 2.2.

## Build

- [x] Day 4, API and database. FastAPI with a health check and settings from environment variables, Postgres with pgvector on Supabase, migrations, row-level security, Supabase sign-in checked by the API, workspace roles, a test that one workspace cannot see another's data, and CI for lint, types and tests. Concepts: migrations, row-level security, JWT, RBAC.
- [x] Day 5, documents. Upload with file checks, text extraction with page numbers, chunking, embeddings and processing status. Concepts: idempotency, retries.
- [ ] Day 6, asking. Hybrid search, the LangGraph agent with citations and "the documents do not cover this" answers, streaming, rate limits, and a small evaluation set. Concepts: RAG, prompt injection, rate limiting.
- [ ] Day 7, web app. Next.js with the design tokens: sign in, documents, asking with the source viewer, a landing page, privacy and terms pages, and a 404 page. Concepts: XSS, CSP, secure cookies.

## Ship

- [ ] Day 8, tests and security. End-to-end tests of the main flows, a security review with fixes, and keyboard and mobile checks. Concepts: threat modeling, OWASP Top 10.
- [ ] Day 9, deploy and showcase. The web app on Vercel, the API on a free host, the host's free subdomain, and a README with screenshots, the architecture, evaluation results and a short demo video. Concepts: deployment, cold starts.

Cut to keep the project small: a background job queue, two-factor sign-in, analytics, feature flags, a full observability stack, load and chaos tests, an SEO day and a staging environment. Each can come back later if a job interview calls for it.

## Launch rules

We do not launch until all of these are true:

- The app is served over HTTPS from the web host's free subdomain.
- The security review has no open high or critical findings.
- The main screens work with a keyboard alone and at phone width.
- The privacy page describes what the app actually does with data.

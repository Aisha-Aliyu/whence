# Roadmap

Whence gets built one day at a time. A day is a milestone, not a calendar day. Small days take one session of one to two hours. Big ones, such as authentication (Day 6), the legal pages (Day 18) and the security audit (Day 21), take several sessions and several pull requests. Every pull request ends with something you can see working.

The plan follows the software development life cycle (SDLC): plan, design, build, test, deploy, operate. We do not skip a phase to go faster, because the skipped phase comes back later as a bug.

## How each day works

1. Read the day's goal and the concepts it covers.
2. Give Claude Code the day's task. Claude Code works on its own branch.
3. Open a pull request. Checks run, CodeRabbit reviews, then an independent review agent reviews.
4. Read the changes and the reviews. Ask about anything you could not explain in an interview.
5. Resolve every comment, then squash and merge.
6. Tick the day off below.

## Phase 1: Plan and design

- [ ] Day 1, plan and guardrails. Name, product spec, architecture, roadmap, working rules. Protected main branch, CodeRabbit, secret scanning, Dependabot, CLAUDE.md. Concepts: SDLC, branch protection, secrets management, CI/CD, IAM.
- [ ] Day 2, development environment and AI guardrails. A dev container for Codespaces (Python, Node, Docker), the Claude Code cloud environment, a Claude Code hook that checks every package before it installs (does it exist, how old is it, does it have known vulnerabilities or malware reports), a read-only review agent, verified commits. Concepts: supply chain attacks, slopsquatting, dependency hell.
- [ ] Day 3, design system. Color tokens from the palette, type, spacing, radius, our own SVG logo, favicon and icons, component rules, wireframes of the main screens, and the application for a free whence.eu.org domain, which can take months to approve. Concepts: design tokens, contrast ratios, WCAG 2.2.

## Phase 2: Build the backend

- [ ] Day 4, API skeleton. FastAPI app, settings from environment variables, `/healthz` and `/readyz`, structured logging, one error format, tests, Dockerfile, CI for lint, types and tests (including the package check's tests), CodeQL, a check that GitHub's dependency graph reads `uv.lock`, and uv's `exclude-newer` setting, so dependencies of dependencies also wait 7 days. Concepts: health checks, liveness and readiness, Docker, API versioning, timeouts, build caching.
- [ ] Day 5, database. Schema, Alembic migrations, indexes, row-level security, database roles, connection pooling, Postgres with pgvector for local development. Concepts: migrations, schema versioning, indexing, N+1 queries, CAP theorem.
- [ ] Day 6, authentication and authorization. Supabase Auth with password rules, Google sign-in, authenticator-app 2FA, CAPTCHA, email verification and a free SMTP service for sign-in emails. A breached-password check. Token verification in the API. Workspace roles. Tests that prove one workspace cannot see another's data. Concepts: OAuth, JWT, key rotation, RBAC, clock skew.
- [ ] Day 7, ingestion part 1. Upload route with file validation, private storage, the job queue, the worker. Concepts: message queues, pessimistic and optimistic locking, idempotency, race conditions, deadlocks, backpressure, sagas.
- [ ] Day 8, ingestion part 2. Text extraction with page numbers, chunking along headings, embeddings in batches, deduplication by content hash, retries with exponential backoff, dead letter state. Embedding model chosen by recall. Concepts: retries, dead letter queues, eventual consistency, memory use.
- [ ] Day 9, retrieval. Hybrid search with pgvector and Postgres full text, reciprocal rank fusion, workspace filters, a reranking experiment, query tuning, caching. Concepts: query optimization, caching, cache invalidation, latency.
- [ ] Day 10, the agent. The LangGraph graph from the architecture doc, conversation history from our own tables, citation checks, prompt injection defenses. Answer model chosen by evaluation. Concepts: circuit breakers, guardrails, cost control.
- [ ] Day 11, the ask API. Streaming with Server-Sent Events, rate limits, request validation, trimmed responses, cost tracking. Concepts: rate limiting, DoS protection, CORS, SSE compared with WebSockets and long polling.
- [ ] Day 12, evaluations. A test set of real questions, metrics (recall@8, citation precision, abstention accuracy), an eval run in CI on every pull request and a full run every night. Concepts: SLIs, regression testing, cron jobs.
- [ ] Day 13, observability. OpenTelemetry traces, model call traces, error tracking, metrics, SLOs, alerts, audit log. Concepts: tracing, metrics, alerting, error budgets, on-call.

## Phase 3: Build the frontend

- [ ] Day 14, web app foundation. Next.js, design tokens, self-hosted fonts, layout, security headers, Content Security Policy, the server-side bridge to the API, and pnpm's `minimumReleaseAge` setting, so JavaScript dependencies also wait 7 days. Concepts: XSS, CSP, reverse proxies.
- [ ] Day 15, account screens. Sign-up, sign-in, 2FA setup and challenge, password reset, email verification, session handling. Concepts: secure cookies, CSRF.
- [ ] Day 16, workspaces and documents. Uploads with progress, statuses, replace and delete, members and invites, skeleton loaders that match each screen.
- [ ] Day 17, asking. Streaming answers, citations, a source viewer that highlights the passage, keyboard and screen reader support.
- [ ] Day 18, public pages and legal. Landing page, how-it-works page, privacy policy, terms of use, cookie policy, acceptable use policy, accessibility statement, cookie consent, a custom 404 page, error pages, footer. Concepts: compliance, dark patterns.
- [ ] Day 19, analytics, flags and speed. Product analytics that load only after consent, feature flags, image and font optimization, bundle size checks, a responsive pass from 280 px to 2560 px. Concepts: CDN, edge caching, canary releases.

## Phase 4: Test, ship and operate

- [ ] Day 20, testing. Unit, integration and end-to-end tests with Playwright, a "try to break it" session, a load test, chaos drills. Concepts: throughput, chaos engineering.
- [ ] Day 21, security audit. A senior security review of the whole codebase, OWASP checks, dependency audit, headers, CORS, row-level security tests, prompt injection tests, then fixes. Concepts: threat modeling, SSRF, open redirects.
- [ ] Day 22, deployment. Free hosting choice, staging and production environments, secrets per environment, a deploy pipeline that runs migrations, health checks, rollback drill, backups and a restore drill, and keeping the free database awake. Concepts: rolling and blue-green deploys, rollbacks, disaster recovery, autoscaling, cold starts.
- [ ] Day 23, domain and edge. whence.eu.org if it has been approved, otherwise the host's free subdomain. DNS, TLS, HSTS, CDN and firewall. Concepts: DNS, TLS, HTTP/2 and HTTP/3.
- [ ] Day 24, search engines and AI assistants. Titles and meta descriptions, sitemap.xml, robots.txt, llms.txt, structured data, Google Search Console, Bing Webmaster Tools, PageSpeed checks.
- [ ] Day 25, launch. Final security audit, independent review, launch checklist, README case study with the architecture and eval results, demo video, interview notes. Concepts: semantic versioning, postmortems.

## Launch rules

We do not launch until all of these are true:

- The app is served over HTTPS from its permanent address: whence.eu.org if it is approved in time, otherwise the host's free subdomain.
- The final security audit has no open high or critical findings.
- Every page passes the accessibility and mobile checks in the definition of done.
- The legal pages describe what the app actually does with data.
- Evaluation results meet the targets in the product spec.

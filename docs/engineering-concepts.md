# Engineering concepts in Whence

How Whence handles the problems production systems run into. Each row says what the concept means in plain words, what we do about it, and the day of the [roadmap](roadmap.md) where it gets built or tested. A dash in the Day column means we do not need it at this size, and the row says what would change that.

## Security

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| SQL injection | User input ends up running as part of a database command | Parameterized queries only. CodeQL and CodeRabbit flag any SQL built from strings | 5 |
| XSS (cross-site scripting) | An attacker's script runs in another user's browser | React escapes output. Answers render as sanitized markdown with no images or raw HTML. A strict Content Security Policy blocks injected scripts, with nonces on signed-in pages and hashes on cached public pages. Tokens sit in cookies that scripts cannot read | 14, 17 |
| CORS | The browser rule that decides which sites may call an API | The browser only talks to our own web server, so the API sends no CORS headers and browsers refuse any cross-origin call to it. If third parties ever need the API, they get API keys and an explicit allowlist, never a wildcard | 11, 14 |
| SSRF | Tricking a server into calling internal addresses for you | Version 1 never fetches URLs from user input. If we add that, we block private IP ranges after DNS resolution and on every redirect | 21 |
| Rate limiting | Capping how many requests one client can make in a time window | The web server limits per IP, because only it sees the visitor's real address: 100 requests per hour on the public demo's ask route with a daily token budget for the demo, and stricter limits on sign-in and sign-up. The API limits each signed-in user per minute. Counters live in shared storage so every instance enforces the same limit | 11 |
| DoS protection | Keeping floods of traffic from taking the service down | CDN firewall, rate limits, request size limits, timeouts and bounded queues | 11, 23 |
| OAuth | Signing in through another provider without sharing your password | Google sign-in through Supabase Auth | 6 |
| JWT rotation | Replacing token signing keys without logging everyone out | Supabase asymmetric signing keys. The API caches the public keys and refetches them when it sees an unknown key ID | 6 |
| TLS and encryption in transit | Encrypting data on the network | HTTPS everywhere, HSTS, TLS to the database | 23 |
| Encryption at rest | Encrypting stored data on disk | Provider disk encryption, plus our own encryption for any third-party credentials we ever store | 5 |
| IAM | Who and what may do which actions in our infrastructure | Least privilege: separate database roles for the app and for migrations, scoped GitHub tokens, 2FA on every account | 1, 5, 22 |
| Secrets management | Keeping keys and passwords out of code | Environment variables, GitHub secrets per environment, secret scanning, and a rotation runbook | 1, 22 |

## Data and consistency

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| Database migrations | Versioned, reviewable changes to the schema | Alembic migrations, reviewed in pull requests, run by the deploy pipeline before new code goes live | 5, 22 |
| Schema versioning | Knowing which schema version is live and changing it safely | Alembic's revision history. Breaking changes use expand then contract: add the new shape, move readers, remove the old shape later | 5 |
| Database indexing | Data structures that make lookups fast | B-tree indexes on foreign keys and filters, HNSW for vectors, GIN for full text | 5, 9 |
| Query optimization | Making queries cheap | `EXPLAIN ANALYZE` on hot queries and a `LIMIT` on every list. An HNSW index ranks first and filters after, so a small workspace could get too few results. pgvector's iterative index scans (version 0.8 and later) fix that, and a test checks recall on a small workspace | 9 |
| N+1 queries | Running one query per item inside a loop | Batch loading, a review checklist item, and tests that count queries | 5 |
| Connection pooling | Reusing database connections instead of opening one per request | A connection pool in the API plus Supabase's pooler in transaction mode. That mode keeps no session state between transactions, so we turn off server-side prepared statements, and the worker's LISTEN connection uses session mode | 5 |
| Optimistic locking | Detecting at save time that someone else changed the record | A version column on documents. A stale update fails with HTTP 409 | 7 |
| Pessimistic locking | Locking a row before working on it | Workers claim jobs with `SELECT ... FOR UPDATE SKIP LOCKED` | 7 |
| Distributed locks | One lock shared by several machines | Postgres advisory locks taken with `pg_try_advisory_xact_lock`, which releases at the end of the transaction and works through a transaction-mode pooler. Each scheduled task (backups, cleanup) runs once even with several instances | 22 |
| Deadlocks | Two transactions each waiting for the other forever | Locks taken in a consistent order, short transactions, a `lock_timeout`, and a retry when Postgres cancels a transaction to break a deadlock (error code 40P01) | 7 |
| Race conditions | Results that depend on timing | Unique constraints, transactions, idempotency keys and `SKIP LOCKED` | 7 |
| Distributed transactions and sagas | Keeping several systems consistent without one shared transaction | One database means no distributed transactions. An upload still touches two systems: file storage, then the database. If the database insert fails, the API deletes the stored file. That compensating step is the core idea of the saga pattern. A scheduled job removes any files a crash left behind | 7 |
| CAP theorem | During a network split, a system has to choose between consistency and availability | One primary Postgres, so we choose consistency | 5 |
| Eventual consistency | Data becomes correct after a delay | A new upload joins search results only after processing finishes. The UI shows its status the whole time | 8 |
| Replication and read replicas | Copies of the database, often used to spread read load | Not needed yet. We add a read replica when reads outgrow one instance | - |
| Sharding and partitioning | Splitting data across servers or tables | Not needed. If `chunks` reaches tens of millions of rows, we partition it by workspace | - |
| Backups | Copies we can restore from | The free database plan has no automatic backups, so a scheduled GitHub Actions workflow takes an encrypted `pg_dump`, with the key kept in GitHub secrets, and keeps it as a workflow artifact for up to 90 days. We practise restoring it | 22 |
| Disaster recovery | The plan for getting service back after losing a system | A written runbook with two targets: a recovery point objective (RPO) of 24 hours, so we lose at most a day of data, and a recovery time objective (RTO) of 4 hours. A restore that long spends more than the month's 3.6-hour error budget, which is the budget doing its job: once it is spent, feature work stops until reliability recovers | 22 |

## Reliability

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| Timeouts | A limit on how long to wait | Every network call, model call and job step has one | 4 onward |
| Retries | Trying a failed operation again | Only for operations that are safe to repeat, with a fixed maximum | 8 |
| Exponential backoff | Waiting longer after each failure, with random jitter so clients do not retry in sync | Job retries and model calls | 8 |
| Idempotency | Doing something twice has the same effect as doing it once | An `Idempotency-Key` header on create routes, and duplicate uploads detected by content hash | 7 |
| Circuit breakers | Stop calling a failing dependency for a while instead of piling up requests | Around model providers. When one is down, users get a clear message at once | 10 |
| Backpressure | Telling producers to slow down when consumers are full | Bounded worker concurrency, and HTTP 429 with `Retry-After` when queues are full | 7, 11 |
| Message queues | Handing work to a background process | The `jobs` table in Postgres | 7 |
| Dead letter queues | Where work goes after too many failures | Jobs move to `dead_letter` after 5 attempts, and admins can see why | 8 |
| Pub/sub | One publisher, many listeners | Postgres `LISTEN/NOTIFY` wakes a long-running worker as soon as a job arrives, over a session-mode connection. If our free host cannot keep a worker running, the API starts each job itself, and a scheduled GitHub Actions workflow calls a protected sweep endpoint to pick up anything missed | 7 |
| Event-driven architecture | Parts of the system react to events instead of calling each other directly | An upload creates a job, the job's status changes stream to the UI | 7 |
| Webhooks | Another service calls your URL when something happens | We verify the signature of every webhook we receive. Sending webhooks to customers is version 2 | 6 |
| Health checks | An endpoint that reports whether the service works | `/healthz` answers if the process is alive. `/readyz` also checks the database | 4 |
| Liveness and readiness probes | Restart a dead instance; send no traffic to one that is not ready | The host polls `/healthz` and `/readyz` | 4, 22 |
| Failover | Switching to a standby when the primary fails | Version 1 runs one database instance, so recovery means restoring from backup within the disaster recovery targets. Automatic failover needs a standby database, which Supabase's free plan does not include | 22 |
| Chaos engineering | Breaking things on purpose to prove the system recovers | Kill the worker in the middle of a job, cut off the model API, slow the database, and check that everything recovers | 20 |
| Network partitions | Parts of the system cannot reach each other | Job leases expire so another worker retries, and writes are idempotent | 7, 20 |
| Clock skew | Machines disagree about the time | Leases use the database clock (`now()`), and token checks allow a few seconds of leeway | 6, 7 |
| Memory leaks | Memory that never gets released | Uploads stream in chunks, caches have size limits, and load tests watch memory | 8, 20 |
| Garbage collection | Automatic memory cleanup | Python frees most objects by reference counting. We avoid holding large documents in long-lived objects | 8 |
| Thread safety | Correct behavior when code runs at the same time | An async API with no shared mutable globals, and one pooled connection per task | 4 |
| Production incidents, on-call and postmortems | Handling outages and learning from them | Alerts to email and phone, a runbook for each alert, and a blameless postmortem template | 13, 25 |

## Performance and scale

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| Caching | Keeping results to avoid repeating work | Embeddings cached by content hash; answers cached per workspace and corpus version | 9 |
| Cache invalidation | Removing stale cached data | Any document change raises the workspace's corpus version, so old cache keys stop matching | 9 |
| CDN | Servers near users that cache files | Static assets and public pages | 19 |
| Edge caching | Caching responses at those servers | Public pages are cached. Anything tied to a session gets `Cache-Control: private, no-store` | 19 |
| Latency | How long one request takes | Measured for retrieval on Day 9, then per route and per agent step from Day 13 | 9, 13 |
| P99 and tail latency | How slow the slowest 1% of requests are | Targets set on p95 and p99, never on averages | 13 |
| Throughput | How much work the system finishes per second | Load test targets on Day 20 | 20 |
| Load balancing | Spreading traffic across instances | The hosting platform does it | 22 |
| Reverse proxies | A server that sits in front of other servers | The CDN sits in front of everything, and the web server forwards API calls | 14, 23 |
| API gateways | One front door that handles auth, limits and routing for APIs | At our size, FastAPI middleware does this job | 11 |
| Horizontal scaling | Adding more instances | The API keeps no state in memory between requests, so we can run more copies | 22 |
| Vertical scaling | Moving to a bigger instance | Usually the first step when the database needs more room, once there is a budget for it | 22 |
| Autoscaling | Adding and removing instances automatically | Serverless functions scale on their own within the free plan's quotas. We track usage against every quota so a busy day cannot get the app suspended | 22 |
| Cold starts | A slow first request after a period of no traffic | Free hosts sleep or cold-start when idle, and Render's free plan takes about a minute to wake. The page shows that the server is waking instead of an error, and Day 22 measures each option | 22 |
| Serverless limits | Caps on run time, memory and payload size | Part of the hosting decision. Vercel's free functions stop after 5 minutes, so ingestion works in batches small enough to finish inside one call | 22 |
| Multi-region deployments | Running in several regions at once | Not needed. One region next to the database | - |
| Service discovery | Services finding each other's addresses | Not needed with two services at fixed URLs | - |
| Kubernetes and Helm charts | Container orchestration and its packaging format | Not needed (decision 12 in the architecture doc) | - |
| Docker | Packaging an app with its whole environment | Images for the API and worker, so development, CI and any container host run the same thing | 4 |
| Infrastructure as code and Terraform | Defining infrastructure in files under version control | Hosting settings live in the repository. Terraform only if we outgrow platform config | 22 |
| Build caching | Reusing work from earlier builds | Package and Docker layer caches in CI | 4 |
| Cost optimization | Spending less for the same result | The budget is zero, so the real limits are free-plan quotas. Token budgets per workspace and for the demo, smaller models for grading, caching, and usage per answer in the admin view keep us inside them | 10, 13 |

## Delivery

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| CI/CD | Automated checks on every change and automated deploys | GitHub Actions: checks on every pull request, deploys on merge | 1, 4, 22 |
| Feature flags | Switching features on or off without a deploy | Flags from the product analytics tool chosen on Day 19. PostHog is the front-runner because it offers analytics and flags together | 19 |
| Blue-green deployments | Two production environments, with traffic switched between them | The platform builds each release separately, switches traffic in one step and keeps the previous release ready. That gives us blue-green behavior without running two environments ourselves | 22 |
| Canary releases | Releasing to a small share of users first | Feature flags at 10% before 100% | 19 |
| Rolling deployments | Replacing instances a few at a time | The platform default | 22 |
| Rollbacks | Going back to the previous version | One-step rollback on the platform. Migrations stay compatible with both the old and the new code | 22 |
| Semantic versioning | MAJOR.MINOR.PATCH version numbers with agreed meanings | Release tags and a changelog built from Conventional Commit titles | 25 |
| API versioning | Changing an API without breaking the clients that use it | A `/v1` prefix on every route | 4 |
| Dependency hell | Packages that need conflicting versions of each other | Lockfiles, one package manager per language, grouped Dependabot updates | 2 |

## Networking

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| HTTP/2 and HTTPS | Faster HTTP that sends many requests over one connection; HTTP over TLS | Served through the CDN | 23 |
| TCP vs UDP | Reliable, ordered delivery vs fast delivery without guarantees | Our traffic runs over TCP. HTTP/3 at the CDN runs on QUIC, which uses UDP | 23 |
| WebSockets | A two-way connection that stays open | Not needed (decision 11). Server-Sent Events cover our one-way streams | - |
| Long polling | Holding a request open until there is news | Not needed. Server-Sent Events replace it | - |
| Server-Sent Events | A one-way stream from server to browser over HTTP | Streaming answers and document status | 11 |
| gRPC | A binary protocol for calls between services | Not needed. We have one public HTTP API and no internal service calls | - |
| DNS | The system that turns names into addresses | Records for the web app and the API on our free domain, if eu.org approves it. A host's free subdomain needs no DNS work | 23 |
| Cron jobs | Tasks that run on a schedule | Backups, cleanup of expired invites and orphaned files, nightly evaluations and the job sweep, run as scheduled GitHub Actions workflows, which are free for public repositories | 12, 22 |

## Observability

| Concept | What it means | What Whence does | Day |
| --- | --- | --- | --- |
| Logging | Records of what happened | Structured JSON logs with a request ID. No secrets and no personal data | 4 |
| Metrics | Numbers tracked over time | Request rate, errors, latency, queue depth, tokens and cost | 13 |
| Distributed tracing | Following one request across every service it touches | OpenTelemetry traces from the web server to the API, the database and the model provider | 13 |
| Monitoring | Watching those numbers | Dashboards built around our SLIs | 13 |
| Alerting | Telling a person when something is wrong | Alerts when we burn error budget too fast or jobs keep failing, sent to email and phone | 13 |
| Observability | Being able to answer new questions about a running system | Logs, metrics and traces linked by request ID | 13 |
| SLIs, SLOs and error budgets | What we measure, the target we promise, and how much failure the target allows | Measured uptime and latency while we are on free hosting, then 99.5% monthly availability for the API once it runs on an always-on host | 13 |

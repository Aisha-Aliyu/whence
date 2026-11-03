# Whence: product spec

Status: draft 1, 2 November 2026. Changes to this file go through a pull request like code.

## Problem

Teams keep the answers to everyday questions in documents: handbooks, policies, onboarding guides, runbooks, contracts and meeting notes. When someone needs an answer, they dig through badly named files, ask a colleague, or guess. Search tools return documents, not answers. General chatbots return answers without sources, and they invent details when the documents say nothing.

## Who it is for

- Workspace owner: creates a workspace, uploads documents, invites people and controls their roles.
- Member: asks questions and checks the sources behind each answer.
- Visitor: tries the public demo without an account.

First target users: teams of 5 to 200 people who have documents but no dedicated knowledge tool.

## What Whence does

1. You upload documents: PDF, Word (DOCX), Markdown, plain text and HTML.
2. You ask a question in plain language.
3. Whence answers in a few sentences. Every claim carries a citation, and each citation opens the exact passage with its page or section highlighted.
4. When your documents do not contain the answer, Whence says so and shows the closest passages it found. It does not guess.
5. When you delete a document, answers stop using it at once. When you upload a new version, answers switch to it as soon as processing finishes.

## Scope for version 1

We scope version 1 as SLC: simple, lovable, complete. Fewer features, each one finished, instead of many half-built ones.

In scope:

- Accounts: email and password with strength rules, Google sign-in, email verification, two-factor authentication with an authenticator app, CAPTCHA on sign-up, sign-in and password reset.
- Workspaces: create, rename, invite by email, roles (owner, admin, member), leave, delete.
- Documents: upload (20 MB per file to start), processing status, replace, delete, a storage limit per workspace.
- Ask: threads with follow-up questions, answers that stream in as they are written, inline citations, a source viewer, copy an answer with its citations, thumbs up or down with an optional reason.
- Admin: members and roles, an audit log (uploads, deletions, role changes, sign-ins), usage per day (questions asked and tokens used against the free quotas).
- Public demo: a read-only workspace with openly licensed documents, no account needed, strict limits.
- Your data: export your data, delete your account, delete a workspace and everything in it.
- Trust pages: privacy policy, terms of use, cookie policy, acceptable use policy, accessibility statement, security page and a list of subprocessors. Every page links to them from the footer.

Out of scope for version 1, and why:

- Connectors to Google Drive, Notion, Slack or Confluence. Each needs its own OAuth review and sync logic. Version 2.
- Scanned PDFs and images (OCR). Version 1 detects pages with no text layer and tells the user.
- SSO, SAML and SCIM. Enterprise features for later, if teams ask.
- Paid plans and billing. Version 1 is free, so it needs no refund policy. We add one the day we charge money.
- Native mobile apps. The web app works on phones.
- Answers from the open web. Whence answers only from your documents.

## Quality targets

These are starting targets. We measure baselines, then adjust the numbers in a pull request.

Speed:

- Public pages: Largest Contentful Paint under 2.0 s on a mid-range phone over 4G, Interaction to Next Paint under 200 ms, Cumulative Layout Shift under 0.05, Lighthouse 95 or higher in all four categories.
- Retrieval (finding the passages): p95 under 300 ms.
- First words of an answer on screen: p95 under 2.5 s on a warm server. Free hosts add a wake-up delay after idle periods, which we measure and show on screen.
- A 50-page PDF becomes searchable in under 60 s.

Answer quality, measured on our evaluation set before every release:

- Recall@8 of at least 0.90: for answerable questions, the right passage appears in the top 8 results.
- Citation precision of at least 0.95: the cited passage supports the sentence it is attached to.
- Abstention accuracy of at least 0.90: for questions the documents cannot answer, Whence says so.

Security and privacy:

- A user can only read data from workspaces they belong to. The API enforces this, and the database enforces it again with row-level security.
- We follow OWASP ASVS Level 2 where it applies, plus the OWASP Top 10 for LLM Applications.
- We collect only what the product needs. Uploaded documents never train any model.
- Users can export and delete their own data without contacting us.

Accessibility: WCAG 2.2 AA. Everything works with a keyboard alone and with a screen reader.

Screens: from 280 px wide (the smallest folding-phone cover screens) to 2560 px and wider, with no horizontal scrolling.

Availability: 99.5% per month for the API. That allows about 3.6 hours of downtime a month, which is our error budget.

## How we will know it works

These numbers live in private product analytics. They never appear on the website as marketing claims.

- Weekly active askers.
- Share of answers rated helpful.
- Share of answers where someone opened a citation. People who check sources trust the product for the right reason.
- Abstention rate. Too high means retrieval misses things. Too low can mean the model is guessing.

## Design direction

- Palette sampled from the reference image: ink #11141B, signal blue #0245CF, paper #EDEDED. The hex codes printed on that image (#FF862D, #01605A, #FFD0A8) describe a different palette, so we sampled the visible colors instead.
- Contrast: blue on white is 7.6:1, blue on paper 6.5:1 and ink on paper 15.7:1. Blue on ink is only 2.4:1, so dark mode uses a lighter blue for text and links.
- Solid colors only. No gradients anywhere.
- Type: one sans serif for the interface and for reading, one monospace for citations and page numbers. Both under the SIL Open Font License and served from our own domain. Front-runner: IBM Plex Sans with IBM Plex Mono. Day 3 confirms it with a specimen.
- Feel: calm, precise and editorial. Citations sit next to the sentence they support and open the passage in one tap.

## Constraints

- One developer, working from an iPad with GitHub, Claude Code and Codespaces.
- Zero budget. Every service must be free, ideally without a payment card. When a free plan carries a cost of its own, such as a server that sleeps when idle, we write the trade-off down instead of paying.
- Personal data handling must meet GDPR (EU and UK users), the Nigeria Data Protection Act 2023, and CCPA/CPRA (California users).

## Open questions

- Answer model: decided on Day 10 from evaluation results, free quotas and the provider's data terms.
- Embedding model: decided on Day 8 from recall on our evaluation set.
- API hosting: decided on Day 22 from cold-start tests on free plans.
- Domain: Whence launches on a free domain. We apply for whence.eu.org on Day 3, and if it has not been approved by Day 23, we launch on the host's free subdomain.
- Upload limit: 20 MB per file to start, revisited after load tests.

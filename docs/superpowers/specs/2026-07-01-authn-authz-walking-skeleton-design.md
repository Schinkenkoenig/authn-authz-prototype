# AuthN/AuthZ Showcase — Design (Sub-project 1: Walking Skeleton)

**Date:** 2026-07-01
**Status:** Approved for implementation planning
**Scope of this document:** Overall project decomposition + full design of **Sub-project 1**. Sub-projects 2 and 3 are sketched only enough to fix boundaries; each gets its own spec later.

---

## 1. Project vision

A prototype that showcases a complete, industry-standard **authentication and authorization flow** end to end. The concrete domain is a **file-storage service** with **prefix-level** access control, chosen because it makes authorization tangible and lets us demonstrate role-based, attribute-based, and claim-based variants against real enforcement.

The distinctive move: **the storage layer participates in authorization.** Ceph RGW's STS `AssumeRoleWithWebIdentity` exchanges a Keycloak token for temporary, scoped S3 credentials, so access is enforced *by storage* on per-request credentials rather than only by application code.

### Target stack (whole project)

- **Backend:** .NET REST API with **FastEndpoints**; CQRS via FastEndpoints' Command/Event APIs (**introduced in sub-project 2**, not the skeleton).
- **Frontend:** Next.js **SPA**, Fluent UI (dark, blue/purple tint) — UI polish is **sub-project 3**.
- **IdP / OIDC provider:** **Keycloak**.
- **Storage:** **Ceph** (RGW with STS enabled). Real Ceph, deliberately — the goal includes battle-testing the IAM `AssumeRoleWithWebIdentity` flow.
- **Database:** **Postgres**.
- **Dev orchestration:** **.NET Aspire** (AppHost + ServiceDefaults).
- **Observability:** **Serilog** structured logging + **OpenTelemetry** traces/metrics into the Aspire dashboard.
- **API docs:** **Scalar** over the OpenAPI document.

---

## 2. Decomposition (approved)

Built in order; each is its own spec → plan → build cycle.

1. **Platform Bones + Walking Skeleton** — *this document.* Thin vertical slice through every layer; kills the highest-risk integration (Ceph RGW STS ↔ Keycloak OIDC) first.
2. **File Storage Domain + Authorization Core** — the domain model, CQRS (FastEndpoints Command/Event), and the policy decision point supporting RBAC / ABAC / claim-based variants. **The star.**
3. **Policy UI, User Management + Consent Dialogue** — Fluent UI policy editor, user management, permission-approval dialogue.

**Rule:** the sub-project-2 policy model is **not finalized** until the skeleton returns empirical verdicts on the Ceph STS capabilities listed in §7.

---

## 3. Authorization model (the backbone, established here, deepened in #2)

- **The .NET API is the Policy Decision Point (PDP).** It validates the caller's token, decides *which Ceph IAM role to assume*, and can attach an **inline session policy** at `AssumeRoleWithWebIdentity` time to narrow that role to the caller's allowed prefix(es).
- **Ceph RGW is the Policy Enforcement Point (PEP).** It enforces the temporary scoped credentials on every S3 operation.
- **Enforcement topology: backend brokers STS.** The browser never talks to Ceph. The API holds the temporary credentials server-side and proxies all S3 I/O.
- The three variants map onto one mechanism (fully realized in #2): **RBAC** = which role you may assume; **ABAC / claim-based** = trust-policy conditions + inline session policy / session tags built from Keycloak claims.

---

## 4. Token model (OIDC-spec-compliant split)

Two tokens, each doing exactly its spec job. **No multi-valued / fat audience is used.**

| Token | `aud` | Purpose | Consumer |
|-------|-------|---------|----------|
| **Access token** | `api` | *Authorizes* the API call | .NET API validates it as the `Authorization: Bearer` |
| **ID token** | `webapp` (SPA client id) | *Asserts identity* for federation | Forwarded to Ceph STS as the WebIdentityToken |

Flow:

1. SPA performs **Authorization Code + PKCE** against Keycloak (public client `webapp`) and receives both tokens (tokens live in the browser).
2. SPA calls the API with **`Authorization: Bearer <access_token>`**; API validates `aud=api`.
3. On storage calls, the SPA **also** sends the **ID token** in a distinct header (`X-Id-Token`). The API forwards *that* to `AssumeRoleWithWebIdentity`.
4. Ceph's OIDC provider is configured with `client_id = webapp`; it validates the ID token's `aud=webapp` against its `client_ids`.

We are **not** using the ID token as an API bearer (the purist anti-pattern): the access token authorizes the API; the ID token travels separately as a federation assertion.

Keycloak needs an **audience mapper** adding `api` to the access token. The SPA client is public; its `client_id` is what Ceph's provider trusts.

---

## 5. Sub-project 1 — architecture

All components orchestrated by the **Aspire AppHost** with **ServiceDefaults** applied.

### Components

- **Keycloak** — realm **imported from committed source** (JSON). Contains: realm, one **public** SPA client `webapp` (Auth Code + PKCE), the `api` audience mapper, a small number of users, one or two roles.
- **Ceph (RGW + STS)** — **pinned image tag** (version is a design decision, not a default). Scripted, reproducible init that:
  - registers Keycloak as an **OIDC provider** entity (client id `webapp`, thumbprint/JWKS config);
  - creates one **IAM role** with a trust policy (`Principal: Federated → keycloak-provider`, `Action: sts:AssumeRoleWithWebIdentity`) and a permission policy scoped to a demo bucket/prefix.
- **Postgres** — connection + **one migration** to prove wiring. **No domain tables.**
- **.NET API** (FastEndpoints) — JWT bearer authn against Keycloak; the two endpoints below. **No CQRS.**
- **Next.js SPA** — `oidc-client-ts` / `react-oidc-context`; tokens in browser; a page showing identity + a button to trigger the storage round-trip through the API.

### Endpoints (skeleton only)

- `GET /whoami` — returns the validated claims from the access token.
- `POST /storage/roundtrip` (name TBD in planning) — reads `X-Id-Token`, calls `AssumeRoleWithWebIdentity(idToken, roleArn, inlineSessionPolicy)`, receives temp creds, then **PUT + GET** a small object under the allowed prefix, returning the result.

### Data flow (the money path)

```
Browser (access token + id token)
  │  Authorization: Bearer <access_token>   (aud=api)
  │  X-Id-Token: <id_token>                 (aud=webapp)
  ▼
.NET API (validates access token; PDP)
  │  AssumeRoleWithWebIdentity(id_token, roleArn, inline session policy)
  ▼
Ceph STS ── temp scoped creds ──▶ back to API
  │
  ▼
S3 PUT/GET under allowed prefix  (Ceph RGW = PEP, enforces)
```

### Observability

- **Serilog** structured logging on the API.
- **OpenTelemetry** traces/metrics via ServiceDefaults into the **Aspire dashboard**; trace context propagated **browser → API → STS/S3**.
- **Scalar** serving the OpenAPI document.

---

## 6. Definition of Done (scope fence)

The skeleton is complete when:

1. OIDC **login works end to end**; the browser holds both tokens.
2. `GET /whoami` returns validated claims from the **access token** (`aud=api`).
3. The storage endpoint performs `AssumeRoleWithWebIdentity` using the **ID token** → temp creds → **PUT + GET a small object under the allowed prefix**, **and specifically proves an inline session policy narrowing the role to that prefix** (not merely a vanilla round-trip).
4. Traces span **browser → API → STS/S3** in the Aspire dashboard; Scalar renders the OpenAPI doc.
5. Postgres wiring proven by one migration applied on startup.

**Explicitly out of scope for #1:** any domain model, CQRS / Command-Event handlers, the policy engine, Fluent UI work, user management, the consent dialogue. Those belong to #2 and #3.

---

## 7. Assumptions to verify during #1 (these gate #2's design)

The skeleton exists to resolve these empirically. Record the verdicts.

1. **ID token accepted by STS.** Sharp, falsifiable hypothesis: Ceph's `AssumeRoleWithWebIdentity` accepts the **ID token** (`aud=webapp`) as the WebIdentityToken and validates it against the provider's `client_ids`. *Fallback if Ceph demands the access token: add `webapp` to the access token audience (or use a `client_id` claim mapper) and forward the access token instead.*
2. **Inline session policy honored.** Does the pinned Ceph version honor the `Policy` parameter on `AssumeRoleWithWebIdentity` to narrow to a prefix? *Fallback: pre-created per-scope roles + trust-policy claim conditions — which changes the policy model in #2 and the policy UI in #3.*
3. **Session tags / principal tags** support (for claim-driven ABAC in #2). Confirm against the pinned version's RGW STS docs.
4. **OIDC provider trust in dev.** How RGW validates Keycloak's signing keys over the dev transport (JWKS/thumbprint), including any http-vs-https constraints inside the Aspire network.

**Do not finalize the sub-project-2 policy model until items 1–3 return verdicts.**

---

## 8. Known risks

- **Ceph in Aspire is heavyweight.** The RGW/STS demo image is large and slow to become healthy; startup orchestration and health checks are a real risk. Pin the tag; script the init idempotently.
- **STS feature support varies by Ceph release** — hence the deliberate tag pin and the verify-list above.
- **Public SPA client with tokens in the browser is the weaker security posture** (OAuth 2.0 for Browser-Based Apps BCP prefers a BFF). Accepted for the prototype; it also makes the flow inspectable for demos. First thing to revisit if this graduates past prototype.

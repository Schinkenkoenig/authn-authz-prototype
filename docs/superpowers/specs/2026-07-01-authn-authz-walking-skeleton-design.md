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

> **Pivoted 2026-07-02** from per-user STS brokering to service-level IAM + application-level authorization, to support multiple storage backends and because Ceph's role-permission-policy actions are not reliably enforced for owner-account roles. History + evidence: STS verdicts note §5–§6. The original per-user model is preserved in git history.

- **The .NET API is both PDP and PEP.** It validates the caller's access token and enforces authorization itself, in application code:
  - **ABAC / claim-based** — every object key is constructed under the caller's own prefix (derived from identity), so cross-tenant access is impossible by construction.
  - **RBAC** — capability is decided from the caller's realm roles (e.g. `writer` may write; `reader` is refused by the API, not the backend).
- **The storage backend is dumb and pluggable** (Ceph RGW today; real S3 / other object stores later). The API authenticates to it at the **service level via IAM** — the AWS SDK's own **web-identity credential provider** (the IRSA / Pod-Identity mechanism), configured purely by env vars. One **service identity** holds broad storage access; there is **no per-user credential brokering** and the browser never talks to storage.
- The three variants map onto this one place (deepened in #2): all decisions are made by the API from Keycloak claims — **RBAC** = capability, **ABAC / claim-based** = resource scope + attribute conditions. The storage backend only ever sees the service identity.

---

## 4. Token & service-identity model

Two **independent** identities, each doing exactly its job. **No multi-valued / fat audience is used for authorization.**

| Token | Client / `aud` | Purpose | Consumer |
|-------|----------------|---------|----------|
| **Access token** (user) | `webapp` → `aud=api` (audience mapper) | *Authorizes* the API call | .NET API validates it as the `Authorization: Bearer` |
| **Service-identity token** | `storage-service` (client-credentials) → `azp=storage-service` | *Authenticates the service* to storage | AWS SDK web-identity provider → `AssumeRoleWithWebIdentity` for the service role |

Flow:

1. SPA performs **Authorization Code + PKCE** against Keycloak (public client `webapp`) and receives the user tokens (tokens live in the browser).
2. SPA calls the API with **`Authorization: Bearer <access_token>`**; API validates `aud=api` (with `MapInboundClaims=false`, realm roles come from the `realm_access` claim). The **ID token is not forwarded** — per-user STS is retired.
3. The API decides authorization from the caller's claims and performs storage I/O with the **service identity**: the AWS SDK resolves credentials from env vars (`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ENDPOINT_URL_STS`) and assumes the service storage role.
4. The service-identity token is a **client-credentials** token for `storage-service`; Ceph's OIDC provider trusts it and the service role's trust policy keys on `azp=storage-service` (its `aud` is multi-valued, so `azp` is used). A **refresher sidecar** keeps the token file fresh; the API never fetches it (it only reads the file), mirroring how a pod reads a projected service-account token.

We are **not** using the ID token as an API bearer, and the API does not proxy the user's identity to storage. The **user** authorizes the API; the **service** authenticates to storage. Keycloak needs an **audience mapper** adding `api` to the access token (on `webapp`) and one adding `storage-service` to the service token (on `storage-service`).

---

## 5. Sub-project 1 — architecture

All components orchestrated by the **Aspire AppHost** with **ServiceDefaults** applied.

### Components

- **Keycloak** — realm **imported from committed source** (JSON). Contains: realm, one **public** SPA client `webapp` (Auth Code + PKCE) with the `api` audience mapper, one **confidential service client `storage-service`** (client-credentials, service accounts) with its audience mapper, a small number of users, roles.
- **Ceph (RGW + STS)** — **pinned image tag** (version is a design decision, not a default). Scripted, reproducible init that:
  - registers Keycloak as an **OIDC provider** entity (client ids `webapp`, `storage-service`; thumbprint/JWKS config);
  - creates one broad **service IAM role** (`DemoService`) whose trust policy keys on `azp=storage-service`. (This role is the *identity vehicle*; authorization is enforced by the API, not by the role's permission policy.)
- **Postgres** — connection + **one migration** to prove wiring. **No domain tables.**
- **.NET API** (FastEndpoints) — JWT bearer authn against Keycloak; PDP+PEP for authorization; storage I/O via the SDK web-identity service identity; the two endpoints below. **No CQRS.**
- **Refresher sidecar** — writes a fresh `storage-service` client-credentials token to the shared token file on an interval (IRSA/Pod-Identity stand-in for dev).
- **Next.js SPA** — `oidc-client-ts` / `react-oidc-context`; tokens in browser; a page showing identity + a button to trigger the storage round-trip through the API.

### Endpoints (skeleton only)

- `GET /whoami` — returns the validated claims from the access token.
- `POST /storage/roundtrip` — the API authorizes the caller (prefix from identity, write capability from role), then **reads** the seeded welcome object and **attempts a write** under the caller's prefix using the **service identity**, returning what was allowed. No token is forwarded to storage.

### Data flow (the money path)

```
Browser (access token in browser)
  │  Authorization: Bearer <access_token>   (aud=api)
  ▼
.NET API  = PDP + PEP
  │  authorize: prefix = caller identity;  write? = caller role (RBAC)
  │  storage creds via AWS SDK web-identity provider (env vars) → assume DemoService
  ▼
S3 PUT/GET under the caller's prefix, using the SERVICE identity  (backend = dumb store)

(separately) refresher sidecar ── client-credentials token ──▶ shared token file ──▶ SDK
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

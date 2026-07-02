# AuthN/AuthZ Showcase — Design (Sub-project 2: Authorization Paradigms)

**Date:** 2026-07-02
**Status:** Approved for implementation planning
**Scope of this document:** Full design of **Sub-project 2**, sliced to its first spec. Follow-on specs (ReBAC, policy-as-code, apples-to-apples comparison, playground frontend) are named only to fix boundaries.

---

## 1. Goal / non-goals

**Goal.** A testbed where object-storage authorization over **arbitrary prefixes** is decided by one of **four in-process paradigms — RBAC, ABAC, claim-based, ACL** — **selectable per request**. Each paradigm demonstrates its **sweet-spot character**: the scenario it expresses most naturally, and the shape of config an administrator must author to get it. Configs are **seeded in Postgres, read-only** this spec.

**North star (whole sub-project).** Show how authorization paradigms differ in the **configuration complexity they impose on the administrator**. This spec is the **foundation** for that, not the comparison itself (see §2).

**Non-goals — explicitly deferred:**

- The **apples-to-apples** admin-burden contrast (one shared scenario expressed under every paradigm). This spec is sweet-spot mode only.
- Config **edit / CRUD** surface. DB is seeded and read; editing lands with the playground that consumes it.
- **ReBAC** (Zanzibar/OpenFGA) and **policy-as-code** (Cedar/OPA) paradigms — each its own follow-on spec behind the same seam.
- The **playground / wiki frontend**.

**Removed from Sub-project 1:** the `prefix == username` coupling. It pre-decided the authorization answer by construction, leaving nothing to authorize. Prefixes are now arbitrary namespaces.

---

## 2. Why this spec is the *foundation*, not the *showcase*

The north star is a **head-to-head**: hold the desired access facts fixed, express them under each paradigm, compare what the administrator had to write. That is the deferred apples-to-apples suite.

**Sweet-spot mode is not a fair head-to-head.** Each paradigm here is configured against a *different, ideal* scenario, so their configs are not directly comparable and running one request through all four does not diff admin burden — it diffs four different worlds. Sweet-spot mode reveals each paradigm's **character**; the burden **contrast** needs the shared scenario + the playground to present it.

So "all loaded, selectable per request" is built here because it is the seam the later comparison and playground require — not because per-request selection is itself the comparison.

**Definition of Done is written accordingly (§8): the four paradigms work and each shows its sweet spot. The burden contrast is out of scope.**

---

## 3. Architecture — Approach A: thin data seam, honest evaluators

One data shape, evaluated by a dispatch function, backed by four **independent** evaluators. No policy-engine class hierarchy — the shared thing is a struct, not an interface tree.

```
AuthzRequest  { Caller (full claim set), Action (Read | Write | List), Resource (object key or prefix) }
AuthzDecision { Effect (Permit | Deny), Reason (string), Paradigm }
```

- **Dispatch** selects an evaluator by paradigm selector: request header `X-Authz-Paradigm: rbac|abac|claims|acl`, with a configured default.
- **Evaluators are pure:** `(caller claims, action, resource, config-as-in-memory-data) -> AuthzDecision`. They never touch `DbContext`, HTTP, or S3.
- **Config loading is a separate seam.** A per-paradigm repository loads DB rows (or, for claim-based, reads the token) into an in-memory config struct; the pure evaluator runs over that struct. This is what keeps decision logic unit-testable without EF — and it matters *more* with DB-backed config than it would with files.

Rejected alternatives (recorded so we don't relitigate):

- **B — uniform internal grant model + per-paradigm compilers.** Rejected: flattening ABAC and claim-based to a precomputed grant table hides the *runtime* evaluation (against attributes / token state) that is the entire point of the showcase. It would make the paradigms look more alike than they are.
- **C — four fully independent verticals, no shared seam.** Rejected: per-request selection and the future compare-all endpoint both need a common dispatch point; without the thin seam it gets rebuilt four times and the playground faces four different contracts.

---

## 4. One shared world (not four mini-worlds)

All four PDPs are loaded simultaneously and **every test user carries roles *and* attributes *and* grant-claims at once**. Therefore there is **one** prefix namespace and **one** principal roster; each paradigm's sweet-spot scenario is a **slice** of that shared world. This is deliberate: the deferred apples-to-apples mode has a shared substrate to build on, rather than four disconnected setups.

**Prefix namespace (arbitrary — no identity coupling):**

```
finance/          engineering/      hr/
shared/           projects/apollo/  projects/gemini/
```

**Principal roster (example — names/attributes adjustable during planning):**

| User  | Realm roles (RBAC) | Attributes (ABAC)        | `storage_grants` claim (claim-based) |
|-------|--------------------|--------------------------|--------------------------------------|
| alice | auditor            | dept=finance, level=2    | `r:finance/`                         |
| bob   | editor             | dept=engineering, level=3| `rw:projects/apollo/`                |
| carol | viewer             | dept=hr, level=1         | `r:hr/`                              |
| dave  | admin              | dept=it, level=4         | `rw:*`                               |
| erin  | editor             | dept=finance, level=3    | `rw:finance/`                        |

(≥2 users share a role so RBAC role-reuse is visible; attributes and claims are populated so ABAC and claim-based have real inputs. ACL references these principals by username/`sub`.)

---

## 5. The four paradigms — sweet spot, config home, config shape

| Paradigm | Sweet-spot scenario | Config home | Config shape |
|----------|---------------------|-------------|--------------|
| **RBAC** | Many users, few reusable roles — capability granted to a role, users mapped to roles. Shines because adding a user is one role assignment. | DB | `roles`; `role_permissions` (role → prefix + Read/Write/List); `user_roles` (subject → role) |
| **ABAC** | Onboarding needs **zero** authz change — access derived from principal attributes matched against the resource. e.g. "read+write under `{department}/`"; "level ≥ 3 → read `hr/`". A new finance hire needs no policy edit. | DB | `abac_rules`: attribute predicate → prefix pattern + permitted actions |
| **Claim-based** | The **IdP issues the grants**; the app is dumb and trusts the token. Decentralized: authoring lives in Keycloak. Contrast to surface: revocation waits for token expiry, and the app must trust the issuer. | **Keycloak** (not our DB) | `storage_grants` token claim, e.g. `["r:finance/","rw:projects/apollo/"]`, produced by a Keycloak claim mapper over user attributes |
| **ACL** | Obvious ad-hoc sharing at small scale — each prefix carries an explicit who-can-do-what list. The "dumb baseline" that shows *why* the others exist: correct and legible, but grows linearly and offers no reuse. | DB | `acl_entries`: (prefix, principal, permitted actions); `*` principal = everyone |

**Prefix matching (shared rule across paradigms that grant on prefixes):** a grant on prefix `P` covers resource key `K` iff `K` starts with `P` (`P` normalized to end in `/` for directory-style prefixes; exact-key grants allowed). Documented once, applied by RBAC, ABAC, claim-based, and ACL alike, so decisions differ because of *config shape*, not matching quirks.

---

## 6. Storage domain + endpoints

Reuse Sub-project 1's **service identity** unchanged: `S3Gateway` + the AWS SDK web-identity credential provider; the backend is a dumb, broad-access store. Prefixes are arbitrary now. The single `/storage/roundtrip` is **replaced** by real operations on caller-supplied keys, each gated by the PDP and honoring the paradigm selector:

- `POST /storage/read` `{ key }` → `PDP(Read, key)` → S3 GET (on Permit)
- `POST /storage/write` `{ key, content }` → `PDP(Write, key)` → S3 PUT (on Permit)
- `GET /storage/list?prefix=` → `PDP(List, prefix)` → S3 list (on Permit)
- `GET /authz/paradigms` — the four paradigm ids + descriptions
- `GET /authz/{paradigm}/config` — the seeded config artifact for that paradigm. Claim-based returns a **pointer**: config lives in Keycloak, plus an echo of the **caller's current `storage_grants` claim** so the surface is still inspectable.

A Deny returns 403 with the `AuthzDecision.Reason`. `GET /whoami` (from SP1) stays.

*(A `POST /authz/evaluate` compare-all endpoint — one request run through every paradigm — is a natural playground feed but is **deferred**; the per-request seam already supports building it.)*

---

## 7. Persistence & identity work

- **EF entities** for RBAC / ABAC / ACL config (§5 shapes), **seeded on migrate**. `AuditEntry` retained; writes continue to be audited.
- Config **repositories** load rows → in-memory structs consumed by the pure evaluators (§3).
- **Keycloak realm export extended:** the §4 users with their realm roles + attributes + a **`storage_grants` claim mapper** derived from attributes. That mapper *is* the claim-based paradigm's administrator surface.

---

## 8. Definition of Done (scope fence)

Complete when:

1. Prefixes are arbitrary; the `prefix == username` coupling is gone.
2. All four paradigms are loaded and **selectable per request** via `X-Authz-Paradigm`; an unknown/absent selector falls back to the configured default.
3. Each paradigm **enforces its sweet-spot scenario** end to end against real Keycloak tokens and real Ceph: for the §4 roster, the intended Permits succeed (S3 I/O happens) and the intended Denies return 403 with a reason — verified per paradigm.
4. `GET /authz/{paradigm}/config` exposes the seeded config; claim-based returns the Keycloak pointer + the caller's live grant claim.
5. Per-evaluator **unit tests** cover permit/deny/edge cases over pure data (no `DbContext`); integration tests cover the §4/§5 scenarios end to end.

**Explicitly out of scope:** the apples-to-apples burden **contrast**; config **edit/CRUD**; ReBAC; policy-as-code; the playground frontend; a compare-all endpoint.

---

## 9. Testing (TDD)

- **Unit (the core):** each evaluator is `(claims, action, resource, config) -> decision`. Cases: permit, deny, wildcard principal (ACL), nested-prefix match, missing/empty attribute (ABAC), empty grant list (claim-based), longest/most-specific match where relevant. No DB, no HTTP, no S3.
- **Config repositories:** loading DB rows → in-memory structs (thin, against a real Postgres via the Aspire test setup — no mocks).
- **Integration:** seeded config + real Keycloak access token + real Ceph, exercising §4 principals against §5 scenarios through the real endpoints for each paradigm.

Test output must be pristine; intentional Deny paths assert on the 403 + reason rather than letting errors leak.

---

## 10. Known risks

- **Sweet-spot mode can be mistaken for the comparison.** Mitigated by §2 and the DoD: this spec is the foundation. Guard against language (in code comments, endpoints, docs) that implies the burden contrast is delivered here.
- **One shared roster must satisfy four paradigms at once.** If the roster/namespace is too thin, some paradigms have nothing interesting to show; if too rich, the seed data balloons. Keep §4 minimal but sufficient; tune during planning.
- **Claim-based config lives outside the app.** Its "admin surface" is a Keycloak claim mapper, so its inspectability and its change-cost story differ structurally from the DB-backed three. This is a genuine finding, not a defect — surface it, don't hide it.
- **Prefix-matching semantics are load-bearing.** A sloppy match rule would make paradigms differ for the wrong reason. Fix the rule once (§5) and test it directly.

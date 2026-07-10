# Concept review: authn/authz approach (2026-07-10)

Scope: the *decisions and concept* of the authentication and authorization approach, not code
polish — this is a comparison showcase and was reviewed as one. Inputs: all seven ADRs,
[authz-paradigms.md](../authz-paradigms.md), and the full enforcement path (JWT setup,
`CallerClaims`, `AuthzDispatcher`, the four pure evaluators, `PolicyInput`, `PrefixMatch`, the three
storage endpoints, `S3Gateway`).

## Verdict

The concept is sound and unusually well-defended in writing. The dangerous-looking decisions
(caller-selected paradigm, union access, single broad service identity, prefix decoupled from
username) are all deliberate, all recorded in ADRs, and the ADRs pre-empt the reflexive "hardening"
a reviewer would otherwise propose. Per ADR 0005, union access is **not** flagged as a bug here.
The findings below are the things the ADRs *don't* cover.

## What's conceptually right

- **Authn chain is production-shaped.** Auth Code + PKCE in the SPA; access token with `aud=api`
  validated against the Keycloak authority; the service-to-storage leg uses the IRSA pattern
  (web-identity token file + `AssumeRoleWithWebIdentity`, refreshed by a sidecar, ADR 0002). The
  API code is identical to what it would be in a real cluster — the right fidelity for a testbed.
- **The PEP shape is correct everywhere.** All three storage endpoints decide *before* any S3
  call, deny with 403 and a reason, and only then touch storage. No decide-after-fetch anywhere.
- **Fail-closed in the right places.** An unconfigured engine gets a deny stand-in, never an
  accidental permit; engine provisioning fails fast at startup; an unknown paradigm inside
  `Decide` denies; a mid-request engine failure throws (500), not permits.
- **One shared `PrefixMatch`** so paradigms differ by config shape, not matching quirks — exactly
  what a comparison needs.
- **ADR discipline.** ADR 0005 and 0007 explicitly disarming future "fixes" is the best part of
  the repo.

## Concept-level gaps

### 1. Identity is keyed on `preferred_username`, not `sub`

RBAC (`RbacEvaluator.cs`), ACL, and the seed data key on `caller.Name` = `preferred_username`.
That claim is mutable and reassignable in Keycloak; `sub` is the stable identifier. Delete `bob`,
create a new `bob`, and the new user inherits every grant. The code comment says "keyed by
username for legible seed data" — fine for the showcase, but this is the one habit from this repo
that must **not** travel to anything real, and unlike the union model it isn't written down
anywhere. Deserves a line in an ADR or the paradigms doc.

### 2. No canonicalization of the resource key before the decision

`PrefixMatch.Covers` operates on the raw string, so `shared/../classified/x` is covered by a
`shared/` grant, and that literal string then goes to Ceph. S3 keys are legitimately literal (so
this is *probably* just a weird key, not traversal), but whether the .NET SDK's HTTP layer or RGW
normalizes dot-segments in the path is unproven — exactly the kind of thing the AGENTS.md
"prove payloads with curl first" rule exists for. One-test question: write
`shared/../classified/x` via `rw:*`, then check whether a `shared/` grant reads it back, and what
key RGW actually stored. **If normalization happens anywhere in the chain, this is a real authz
bypass** — the only item in this review that could be a bypass rather than a documented trade-off.

Related smaller edge: an exact-key grant (`shared/notes.txt`) permits *list* with that string as
the S3 prefix, which also returns `shared/notes.txt.backup` — prefix-boundary semantics differ
between `PrefixMatch` (directory boundary) and S3's raw prefix filter.

### 3. Resource attributes are inferred from the key name, fail-open

`PolicyInput` maps an unknown top folder to classification 1 (public). So for the Cedar/OPA
paradigms, any level-1 caller reads anything outside `{public, internal, classified}` — and
whoever *names* a key chooses its classification. This is the attribute-provenance problem the
ABAC section of authz-paradigms.md already warns about, but applied to *resource* attributes and
silent. Arguably the honest demo of the weakness; it deserves a sentence in the doc the same way
token-trust does for the claims paradigm.

### 4. Audit is vestigial and asymmetric

Only successful *writes* get an `AuditEntry`; reads, lists, and — critically — **denials and
break-glass uses** leave no record. Break-glass is the one mechanism whose entire real-world
contract is "permitted *because* it's audited," so demonstrating it without the audit half
slightly misrepresents the paradigm. Also the `RoleArn` column now stores the paradigm name —
naming debt from SP1.

### 5. Unknown paradigm header silently falls back to `rbac`

`AuthzDispatcher.Resolve` treats a typo'd `X-Authz-Paradigm: rebak` as "use rbac". For a
comparison tool that's actively misleading — you think you tested ReBAC and got an RBAC answer. A
400 on *unknown* (keeping the default only for *absent*) would be more honest and costs nothing.

## Production-maturity items (known, mostly documented)

Correctly acknowledged as showcase trade-offs; listed for completeness, no action needed:

- `RequireHttpsMetadata=false` + plain-HTTP issuer (ADR 0006, deferred).
- Single broad `DemoService` storage role with no backend guardrail beneath the API (ADR 0001 —
  in production, at least bucket-scope that role so an API bug's blast radius is the demo bucket,
  not the account).
- No rate limiting.
- Claims-paradigm revocation latency (documented in authz-paradigms.md).
- World-readable token file in `/tmp/webid/token`.

## Recommended actions

1. Run the key-normalization test from finding 2 (the only potential bypass).
2. Document the username-vs-`sub` keying decision (finding 1).
3. Optional, cheap: 400 on unknown paradigm selector (finding 5); a sentence on fail-open
   resource classification (finding 3); audit break-glass/denials or note the omission (finding 4).

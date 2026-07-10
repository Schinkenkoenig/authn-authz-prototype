# Pluggable PDP behind a thin data seam

Authorization is a **thin data seam**, not an engine hierarchy: every paradigm is a function from an
`AuthzRequest{Caller, Action, Resource}` to an `AuthzDecision{permit, reason, paradigm}`, selected per
request by the `X-Authz-Paradigm` header. Adding a paradigm is adding a case, not subclassing a
framework.

## Context

The whole point of the project is to compare paradigms *side by side* over one shared world. That only
works if paradigms are cheap to add and swap, and if none of them can reach around the seam into
request plumbing or storage. The temptation was a rich `IAuthorizer` abstraction with per-paradigm
inheritance; that buys nothing here and hides where decisions actually happen.

## Decision

- One request record in, one decision record out. `AuthzDispatcher` routes by paradigm name — a
  `switch`, no polymorphic dispatch tree.
- The four in-process paradigms (`rbac`, `abac`, `claims`, `acl`) are **pure, synchronous functions**
  of `(caller, action, resource, config)` — trivially unit-testable with no DbContext, no I/O.
- Config loading is a *separate* seam (DB rows loaded once into memory at startup), so evaluator tests
  never touch a database.
- The external engines share the same request/decision shape through an async variant of the seam —
  see [ADR 0004](0004-external-engines-provisioned-at-startup.md).

## Consequences

- A new in-process paradigm = one pure function + a dispatch case + its seeded config. This is
  deliberately boring.
- Because the seam is uniform, one config-surface endpoint (`/authz/{paradigm}/config`) and one
  selector header generalize across all seven paradigms.
- Claim-based is the outlier: its "config" is a Keycloak claim mapper, not a DB row — the seam
  accommodates it because the evaluator just reads the token.

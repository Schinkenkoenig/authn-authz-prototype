# Authz Phase 2: Review Pass Design

## Context

Phase 1 (seven authz paradigms: rbac, abac, claims, acl, rebac, cedar, opa) is done and merged.
Nils's standing three-phase plan calls Phase 2 "a dedicated review pass for open issues + more
thorough live testing across all 7 paradigms." Of the open items tracked from SP2/SP3/SP4, only
one was flagged by Nils as worth revisiting now (SP3 open point #4); everything else was
explicitly dispositioned as Phase 3 (deployment/provisioning topics) or "leave as-is." Live
testing is scoped to two dimensions Nils confirmed: edge/negative cases per paradigm, and
cross-paradigm consistency (not failure-mode/concurrency testing — those overlap Phase 3).

This is a review-and-harden pass, not new functionality. No new paradigms, no new endpoints, no
architecture changes.

## 1. ReBAC silent-deny observability fix

**Root cause (confirmed in code):** `RebacEvaluator.PrefixObject` maps a resource key to its
containing folder string. `RebacSeeder.Tuples` wires `parent` edges between specific literal
prefix strings (`projects/` → `projects/apollo/` → `projects/apollo/specs/`). A resource whose
containing folder isn't one of those exact wired strings (e.g.
`projects/apollo/specs/deep/nested.txt` → `prefix:projects/apollo/specs/deep/`) falls off the
graph and denies — indistinguishable from a legitimate "user lacks access" deny, since OpenFGA's
`Check` only returns a boolean.

**Fix:** `RebacSeeder` gains a computed `ModeledPrefixes` set (`IReadOnlySet<string>`) — every
distinct string starting with `"prefix:"` that appears as either the `User` or `Object` side of
any tuple in `RebacSeeder.Tuples`. `RebacEvaluator.EvaluateAsync`, on deny, checks whether `obj`
(the resource's containing prefix) is in that set:
- **In the set, denied** → reason unchanged: `"OpenFGA: {user} lacks {relation} on {obj}"`.
- **Not in the set** → reason becomes: `"OpenFGA: {obj} has no seeded tuple at this depth
  (unmodeled — not a policy decision)"`.

No behavior change (still 403 either way). `AuthzDecision.Reason` already flows into the HTTP
response body (`StorageReadEndpoint`/`StorageWriteEndpoint`/`StorageListEndpoint`) and is already
printed by `verify-authz.py` — no new plumbing needed.

**Tests (TDD, red first):** unit tests alongside the existing `RebacEvaluator` tests — a denied
check against a modeled prefix keeps the existing reason wording; a denied check against an
unmodeled prefix gets the new wording. `ModeledPrefixes` itself gets a direct test asserting the
expected set given `RebacSeeder.Tuples`.

## 2. Edge/negative test cases (verify-authz.py)

New cases appended to the existing `CASES` list, grounded in the real seed data (Keycloak realm
attributes, `AuthzSeeder`, `RebacSeeder`, PaC scenario) — not synthetic. Each targets a category
the current matrix under-covers:

**Correct-prefix-wrong-action** (RBAC, ABAC): a caller whose role/attribute matches the resource
but lacks the specific action, distinct from "no permission at all":
- `carol, rbac, write shared/notes.txt` → deny (viewer role grants `Read,List` on `shared/`, not `Write`).
- `dave, abac, read hr/records.txt` → permit (`level:4 >= 3` rule grants Read).
- `dave, abac, write hr/records.txt` → deny (same rule doesn't grant Write; dave's department `it` doesn't match `hr/`).

**Prefix-subtree boundary** (Claims): same top-level segment, different subtree — tests that
grant matching isn't looser than the literal prefix:
- `bob, claims, read projects/other/x.txt` → deny (grant is `rw:projects/apollo/`, not `projects/`).

**Identity-vs-attribute divergence** (ACL vs ABAC on the same resource): a caller whose
*attribute* matches but who isn't on the explicit ACL list — highlights ACL's per-identity model
vs ABAC's per-attribute model:
- `alice, acl, write finance/a.txt` → deny (ACL only lists `erin` for `finance/`; alice's
  matching `department: finance` attribute is irrelevant to ACL).

**Unmodeled depth** (ReBAC): exercises the Section 1 fix directly:
- `bob, rebac, write projects/apollo/specs/deep/nested.txt` → deny, reason shows the new
  "unmodeled" wording (bob has inherited `editor` down to `specs/`, but no `parent` edge exists
  from `specs/` to `deep/`).

**Header-without-role** (OPA, Cedar): complements the existing "role-without-header" case
(carol, no header):
- `dave, opa, read classified/x` with `X-Break-Glass: true` → deny (dave lacks
  `incident_responder`).
- same for `cedar`.

**Untested classification tier** (OPA, Cedar): the matrix currently only exercises the
`classified` tier (level 3) boundary; `internal` (level 2) has no read case at all:
- `alice, opa, read internal/x` → permit (`level:2 >= 2`, exact boundary).
- `carol, opa, read internal/x` → deny (`level:1 < 2`).
- same pair for `cedar`.

## 3. Cross-paradigm consistency table

**Not** the deferred apples-to-apples project (priority #3) — that requires one fixed scenario
authored identically under every paradigm, which is real future work with its own design. This is
lighter: reuse each paradigm's *existing* demo data, run the same `(caller, action, resource)`
tuple through all 7 paradigms via `X-Authz-Paradigm`, and print a table so differences are visible
and each can be checked against that paradigm's own model rather than eyeballing disjoint
PASS/FAIL lines.

Implementation: a second block in `verify-authz.py`, `COMPARISON = [(user, method, path, body,
annotation), ...]`, separate from `CASES` — no `expect`, since there's no single correct answer
across independently-configured paradigms. For each tuple, loop the 7 paradigm headers, call the
API, print `paradigm | permit | reason`. Purely observational: does not affect the script's exit
code.

Two tuples (both real seed data, verified by hand against each paradigm's rules/tuples/policies):

1. **`alice writes finance/a.txt`** — expected spread: RBAC deny (auditor role has no write
   permission anywhere), ABAC **permit** (own-department rule, no level condition on write),
   Claims deny (alice's grant is `r:finance/`, read-only), ACL deny (only `erin` is listed for
   `finance/`), ReBAC deny/unmodeled (`finance/` was never part of the ReBAC scenario — this row
   doubles as a live example of the Section 1 fix), OPA/Cedar deny (derived `owner_department`
   from the path doesn't match `alice`'s department under this path shape). Only ABAC permits —
   illustrates that ABAC is the only paradigm here keying off a live attribute rather than a
   fixed grant/role/tuple/policy wired to a specific path.

2. **`carol reads shared/notes.txt`** — expected spread: RBAC permit (viewer role), ABAC deny (no
   rule covers `shared/`; carol's own-department rule template is `hr/`), Claims deny (carol's
   grant is `r:hr/`), ACL permit (wildcard `*` on `shared/`), ReBAC permit (`user:*` viewer
   wildcard tuple), OPA/Cedar permit (default classification `public` = 1, carol's level 1 meets
   it). Only ABAC and Claims deny — illustrates that per-attribute and per-token-grant models
   don't have a "public" concept the way ACL/ReBAC/PaC's classification default do.

Each row gets its annotation printed alongside the table (or in a comment above `COMPARISON`) so
the "why" is documented next to the data, not left implicit.

## Out of scope (explicitly deferred, not overlooked)

- OpenFGA in-memory persistence, store-reuse model-drift, manual `fga model transform` step —
  Phase 3 (deployment/provisioning).
- PaC in-memory policy loss on container recreate — Phase 3.
- `StorageListEndpoint` not catching `AmazonS3Exception` — dispositioned "leave as-is" (a
  try/catch would mask a pre-existing SP2 infra issue, unrelated to authz correctness).
- Failure-mode testing (engine unreachable, bad token) and concurrency/restart testing — Nils
  did not select these as in-scope dimensions for this pass.
- Apples-to-apples comparison (one identical scenario across all paradigms) — priority #3, its
  own future spec.

## Testing approach

1. TDD the `RebacSeeder.ModeledPrefixes` + `RebacEvaluator` reason-string change (red/green, unit
   tests first).
2. `dotnet test` full suite green.
3. Extend `verify-authz.py` with the new `CASES` entries and the `COMPARISON` block.
4. Run `verify-authz.py` against the live stack (KC + Ceph + OpenFGA + OPA + cedar-agent) — all
   `CASES` must pass; `COMPARISON` output reviewed by hand against the expected spread above.
5. Update the run note with the new pass/fail count and a note on the comparison table findings.

# Authorization paradigms

This service implements the **same** storage-access decision (`read` / `write` / `list` on an object
key) under seven interchangeable authorization paradigms. The caller selects one per request with the
`X-Authz-Paradigm` header (default `rbac`); the config-surface for any paradigm is exposed at
`GET /authz/{paradigm}/config`.

> **Security model:** this is a *comparison showcase*, not layered defense. The caller picks the
> paradigm, so effective access is the UNION of what any paradigm would grant. The seeded config is
> kept mutually consistent across paradigms; do not read this as defense-in-depth.

All paradigms reason over one shared world: a single prefix namespace (`projects/`, `finance/`,
`hr/`, `shared/`, `internal/`, `classified/`, …) and one roster (`alice`, `bob`, `carol`, `dave`,
`erin`). Each paradigm below is showcased on the slice of that world it expresses best.

The four in-process paradigms (`rbac`, `abac`, `claims`, `acl`) are pure functions of
`(caller, action, resource, config)`. The three external paradigms (`rebac`, `cedar`, `opa`) delegate
to a dedicated engine over HTTP, provisioned at startup.

---

## RBAC — Role-Based Access Control

**Elevator pitch.** Users are assigned roles; roles carry permissions. Access is decided by asking
"does any of the caller's roles grant this action on this prefix?" It is the workhorse of enterprise
authz because many users share a few roles, so onboarding is a single row.

**Trade-offs.**
- Reuse is the win: add a user to a role and they inherit everything that role can do.
- Coarse-grained: fine-grained needs cause *role explosion* (one role per resource/permission combo).
- No per-resource nuance and no context — a role either covers a prefix or it doesn't.

**Configuration surface** — DB rows: user→role assignments and role→(prefix, actions) permissions.
Keyed by username so seed data reads clearly.

```
user_roles:        bob → editor,  erin → editor,  carol → viewer,  dave → admin
role_permissions:  editor → projects/  (Read,Write,List)
                   viewer → shared/    (Read,List)
                   admin  → *          (Read,Write,List)
```
`bob` writing `projects/apollo/a.txt` → permit (role `editor` grants Write on `projects/`).

---

## ABAC — Attribute-Based Access Control

**Elevator pitch.** Access is derived from attributes of the caller (department, clearance level)
matched against the resource, with no explicit user-to-resource wiring. A rule applies when all its
conditions hold and its prefix template resolves. The sweet spot is zero-touch onboarding: a new
finance hire is covered by the department rule the moment their `department` attribute is set.

**Trade-offs.**
- Onboarding and reorganizations need no authz change — the attributes do the work.
- Expressive when you have good attribute data; rules stay small and general.
- "Who can access X?" is *implicit* and hard to audit; correctness depends entirely on attribute
  quality and provenance (the IdP must be trusted to set them).

**Configuration surface** — rules of `(conditions, prefix-template, actions)`, where the template may
interpolate caller attributes (`{department}/`). Attributes arrive as token claims (`department`,
`level`).

```
rule 1:  conditions []                    prefix "{department}/"  actions Read,Write,List
rule 2:  conditions [level >= 3]          prefix "hr/"            actions Read,List
```
`alice` (department=finance) writing `finance/a.txt` → permit (rule 1 resolves to `finance/`).
`alice` (level 2) reading `hr/records.txt` → deny; `bob` (level 3) → permit (rule 2).

---

## Claim-based — grants carried in the token

**Elevator pitch.** The identity provider issues the access grants directly inside the token and the
application simply trusts them. There is **no application-side config** — the admin surface is the
Keycloak claim mapper. The app reduces to reading `storage_grants` and matching them against the
request.

**Trade-offs.**
- Fully decentralized and stateless: the API needs no authz database, and grants travel with the caller.
- Scales across services that share the IdP.
- Revocation waits for token expiry (a grant removed at the IdP still works until the token dies), the
  app blindly trusts the issuer, and rich grant sets bloat every token.

**Configuration surface** — Keycloak claim mapper emitting `storage_grants`. Grants are
`caps:prefix`, caps ∈ {`r`,`w`} (read implies list).

```
alice.storage_grants = ["r:finance/"]
bob.storage_grants   = ["rw:projects/apollo/"]
dave.storage_grants  = ["rw:*"]
```
`bob` writing `projects/apollo/a.txt` → permit (grant `rw:projects/apollo/`).

---

## ACL — Access Control Lists

**Elevator pitch.** Each prefix carries an explicit list of who-can-do-what, with `*` meaning
everyone. It is the dumb baseline: immediately obvious for small, ad-hoc sharing, with no indirection
to reason about. It is also the first thing to buckle at scale.

**Trade-offs.**
- Dead simple and transparent — the entry *is* the decision, nothing is inferred.
- Great for one-off shares ("give erin access to finance/").
- Grows linearly with users × resources and offers no reuse; large deployments become unmanageable.

**Configuration surface** — entries of `(prefix, principal, actions)`; principal `*` = everyone.

```
shared/                → *     (Read,List)          # public read
shared/announcements/  → dave  (Read,Write,List)
projects/apollo/       → bob   (Read,Write,List)
finance/               → erin  (Read,Write,List)
```
`carol` reading `shared/notes.txt` → permit (wildcard); writing it → deny (no write entry for carol).

---

## ReBAC — Relationship-Based Access Control (OpenFGA / Zanzibar)

**Elevator pitch.** Access follows *relationships* in a graph: ownership, group membership, and
folder-hierarchy inheritance. It expresses things RBAC and ACL can't say cleanly — "editors of a
folder are editors of everything beneath it" and "the eng team is editor here" — as composable graph
edges. The decision is a reachability query in the engine (OpenFGA).

**Trade-offs.**
- Models hierarchies, groups, and ownership natively; a single edge cascades down a subtree.
- The right tool for documents/folders/orgs where access is inherently relational.
- Needs an external engine and graph-shaped thinking; each decision is a network Check; the model is
  its own artifact to author and version.

**Configuration surface** — an OpenFGA authorization **model** (the schema) plus **tuples** (the data).

```
type prefix
  relations
    define parent: [prefix]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, user:*, team#member] or editor or viewer from parent
```
```
tuples:  prefix:projects/ --parent--> prefix:projects/apollo/     # hierarchy
         user:bob --member--> team:eng                            # group
         team:eng#member --editor--> prefix:projects/             # group × inheritance
         user:* --viewer--> prefix:shared/                        # public read
```
`carol` (viewer on `projects/`) reading `projects/apollo/specs/design.md` → permit (inherited down
two `parent` edges — the ReBAC-only move).

---

## Cedar — policy-as-code (typed authorization DSL)

**Elevator pitch.** Authorization is a set of `permit`/`forbid` policies written in Cedar, a language
purpose-built for access control, evaluated by an external agent (`cedar-agent`). Policies are
readable, strictly typed, and `forbid` always overrides `permit`, giving safe deny-by-default
semantics. It excels when you want auditable, human-authorable rules that combine attributes and
request context.

**Trade-offs.**
- Readable and opinionated — basic policies are legible to non-experts, and the type system catches
  mistakes before deploy.
- Native deny-override and request context that flat DB-row paradigms can't express.
- Requires an external engine and policy-authoring skill; its principal/action/resource/context model
  overlaps conceptually with RBAC+ABAC, so it earns its keep on *conditional* logic.

**Configuration surface** — Cedar policies; here all decision data rides in `context` (storage keys
are dynamic, so resources aren't pre-registered).

```cedar
permit(principal, action == Action::"read", resource)
  when { context.classification <= context.level };

forbid(principal, action == Action::"write", resource)
  when { context.frozen };                          // legal hold overrides every permit

permit(principal, action == Action::"read", resource)
  when { context.roles.contains("incident_responder") && context.break_glass };
```
Writing under a `frozen/` path → deny even for an owner (the `forbid` wins).

---

## OPA / Rego — policy-as-code (general-purpose engine)

**Elevator pitch.** Open Policy Agent evaluates policies written in Rego, a general-purpose
declarative language, over a per-request JSON `input` document. The same engine can enforce authz,
admission control, and config validation across the whole stack, so policy lives in one decoupled,
independently testable place. It trades authz-specific ergonomics for the ability to express
essentially any rule.

**Trade-offs.**
- Maximally general — if you can describe it over the input data, Rego can decide it.
- Decouples policy from application code and is reusable far beyond this one service.
- Rego has a real learning curve (Datalog-derived) and is less opinionated about authorization, so
  deny-override and defaults are things you write explicitly.

**Configuration surface** — a Rego module evaluated over `input`; `permit`/`deny` rules combined into
a decision (deny wins).

```rego
package authz
default permit := false
default deny := false
default allow := false

permit if {                                    # clearance read
  input.action == "read"
  input.resource.classification <= input.caller.level
}
deny if {                                       # legal hold — overrides
  input.action == "write"
  input.resource.frozen
}
allow if { permit; not deny }                   # deny beats permit (written explicitly)
decision := {"permit": allow}
```
Same scenario as Cedar, expressed in a general-purpose engine — the head-to-head the two policy-as-code
paradigms exist to compare.

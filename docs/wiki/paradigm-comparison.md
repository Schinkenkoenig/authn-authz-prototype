---
title: Authorization paradigm comparison
slug: index
---

Seven interchangeable authorization paradigms decide the **same** storage-access question —
`read` / `write` / `list` on an object key — in this testbed. This page compares them along a fixed
six-axis schema so their configuration burden and expressiveness can be read side by side.

The live seeded configuration and worked decision examples for every paradigm are in
[authz-paradigms.md](https://github.com/Schinkenkoenig/authn-authz-prototype/blob/main/docs/authz-paradigms.md); this page compares, that page demonstrates. The
**apples-to-apples view** — one fixed scenario expressed under every paradigm — is a separate view,
not part of this comparison. Security caveat: the caller picks the paradigm per request, so
effective access is the UNION across paradigms by design
([ADR 0005](https://github.com/Schinkenkoenig/authn-authz-prototype/blob/main/docs/adr/0005-caller-selected-paradigm-union-access.md)).

## How to read the axes

- **Elevator pitch** — what the paradigm is, in two sentences.
- **Grant grain** — what one act of granting covers: **per-user** (one grant, one person),
  **per-group** (one grant, every member of a named collection), or **per-rule** (one grant,
  everyone matching a condition). A paradigm may support several; the **characteristic** grain —
  the one its day-to-day administration actually happens at — is highlighted. Resource-side
  coverage (e.g. a grant cascading down a folder subtree) is *not* a grain; it appears in the
  ReBAC prose where it belongs.
- **Configuration surface** — the artifacts you must author and maintain, each annotated with
  *what it is / where it lives / who configures it*. Loci: **app DB**, **IdP**, **external
  engine**. Personas: **app admin**, **IdP admin**, **policy author**. The locus is a property of
  the artifact, not the paradigm — a paradigm's locus *set* is itself comparative signal (ABAC
  needs two admins to cooperate; claims needs no app-side config at all).
- **Enterprise-IdP leverage** — how much of the configuration burden is absorbed by data an
  enterprise IdP **already maintains** (security groups, HR-fed departments, profile attributes),
  and how easily the paradigm taps it. Leverage of *pre-existing* config, not migration of ours.
  Full analysis with primary sources:
  [Enterprise-IdP leverage per paradigm](https://github.com/Schinkenkoenig/authn-authz-prototype/blob/main/docs/research/2026-07-11-entra-idp-leverage-per-paradigm.md).
- **Upsides / Downsides** — the trade-offs, closed by a **sweet spot / worst fit** verdict.

## Overview matrix

| Paradigm | Characteristic grant grain | Locus set | Enterprise-IdP leverage |
|---|---|---|---|
| [RBAC](#rbac--role-based-access-control) | per-group | app DB | **high** — groups→app-roles absorb the churny half |
| [ABAC](#abac--attribute-based-access-control) | per-rule | app DB + IdP | **high** — attributes are the directory's day job |
| [Claim-based](#claim-based--grants-carried-in-the-token) | per-user | IdP | **lowest** — grants are new data, not pre-existing |
| [ACL](#acl--access-control-lists) | per-user | app DB | **minimal** — identity only, plus optional group principals |
| [ReBAC](#rebac--relationship-based-access-control) | per-group | external engine | **medium** — memberships free, plumbing expensive |
| [Cedar](#cedar--policy-as-code-typed-authorization-dsl) | per-rule | external engine + IdP | **medium** — data absorbed, but the app carries it per request |
| [OPA / Rego](#opa--rego--policy-as-code-general-purpose-engine) | per-rule | external engine + IdP | **medium** — token claims first-class; a menu beyond |

Leverage ranking: **rbac ≈ abac > opa ≈ cedar ≈ rebac > acl > claims** — with the caveat that
ReBAC's leverage comes bundled with the most plumbing.

---

## RBAC — Role-Based Access Control

**Elevator pitch.** Users are assigned roles; roles carry permissions. Access is decided by asking
"does any of the caller's roles grant this action on this prefix?" — the workhorse of enterprise
authz because many users share a few roles, so onboarding is a single row.

**Grant grain.** Supported: **per-group** and per-user. The characteristic grain is
**per-group**: the defining move is granting a permission to the *role* — one
`role_permissions` row covers every member, present and future. The per-user act (assigning a user
a role) is the day-to-day churn, but it grants nothing new; it only moves people in and out of
grants that already exist.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| `user_roles` rows | user→role assignments | app DB | app admin |
| `role_permissions` rows | role→(prefix, actions) grants | app DB | app admin |

Locus set: **app DB** only — one persona owns everything.

**Enterprise-IdP leverage: high** — the highest of the seven. The `user_roles` half — the part that
churns with every hire and reorg — maps directly onto data the enterprise already curates: declare
app roles on the app registration, assign existing security groups to them, and the token's `roles`
claim replaces the table. Onboarding stays what it already is: add the user to the group. What
stays app-side is `role_permissions` — the IdP has no concept of this app's prefixes and actions —
but that's the low-churn half.

**Upsides.**
- Reuse is the win: add a user to a role and they inherit everything that role can do.
- Trivially auditable — "who can access X" is two small joins.
- Rides existing enterprise group hygiene with almost no plumbing.

**Downsides.**
- Coarse-grained: fine-grained needs cause *role explosion* — one role per resource/permission combo.
- No per-resource nuance and no context: a role either covers a prefix or it doesn't.

**Sweet spot.** Access that mirrors stable job functions — many users, few roles, permissions that
change rarely. **Worst fit.** Fine-grained or ad-hoc per-resource sharing; every exception mints
another role until the role list *is* the ACL, without its transparency.

---

## ABAC — Attribute-Based Access Control

**Elevator pitch.** Access is derived from attributes of the caller (department, clearance level)
matched against the resource, with no explicit user-to-resource wiring. The sweet spot is
zero-touch onboarding: a new finance hire is covered by the department rule the moment their
`department` attribute is set.

**Grant grain.** **Per-rule** only — and characteristically so. One rule
(`department` interpolates into the prefix) covers every matching caller, current and future.
There is no per-user or per-group act of granting at all; individuals gain access by acquiring
attributes, not grants.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Rules | (conditions, prefix-template, actions) | app DB | app admin |
| Caller attributes | `department`, `level` claims on the token | IdP | IdP admin |

Locus set: **app DB + IdP** — the paradigm only works when two personas cooperate: the app admin
writes rules against attributes the IdP admin must keep flowing and trustworthy.

**Enterprise-IdP leverage: high.** The paradigm's entire value proposition is IdP-maintained
attributes, and the enterprise directory genuinely maintains the flagship one: `department` is a
standard, HR-fed profile attribute, selectable as a token claim. Non-standard attributes (`level`)
become directory extensions — also token-emittable, with ceremony. What stays app-side is the rule
text, which the directory can't hold. Trap to know: Entra's "custom security attributes" are never
emitted in tokens, despite the name.

**Upsides.**
- Onboarding and reorganizations need no authz change — the attributes do the work.
- Expressive when attribute data is good; rules stay small and general.

**Downsides.**
- "Who can access X?" is *implicit* — auditing means evaluating rules over the whole roster.
- Correctness depends entirely on attribute quality and provenance; the IdP must be trusted to set
  them, and a wrong `department` is a wrong access decision.

**Sweet spot.** Organizations whose access boundaries mirror facts the directory already tracks —
department shares, clearance tiers — with real HR-feed hygiene behind them. **Worst fit.** Ad-hoc,
one-off sharing ("give erin access to finance/") — there is no attribute for *erin specifically*,
so exceptions force either attribute pollution or a second paradigm on the side.

---

## Claim-based — grants carried in the token

**Elevator pitch.** The identity provider issues the access grants directly inside the token and
the application simply trusts them. There is **no application-side config** — the admin surface is
the IdP's claim mapper, and the app reduces to matching `storage_grants` against the request.

**Grant grain.** **Per-user** only, and characteristically so: each grant (`rw:projects/apollo/`)
is authored onto one user's claim set. There is no aggregate construct — covering a team means
repeating the grant on every member.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Claim mapper + per-user grants | `storage_grants` list (`caps:prefix`) on each user | IdP | IdP admin |

Locus set: **IdP** only — the single-locus mirror image of ACL. One persona, zero app artifacts.

**Enterprise-IdP leverage: lowest** — and this is the instructive inversion. The paradigm is
maximally IdP-*coupled* but leans on **pre-existing** IdP data minimally: no security group or HR
attribute encodes `rw:projects/apollo/`. The grant list is new, app-specific, per-user data someone
must author wherever it lives; only identity itself and the emission machinery come free.
"The IdP holds the config" and "the enterprise already maintains the config" are different claims —
this axis measures the second.

**Upsides.**
- Fully decentralized and stateless: the API needs no authz database, and grants travel with the caller.
- Scales across services that share the IdP — one grant vocabulary, many consumers.

**Downsides.**
- Revocation waits for token expiry: a grant removed at the IdP keeps working until the token dies.
- The app blindly trusts the issuer, and rich grant sets bloat every token.
- Per-user authoring with no reuse — ACL's growth curve, relocated into the IdP.

**Sweet spot.** Many small services behind one IdP needing coarse, stable, low-cardinality grants
with zero app-side state. **Worst fit.** Anything needing prompt revocation or rich per-resource
grant sets — the token is the wrong vehicle for a large, frequently-edited ACL.

---

## ACL — Access Control Lists

**Elevator pitch.** Each prefix carries an explicit list of who-can-do-what, with `*` meaning
everyone. The dumb baseline: immediately obvious for small, ad-hoc sharing, with no indirection to
reason about — and the first thing to buckle at scale.

**Grant grain.** **Per-user**, characteristically: an entry names one principal on one prefix. The
`*` wildcard entry ("everyone") is the single aggregate the paradigm offers; enterprise variants
extend entries to name groups, but the seeded testbed form is individuals plus `*`.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Entries | (prefix, principal, actions) triples | app DB | app admin |

Locus set: **app DB** only.

**Enterprise-IdP leverage: minimal.** Only the principal identifier comes free (a stable `oid`
claim — not mutable email/UPN). If entries are extended to accept *group* principals, membership
evaluation rides the token's groups claim — one entry covering a team the enterprise already
curates is the one worthwhile borrowing. Everything else — every entry — is inherently app-local;
the linear users×resources growth that makes ACL buckle is precisely the part no directory can
absorb.

**Upsides.**
- Dead simple and transparent — the entry *is* the decision; nothing is inferred.
- Great for one-off shares ("give erin access to finance/") — the exception case every
  aggregate paradigm handles badly.

**Downsides.**
- Grows linearly with users × resources and offers no reuse.
- Large deployments become unmanageable; auditing means reading the whole list.

**Sweet spot.** Small rosters, ad-hoc sharing, and as the explicit exception mechanism beside a
coarser paradigm. **Worst fit.** Scale in either dimension — many users or many resources — where
the entry count and its churn overwhelm any admin.

---

## ReBAC — Relationship-Based Access Control

*(OpenFGA / Zanzibar)*

**Elevator pitch.** Access follows *relationships* in a graph: ownership, group membership, and
folder-hierarchy inheritance. It expresses what RBAC and ACL can't say cleanly — "editors of a
folder are editors of everything beneath it", "the eng team is editor here" — as composable graph
edges; the decision is a reachability query in the engine.

**Grant grain.** Supported: **per-group** and per-user. The characteristic grain is **per-group**:
the signature move is one edge (`team:eng#member --editor--> prefix:projects/`) covering every team
member. Direct per-user edges and the `user:*` public edge exist too. Note the paradigm's other
famous coverage — a grant cascading down a folder subtree via `parent` edges — is *resource-side*
coverage, not a grantee grain: one edge covers many resources, orthogonal to how many users it
covers. The two multiply, which is why single edges go so far here.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Authorization model | the type/relation schema (`define editor: … or editor from parent`) | external engine (OpenFGA) | policy author |
| Relationship tuples | the data: hierarchy `parent` edges, memberships, team→resource role edges | external engine (OpenFGA) | app admin |

Locus set: **external engine** — but two personas split it: the model is authored and versioned
like code; the tuples are day-to-day administration.

**Enterprise-IdP leverage: medium — with the highest plumbing bill.** The membership tuples
(`user:bob --member--> team:eng`) *are* enterprise security-group memberships — the churniest slice
of the tuple set, with joiner/leaver processes already attached. But tapping them means either a
sync pipeline you build and operate (SCIM/Graph-delta → Write API, with a staleness window) or
contextual tuples derived from the token's groups claim per request (no persistence, token-lifetime
staleness, Check-family queries only). The model, hierarchy edges, and team→resource edges — the
actual authoring surface — stay yours regardless.

**Upsides.**
- Models hierarchies, groups, and ownership natively; a single edge cascades down a subtree.
- The right tool where access is inherently relational — documents, folders, org trees.

**Downsides.**
- Needs an external engine and graph-shaped thinking; each decision is a network Check.
- The model is its own artifact to author, version, and re-provision on change.

**Sweet spot.** Document/folder/org domains where "access follows structure" — inheritance and
group edges collapse what would be entry explosions elsewhere. **Worst fit.** Flat, condition-shaped
questions ("clearance ≥ classification", "deny while frozen") — there is no relationship to
traverse, and simple deployments that don't want to run and feed an engine.

---

## Cedar — policy-as-code (typed authorization DSL)

**Elevator pitch.** Authorization is a set of `permit`/`forbid` policies written in Cedar, a
language purpose-built for access control, evaluated by an external agent. Policies are readable
and strictly typed, and `forbid` always overrides `permit`, giving safe deny-by-default semantics.

**Grant grain.** Supported: **per-rule**, per-group, per-user. The characteristic grain is
**per-rule**: a policy covers every request satisfying its `when` clause
(`context.classification <= context.level` covers whoever clears the bar). Policies *can* pin a
single principal or a group, but if that's the daily pattern you're paying an engine for ACL/RBAC.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Cedar policies | `permit`/`forbid` rules over principal/action/resource/context | external engine (cedar-agent) | policy author |
| Caller attributes | the claims the policies condition on (`level`, roles) | IdP | IdP admin |

Locus set: **external engine + IdP**. Cedar has no data-fetch machinery — the app must gather
entities and context and hand them over on every request; that marshalling code is the app's,
even though it isn't a configuration artifact.

**Enterprise-IdP leverage: medium.** The principal's attributes and group memberships are absorbed
as *data* to the same degree as ABAC — enterprise groups map naturally onto Cedar group entities,
mapped claims onto principal attributes. But the engine never talks to the IdP: the app is the ETL
on every request, translating token claims (or directory pulls) into Cedar entities and context.
The policy text and schema stay yours by construction.

**Upsides.**
- Readable and opinionated — basic policies are legible to non-experts; the type system catches
  mistakes before deploy.
- Native deny-override and request context that flat DB-row paradigms can't express.

**Downsides.**
- Requires an external engine and policy-authoring skill.
- Its principal/action/resource/context model overlaps conceptually with RBAC+ABAC, so it earns
  its keep only on *conditional* logic.

**Sweet spot.** Auditable, human-authorable conditional rules — clearance checks, legal holds,
break-glass — where deny-must-win semantics and type checking pay for the engine. **Worst fit.**
Plain static mappings a DB row already expresses; running a policy engine to encode
"bob may write projects/" is pure overhead.

---

## OPA / Rego — policy-as-code (general-purpose engine)

**Elevator pitch.** Open Policy Agent evaluates policies written in Rego, a general-purpose
declarative language, over a per-request JSON `input` document. The same engine can enforce authz,
admission control, and config validation across the whole stack — it trades authz-specific
ergonomics for the ability to express essentially any rule.

**Grant grain.** Supported: **per-rule**, per-group, per-user — the same spread as Cedar, for the
same reason, with the same characteristic grain: **per-rule**. A Rego rule covers everyone the
`input` predicate matches; naming individuals is possible and equally beside the point.

**Configuration surface.**

| Artifact | What it is | Where it lives | Who configures it |
|---|---|---|---|
| Rego module | `permit`/`deny` rules combined into a decision (deny-wins written explicitly) | external engine (OPA) | policy author |
| Caller attributes | the claims the policy reads from `input.caller` | IdP | IdP admin |

Locus set: **external engine + IdP**. As with Cedar, the app builds the `input` document per
request — app code, not a config artifact, but a real part of the burden.

**Enterprise-IdP leverage: medium — with the most flexible mechanism menu.** Token claims dropping
into `input` is a documented first-class pattern, so for token-sized data OPA is as effortless as
it gets. Beyond the token, OPA offers an explicit staleness/complexity trade-off menu: periodic
bundle snapshots (staleness window, memory ceiling), pushed deltas (replicator you build), or
`http.send` mid-policy (current but network-bound). The Rego module and input construction stay
yours.

**Upsides.**
- Maximally general — if you can describe it over the input data, Rego can decide it.
- Decouples policy from application code; one engine reusable across the whole stack.

**Downsides.**
- Rego has a real learning curve (Datalog-derived).
- Less opinionated about authorization: deny-override and safe defaults are things you must write
  explicitly (`default allow := false`) — forget them and a miss returns nothing rather than deny.

**Sweet spot.** Organizations standardizing *one* policy engine across many concerns, with policy
authors on staff — authz becomes one more Rego module in an existing practice. **Worst fit.** A
single app wanting authorization ergonomics out of the box; general-purpose power costs exactly the
guardrails Cedar builds in.

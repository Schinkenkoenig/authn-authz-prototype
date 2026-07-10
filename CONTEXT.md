# authn-authz

The ubiquitous language of an authorization-paradigm comparison testbed: one storage-access decision,
expressed under seven interchangeable paradigms so their configuration burden can be compared. This
file is the glossary. For how each paradigm actually decides, see
[docs/authz-paradigms.md](docs/authz-paradigms.md); for why the system is shaped as it is, see
[docs/adr/](docs/adr/).

## Language

**Paradigm**:
One way of authorizing an access request — RBAC, ABAC, claim-based, ACL, ReBAC, Cedar, or OPA. The
unit of comparison. Every paradigm answers the same question over the same world; they differ only in
what an administrator must configure to get there.
_Avoid_: model, strategy, scheme.

**Caller**:
The authenticated human making a request, identified by the access token and its claims (username,
department, level, roles, grants). The subject of a decision.
_Avoid_: user, principal, subject, account.

**Action**:
What the caller wants to do to a resource: `read`, `write`, or `list`. The fixed, finite verb set every
paradigm reasons over.
_Avoid_: operation, permission, verb.

**Resource**:
The object being accessed, named by its storage key (e.g. `projects/apollo/design.md`). The target of
a decision.
_Avoid_: object, target, file.

**Prefix**:
A namespace segment of the key hierarchy (`projects/`, `finance/`, `hr/`). Access is reasoned about at
prefix granularity, and prefixes nest to form the folder hierarchy that ReBAC inherits down. A prefix
is an arbitrary namespace — it is deliberately *not* tied to a caller's identity.
_Avoid_: folder, path, directory, bucket, namespace (when you mean this specific segment).

**Decision**:
The paradigm's answer for one request: permit or deny, with a human-readable reason and the paradigm
that produced it. Deny is always the safe default.
_Avoid_: result, verdict, outcome, response.

**PDP** (Policy Decision Point):
The role of *deciding* whether an access request is permitted. Here the API is the PDP — it runs the
selected paradigm and produces the decision.

**PEP** (Policy Enforcement Point):
The role of *enforcing* a decision — allowing or blocking the actual object I/O. Here the API is also
the PEP: it enforces its own decision before touching storage. (One process holds both roles; see
[ADR 0001](docs/adr/0001-service-iam-app-level-authz.md).)

**Service identity**:
The single machine identity the API uses to reach storage, independent of any caller. Storage sees
only this identity with broad access; per-caller authorization happens in the API, above it, never in
the storage backend.
_Avoid_: service account, robot user, machine user, the DemoService role (that's the implementation).

**Break-glass**:
Emergency access granted to an incident responder that bypasses the normal rules, but only when the
request explicitly asserts it. The showcase scenario for request *context* affecting a decision.
_Avoid_: override, emergency access, escalation.

**Classification / Clearance**:
**Classification** is the sensitivity level attached to a resource (derived from its top prefix);
**clearance** (a.k.a. *level*) is the sensitivity a caller is trusted with. A read is permitted when
clearance meets or exceeds classification. Keep the two words distinct — one is on the resource, one is
on the caller.
_Avoid_: using "level" for both, security level, sensitivity (unqualified).

**Sweet-spot mode**:
Showcasing each paradigm on the slice of the world it expresses *best* — its ideal scenario. The
current comparison mode. It shows each paradigm's character but is deliberately not a fair head-to-head.
_Avoid_: demo mode, best-case.

**Apples-to-apples mode**:
The planned fair comparison: one fixed scenario expressed under *every* paradigm, to show the
admin-configuration burden side by side. The north star the sweet-spot mode is a stepping stone toward.
_Avoid_: head-to-head (ambiguous), fair mode.

# SP3 — ReBAC via OpenFGA

Fifth authorization paradigm for the showcase (see [SP2 spec](2026-07-02-authz-paradigms-showcase-design.md)): a
Zanzibar/OpenFGA relationship graph, selectable per request via `X-Authz-Paradigm: rebac`. Sweet-spot mode only —
apples-to-apples is still deferred to a later sub-project.

## Character to demonstrate

ReBAC's distinctive move is that permission flows through **edges between objects**, so a single grant reaches many
resources without per-resource config. Two composed edge types show it:

1. **Folder-hierarchy inheritance** — a grant on `projects/` reaches every descendant prefix via a recursive `parent`
   relation. Contrast: RBAC/ACL would need a row per prefix.
2. **Group membership** — a team owns/edits a folder; every member inherits that access, and onboarding a member is one
   `team#member` tuple. Contrast: RBAC needs a role grant per user; ACL needs a per-user entry per prefix.

## Authorization model (OpenFGA DSL — source of truth)

```
model
  schema 1.1

type user

type team
  relations
    define member: [user]

type prefix
  relations
    define parent: [prefix]
    define owner: [user, team#member]
    define editor: [user, team#member] or owner or editor from parent
    define viewer: [user, user:*, team#member] or editor or viewer from parent
```

- `editor from parent` / `viewer from parent` give recursive top-down inheritance (the canonical Zanzibar folders
  example). `owner ⊂ editor ⊂ viewer` by construction.
- `user:*` on `viewer` is public read (used for `shared/`).
- Loaded into OpenFGA as JSON (transformed from this DSL with the official `fga model transform` CLI, committed
  alongside) via `ClientWriteAuthorizationModelRequest.FromJson`. We do **not** hand-build the SDK object graph.

## Seed world (aligned to realm users alice/bob/carol/dave/erin)

Tuples written to OpenFGA at startup:

| user / userset            | relation | object                       | shows                     |
|---------------------------|----------|------------------------------|---------------------------|
| `prefix:projects/`        | parent   | (of) `prefix:projects/apollo/`        | hierarchy edge   |
| `prefix:projects/apollo/` | parent   | (of) `prefix:projects/apollo/specs/`  | hierarchy edge   |
| `user:bob`                | member   | `team:eng`                   | group membership          |
| `user:erin`               | member   | `team:eng`                   | group membership          |
| `team:eng#member`         | editor   | `prefix:projects/`           | group × inheritance (star)|
| `user:carol`              | viewer   | `prefix:projects/`           | inheritance (read)        |
| `user:alice`              | owner    | `prefix:projects/apollo/`    | owner ⇒ editor            |
| `user:*`                  | viewer   | `prefix:shared/`             | public read               |

Inheritance only resolves where the **whole parent chain is seeded** — every verify target lands on a seeded chain by
construction.

## Action → relation mapping

`Read`/`List` → `viewer`; `Write` → `editor`. The resource key maps to the **containing prefix object**: a key
`projects/apollo/specs/design.md` → check `prefix:projects/apollo/specs/`; a list prefix (ends in `/`) is used as-is.
OpenFGA's `from parent` walks up the seeded chain.

## The seam (async variant)

The four in-process evaluators stay **pure static** and the sync `AuthzDispatcher.Decide` is unchanged. ReBAC needs an
awaited network `Check`, so:

- Add `AuthzDispatcher.DecideAsync(paradigm, req, cfg, IRebacClient?, ct)`: returns `Task.FromResult(Decide(...))` for
  the four sync paradigms, and awaits `RebacEvaluator.EvaluateAsync(...)` for `rebac`. `"rebac"` joins `Paradigms`.
- `RebacEvaluator` is **not** pure: it owns the pure mapping (action→relation, key→containing-prefix — both unit-tested)
  and the awaited `IRebacClient.CheckAsync`.
- `IRebacClient` wraps the configured `OpenFgaClient` (store id + model id baked in): `Task<bool> CheckAsync(user,
  relation, obj, ct)`.
- Endpoints (`read`/`write`/`list`) inject `IRebacClient` and `await DecideAsync(...)`.

## Provisioning & infra

- `OpenFga.Sdk` 0.10.3. OpenFGA runs as fixed-IP infra in `scripts/dev-up.sh` (like Keycloak/Ceph), in-memory
  datastore, `172.30.0.30:8080`. `Openfga:ApiUrl` in config; env in `AppHost.cs`.
- Startup provisioner (fail-fast, like DB migrate→seed): `ListStores`, reuse the store named `authn-authz` if present
  else `CreateStore`; write the model; write seed tuples (write-if-absent). Holds store id + model id for the client.
  In-memory OpenFGA loses state on restart, so seeding runs every startup — reuse-by-name avoids store pile-up.
- `/authz/rebac/config` returns the DSL text + the seed tuples (the ReBAC config artifact).

## Testing

- **Unit** (no OpenFGA): action→relation and key→containing-prefix mapping; `DecideAsync` routing (rebac → evaluator,
  four → sync, rebac with null client → deny).
- **E2E** (real OpenFGA, no mocks — the real correctness gate) in `scripts/verify-authz.py`: carol reads
  `projects/apollo/specs/design.md` (inherited viewer) → permit; bob writes under `projects/` (eng editor, inherited) →
  permit; carol writes there → deny; dave reads `projects/...` → deny; alice writes `projects/apollo/x` (owner) →
  permit; any user reads `shared/...` → permit (public).

## Out of scope

Config editing/CRUD, apples-to-apples, playground frontend — all later sub-projects.

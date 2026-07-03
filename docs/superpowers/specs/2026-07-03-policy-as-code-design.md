# SP4 — Policy-as-code (Cedar + OPA/Rego) design

## Goal

Add **policy-as-code** as the sixth authorization paradigm — but represented by **two** engines,
because "PaC" has two genuinely different flavors and the project's north star is comparison:

- **`cedar`** — AWS Cedar, a typed, purpose-built *authorization* policy language, run as an
  out-of-process decision service (`cedar-agent`, Permit.io OSS).
- **`opa`** — Open Policy Agent, a general-purpose policy engine; policies in **Rego**, run as an
  out-of-process decision service (`opa run --server`).

Both express the **same** scenario, so the demo is a true head-to-head: identical policy intent,
two engines, judge authoring/readability/ergonomics side by side. This is a PaC-scoped preview of
the later apples-to-apples work (see [[authz-followons-and-learnings]]).

Both plug into the existing seam exactly like ReBAC did (see the SP3 spec): an external engine,
provisioned at startup (fail-fast), decided via an **awaited** HTTP call. Paradigm list becomes
`[rbac, abac, claims, acl, rebac, cedar, opa]`.

## The shared scenario

PaC's character is what the DB-row paradigms (rbac/abac/acl) *cannot* express cleanly: arbitrary
boolean logic, **deny that overrides allow**, and **request context**. The scenario reuses the
existing storage domain (caller claims `department`, `level`, `Roles`; resource = object key;
`Action` ∈ {Read, Write, List}) so it contrasts directly with the paradigms already built.

Resource **classification** is derived from the key's top prefix:

| Prefix | Classification |
|---|---|
| `public/…` | 1 |
| `internal/…` | 2 |
| `classified/…` | 3 |

Rules (evaluated identically by Cedar and Rego):

1. **Permit read** if `caller.level ≥ resource.classification` (clearance dominance). *Baseline — looks
   ABAC-ish on purpose, so the contrast with the next rules is legible.*
2. **Permit write** if `caller.department == resource.owner_department` **and** `caller.level ≥
   resource.classification`. Owner department is derived from the second path segment
   (`internal/finance/…` → `finance`).
3. **FORBID write** to any key containing a `frozen/` segment — a hard deny that **overrides every
   permit** (legal hold). *Cedar `forbid`; Rego explicit `deny`. Neither rbac/abac/acl expresses
   deny-override cleanly.*
4. **Break-glass read**: a caller whose `Roles` include `incident_responder` may read **anything**,
   but **only** when the request carries `context.break_glass == true`. *Request-context conditional —
   DB rows have no request context.*

Rules 3 and 4 are the PaC-only character; 1–2 anchor it to something recognizable.

### Seed world (illustrative)

Existing realm users carry `department` + `level` (SP2 mappers). Mapping onto the scenario:

- `bob` (level 3) reads `classified/x` → permit (rule 1); reads work across classifications ≤ 3.
- `alice` (level 2) reads `classified/x` → deny (rule 1); reads `internal/x` → permit.
- writer in `finance` writes `internal/finance/y` → permit (rule 2); writes `internal/eng/y` → deny.
- anyone writes `…/frozen/…` → deny (rule 3), even with a role/dept that would otherwise permit.
- `incident_responder` reads `classified/x` with `break_glass=true` → permit (rule 4); same read
  **without** the flag → deny.

**Realm dependency:** rule 4 needs a user with the `incident_responder` realm role. If no existing
user has it, add it to the realm export and re-import (`docker rm -f kc-spike && bash
scripts/dev-up.sh` — the fixed IP is preserved, so Ceph OIDC trust is unaffected). Flagged, not yet
confirmed against the current realm.

## Seam changes

### 1. `IExternalEvaluator` — replace the single-`IRebacClient` param

Three external engines can't each ride a nullable `DecideAsync` parameter. Introduce one interface,
one implementation per engine, resolved by paradigm:

```csharp
public interface IExternalEvaluator
{
    string Paradigm { get; }                                         // "rebac" | "cedar" | "opa"
    Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct);
}
```

`DecideAsync` dispatches to the matching external evaluator, else falls back to the pure sync
`Decide`. The four in-process evaluators stay **pure and untouched**:

```csharp
public static Task<AuthzDecision> DecideAsync(
    string paradigm, AuthzRequest req, AuthzConfig cfg,
    IReadOnlyDictionary<string, IExternalEvaluator> external, CancellationToken ct)
    => external.TryGetValue(paradigm, out var ev)
        ? ev.EvaluateAsync(req, ct)
        : Task.FromResult(Decide(paradigm, req, cfg));
```

ReBAC migrates into this shape: a `RebacExternalEvaluator` wraps the existing `IRebacClient` +
`RebacEvaluator` pure mapping (behavior identical; SP3 tests must still pass). DI registers the set
as `IEnumerable<IExternalEvaluator>`; the three storage endpoints inject it (built into a
paradigm→evaluator dictionary once) instead of the single `IRebacClient`.

### 2. Request context

Rule 4 needs a break-glass flag. Add an optional context to the request (additive, nullable):

```csharp
public sealed record AuthzContext(bool BreakGlass);
public sealed record AuthzRequest(CallerClaims Caller, StorageAction Action, string Resource,
    AuthzContext? Context = null);
```

Endpoints populate `Context` from a request header (`X-Break-Glass: true`); the sync paradigms
ignore it. `verify-authz.py` sends the header for the break-glass cases.

## Cedar specifics

- **Engine:** `cedar-agent` container. It holds a policy store + a data (entities) store and answers
  `is_authorized` over REST. Exact routes (policy push, entity push, decision) are **pinned during
  TDD** against the running container, not guessed here.
- **Model:** principals = `User`; resources = `Resource` with attributes `{classification,
  owner_department}`; actions = `read` / `write`. Caller `level`, `department`, `Roles` become
  principal attributes; `break_glass` rides the request **context**.
- **Policy (illustrative — exact syntax validated during TDD):**

  ```cedar
  permit(principal, action == Action::"read", resource)
    when { principal.level >= resource.classification };

  permit(principal, action == Action::"write", resource)
    when { principal.department == resource.owner_department
           && principal.level >= resource.classification };

  forbid(principal, action == Action::"write", resource)
    when { resource.frozen };

  permit(principal, action == Action::"read", resource)
    when { principal.roles.contains("incident_responder") && context.break_glass };
  ```

  Cedar's `forbid` naturally overrides `permit` (rule 3). `frozen` is precomputed per-entity from the
  key.

## OPA / Rego specifics

- **Engine:** `opa run --server` container. Push the `.rego` policy (`PUT /v1/policies/<id>`) and any
  static data (`PUT /v1/data/<path>`) at startup; decide with `POST /v1/data/authz/decision`
  carrying `{"input": {...}}`. Routes confirmed during TDD against the container.
- **Input:** `{caller:{level,department,roles}, action, resource:{classification, owner_department,
  frozen}, context:{break_glass}}`, assembled by the API from the request.
- **Policy (illustrative — exact syntax validated during TDD):**

  ```rego
  package authz
  import future.keywords.if
  import future.keywords.in

  default permit := false
  default deny := false

  permit if {                                   # rule 1
    input.action == "read"
    input.resource.classification <= input.caller.level
  }
  permit if {                                   # rule 2
    input.action == "write"
    input.caller.department == input.resource.owner_department
    input.resource.classification <= input.caller.level
  }
  permit if {                                   # rule 4
    input.action == "read"
    "incident_responder" in input.caller.roles
    input.context.break_glass
  }
  deny if {                                     # rule 3 — overrides
    input.action == "write"
    input.resource.frozen
  }
  allow if {                                    # deny wins over any permit
    permit
    not deny
  }
  decision := {"permit": allow}                 # API reads decision.permit
  ```

  Rego has no built-in allow/deny precedence — the deny-override is explicit in `allow`.

## Provisioning & infra

- **`dev-up.sh`:** two new containers on `cephnet`, health-checked like OpenFGA:
  - `cedar-agent` at **172.30.0.40:8180** (cedar-agent's default port)
  - `opa` at **172.30.0.50:8181** (OPA server's default port). Reached directly at the fixed IP:port
    on `cephnet` — no host port mapping.
- **API startup:** provisioners push each engine's policy + data, fail-fast (ReBAC pattern). Config
  URLs in `appsettings.Development.json` (`Cedar:ApiUrl`, `Opa:ApiUrl`) and AppHost env
  (`Cedar__ApiUrl`, `Opa__ApiUrl`). When a URL is absent, that paradigm has no registered external
  evaluator and denies (same as ReBAC-unconfigured).
- **Config surface:** `/authz/cedar/config` returns the Cedar policy + entities; `/authz/opa/config`
  returns the Rego module + input shape.

## Testing

- **Unit (pure, no engine):** per-engine mapping — classification-from-prefix, owner-department
  extraction, `frozen` detection, input/entity assembly, context plumbing; `DecideAsync` routing
  (paradigm→evaluator dispatch, unconfigured-denies).
- **e2e (`verify-authz.py`):** parallel `cedar` and `opa` cases over the **same four rules** — the
  matrix itself proves the two engines agree (the head-to-head). Cases: clearance permit/deny (r1),
  department write permit/deny (r2), frozen forbid overrides (r3), break-glass with/without header
  (r4). Real Keycloak tokens + real Ceph + real cedar-agent + real OPA.

## Out of scope (later phases)

- Persistent policy stores / hot-reload of policy edits (phase 3 dynamic-config work).
- The full apples-to-apples matrix across *all* paradigms (priority #3).
- Playground UI showing the Cedar-vs-Rego source side by side (priority #4) — this spec only exposes
  both via `/authz/{paradigm}/config`.
- Policy administration / delegation, schema-driven validation surfaced to users.

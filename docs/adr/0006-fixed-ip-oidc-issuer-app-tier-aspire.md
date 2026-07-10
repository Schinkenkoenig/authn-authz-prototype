# Fixed-IP OIDC issuer, app-tier-only Aspire

Infrastructure (Keycloak, Ceph, the external engines, the token sidecar) runs on a **fixed-IP Docker
bridge** via `scripts/dev-up.sh`; only the **app tier** (Postgres + API + SPA) runs under .NET Aspire.
Aspire does **not** orchestrate the infra containers.

## Context

The walking skeleton needs a single OIDC issuer string that is simultaneously reachable *and* valid
from three places at once: the browser (on the host), the API (a process), and Ceph RGW (a container
whose OIDC-provider trust and role trust-policy `aud` condition are pinned to that exact issuer
string). Change the issuer and Ceph's trust breaks.

Aspire hands Keycloak a **random host port** and fights fixed container IPs. So a Keycloak run under
Aspire produces an issuer that won't satisfy all three consumers without real work. The host also has
flaky container↔host routing for synthetic health probes, which full-container Aspire would depend on.

## Decision

Split the tiers:

- **Infra** on a fixed bridge IP — Keycloak at `172.30.0.20:8080`, so the issuer
  `http://172.30.0.20:8080/realms/authn-authz` is stable and reachable from browser, host, and
  containers alike. Provisioned by `dev-up.sh`.
- **App tier** under Aspire — the API runs as an Aspire *project* (a host process), so it reaches the
  fixed-IP infra directly; Aspire orchestrates Postgres + API + SPA and gives the dashboard.

Full-container Aspire (Keycloak + Ceph inside the AppHost on a shared network) was **not** attempted —
it fights Aspire's networking model, and the fixed-IP approach was already proven end-to-end.

## Consequences

- Two commands to run the stack: `dev-up.sh`, then `dotnet run --project src/AppHost`. Don't run the
  SPA standalone — it squats `:3000` and blocks Aspire's web resource.
- A proper Aspire issuer strategy remains **deferred** work, not abandoned — this is a deliberate
  walking-skeleton workaround, documented at the top of `dev-up.sh`.
- The fixed IPs are load-bearing for Ceph's OIDC trust; recreating Keycloak preserves the IP so trust
  survives (see the realm-hot-reload gotcha in AGENTS.md).

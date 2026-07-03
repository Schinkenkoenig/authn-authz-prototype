# SP4 Policy-as-code (Cedar + OPA/Rego) — run & verify note

## What it adds

Two new authorization paradigms — `cedar` (AWS Cedar via `cedar-agent`) and `opa` (OPA/Rego) —
selectable via `X-Authz-Paradigm`. Both evaluate the **same** four-rule scenario (clearance read,
department write, `frozen/` forbid-override, break-glass context), so they can be compared side by
side. See the [design spec](../specs/2026-07-03-policy-as-code-design.md) and the
[paradigm reference](../../authz-paradigms.md).

Both plug into the ReBAC seam via a new `IExternalEvaluator` (paradigm → evaluator dictionary); the
four in-process paradigms stay pure/sync. All decision data rides in the per-request payload
(OPA `input` / Cedar `context`) — no dynamic storage key is ever registered as an engine entity.

## Run (full stack)

```bash
bash scripts/dev-up.sh            # now also starts OPA (172.30.0.50:8181) + cedar-agent (172.30.0.40:8180)
dotnet run --project src/AppHost  # API pushes the Rego + Cedar policies to the engines at startup
```

## Fast verify (standalone API, no Aspire) — how this was verified

Same pattern as SP2/SP3: temp Postgres + the AppHost env, API on a fixed port, then run the matrix.
`appsettings.Development.json` carries the fixed infra URLs (incl. `Opa:ApiUrl`, `Cedar:ApiUrl`).

```bash
bash scripts/dev-up.sh
docker run -d --name sp4-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16

ASPNETCORE_ENVIRONMENT=Development \
ConnectionStrings__appdb="Host=localhost;Port=5433;Database=appdb;Username=postgres;Password=postgres" \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198

python3 scripts/verify-authz.py http://127.0.0.1:5198
```

## Result (2026-07-03)

- `dotnet test` → **69/69** unit tests (22 new: seam dispatch, context, PolicyInput derivation,
  Cedar + OPA evaluator routing).
- `verify-authz.py` → **31/31 ALL PASS** against real Keycloak tokens + real Ceph + real OpenFGA +
  real OPA + real cedar-agent, including the 7 OPA and 7 Cedar cases over the **same** scenario:
  - clearance read (bob level 3 permit `classified/`, alice level 2 deny);
  - department write (erin writes `internal/finance/` permit, `internal/eng/` deny);
  - `frozen/` write → deny even when the department rule would permit (Cedar reason
    `r3-forbid-frozen` — `forbid` overrides `permit`);
  - break-glass: carol (`incident_responder`, level 1) reads `classified/` → permit **only** with
    `X-Break-Glass: true`, deny without.
  - The OPA and Cedar rows agree row-for-row — the head-to-head the two paradigms exist to compare.
- `/authz/paradigms` → `[rbac, abac, claims, acl, rebac, cedar, opa]`; `/authz/opa/config` returns
  the Rego module; `/authz/cedar/config` returns the Cedar policies.

## Notes / gotchas

- **Realm dependency:** rule 4 needs a user with the `incident_responder` realm role. It was added to
  the realm export and assigned to **carol** (level 1) so break-glass is *demonstrable* — her
  clearance fails rule 1, so only the flag permits. Realm JSON does not hot-reload: pick up the change
  with `docker rm -f kc-spike && bash scripts/dev-up.sh` (fixed IP 172.30.0.20 preserved).
- **In-memory engines:** OPA and cedar-agent lose their pushed policy when the container is recreated;
  the API re-pushes at startup (fail-fast if unreachable), so it self-heals. A **policy edit** to
  `authz.rego` / `cedar-policies.json` needs the **API restarted** to re-push (the engines don't watch
  the files).
- **`list` under policy-as-code:** the scenario defines only read/write rules, so `list` has no
  matching permit and denies. Intentional (same as ReBAC skipping list).
- Teardown of the fast-verify scaffolding: kill the API process, `docker rm -f sp4-pg`. Leave the
  fixed-IP infra (kc-spike, ceph-demo, openfga, opa, cedar-agent, webid-refresher) up.

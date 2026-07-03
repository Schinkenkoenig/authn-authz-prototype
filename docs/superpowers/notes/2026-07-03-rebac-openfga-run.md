# SP3 ReBAC/OpenFGA — run & verify note

## What it adds

Fifth authorization paradigm `rebac`, backed by an OpenFGA relationship graph (Zanzibar-style folder
hierarchy + group membership). Selectable per request via `X-Authz-Paradigm: rebac`. See the
[design spec](../specs/2026-07-03-rebac-openfga-design.md).

## Run (full stack)

```bash
bash scripts/dev-up.sh            # now also starts OpenFGA at 172.30.0.30:8080 (in-memory)
dotnet run --project src/AppHost  # API provisions the OpenFGA store/model/tuples at startup
```

## Fast verify (standalone API, no Aspire) — how this was verified

Same pattern as SP2: run the API on a fixed port with the AppHost env + a temp Postgres, then run
the matrix. `appsettings.Development.json` already carries the fixed infra URLs (incl.
`Openfga:ApiUrl`); the AWS web-identity env must be supplied for the S3 write path.

```bash
bash scripts/dev-up.sh
docker run -d --name sp3-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16

ASPNETCORE_ENVIRONMENT=Development \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198

python3 scripts/verify-authz.py http://127.0.0.1:5198
```

## Result (2026-07-03)

- `dotnet test` → **47/47** unit tests pass (12 new: mapping + async dispatch routing).
- `verify-authz.py` → **17/17 ALL PASS** against real Keycloak tokens + real Ceph + real OpenFGA,
  including the 6 rebac cases:
  - carol reads `projects/apollo/specs/design.md` → **permit** (viewer on `projects/` inherited down
    the hierarchy — the ReBAC-only move).
  - bob writes under `projects/apollo/` → **permit** (member of `team:eng`, which is editor on
    `projects/`; group × inheritance).
  - alice writes `projects/apollo/x.txt` → **permit** (owner ⇒ editor).
  - dave reads `shared/notes.txt` → **permit** (public `user:*`).
  - carol writes there → **deny** (viewer only); dave reads `projects/apollo/` → **deny** (no edge).
- `/authz/paradigms` → `["rbac","abac","claims","acl","rebac"]`; `/authz/rebac/config` returns the
  DSL model + seed tuples.

## Notes / gotchas

- OpenFGA is **in-memory**: it loses the store when the container is recreated (or the host reboots).
  The startup provisioner reuses the store by name if present, else recreates model + tuples — so the
  API self-heals. `docker start openfga` after a stop also loses tuples (process restart), and the API
  re-provisions on its next start.
- The model DSL (`src/Api/Authz/rebac/model.fga`) is the source of truth; `model.json` is the
  `fga model transform` output that OpenFGA loads. Regenerate with:
  `docker run --rm -i openfga/cli model transform --input-format fga --file /dev/stdin < model.fga`.
- Teardown of the fast-verify scaffolding: stop the API process, `docker rm -f sp3-pg`. Leave the
  fixed-IP infra (kc-spike, ceph-demo, openfga, webid-refresher) up.

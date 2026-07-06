# Authz Phase 2 review pass — run & verify note

## What it adds

Fixes the SP3-flagged ReBAC silent-deny sharp edge (a resource at a path depth never wired into
the seeded relationship graph denied indistinguishably from a real policy deny) — the deny reason
now says so explicitly. Adds edge/negative test cases across all 7 paradigms and a cross-paradigm
consistency table to `scripts/verify-authz.py`. See the
[design spec](../specs/2026-07-05-authz-review-pass-design.md) and the
[implementation plan](../plans/2026-07-05-authz-review-pass.md).

## Run (full stack)

```bash
bash scripts/dev-up.sh
dotnet run --project src/AppHost
```

## Fast verify (standalone API, no Aspire)

```bash
bash scripts/dev-up.sh
docker run -d --name sp5-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16

ASPNETCORE_ENVIRONMENT=Development \
ConnectionStrings__appdb="Host=localhost;Port=5433;Database=appdb;Username=postgres;Password=postgres" \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198

python3 scripts/verify-authz.py http://127.0.0.1:5198
```

### Seeding read-target objects (fresh Ceph only)

`scripts/verify-authz.py` assumes certain read-only S3 objects already exist (the sweet-spot
scenarios only exercise a handful of writes; the rest are pre-seeded once and normally persist in
the long-lived `ceph-demo` container across sessions). Against a freshly recreated `ceph-demo`,
seed them once via an admin (rbac) write before running the matrix:

```bash
KC="http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token"
API="http://127.0.0.1:5198"
DAVE=$(curl -s -d client_id=webapp -d grant_type=password -d username=dave -d password=dave -d scope=openid "$KC" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
for key in "hr/records.txt" "shared/notes.txt" "projects/apollo/specs/design.md" "classified/x" "internal/x"; do
  curl -s -X POST "$API/storage/write" -H "Authorization: Bearer $DAVE" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d "{\"key\":\"$key\",\"content\":\"seed\"}"
done
```

## Result (2026-07-06)

- `dotnet test` → **73/73** unit tests (4 new: `ModeledPrefixes`, modeled-vs-unmodeled ReBAC deny
  reason, ReBAC permit-reason regression).
- `verify-authz.py` → **45/45 ALL PASS** (33 existing + 12 new edge/negative cases), against real
  Keycloak + Ceph + OpenFGA + OPA + cedar-agent. Confirmed the ReBAC observability fix live: the
  `bob` write to an unmodeled depth (`projects/apollo/specs/deep/nested.txt`) now returns reason
  `"OpenFGA: prefix:projects/apollo/specs/deep/ has no seeded tuple at this depth (unmodeled — not
  a policy decision)"` instead of the old, indistinguishable "lacks editor" wording.
- Cross-paradigm consistency table: both rows matched the design spec's predicted spread exactly,
  with no discrepancies to root-cause.
  - `alice writes finance/a.txt` → only ABAC permits (own-department rule); RBAC/Claims/ACL/OPA/Cedar
    deny for reasons specific to each model, and **ReBAC denies via the new unmodeled-depth reason**
    (`finance/` was never wired into the ReBAC seed graph at all) — an unplanned but welcome live
    confirmation of the Task 1/2 fix, surfacing organically rather than only in the case built to
    exercise it.
  - `carol reads shared/notes.txt` → RBAC/ACL/ReBAC/OPA/Cedar permit (each via its own "public
    read" mechanism — role, wildcard, `user:*` tuple, default classification); ABAC/Claims deny
    (neither models a concept of public access outside their own attribute/grant surface).

## Notes / gotchas

- **Host disk exhaustion blocked the run.** The long-lived `ceph-demo` container (up since
  2026-07-01, continuously restarted across SP2–SP4) had accumulated a 107GB writable layer from
  Ceph's own internal churn (degraded PGs, crashed mgr modules — it had been running in
  `HEALTH_WARN` since day one). Combined with unrelated host disk pressure (95% full, 47GB free
  against a 931GB disk), Ceph's monitor refused to start below its 5% free-space safety margin.
  Fix: removed the container (`docker rm -f ceph-demo`), freed the space, and let `dev-up.sh`
  recreate it fresh. All prior "permanent" demo data in Ceph was reproducible from documented
  `curl` seed commands (see above) — nothing irreplaceable was lost, but this is worth knowing
  before assuming `ceph-demo`'s state is durable indefinitely. A fresh container's *first* boot
  attempt also failed once with leftover partial state from an earlier aborted-boot artifact
  (`/var/lib/ceph/` was non-empty from the disk-space failure); removing and recreating once more
  resolved it cleanly.
- **Read-target seed objects are not tracked anywhere as a script** — they were seeded ad hoc via
  curl the first time each was needed (SP2's run note has the original two; this note now has the
  full list of five). If `ceph-demo` is ever rebuilt again, re-run the seeding block above before
  `verify-authz.py`, or reads will 500 (S3 `GetObject` on a missing key) even though authz
  correctly permitted the request.
- Teardown of the fast-verify scaffolding: killed the standalone API process, `docker rm -f
  sp5-pg`. Left the fixed-IP infra (kc-spike, ceph-demo, openfga, opa, cedar-agent,
  webid-refresher) up.

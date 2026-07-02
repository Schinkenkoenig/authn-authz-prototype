# Sub-project 2 — Authorization Paradigms: how to run & verify

**Date:** 2026-07-02

Four in-process authorization paradigms decide object-storage access over **arbitrary prefixes**,
selectable per request. Config for RBAC/ABAC/ACL is seeded in Postgres (read-only); claim-based
config lives in Keycloak.

## Run

1. `bash scripts/dev-up.sh` — fixed-IP infra: Keycloak (`kc-spike` 172.30.0.20), Ceph
   (`ceph-demo` 172.30.0.10), the `webid-refresher` sidecar.
2. `source ~/.bash_profile && dotnet run --project src/AppHost` — Aspire orchestrates Postgres +
   API + SPA. On startup the API runs **migrate → seed → load**: the config tables are seeded with
   the shared world and loaded into the in-memory `AuthzConfigStore`.
3. Read the **API base URL from the Aspire dashboard resource view** (the `api` resource) — Aspire
   assigns a dynamic port, so do not assume `:5000`.

## Selecting a paradigm

Every storage call honours the **`X-Authz-Paradigm`** header: `rbac` | `abac` | `claims` | `acl`.
Absent/unknown → defaults to `rbac`. The response echoes the resolved paradigm, the permit/deny
verdict, and the reason. A denied call returns **HTTP 403** with the reason.

**Security model:** the caller chooses the paradigm, so effective access is the *union* of what any
paradigm would grant that caller — this is a comparison showcase, not layered defence.

## Endpoints

- `POST /storage/read`  `{ "key": "finance/q1.txt" }`
- `POST /storage/write` `{ "key": "...", "content": "..." }`  (writes are audited)
- `GET  /storage/list?prefix=finance/`
- `GET  /authz/paradigms` — the four paradigm ids
- `GET  /authz/{paradigm}/config` — the seeded config artifact; `claims` returns a Keycloak pointer
  plus the caller's live `storage_grants` claim
- `GET  /whoami` — the validated caller claims

## Seeded shared world

Prefixes: `finance/ engineering/ hr/ shared/ projects/apollo/ projects/gemini/`.
Roster (each user carries roles-via-DB + attributes + a `storage_grants` token claim):

| user  | dept        | level | RBAC role | storage_grants        |
|-------|-------------|-------|-----------|-----------------------|
| alice | finance     | 2     | auditor   | `r:finance/`          |
| bob   | engineering | 3     | editor    | `rw:projects/apollo/` |
| carol | hr          | 1     | viewer    | `r:hr/`               |
| dave  | it          | 4     | admin     | `rw:*`                |
| erin  | finance     | 3     | editor    | `rw:finance/`         |

Passwords equal usernames (dev only); `webapp` has direct-access grants enabled for scripting.

## Verify (scripted, real tokens + real Ceph)

Seed the two read-targets the script expects (writes create their own), using dave (admin / `rw:*`):

```bash
source ~/.bash_profile
KC=http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token
API=<api-base-url-from-aspire-dashboard>
DAVE=$(curl -s -d client_id=webapp -d grant_type=password -d username=dave -d password=dave -d scope=openid "$KC" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST "$API/storage/write" -H "Authorization: Bearer $DAVE" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"hr/records.txt","content":"seed"}'
curl -s -X POST "$API/storage/write" -H "Authorization: Bearer $DAVE" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"shared/notes.txt","content":"seed"}'
```

Then run the paradigm matrix:

```bash
python3 scripts/verify-authz.py "$API"
```

Expected: every line `PASS`, final `ALL PASS`.

## Note for the future playground

A browser playground will send `X-Authz-Paradigm` from JS. The API's CORS policy currently allows
only the `Authorization` / `Content-Type` request headers — add `X-Authz-Paradigm` to
`WithHeaders(...)` in `Program.cs` when that lands. Server-side callers (curl/python) are unaffected.

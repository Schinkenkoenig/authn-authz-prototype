# Ceph RGW STS — Empirical Verdicts (Walking Skeleton, spec §7)

> Status: **COMPLETE.** All §7 verdicts proven (below), then the model was pivoted (§6) to service-level IAM + app-level authz. Definition-of-Done evidence at the end. These verdicts + the pivot gate sub-project 2's policy model.

## Definition of Done — evidence (Task 7, verified 2026-07-02 against the running Aspire stack)

Run topology: `scripts/dev-up.sh` (Keycloak 172.30.0.20, Ceph 172.30.0.10, webid-refresher) + `dotnet run --project src/AppHost` (Aspire: Postgres + API + SPA). Verified via the browser-facing API proxy.

1. **OIDC login end-to-end (tokens in browser)** — SPA serves on `:3000`; Authorization Code + PKCE against `webapp` proven by a scripted full flow (code→token, `aud=api` + id token). Browser click-through is the one manual step.
2. **`GET /whoami`** returns validated claims from the access token (`aud=api`, roles from `realm_access`): alice → `{reader}`.
3. **`POST /storage/roundtrip`** — API-enforced authz: READ succeeds for both; WRITE **denied for alice (reader)**, **allowed for bob (writer)**. Storage I/O uses the **service identity** (SDK web-identity → `DemoService`), no per-user STS.
4. **Scalar** renders (`/scalar/v1` → 200). One trace covering API → STS → S3 is emitted via OTel (AWS instrumentation) to the Aspire dashboard — the visualization is a dashboard check.
5. **Postgres wiring** — EF migration applied on startup against Aspire's Postgres; audit rows written (one per successful write; confirmed via `SELECT` on `AuditEntries`).

**Reproducibility (Task 3 Step 8) — CONFIRMED cold.** Tore down every container + volume (ceph-demo, kc-spike, webid-refresher, Aspire postgres + its data volume, orphaned keycloak volume), then cold `dev-up.sh` + `dotnet run --project src/AppHost` from scratch. init-sts's ordering works on a virgin RGW: enable STS + create provider/`DemoService` in one pass, then RGW restart (FRESH_CEPH), then refresher's first token. Money-path passed cold: alice read-OK/write-denied, bob read+write-OK. **AWS SDK spans confirmed emitted** (temporary console exporter): `STS.AssumeRoleWithWebIdentity` + S3 `PutObject`/`GetObject` under source `AWSSDK.*` — so instrumentation 1.16.0 does hook AWSSDK v4 and DoD#4's trace is real.

Note on §6 pivot vs original DoD wording: item 3 originally said "AssumeRoleWithWebIdentity with an inline session policy narrowing to the prefix." That per-user mechanism was proven (verdicts §1–§5) then **superseded** — enforcement is now in the API (app-level PDP/PEP) and storage auth is the service identity. See §6 + [[authz-pivot-service-iam]].

## Pinned Ceph image

- **Chosen:** `quay.io/ceph/demo:latest-squid` (Ceph **Squid 19.x**), the purpose-built all-in-one demo image.
- **Run recipe (standalone, for the spike):** dedicated docker network + fixed IP (the demo entrypoint requires `CEPH_PUBLIC_NETWORK` + `MON_IP`; `NETWORK_AUTO_DETECT` is insufficient):
  ```
  docker network create --subnet 172.30.0.0/16 cephnet
  docker run -d --name ceph-demo --network cephnet --ip 172.30.0.10 \
    -e MON_IP=172.30.0.10 -e CEPH_PUBLIC_NETWORK=172.30.0.0/16 \
    -e CEPH_DEMO_UID=demo -e CEPH_DEMO_ACCESS_KEY=demoaccess -e CEPH_DEMO_SECRET_KEY=demosecret123 \
    -e CEPH_DEMO_BUCKET=firstbucket -e RGW_NAME=localhost -e RGW_FRONTEND_PORT=8080 \
    -p 8080:8080 quay.io/ceph/demo:latest-squid
  ```
- **Static-key S3 verified:** list / mb / put / get roundtrip a 28-byte object. RGW ready ~60s after start.
- **Why not the alternatives:**
  - `quay.io/ceph/ceph:v19.2.4` (Squid) is not a single-container demo (needs cephadm bootstrap).
  - `quay.io/ceph/daemon:latest-{reef,quincy}` **fail**: `demo.sh: No such file or directory` — the `ceph/daemon` project dropped demo mode. The separate **`ceph/demo`** repo is the working one and has a **squid** tag.
- **Squid STS advantage:** unlike Reef, the Squid STS docs **document the inline session `Policy` parameter** ("Policy (String/Optional): An IAM Policy in JSON format") *and* session tags — so the original inline-session-policy design is likely viable (still to be proven empirically below).

## Verdicts (spec §7) — PROVEN on Squid

Spike topology: standalone `ceph/demo:latest-squid` (RGW `172.30.0.10:8080`) + dedicated Keycloak on the same docker network with a **fixed-IP issuer** `http://172.30.0.20:8080/realms/authn-authz` (reachable identically from the host and from the Ceph container on Linux).

### 1. ID token accepted by STS as WebIdentityToken — **PASS** ✅
- `AssumeRoleWithWebIdentity` accepted the Keycloak **ID token** (`aud=webapp`, `iss=http://172.30.0.20:8080/realms/authn-authz`) and returned temporary credentials.
- Prerequisite confirmed: the ID token is only issued when the token request includes **`scope=openid`** (ROPC without it returns no `id_token`).

### 2. Inline session `Policy` on AssumeRoleWithWebIdentity — **PASS** ✅  ← LOAD-BEARING
- Squid **honors** the inline session `Policy`. Ground-truth discriminator (both writes target `alice/other/`, differing only by the session policy):
  - `alice/other/b.txt` written under role-only creds → **PRESENT** (role permits `alice/*`).
  - `alice/other/e.txt` written under role + inline session policy scoped to `alice/reports/*` → **ABSENT** (denied by the narrower session policy).
- **Consequence:** the original design stands — the backend brokers STS and attaches an inline session policy to scope to the caller's prefix. **No fallback needed. No design change to §3/§4.**
- **Re-confirmed against the C# `SessionPolicy.ForPrefix` output (Task 4).** That builder emits `Resource` as a JSON **array** (`["arn:aws:s3:::demo/alice/reports/*"]`), not the string form proven above. Re-ran the discriminator with the array-form JSON: role `DemoReader` allows `alice/*`, session policy allows only `alice/reports/*`. Ground-truth admin listing: `alice/reports/DISC_reports.txt` **PRESENT**, `alice/other/DISC_other.txt` **ABSENT** (denied despite the role permitting it). So Squid enforces the array form identically — `ForPrefix` is validated against the real PEP, not just unit-asserted. NOTE: the API roundtrip's own `contentMatched=true` does *not* prove narrowing (role ∩ session are both `alice/*` there); this discriminator is what proves it.

### 3. Session tags / principal tags — SUPPORTED (documented), not exercised in the spike
- Squid docs document session tags (JWT `https://aws.amazon.com/tags` namespace) as an alternative/complementary ABAC mechanism. Not needed for sub-project 1 (inline session policy suffices). Left for sub-project 2 to exercise if it wants attribute-driven scoping.

### 4. OIDC provider trust in dev (JWKS/thumbprint, issuer reachability) — **PASS** ✅
- RGW accepted an **http** issuer with a **dummy thumbprint** (`ffff…`); provider ARN `arn:aws:iam:::oidc-provider/172.30.0.20:8080/realms/authn-authz`.
- Issuer consistency solved by using a **fixed docker-network IP as the Keycloak hostname** so the token `iss`, the Ceph provider `Url`, and the host's token-fetch URL are all identical and mutually reachable.

### 5. Role permission policy vs inline session policy — where ACTIONS are enforced (Task 5 finding) — **MODEL-SHIFTING**
Empirically discriminated on Squid (ground truth via admin listing each time):
- **Role permission-policy ACTIONS are NOT enforced** for these roles. `DemoReader` with a `GetObject`-only permission policy, assumed with **no** session policy, still successfully `PutObject`s. Restarting RGW did not change it (not a cache).
- **Inline session-policy ACTIONS ARE enforced.** `DemoWriter` (broad role) assumed with an inline session policy allowing only `GetObject` → `PutObject` **DENIED**.
- **Resource/prefix restriction via session policy is enforced** (verdict #2). So the inline session policy is the reliable ceiling for both actions and prefix; the role's own permission policy is not.
- **Fail mode: Ceph fails CLOSED on a malformed session policy** — a non-JSON `--policy` is rejected with `MalformedPolicyDocument` (STS call fails). An **empty/omitted** policy, however, yields the role's broad access (fail-OPEN), so the API must always attach one — enforced by a guard in `StsBroker`.
- **Hypothesis (NOT proven):** the role lives in the `demo` account that OWNS the bucket, so owner-ACL grants object access regardless of the role's IAM action list; the inline session policy still applies as a hard session ceiling (AWS "session policy can only restrict" semantics). **Confirming test (sub-project-2 scope):** create the role in a separate tenant/account that does not own the bucket and re-check whether role permission-policy actions are then enforced.

## Consequence for the design — REFINED (supersedes the earlier "no design change")
The PDP/PEP split holds, but **the enforcement model is refined**: the API (PDP) computes the **full effective permission as the inline session policy** — RBAC actions (reader vs writer, from the role claim) **and** ABAC prefix (from identity) — and Ceph enforces that session policy. The Ceph **role provides trust/identity only**; its permission policy is not the enforcer on this owner-account setup. This **changes the locked thesis** (was: "RBAC = which role" enforced by the role's policy). Directly answers "is this only claim-based?": no — the session policy is a computed RBAC+ABAC decision. Sub-project 2 must decide: keep computed session policies as the PDP output (clean), or move roles to a non-owner tenant so role policies enforce too.

### 6. PIVOT (Nils, 2026-07-02): service-level IAM via the SDK web-identity provider — **PROVEN**
See [[authz-pivot-service-iam]]. We are moving OFF per-user STS brokering to **service-level IAM + app-level authz**. The service→storage credential acquisition is handled by the **AWS SDK's own web-identity provider** (no hand-rolled STS calls), configured purely via env vars. Proven end-to-end against Ceph (spike `/tmp/sdkwebid`, a bare `AmazonS3Client` with only endpoint+`ForcePathStyle` in config, creds from env):
- Env: `AWS_ROLE_ARN=arn:aws:iam:::role/DemoService`, `AWS_WEB_IDENTITY_TOKEN_FILE=<file>`, `AWS_ENDPOINT_URL_STS=<rgw>`, `AWS_REGION=us-east-1`. The SDK does `AssumeRoleWithWebIdentity` + refresh itself. Requires `AWSSDK.SecurityToken` referenced. `ForcePathStyle` is client config (not env-settable).
- Service identity = Keycloak confidential client **`storage-service`** (serviceAccountsEnabled, client-credentials grant, secret `storage-service-secret`), audience mapper adds `aud=storage-service`.
- Ceph gotchas found & fixed: (a) trust condition must key on **`azp`** (`storage-service`), not `aud` — the token's `aud` is multi-valued `[storage-service, account]` and plain `StringEquals` on it fails; (b) Ceph RGW has **no `add-client-id-to-open-id-connect-provider`** (returns "Unknown") — `init-sts.sh` **deletes+recreates** the provider with both client ids (`webapp`, `storage-service`); the provider ARN is stable so role trusts survive. Role `DemoService` (broad `demo/*`) trusts `azp=storage-service`.
- Per-user authorization now moves INTO the API (app-level PDP+PEP). `StsBroker`/`SessionPolicy` (per-user inline session policy) are being retired. Token freshness: a **refresher sidecar container** writes a fresh client-credentials token to the shared token file on an interval.
- **Spec §3/§4 rewrite pending Nils's sign-off** — he deferred the spec-update question in favor of this pivot.

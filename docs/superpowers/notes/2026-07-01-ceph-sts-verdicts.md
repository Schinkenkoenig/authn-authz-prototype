# Ceph RGW STS — Empirical Verdicts (Walking Skeleton, spec §7)

> Status: **IN PROGRESS.** Doc-based findings are marked *(preliminary)*; they are not final until proven by the raw round-trip in Task 3. These verdicts gate sub-project 2's policy model.

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
The PDP/PEP split holds, but **the enforcement model is refined**: the API (PDP) computes the **full effective permission as the inline session policy** — RBAC actions (reader vs writer, from the role claim) **and** ABAC prefix (from identity) — and Ceph enforces that session policy. The Ceph **role provides trust/identity only**; its permission policy is not the enforcer on this owner-account setup. This **changes the locked thesis** (was: "RBAC = which role" enforced by the role's policy). Directly answers "is this only claim-based?": no — the session policy is a computed RBAC+ABAC decision. **Spec §3/§4 should be updated to reflect this** (pending Nils's sign-off). Sub-project 2 must decide: keep computed session policies as the PDP output (clean), or move roles to a non-owner tenant so role policies enforce too.

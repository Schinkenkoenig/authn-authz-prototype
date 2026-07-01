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

### 3. Session tags / principal tags — SUPPORTED (documented), not exercised in the spike
- Squid docs document session tags (JWT `https://aws.amazon.com/tags` namespace) as an alternative/complementary ABAC mechanism. Not needed for sub-project 1 (inline session policy suffices). Left for sub-project 2 to exercise if it wants attribute-driven scoping.

### 4. OIDC provider trust in dev (JWKS/thumbprint, issuer reachability) — **PASS** ✅
- RGW accepted an **http** issuer with a **dummy thumbprint** (`ffff…`); provider ARN `arn:aws:iam:::oidc-provider/172.30.0.20:8080/realms/authn-authz`.
- Issuer consistency solved by using a **fixed docker-network IP as the Keycloak hostname** so the token `iss`, the Ceph provider `Url`, and the host's token-fetch URL are all identical and mutually reachable.

## Consequence for the design
**None — the original architecture is validated.** Backend = PDP (assume role + inline session policy), Ceph = PEP. RBAC = which role; ABAC = inline session policy (session tags available as a future alternative). Sub-project 2 may proceed on the design as written.

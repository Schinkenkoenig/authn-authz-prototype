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

## Verdicts (spec §7)

### 1. ID token accepted by STS as WebIdentityToken
- **Status:** PENDING empirical (Task 3 Step 4).
- Hypothesis: RGW accepts the Keycloak **ID token** (`aud=webapp`) and validates it against the provider's client-id list.
- Confirmed prerequisite: the ID token is only issued when the token request includes **`scope=openid`** (verified in Task 1 — ROPC without it returns no `id_token`).

### 2. Inline session `Policy` on AssumeRoleWithWebIdentity  ← LOAD-BEARING
- **Status:** *(preliminary: NOT SUPPORTED)* — the Ceph Reef/Quincy STS docs do **not** document an inline session `Policy` parameter for `AssumeRoleWithWebIdentity`. To be confirmed empirically (Task 3 Step 6): pass `Policy=...` and observe whether scoping is honored.
- **Impact if confirmed:** the design's "backend builds an inline session policy to narrow to the caller's prefix" does not work. Use the session-tag path (below) instead — this changes the token model (§4) and sub-project 2's policy model.

### 3. Session tags / principal tags
- **Status:** *(preliminary: SUPPORTED)* — Ceph docs: "RGW now supports Session tags that can be passed in the web token to AssumeRoleWithWebIdentity." Tags travel in the JWT under the `https://aws.amazon.com/tags` namespace; Keycloak maps a user attribute → that claim via a protocol mapper.
- **Implication (the adapted ABAC mechanism):** the caller's allowed prefix is a Keycloak **user attribute** → mapped into the token as an AWS **session tag** → RGW enforces via a permission-policy `Condition` on `aws:PrincipalTag/<key>`. To be proven in Task 3 Step 7.

### 4. OIDC provider trust in dev (JWKS/thumbprint, issuer reachability)
- **Status:** PENDING empirical (Task 3 Step 2).
- Concern: the token `iss` (Keycloak's Aspire-mapped URL) must be reachable *from inside the Ceph container* for JWKS validation. Requires Ceph + Keycloak on a shared network with a consistent issuer URL. Record the exact resolution.

## Consequence for the design (if #2 FAIL / #3 PASS hold)
ABAC shifts from **backend-constructed inline session policy** → **Keycloak-issued session tags + role permission-policy `aws:PrincipalTag` conditions**. RBAC (which role you may assume) is unchanged. This simplifies the API broker (no per-request policy JSON) and moves prefix scoping into Keycloak user attributes + the role policy. **Surface to Nils with empirical proof before finalizing sub-project 2.**

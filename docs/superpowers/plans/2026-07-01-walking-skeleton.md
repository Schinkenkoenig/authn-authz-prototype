# Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the full authn/authz money-path end to end — Keycloak login → Keycloak token → Ceph RGW `AssumeRoleWithWebIdentity` → temporary prefix-scoped S3 credentials → object I/O — all orchestrated by .NET Aspire, with a Next.js SPA front door and observability.

**Architecture:** Aspire AppHost orchestrates Keycloak, Ceph (RGW+STS), Postgres, the FastEndpoints API, and the Next.js SPA. The API is the PDP (validates the access token, brokers `AssumeRoleWithWebIdentity` with the ID token, attaches an inline session policy); Ceph RGW is the PEP. The SPA holds tokens in the browser (Auth Code + PKCE, public client). Access token (`aud=api`) authorizes the API; ID token (`aud=webapp`) is forwarded to STS.

**Tech Stack:** .NET (latest LTS) + Aspire + FastEndpoints + AWSSDK (S3 + SecurityToken) + Serilog + OpenTelemetry + Scalar; Keycloak; Ceph RGW; Postgres + EF Core; Next.js + `oidc-client-ts`/`react-oidc-context`.

**Plan shape (read this first):** This is a walking-skeleton **integration spike**, not a pure-TDD feature. Tasks are **risk-ordered**: the riskiest, least-documented integration (Ceph RGW STS ↔ Keycloak) is proven **via shell/CLI before any C# is written**. Where an exact command is a genuine unknown, the step names the authoritative doc page and makes the command's discovery + an **empirical verification** the deliverable — it does **not** invent flags. Real red-green TDD is applied only to genuinely pure logic (claim→role mapping, session-policy JSON construction); everything touching Ceph/Keycloak is verified by running it (no mocked-integration tests).

**Reference doc pages (authoritative levers for the Ceph tasks):**
- STS in Ceph: https://docs.ceph.com/en/latest/radosgw/STS/
- Integrating Keycloak with RadosGW: https://docs.ceph.com/en/latest/radosgw/keycloak/
- RGW STS modernization (2025): https://ceph.io/en/news/blog/2025/rgw-modernizing-sts/
- Aspire Keycloak integration: https://learn.microsoft.com/en-us/dotnet/aspire/authentication/keycloak-integration

---

## File Structure

```
authn-authz.sln
src/
  AppHost/                         # Aspire orchestration — the single source of dev topology
    AppHost.csproj
    Program.cs                     # AddKeycloak, AddPostgres, AddContainer(ceph), AddProject(api/web)
    realms/authn-authz-realm.json  # committed Keycloak realm (clients, mappers, users, roles)
    ceph/                          # Ceph container init assets (entrypoint/init script, policies)
      init-sts.sh                  # idempotent: create users/caps, OIDC provider, role, bucket
      trust-policy.json            # role trust policy (Federated -> keycloak provider)
      permission-policy.json       # role permission policy (prefix-scoped)
  ServiceDefaults/                 # shared OTel + Serilog + health wiring
    ServiceDefaults.csproj
    Extensions.cs
  Api/                             # FastEndpoints REST API (PDP + STS broker)
    Api.csproj
    Program.cs                     # FastEndpoints, JWT bearer, Scalar, Serilog, EF Core
    Auth/CallerClaims.cs           # pure: extract identity/roles from validated principal
    Authz/RoleResolver.cs          # pure: claims -> Ceph role ARN (RBAC)
    Authz/SessionPolicy.cs         # pure: build inline session policy JSON for a prefix (ABAC)
    Storage/StsBroker.cs           # AssumeRoleWithWebIdentity -> temp creds (integration)
    Storage/S3Gateway.cs           # PUT/GET/list with temp creds (integration)
    Endpoints/WhoAmIEndpoint.cs
    Endpoints/StorageRoundtripEndpoint.cs
    Data/AppDbContext.cs           # one trivial entity to prove Postgres wiring
    Data/Migrations/               # one EF migration
  Web/                             # Next.js SPA
    package.json
    src/auth/oidc.ts               # oidc-client-ts UserManager config
    src/app/...                    # login callback + home page (whoami + roundtrip button)
tests/
  Api.Tests/                       # unit tests for PURE logic only
    RoleResolverTests.cs
    SessionPolicyTests.cs
    CallerClaimsTests.cs
docs/superpowers/notes/
  2026-07-01-ceph-sts-verdicts.md  # deliverable of Task 3 — §7 verdicts
```

**Split rationale:** pure authz logic (`RoleResolver`, `SessionPolicy`, `CallerClaims`) is isolated from I/O (`StsBroker`, `S3Gateway`) so it is unit-testable without Ceph and reusable by sub-project 2's policy engine. Ceph init assets live beside the AppHost that mounts them.

---

## Task 1: Aspire skeleton + Keycloak + Postgres up and healthy

**Files:**
- Create: `authn-authz.sln`, `src/AppHost/*`, `src/ServiceDefaults/*`, `src/AppHost/realms/authn-authz-realm.json`

- [ ] **Step 1: Scaffold the solution and Aspire projects**

Run (pins current versions via the installed templates — do NOT hardcode versions):
```bash
dotnet new install Aspire.ProjectTemplates
dotnet new aspire-apphost -n AppHost -o src/AppHost
dotnet new aspire-servicedefaults -n ServiceDefaults -o src/ServiceDefaults
dotnet new sln -n authn-authz
dotnet sln add src/AppHost src/ServiceDefaults
```
Expected: solution builds. `dotnet build` → 0 errors.

- [ ] **Step 2: Add Keycloak + Postgres hosting packages to AppHost**

Run:
```bash
dotnet add src/AppHost package Aspire.Hosting.Keycloak
dotnet add src/AppHost package Aspire.Hosting.PostgreSQL
```

- [ ] **Step 3: Author a minimal committed realm**

Create `src/AppHost/realms/authn-authz-realm.json` with (author by hand or export from a throwaway Keycloak, then trim):
- realm `authn-authz`
- **public** client `webapp`: standard flow on, PKCE `S256` required, redirect URIs `http://localhost:3000/*`, web origins `+`
- a protocol mapper on `webapp` adding audience `api` to the **access token** (Audience mapper, `included.client.audience=api`, access token = true, id token = false)
- realm roles: `reader`, `writer`
- one user `alice` (password set, role `reader`) and one user `bob` (role `writer`)

> Exact JSON is large; the reliable path is: bring up a bare Keycloak (Step 4), configure the above in the admin console, export the realm (`/opt/keycloak/bin/kc.sh export`), commit the trimmed file. Do NOT hand-fabricate mapper GUIDs.

- [ ] **Step 4: Wire Keycloak + Postgres in AppHost `Program.cs`**

```csharp
var builder = DistributedApplication.CreateBuilder(args);

var kcPassword = builder.AddParameter("keycloak-admin", secret: true);
var keycloak = builder.AddKeycloak("keycloak", adminPassword: kcPassword)
    .WithRealmImport("./realms")
    .WithDataVolume();

var postgres = builder.AddPostgres("postgres").WithDataVolume();
var appdb = postgres.AddDatabase("appdb");

builder.Build().Run();
```

- [ ] **Step 5: Run and verify Keycloak + realm**

Run: `dotnet run --project src/AppHost`
Expected: Aspire dashboard opens; `keycloak` and `postgres` reach **Running/Healthy**. Open the Keycloak console, confirm realm `authn-authz` and client `webapp` exist.

- [ ] **Step 6: Verify a token can be obtained (curl, no app)**

Against the Keycloak endpoint shown in the dashboard, run the OIDC discovery + a Direct Access Grant (enable it temporarily on `webapp` or use a throwaway confidential client) to fetch a token:
```bash
curl -s "$KC/realms/authn-authz/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=webapp -d username=alice -d password=... | jq .
```
Expected: a JSON with `access_token` and `id_token`. Decode both (`jq -R 'split(".")[1]|@base64d|fromjson'`) and **confirm** `access_token.aud` contains `api` and `id_token.aud == "webapp"`. Record the two `aud` values — Task 3 depends on them.

- [ ] **Step 7: Commit**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: aspire skeleton with keycloak realm and postgres"
```

---

## Task 2: Ceph RGW up as an Aspire container with working S3 (static key)

**Files:**
- Create: `src/AppHost/ceph/init-sts.sh` (S3 part only in this task), AppHost `Program.cs` (Ceph resource)

- [ ] **Step 1: Select and PIN a runnable single-node Ceph+RGW image (deliverable: a working tag)**

This is a genuine unknown — resolve empirically, do not assume. Evaluate candidates in order and pick the first that yields a reachable RGW S3 endpoint:
1. `quay.io/ceph/demo` (all-in-one demo, RGW included)
2. `quay.io/ceph/daemon` in `demo` mode
3. latest `quay.io/ceph/ceph:v<pinned>` with RGW started via the container's tooling

Record the exact image+tag chosen in `docs/superpowers/notes/2026-07-01-ceph-sts-verdicts.md` under "Pinned Ceph image". STS support varies by release — this pin is a design decision.

- [ ] **Step 2: Add the Ceph container to AppHost**

```csharp
var ceph = builder.AddContainer("ceph", "<pinned-image>")
    .WithEnvironment(/* demo-mode env from the chosen image's docs */)
    .WithHttpEndpoint(targetPort: 8080, name: "s3")     // RGW S3 port per image
    .WithBindMount("./ceph", "/ceph-init", isReadOnly: true);
```
> The env vars (e.g. RGW user/key, demo flags) are image-specific — take them verbatim from the chosen image's documentation. Do not invent them.

- [ ] **Step 3: Verify raw S3 works with a static key (aws-cli, no app)**

Run against the RGW endpoint from the dashboard:
```bash
aws --endpoint-url "$RGW" --no-verify-ssl s3 mb s3://demo
aws --endpoint-url "$RGW" s3 cp /etc/hostname s3://demo/probe.txt
aws --endpoint-url "$RGW" s3 ls s3://demo/
```
Expected: bucket created, object uploaded and listed. This proves RGW S3 is reachable before any STS/OIDC work.

- [ ] **Step 4: Commit**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: ceph rgw container with working s3"
```

---

## Task 3: THE SPIKE — raw `AssumeRoleWithWebIdentity` round-trip (no C#), record §7 verdicts

This is the task the whole sub-project exists for. It must succeed via shell/CLI so that any failure is unambiguously Ceph/Keycloak config, not application code.

**Files:**
- Create: `src/AppHost/ceph/init-sts.sh`, `trust-policy.json`, `permission-policy.json`, `docs/superpowers/notes/2026-07-01-ceph-sts-verdicts.md`

- [ ] **Step 1: Create RGW admin + STS users with caps**

Following https://docs.ceph.com/en/latest/radosgw/STS/ , exec into the Ceph container and create a user with `oidc-provider=*` and `roles=*` caps (exact commands per that page, against the pinned version). Verify: `radosgw-admin caps` output shows the caps.

- [ ] **Step 2: Register Keycloak as an OIDC provider in RGW**

Following https://docs.ceph.com/en/latest/radosgw/keycloak/ , create the OIDC provider entity pointing at the realm's issuer, with `client_id = webapp` (the ID token's `aud` from Task 1 Step 6). **Verdict item 4 (JWKS/thumbprint trust):** record exactly how RGW is pointed at Keycloak's signing keys over the Aspire network (issuer URL reachability, thumbprint if required, http-vs-https). If Keycloak's internal URL differs from the token `iss`, resolve it here and record how.

- [ ] **Step 3: Create the IAM role (trust + prefix-scoped permission policy)**

Author `trust-policy.json` (`Principal.Federated` → the provider ARN, `Action: sts:AssumeRoleWithWebIdentity`, `Condition` matching `aud`/`azp = webapp`) and `permission-policy.json` (`Allow` `s3:*` on `arn:aws:s3:::demo/alice/*` + the bucket-level list scoped by prefix). Create the role and attach the permission policy per the STS doc page. Verify: `radosgw-admin role get`.

- [ ] **Step 4: RAW round-trip — token → STS → temp creds**

```bash
# 1) get ID token for alice (from Task 1 Step 6 method)
ID_TOKEN=$(curl -s "$KC/.../token" -d grant_type=password -d client_id=webapp -d username=alice -d password=... | jq -r .id_token)
# 2) assume role with the ID token
aws --endpoint-url "$RGW" sts assume-role-with-web-identity \
  --role-arn "arn:aws:iam:::role/DemoReader" \
  --role-session-name alice \
  --web-identity-token "$ID_TOKEN"
```
Expected: temporary `AccessKeyId`/`SecretAccessKey`/`SessionToken`.
**Verdict item 1 (ID token accepted):** record PASS/FAIL. If FAIL because RGW wants the access token, retry with `access_token`; if that works, record the fallback (access token + `webapp` in access-token `aud` via realm mapper) and update the token model note.

- [ ] **Step 5: PROVE prefix enforcement with the temp creds**

Export the temp creds and confirm the PEP enforces the prefix:
```bash
aws --endpoint-url "$RGW" s3 cp /etc/hostname s3://demo/alice/ok.txt   # expect SUCCESS
aws --endpoint-url "$RGW" s3 cp /etc/hostname s3://demo/bob/nope.txt    # expect AccessDenied
aws --endpoint-url "$RGW" s3 cp s3://demo/alice/ok.txt -                # expect SUCCESS
```
Expected: writes/reads under `alice/` succeed; `bob/` is denied.

- [ ] **Step 6: PROVE inline session policy narrows further (the load-bearing verdict)**

Re-run Step 4 adding `--policy` (an inline session policy allowing only `arn:aws:s3:::demo/alice/reports/*`), then confirm `alice/reports/x` succeeds but `alice/other/x` is denied even though the role permits it.
**Verdict item 2 (inline session policy honored):** record PASS/FAIL. If FAIL, record the fallback: pre-created per-scope roles + trust-policy claim conditions (flag: this changes sub-project 2's policy model and sub-project 3's UI).

- [ ] **Step 7: Probe session tags (informational verdict for sub-project 2)**

Attempt a session/principal-tag-conditioned policy driven by a token claim (per the STS doc page's tagging section). **Verdict item 3 (session tags):** record supported/not — informational; do not block on it.

- [ ] **Step 8: Make the setup reproducible in `init-sts.sh` and wire it as container init**

Fold the exact working commands from Steps 1–3 into an **idempotent** `init-sts.sh`, run it from the Ceph container start (or as a dependent init step in AppHost). Verify: tearing down volumes and `dotnet run --project src/AppHost` from scratch reproduces a working role without manual steps.

- [ ] **Step 9: Write the verdicts note and commit**

Fill `docs/superpowers/notes/2026-07-01-ceph-sts-verdicts.md` with the four verdicts + the exact winning config (image, provider, role, which token, session-policy support). Commit.
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: prove AssumeRoleWithWebIdentity round-trip with prefix + session policy"
```

**⛔ Gate:** Do not start Task 4 until Steps 4–6 are PASS (or their fallbacks are recorded and applied). The API broker is built on whatever config wins here.

---

## Task 4: .NET API — PDP + STS broker (TDD for pure logic, integration-verified I/O)

**Files:**
- Create: `src/Api/*`, `tests/Api.Tests/*`; Modify: AppHost `Program.cs` (AddProject api, reference keycloak/ceph/appdb)

- [ ] **Step 1: Scaffold API + test project, reference ServiceDefaults**
```bash
dotnet new web -n Api -o src/Api
dotnet add src/Api reference src/ServiceDefaults
dotnet add src/Api package FastEndpoints
dotnet add src/Api package FastEndpoints.Security
dotnet add src/Api package Scalar.AspNetCore
dotnet add src/Api package AWSSDK.S3
dotnet add src/Api package AWSSDK.SecurityToken
dotnet add src/Api package Microsoft.EntityFrameworkCore.Design
dotnet add src/Api package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet new xunit -n Api.Tests -o tests/Api.Tests
dotnet add tests/Api.Tests reference src/Api
dotnet sln add src/Api tests/Api.Tests
```

- [ ] **Step 2: RoleResolver — write the failing test (RBAC, pure)**
```csharp
public class RoleResolverTests {
    [Fact] public void Reader_role_maps_to_reader_arn() {
        var arn = RoleResolver.ResolveRoleArn(new[] { "reader" });
        Assert.Equal("arn:aws:iam:::role/DemoReader", arn);
    }
    [Fact] public void Writer_role_wins_over_reader() {
        var arn = RoleResolver.ResolveRoleArn(new[] { "reader", "writer" });
        Assert.Equal("arn:aws:iam:::role/DemoWriter", arn);
    }
    [Fact] public void No_known_role_throws() =>
        Assert.Throws<UnauthorizedAccessException>(() => RoleResolver.ResolveRoleArn(new[] { "guest" }));
}
```

- [ ] **Step 3: Run → FAIL** — `dotnet test tests/Api.Tests` → RoleResolver not defined.

- [ ] **Step 4: Implement `RoleResolver.ResolveRoleArn`** (pure switch on roles; writer beats reader). Use the exact role ARNs proven in Task 3.

- [ ] **Step 5: Run → PASS.** `dotnet test tests/Api.Tests`.

- [ ] **Step 6: SessionPolicy — failing test (ABAC, pure)**
```csharp
[Fact] public void Builds_prefix_scoped_policy() {
    var json = SessionPolicy.ForPrefix("demo", "alice/");
    using var doc = JsonDocument.Parse(json);
    var res = doc.RootElement.GetProperty("Statement")[0].GetProperty("Resource");
    Assert.Contains("arn:aws:s3:::demo/alice/*", res.EnumerateArray().Select(e => e.GetString()));
}
```

- [ ] **Step 7: Run → FAIL, implement `SessionPolicy.ForPrefix` (emit the exact session-policy JSON proven in Task 3 Step 6), Run → PASS.**

- [ ] **Step 8: CallerClaims — failing test then implement** (pure: pull `sub`, name, realm roles from `ClaimsPrincipal`; matches the realm-role claim path in the Task 1 token). Run → PASS.

- [ ] **Step 9: Wire Program.cs — Serilog, JWT bearer (validate `aud=api` against Keycloak), FastEndpoints, Scalar, EF Core**
```csharp
builder.AddServiceDefaults();
builder.Services.AddAuthenticationJwtBearer(...) // authority = keycloak realm, audience = "api"
builder.Services.AddAuthorization().AddFastEndpoints();
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(builder.Configuration.GetConnectionString("appdb")));
var app = builder.Build();
app.UseAuthentication().UseAuthorization().UseFastEndpoints();
app.MapScalarApiReference();   // /scalar
app.MapDefaultEndpoints();
app.Run();
```
> Confirm the exact FastEndpoints JWT setup from its current docs; `authority`/`audience` come from Task 1.

- [ ] **Step 10: `WhoAmIEndpoint` (`GET /whoami`, requires auth)** — returns `CallerClaims` from the validated principal. No test bolted on (thin controller over tested pure logic); verified by integration in Step 14.

- [ ] **Step 11: `StsBroker` — AssumeRoleWithWebIdentity against Ceph**
```csharp
var sts = new AmazonSecurityTokenServiceClient(
    new AnonymousAWSCredentials(),
    new AmazonSecurityTokenServiceConfig { ServiceURL = cephEndpoint, AuthenticationRegion = "us-east-1" });
var resp = await sts.AssumeRoleWithWebIdentityAsync(new AssumeRoleWithWebIdentityRequest {
    RoleArn = roleArn, RoleSessionName = sub, WebIdentityToken = idToken,
    Policy = sessionPolicyJson, DurationSeconds = 900 });
```
> Use the token type (id vs access) that WON in Task 3 Step 4. `ServiceURL` = the Ceph endpoint injected by Aspire.

- [ ] **Step 12: `S3Gateway` — PUT/GET with the temp creds** (`AmazonS3Client` with `SessionAWSCredentials`, `ForcePathStyle = true`, `ServiceURL = cephEndpoint`).

- [ ] **Step 13: `StorageRoundtripEndpoint` (`POST /storage/roundtrip`)** — reads `X-Id-Token` header (or the winning token), resolves role (`RoleResolver`) + session policy (`SessionPolicy`) from `CallerClaims`, calls `StsBroker`, PUTs a small object under the caller's prefix, GETs it back, returns the result.

- [ ] **Step 14: Wire AppHost + integration-verify against running Ceph**

AppHost: `builder.AddProject<Projects.Api>("api").WithReference(keycloak).WithReference(appdb).WithReference(ceph.GetEndpoint("s3"))`.
Run `dotnet run --project src/AppHost`, get a token (Task 1 method), then:
```bash
curl -s "$API/whoami" -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
curl -s -X POST "$API/storage/roundtrip" -H "Authorization: Bearer $ACCESS_TOKEN" -H "X-Id-Token: $ID_TOKEN" | jq .
```
Expected: `/whoami` returns alice's claims; `/storage/roundtrip` reports a successful PUT+GET under `alice/`. Confirm Scalar renders at `/scalar`.

- [ ] **Step 15: Postgres wiring — one migration**
```bash
dotnet tool install --global dotnet-ef
dotnet ef migrations add Initial --project src/Api
```
Add a trivial `AuditEntry` entity + `DbSet`; apply migrations on startup (`db.Database.Migrate()`), write one row per roundtrip. Verify: the row exists in `appdb` after a roundtrip. This proves DB wiring; no domain modeling.

- [ ] **Step 16: Commit**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: api pdp + sts broker with prefix-scoped roundtrip"
```

---

## Task 5: Next.js SPA — login + roundtrip

**Files:**
- Create: `src/Web/*`; Modify: AppHost `Program.cs` (AddNpmApp/AddNodeApp for web)

- [ ] **Step 1: Scaffold the SPA and add OIDC**
```bash
npx create-next-app@latest src/Web --ts --app --eslint
cd src/Web && npm i oidc-client-ts react-oidc-context
```

- [ ] **Step 2: Configure `src/auth/oidc.ts`** — `UserManager` with `authority = <keycloak realm>`, `client_id = webapp`, `redirect_uri = http://localhost:3000/callback`, `response_type = code`, PKCE default, `scope = "openid profile"`. Add the `api` audience via a `resource`/scope if the realm requires it (per Task 1 mapper).

- [ ] **Step 3: Login + callback pages** — `AuthProvider` (react-oidc-context), a Sign-in button, `/callback` completing the code exchange. Verify: clicking Sign in redirects to Keycloak, logging in as alice returns to the app authenticated; `access_token` + `id_token` present in the `User`.

- [ ] **Step 4: Home page — whoami + roundtrip button** — calls `GET /whoami` with `Authorization: Bearer <access_token>` and renders claims; a button POSTs `/storage/roundtrip` with `Authorization: Bearer <access_token>` and `X-Id-Token: <id_token>`, rendering the result.

- [ ] **Step 5: Orchestrate the SPA in AppHost**
```csharp
builder.AddNpmApp("web", "../Web", "dev")
    .WithReference(api).WithHttpEndpoint(env: "PORT", port: 3000)
    .WithEnvironment("NEXT_PUBLIC_API_URL", api.GetEndpoint("http"))
    .WithEnvironment("NEXT_PUBLIC_KEYCLOAK", keycloak.GetEndpoint("http"));
```
> Confirm the exact `AddNpmApp` signature from current Aspire docs.

- [ ] **Step 6: Full end-to-end verify** — `dotnet run --project src/AppHost`, open the SPA, sign in as alice, click roundtrip → success under `alice/`. Sign in as bob → roundtrip lands under `bob/`; confirm alice cannot reach bob's prefix (already proven at the STS layer in Task 3).

- [ ] **Step 7: Commit**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: next.js spa login and prefix-scoped roundtrip"
```

---

## Task 6: Observability — Serilog, end-to-end traces, Scalar

**Files:**
- Modify: `src/ServiceDefaults/Extensions.cs`, `src/Api/Program.cs`, `src/Web` fetch calls

- [ ] **Step 1: Serilog structured logging in the API** — replace default logging with Serilog (console + OTLP sink via ServiceDefaults). Verify: logs appear structured in the Aspire dashboard.

- [ ] **Step 2: OpenTelemetry spans across the money-path** — ensure ServiceDefaults' OTel wires ASP.NET Core + HttpClient + AWS SDK instrumentation so a single trace spans **SPA fetch → API → STS → S3**. Add the AWSSDK OTel instrumentation package if needed. Propagate `traceparent` from the SPA fetch calls.

- [ ] **Step 3: Verify one trace end-to-end** — run a roundtrip from the SPA, open the Aspire dashboard Traces view, confirm a single trace contains spans for the SPA request, `/storage/roundtrip`, the `AssumeRoleWithWebIdentity` call, and the S3 PUT/GET.

- [ ] **Step 4: Confirm Scalar** renders the full OpenAPI (both endpoints, auth scheme) at `/scalar`.

- [ ] **Step 5: Commit**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "feat: serilog + end-to-end otel tracing + scalar"
```

---

## Task 7: Definition-of-Done verification

**Files:** Modify: `docs/superpowers/notes/2026-07-01-ceph-sts-verdicts.md` (final)

- [ ] **Step 1: Walk the DoD (spec §6) and check each item against the running system**, recording evidence:
  1. OIDC login works end-to-end; browser holds both tokens.
  2. `GET /whoami` returns validated claims from the access token (`aud=api`).
  3. Roundtrip does `AssumeRoleWithWebIdentity` → temp creds → PUT+GET under the allowed prefix, **with an inline session policy narrowing to that prefix** (or the recorded fallback).
  4. One trace spans SPA → API → STS/S3 in the dashboard; Scalar renders.
  5. Postgres wiring proven by the applied migration + a written row.

- [ ] **Step 2: Confirm the four §7 verdicts are recorded** (ID-token accepted, inline session policy honored, session tags, JWKS/thumbprint trust) — these gate sub-project 2. Flag any fallback that changes the sub-project-2 policy model.

- [ ] **Step 3: Final commit + open the branch for integration**
```bash
git -C .claude/worktrees/subproject-1-walking-skeleton add -A
git -C .claude/worktrees/subproject-1-walking-skeleton commit -m "docs: record walking-skeleton DoD evidence and STS verdicts"
```

---

## Self-Review

**Spec coverage (§ by §):**
- §3 authz model (PDP/PEP, backend brokers STS): Tasks 3–4. ✅
- §4 token model (access `aud=api` to API, ID `aud=webapp` to STS): Task 1 Step 6 (verify), Task 4 Steps 9/11, Task 5. ✅
- §5 components: Keycloak+Postgres (T1), Ceph (T2), API (T4), SPA (T5); realm import (T1); Ceph OIDC provider + role scripted init (T3 Step 8). ✅
- §5 endpoints `/whoami`, `/storage/roundtrip`: T4 Steps 10, 13. ✅
- §5 observability (Serilog, OTel→dashboard, Scalar): T6. ✅
- §6 DoD: T7 (+ inline-session-policy proof at T3 Step 6). ✅
- §7 verdicts (all four, recorded, gating #2): T3 Steps 2/4/6/7, T7 Step 2. ✅
- §8 risks (Ceph-in-Aspire, version pin): T2 Step 1 (pin), T3 (spike). ✅
- Postgres one-migration, no domain: T4 Step 15. ✅  No CQRS / domain / Fluent UI: correctly absent (sub-projects 2–3). ✅

**Placeholder scan:** No fabricated Ceph flags — every genuinely-unknown command is a doc-referenced discovery step with an empirical verification (T2 S1, T3 S1–3). No "TODO/TBD" requirements. Realm JSON and Ceph env are explicitly "export/copy from source, do not hand-fabricate."

**Type consistency:** `RoleResolver.ResolveRoleArn(roles)`, `SessionPolicy.ForPrefix(bucket, prefix)`, `CallerClaims`, `StsBroker`, `S3Gateway` names are consistent between definition (T4) and use (T4 S13). Role ARNs are defined once in T3 and reused in T4.

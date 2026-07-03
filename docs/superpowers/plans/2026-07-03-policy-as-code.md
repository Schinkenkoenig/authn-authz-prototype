# Policy-as-code (Cedar + OPA/Rego) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add policy-as-code as the sixth paradigm, represented by two external engines — Cedar
(`cedar-agent`) and OPA/Rego — that evaluate the **same** four-rule scenario, so they can be compared
side by side.

**Architecture:** Both engines follow the ReBAC seam: an external decision service, provisioned at
startup (fail-fast), queried by an awaited HTTP call. A new `IExternalEvaluator` interface replaces
the single `IRebacClient` parameter on `DecideAsync` so three external engines dispatch by paradigm
name. All decision data (classification from prefix, owner-department from the 2nd path segment,
`frozen` flag, caller level/department/roles, break-glass) rides in the per-request payload — proven
in the spec's engine spike, so neither engine pre-registers dynamic storage keys. A single pure
`PolicyInput` is computed once and serialized two ways.

**Tech Stack:** .NET 10, FastEndpoints, `System.Net.Http.HttpClient` + `System.Text.Json` (no new
NuGet packages), `permitio/cedar-agent`, `openpolicyagent/opa`, Keycloak realm, Python verify script.

**Reference:** design spec `docs/superpowers/specs/2026-07-03-policy-as-code-design.md` (contains the
spike-verified Cedar + Rego policy text). Dev setup: `source ~/.bash_profile` before every `dotnet`;
fast-verify pattern in `docs/superpowers/notes/2026-07-03-rebac-openfga-run.md`.

---

## Task 1: Seam refactor — `IExternalEvaluator`, migrate ReBAC, dispatch by dict

Replace the single-`IRebacClient` `DecideAsync` parameter with a paradigm→evaluator dictionary. No
behavior change: all 47 existing tests must still pass at the end.

**Files:**
- Create: `src/Api/Authz/IExternalEvaluator.cs`
- Create: `src/Api/Authz/RebacExternalEvaluator.cs`
- Modify: `src/Api/Authz/AuthzDispatcher.cs` (Paradigms list, DecideAsync signature)
- Modify: `src/Api/Authz/OpenFgaRebacClient.cs` (drop `UnconfiguredRebacClient`)
- Modify: `src/Api/Program.cs` (register evaluators + dict)
- Modify: `src/Api/Endpoints/StorageReadEndpoint.cs`, `StorageWriteEndpoint.cs`, `StorageListEndpoint.cs`
- Modify: `tests/Api.Tests/RebacDispatchTests.cs`

- [ ] **Step 1: Add the interface and a generic unconfigured stand-in**

Create `src/Api/Authz/IExternalEvaluator.cs`:

```csharp
namespace Api.Authz;

// An authorization paradigm whose decision requires awaited I/O to an external engine (OpenFGA,
// cedar-agent, OPA). Registered once per engine; DecideAsync dispatches by Paradigm. The four
// in-process paradigms stay pure/sync in AuthzDispatcher.Decide and do NOT implement this.
public interface IExternalEvaluator
{
    string Paradigm { get; }
    Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct);
}

// Stand-in for an external engine whose URL is unset: selecting that paradigm denies rather than
// throwing, so the other paradigms keep working without the engine.
public sealed class UnconfiguredEvaluator(string paradigm) : IExternalEvaluator
{
    public string Paradigm => paradigm;
    public Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct) =>
        Task.FromResult(new AuthzDecision(false, $"{paradigm} engine not configured", paradigm));
}
```

- [ ] **Step 2: Add the ReBAC wrapper**

Create `src/Api/Authz/RebacExternalEvaluator.cs`:

```csharp
using Api.Auth;

namespace Api.Authz;

// Adapts the existing ReBAC pieces (pure RebacEvaluator mapping + IRebacClient OpenFGA Check) to
// the IExternalEvaluator seam. Behavior is unchanged from SP3.
public sealed class RebacExternalEvaluator(IRebacClient client) : IExternalEvaluator
{
    public string Paradigm => "rebac";
    public Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct) =>
        RebacEvaluator.EvaluateAsync(req.Caller, req.Action, req.Resource, client, ct);
}
```

- [ ] **Step 3: Rewrite the dispatch in `AuthzDispatcher.cs`**

In `src/Api/Authz/AuthzDispatcher.cs`, change the Paradigms list:

```csharp
    public static readonly IReadOnlyList<string> Paradigms = ["rbac", "abac", "claims", "acl", "rebac", "cedar", "opa"];
```

Replace the entire `DecideAsync` method (and its comment) with:

```csharp
    // The async variant of the seam. External engines (rebac/cedar/opa) each decide via an awaited
    // network call, so they can't be pure (claims,action,resource,config) functions. They are
    // resolved from the injected dictionary by paradigm; everything else delegates to the pure
    // sync Decide. A selected external paradigm absent from the map denies (see UnconfiguredEvaluator).
    public static Task<AuthzDecision> DecideAsync(
        string paradigm, AuthzRequest req, AuthzConfig cfg,
        IReadOnlyDictionary<string, IExternalEvaluator> external, CancellationToken ct)
        => external.TryGetValue(paradigm, out var ev)
            ? ev.EvaluateAsync(req, ct)
            : Task.FromResult(Decide(paradigm, req, cfg));
```

- [ ] **Step 4: Drop `UnconfiguredRebacClient`**

In `src/Api/Authz/OpenFgaRebacClient.cs`, delete the `UnconfiguredRebacClient` class (the last
class in the file) and its comment. Keep `OpenFgaRebacClient`. It is replaced by the generic
`UnconfiguredEvaluator("rebac")`.

- [ ] **Step 5: Update the three endpoints**

In each of `StorageReadEndpoint.cs`, `StorageWriteEndpoint.cs`, `StorageListEndpoint.cs`:

Change the constructor parameter `IRebacClient rebac` → `IReadOnlyDictionary<string, IExternalEvaluator> external`.

Change the `DecideAsync(...)` call's last-but-one argument from `rebac` to `external`. Example
(StorageReadEndpoint.cs):

```csharp
public sealed class StorageReadEndpoint(AuthzConfigStore store, S3Gateway s3,
    IReadOnlyDictionary<string, IExternalEvaluator> external)
    : Endpoint<ReadRequest, StorageResult>
```
```csharp
        var decision = await AuthzDispatcher.DecideAsync(paradigm,
            new AuthzRequest(caller, StorageAction.Read, req.Key), store.Current, external, ct);
```

`StorageWriteEndpoint` keeps its `AppDbContext db` parameter — only swap the `rebac` parameter and
the `DecideAsync` argument. Do the same for `StorageListEndpoint` (`StorageAction.List`, `req.Prefix`).

- [ ] **Step 6: Rewire `Program.cs`**

In `src/Api/Program.cs`, replace the ReBAC registration block:

```csharp
var openfgaUrl = builder.Configuration["Openfga:ApiUrl"];
Api.Authz.IRebacClient rebac = string.IsNullOrEmpty(openfgaUrl)
    ? new Api.Authz.UnconfiguredRebacClient()
    : new Api.Authz.OpenFgaRebacClient(
        await Api.Authz.RebacProvisioner.ProvisionAsync(openfgaUrl, Api.Authz.RebacModel.Json, CancellationToken.None));
builder.Services.AddSingleton(rebac);
```

with:

```csharp
// External authorization engines: each provisioned at startup like the DB migrate→seed (fail-fast
// if configured but unreachable). When a URL is unset, a deny stand-in keeps the other paradigms
// working. All are registered as IExternalEvaluator and dispatched by paradigm name.
var openfgaUrl = builder.Configuration["Openfga:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(openfgaUrl)
    ? new Api.Authz.UnconfiguredEvaluator("rebac")
    : new Api.Authz.RebacExternalEvaluator(new Api.Authz.OpenFgaRebacClient(
        await Api.Authz.RebacProvisioner.ProvisionAsync(openfgaUrl, Api.Authz.RebacModel.Json, CancellationToken.None))));

builder.Services.AddSingleton<IReadOnlyDictionary<string, Api.Authz.IExternalEvaluator>>(sp =>
    sp.GetServices<Api.Authz.IExternalEvaluator>().ToDictionary(e => e.Paradigm));
```

(Cedar and OPA registrations are added in Tasks 5 and 6, above the dictionary registration.)

- [ ] **Step 7: Rewrite `RebacDispatchTests.cs` for the new signature**

Replace the whole file `tests/Api.Tests/RebacDispatchTests.cs` with:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

// DecideAsync now dispatches external paradigms from a paradigm→evaluator dictionary. These tests
// cover the routing/wrapping; a stub stands in for OpenFGA (the real graph Check is an e2e concern).
public class RebacDispatchTests
{
    sealed class StubRebac(bool allowed) : IRebacClient
    {
        public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
            Task.FromResult(allowed);
    }

    static IReadOnlyDictionary<string, IExternalEvaluator> Engines(IRebacClient rebac) =>
        new Dictionary<string, IExternalEvaluator> { ["rebac"] = new RebacExternalEvaluator(rebac) };

    static readonly IReadOnlyDictionary<string, IExternalEvaluator> Unconfigured =
        new Dictionary<string, IExternalEvaluator> { ["rebac"] = new UnconfiguredEvaluator("rebac") };

    static readonly AuthzConfig Config = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>> { ["bob"] = ["editor"] },
            [new RolePermission("editor", "projects/", [StorageAction.Write])]),
        new AbacConfig([]),
        new AclConfig([]));

    static AuthzRequest Req(StorageAction action, string resource) =>
        new(new CallerClaims("sub", "bob", [], new Dictionary<string, string>(), []), action, resource);

    [Fact]
    public void Rebac_cedar_opa_are_registered_paradigms()
    {
        Assert.Contains("rebac", AuthzDispatcher.Paradigms);
        Assert.Contains("cedar", AuthzDispatcher.Paradigms);
        Assert.Contains("opa", AuthzDispatcher.Paradigms);
    }

    [Fact]
    public async Task Rebac_permit_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, Engines(new StubRebac(true)), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rebac", d.Paradigm);
    }

    [Fact]
    public async Task Rebac_deny_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, Engines(new StubRebac(false)), CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Unconfigured_external_paradigm_denies_rather_than_throws()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, Unconfigured, CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Sync_paradigm_routes_to_the_pure_evaluator_ignoring_the_map()
    {
        var d = await AuthzDispatcher.DecideAsync("rbac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, Unconfigured, CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rbac", d.Paradigm);
    }
}
```

- [ ] **Step 8: Build and run all tests**

Run: `source ~/.bash_profile && dotnet test`
Expected: `Passed! - Failed: 0, Passed: 47` (count unchanged; behavior identical).

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -m "refactor(authz): IExternalEvaluator seam for N external engines"
```

---

## Task 2: Request context (break-glass plumbing)

Add an optional context to the request so rule 4 can read a break-glass flag. Additive; sync
paradigms ignore it.

**Files:**
- Modify: `src/Api/Authz/AuthzModel.cs`
- Modify: `src/Api/Endpoints/StorageReadEndpoint.cs`, `StorageWriteEndpoint.cs`, `StorageListEndpoint.cs`
- Test: `tests/Api.Tests/AuthzContextTests.cs`

- [ ] **Step 1: Write the failing test**

Create `tests/Api.Tests/AuthzContextTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AuthzContextTests
{
    [Fact]
    public void Request_context_defaults_to_null()
    {
        var caller = new CallerClaims("s", "n", [], new Dictionary<string, string>(), []);
        var req = new AuthzRequest(caller, StorageAction.Read, "k");
        Assert.Null(req.Context);
    }

    [Fact]
    public void Request_carries_break_glass_when_supplied()
    {
        var caller = new CallerClaims("s", "n", [], new Dictionary<string, string>(), []);
        var req = new AuthzRequest(caller, StorageAction.Read, "k", new AuthzContext(BreakGlass: true));
        Assert.True(req.Context!.BreakGlass);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source ~/.bash_profile && dotnet test --filter AuthzContextTests`
Expected: FAIL — `AuthzContext` / `Context` do not exist (compile error).

- [ ] **Step 3: Add the type**

In `src/Api/Authz/AuthzModel.cs`, add the record and extend `AuthzRequest`:

```csharp
// Optional per-request context. Only the policy-as-code paradigms read it (break-glass); the DB-row
// paradigms ignore it.
public sealed record AuthzContext(bool BreakGlass);

public sealed record AuthzRequest(CallerClaims Caller, StorageAction Action, string Resource,
    AuthzContext? Context = null);
```

(Replace the existing `AuthzRequest` record line.)

- [ ] **Step 4: Populate context in the three endpoints**

In each endpoint's `HandleAsync`, after the `paradigm` line, read the header and pass the context.
Example (StorageReadEndpoint.cs):

```csharp
        var ctx = new AuthzContext(
            HttpContext.Request.Headers["X-Break-Glass"].ToString().Equals("true", StringComparison.OrdinalIgnoreCase));
        var decision = await AuthzDispatcher.DecideAsync(paradigm,
            new AuthzRequest(caller, StorageAction.Read, req.Key, ctx), store.Current, external, ct);
```

Do the same in `StorageWriteEndpoint` (`StorageAction.Write, req.Key`) and `StorageListEndpoint`
(`StorageAction.List, req.Prefix`).

- [ ] **Step 5: Run tests**

Run: `source ~/.bash_profile && dotnet test`
Expected: `Passed! - Failed: 0, Passed: 49`.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(authz): optional request context for break-glass"
```

---

## Task 3: `PolicyInput` — pure derivation of decision data

The single source of the values both engines evaluate. Pure and fully unit-tested.

**Files:**
- Create: `src/Api/Authz/PolicyInput.cs`
- Test: `tests/Api.Tests/PolicyInputTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/Api.Tests/PolicyInputTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class PolicyInputTests
{
    static CallerClaims Caller(string dept, string level, params string[] roles) =>
        new("sub", "u", roles, new Dictionary<string, string> { ["department"] = dept, ["level"] = level }, []);

    static PolicyInput In(StorageAction a, string key, CallerClaims c, bool breakGlass = false) =>
        PolicyInput.From(new AuthzRequest(c, a, key, new AuthzContext(breakGlass)));

    [Theory]
    [InlineData("public/x", 1)]
    [InlineData("internal/finance/x", 2)]
    [InlineData("classified/x", 3)]
    [InlineData("unlabeled/x", 1)]      // unknown prefix defaults to public
    public void Classification_comes_from_the_top_prefix(string key, int expected) =>
        Assert.Equal(expected, In(StorageAction.Read, key, Caller("finance", "2")).Classification);

    [Theory]
    [InlineData("internal/finance/report.txt", "finance")]
    [InlineData("classified/x", "x")]   // 2nd segment even if it is a file
    [InlineData("solo", "")]            // no 2nd segment
    public void Owner_department_is_the_second_path_segment(string key, string expected) =>
        Assert.Equal(expected, In(StorageAction.Write, key, Caller("finance", "2")).OwnerDepartment);

    [Theory]
    [InlineData("internal/frozen/x", true)]
    [InlineData("internal/finance/frozen/y", true)]
    [InlineData("frozen/x", true)]
    [InlineData("internal/finance/notfrozen.txt", false)]
    public void Frozen_is_a_frozen_path_segment(string key, bool expected) =>
        Assert.Equal(expected, In(StorageAction.Write, key, Caller("finance", "2")).Frozen);

    [Fact]
    public void Caller_fields_and_context_map_across()
    {
        var p = In(StorageAction.Read, "classified/x", Caller("hr", "1", "incident_responder"), breakGlass: true);
        Assert.Equal(1, p.Level);
        Assert.Equal("hr", p.CallerDepartment);
        Assert.Contains("incident_responder", p.Roles);
        Assert.True(p.BreakGlass);
        Assert.Equal("read", p.Action);
    }

    [Fact]
    public void Missing_level_is_zero_and_missing_department_is_empty()
    {
        var c = new CallerClaims("s", "u", [], new Dictionary<string, string>(), []);
        var p = PolicyInput.From(new AuthzRequest(c, StorageAction.Write, "public/x"));
        Assert.Equal(0, p.Level);
        Assert.Equal("", p.CallerDepartment);
        Assert.False(p.BreakGlass);   // null context
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source ~/.bash_profile && dotnet test --filter PolicyInputTests`
Expected: FAIL — `PolicyInput` does not exist.

- [ ] **Step 3: Implement `PolicyInput`**

Create `src/Api/Authz/PolicyInput.cs`:

```csharp
using Api.Auth;

namespace Api.Authz;

// The decision data both policy-as-code engines evaluate, derived once from the request. Classification
// is inferred from the key's top folder; owner-department from the second path segment; a `frozen`
// path segment marks a legal hold. Caller level/department come from token attributes; roles and the
// break-glass flag pass through. Serialized into OPA `input` and Cedar `context`.
public sealed record PolicyInput(
    string Action,
    int Classification,
    string OwnerDepartment,
    bool Frozen,
    int Level,
    string CallerDepartment,
    IReadOnlyList<string> Roles,
    bool BreakGlass)
{
    static readonly Dictionary<string, int> ClassByPrefix =
        new() { ["public"] = 1, ["internal"] = 2, ["classified"] = 3 };

    public static PolicyInput From(AuthzRequest req)
    {
        var segments = req.Resource.Split('/');
        var top = segments.Length > 0 ? segments[0] : "";
        var classification = ClassByPrefix.TryGetValue(top, out var c) ? c : 1;   // unknown → public
        var owner = segments.Length > 1 ? segments[1] : "";
        var frozen = ("/" + req.Resource).Contains("/frozen/");

        var attrs = req.Caller.Attributes;
        var level = attrs.TryGetValue("level", out var lv) && int.TryParse(lv, out var l) ? l : 0;
        var dept = attrs.TryGetValue("department", out var d) ? d : "";

        var action = req.Action switch
        {
            StorageAction.Read => "read",
            StorageAction.Write => "write",
            _ => "list",
        };

        return new PolicyInput(action, classification, owner, frozen, level, dept,
            req.Caller.Roles, req.Context?.BreakGlass ?? false);
    }
}
```

- [ ] **Step 4: Run tests**

Run: `source ~/.bash_profile && dotnet test`
Expected: `Passed! - Failed: 0, Passed: 62` (13 new).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(authz): PolicyInput — pure decision-data derivation for policy-as-code"
```

---

## Task 4: Policy assets (Rego + Cedar) + loader

Commit the spike-verified policy files and a loader that reads them from the output directory.

**Files:**
- Create: `src/Api/Authz/policy/authz.rego`
- Create: `src/Api/Authz/policy/cedar-policies.json`
- Create: `src/Api/Authz/policy/cedar-entities.json`
- Create: `src/Api/Authz/PolicyAssets.cs`
- Modify: `src/Api/Api.csproj` (copy assets to output)

- [ ] **Step 1: Rego policy**

Create `src/Api/Authz/policy/authz.rego` (verbatim from the spec spike — `default allow := false` is
required or a deny returns `{}`):

```rego
package authz
import future.keywords.if
import future.keywords.in

default permit := false
default deny := false
default allow := false

permit if {
	input.action == "read"
	input.resource.classification <= input.caller.level
}
permit if {
	input.action == "write"
	input.caller.department == input.resource.owner_department
	input.resource.classification <= input.caller.level
}
permit if {
	input.action == "read"
	"incident_responder" in input.caller.roles
	input.context.break_glass
}
deny if {
	input.action == "write"
	input.resource.frozen
}
allow if {
	permit
	not deny
}
decision := {"permit": allow}
```

- [ ] **Step 2: Cedar policies**

Create `src/Api/Authz/policy/cedar-policies.json` (spike-verified content-in-context form):

```json
[
  {"id":"r1-read-clearance","content":"permit(principal, action == Action::\"read\", resource) when { context.classification <= context.level };"},
  {"id":"r2-write-dept","content":"permit(principal, action == Action::\"write\", resource) when { context.caller_department == context.owner_department && context.classification <= context.level };"},
  {"id":"r3-forbid-frozen","content":"forbid(principal, action == Action::\"write\", resource) when { context.frozen };"},
  {"id":"r4-break-glass","content":"permit(principal, action == Action::\"read\", resource) when { context.roles.contains(\"incident_responder\") && context.break_glass };"}
]
```

- [ ] **Step 3: Cedar entities (the finite Action set)**

Create `src/Api/Authz/policy/cedar-entities.json`:

```json
[
  {"uid":{"type":"Action","id":"read"},"attrs":{},"parents":[]},
  {"uid":{"type":"Action","id":"write"},"attrs":{},"parents":[]}
]
```

- [ ] **Step 4: Loader**

Create `src/Api/Authz/PolicyAssets.cs`:

```csharp
namespace Api.Authz;

// Policy artifacts copied next to the assembly at build (see Api.csproj). The Rego module and the
// Cedar policy/entity JSON are the source of truth, pushed to the engines at startup and surfaced
// by /authz/{opa,cedar}/config.
public static class PolicyAssets
{
    static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "Authz", "policy");

    public static string Rego => File.ReadAllText(Path.Combine(Dir, "authz.rego"));
    public static string CedarPolicies => File.ReadAllText(Path.Combine(Dir, "cedar-policies.json"));
    public static string CedarEntities => File.ReadAllText(Path.Combine(Dir, "cedar-entities.json"));
}
```

- [ ] **Step 5: Copy assets to output**

In `src/Api/Api.csproj`, add to the existing `<ItemGroup>` that has the ReBAC `None Update` lines:

```xml
    <None Update="Authz\policy\authz.rego" CopyToOutputDirectory="PreserveNewest" />
    <None Update="Authz\policy\cedar-policies.json" CopyToOutputDirectory="PreserveNewest" />
    <None Update="Authz\policy\cedar-entities.json" CopyToOutputDirectory="PreserveNewest" />
```

- [ ] **Step 6: Build (assets present, no test yet)**

Run: `source ~/.bash_profile && dotnet build src/Api`
Expected: `Build succeeded`. Confirm copy:
Run: `ls src/Api/bin/Debug/net10.0/Authz/policy/`
Expected: `authz.rego  cedar-entities.json  cedar-policies.json`.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(authz): spike-verified Rego + Cedar policy assets + loader"
```

---

## Task 5: OPA end-to-end

Client, provisioner, evaluator, wiring, config surface, infra, e2e.

**Files:**
- Create: `src/Api/Authz/IOpaClient.cs`, `OpaClient.cs`, `OpaProvisioner.cs`, `OpaEvaluator.cs`
- Modify: `src/Api/Program.cs`, `src/Api/Endpoints/AuthzConfigEndpoint.cs`,
  `src/Api/appsettings.Development.json`, `src/AppHost/AppHost.cs`, `scripts/dev-up.sh`,
  `scripts/verify-authz.py`
- Test: `tests/Api.Tests/OpaEvaluatorTests.cs`

- [ ] **Step 1: Client interface + HTTP client**

Create `src/Api/Authz/IOpaClient.cs`:

```csharp
namespace Api.Authz;

public interface IOpaClient
{
    // POSTs {"input": input} to the decision rule and returns decision.permit.
    Task<bool> DecideAsync(object input, CancellationToken ct);
}
```

Create `src/Api/Authz/OpaClient.cs`:

```csharp
using System.Net.Http.Json;
using System.Text.Json;

namespace Api.Authz;

// IOpaClient over the OPA REST API. The policy is loaded at startup by OpaProvisioner; each call
// POSTs the input document to the decision rule and reads decision.permit.
public sealed class OpaClient(HttpClient http) : IOpaClient
{
    public async Task<bool> DecideAsync(object input, CancellationToken ct)
    {
        var resp = await http.PostAsJsonAsync("/v1/data/authz/decision", new { input }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        return doc.RootElement.TryGetProperty("result", out var result)
            && result.TryGetProperty("permit", out var permit)
            && permit.ValueKind == JsonValueKind.True;
    }
}
```

- [ ] **Step 2: Provisioner**

Create `src/Api/Authz/OpaProvisioner.cs`:

```csharp
using System.Text;

namespace Api.Authz;

// Startup provisioning of OPA: PUT the Rego module. Fail-fast — an unreachable engine or a policy
// that OPA rejects throws and the app refuses to start. Returns a ready IOpaClient.
public static class OpaProvisioner
{
    public static async Task<IOpaClient> ProvisionAsync(string apiUrl, string rego, CancellationToken ct)
    {
        var http = new HttpClient { BaseAddress = new Uri(apiUrl) };
        var resp = await http.PutAsync("/v1/policies/authz",
            new StringContent(rego, Encoding.UTF8, "text/plain"), ct);
        resp.EnsureSuccessStatusCode();
        return new OpaClient(http);
    }
}
```

- [ ] **Step 3: Evaluator**

Create `src/Api/Authz/OpaEvaluator.cs`:

```csharp
namespace Api.Authz;

// Policy-as-code via OPA/Rego. Serializes PolicyInput into the Rego `input` document and reads the
// engine's decision. The policy logic (clearance, department, frozen-deny-override, break-glass)
// lives in authz.rego, not here.
public sealed class OpaEvaluator(IOpaClient client) : IExternalEvaluator
{
    public string Paradigm => "opa";

    public async Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct)
    {
        var p = PolicyInput.From(req);
        var input = new
        {
            action = p.Action,
            caller = new { level = p.Level, department = p.CallerDepartment, roles = p.Roles },
            resource = new { classification = p.Classification, owner_department = p.OwnerDepartment, frozen = p.Frozen },
            context = new { break_glass = p.BreakGlass },
        };
        var permit = await client.DecideAsync(input, ct);
        return new AuthzDecision(permit, $"OPA/Rego: {(permit ? "permit" : "deny")}", "opa");
    }
}
```

- [ ] **Step 4: Unit test (stub client — routing + shape)**

Create `tests/Api.Tests/OpaEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class OpaEvaluatorTests
{
    sealed class StubOpa(bool permit) : IOpaClient
    {
        public object? LastInput;
        public Task<bool> DecideAsync(object input, CancellationToken ct)
        {
            LastInput = input;
            return Task.FromResult(permit);
        }
    }

    static AuthzRequest Req() => new(
        new CallerClaims("s", "carol", ["incident_responder"],
            new Dictionary<string, string> { ["department"] = "hr", ["level"] = "1" }, []),
        StorageAction.Read, "classified/x", new AuthzContext(true));

    [Fact]
    public void Paradigm_is_opa() => Assert.Equal("opa", new OpaEvaluator(new StubOpa(true)).Paradigm);

    [Fact]
    public async Task Permit_flows_through()
    {
        var d = await new OpaEvaluator(new StubOpa(true)).EvaluateAsync(Req(), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("opa", d.Paradigm);
    }

    [Fact]
    public async Task Deny_flows_through()
    {
        var d = await new OpaEvaluator(new StubOpa(false)).EvaluateAsync(Req(), CancellationToken.None);
        Assert.False(d.Permit);
    }
}
```

Run: `source ~/.bash_profile && dotnet test --filter OpaEvaluatorTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Register in `Program.cs`**

In `src/Api/Program.cs`, add above the `IReadOnlyDictionary<...>` registration:

```csharp
var opaUrl = builder.Configuration["Opa:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(opaUrl)
    ? new Api.Authz.UnconfiguredEvaluator("opa")
    : new Api.Authz.OpaEvaluator(
        await Api.Authz.OpaProvisioner.ProvisionAsync(opaUrl, Api.Authz.PolicyAssets.Rego, CancellationToken.None)));
```

- [ ] **Step 6: Config surface**

In `src/Api/Endpoints/AuthzConfigEndpoint.cs`, add a case before the `_ => null` arm:

```csharp
            "opa" => new
            {
                engine = "opa",
                note = "config is a Rego module evaluated over a per-request input document",
                rego = PolicyAssets.Rego,
            },
```

- [ ] **Step 7: Config URLs (appsettings + AppHost)**

In `src/Api/appsettings.Development.json`, add alongside the `Openfga` entry:

```json
  "Opa": { "ApiUrl": "http://172.30.0.50:8181" },
```

In `src/AppHost/AppHost.cs`, add the constant near `openfgaUrl`:

```csharp
const string opaUrl = "http://172.30.0.50:8181";
```

and on the `api` resource add:

```csharp
    .WithEnvironment("Opa__ApiUrl", opaUrl)
```

- [ ] **Step 8: Infra — OPA container in `dev-up.sh`**

In `scripts/dev-up.sh`, after the OpenFGA block, add:

```bash
echo ">> OPA (opa, 172.30.0.50) — Rego policy engine"
if exists opa; then docker start opa >/dev/null; else
  docker run -d --name opa --network "$NET" --ip 172.30.0.50 \
    openpolicyagent/opa run --server --addr :8181 >/dev/null
fi
```

After the OpenFGA `wait_http` line, add:

```bash
wait_http "http://172.30.0.50:8181/health" OPA
```

Add OPA to the summary heredoc (a line under the OpenFGA line):

```
   OPA      : http://172.30.0.50:8181  (Rego policy pushed by the API at startup)
```

- [ ] **Step 9: verify-authz.py — allow per-case headers + OPA cases**

In `scripts/verify-authz.py`, change `call` to accept extra headers:

```python
def call(method, path, tok, paradigm, body=None, extra=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
               "X-Authz-Paradigm": paradigm}
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)
```

Change the loop to unpack an optional 7th element:

```python
for case in CASES:
    user, paradigm, method, path, body, expect = case[:6]
    extra = case[6] if len(case) > 6 else None
    status, resp = call(method, path, token(user), paradigm, body, extra)
    permit = resp.get("permit", status == 200)
    ok = permit == expect and (status == 200 if expect else status == 403)
    print(f"{'PASS' if ok else 'FAIL'}  {user:6} {paradigm:6} {path:16} -> {status} permit={permit} (want {expect}) :: {resp.get('reason','')}")
    fails += 0 if ok else 1
```

Add OPA cases to `CASES` (before the closing `]`). These reuse the realm users; carol gets the
`incident_responder` role in Task 7 (the two break-glass cases pass only after that):

```python
    # OPA/Rego (policy-as-code): clearance, department, frozen-deny-override, break-glass.
    ("bob",   "opa", "POST", "/storage/read",  {"key": "classified/x"}, True),                       # level3 >= 3
    ("alice", "opa", "POST", "/storage/read",  {"key": "classified/x"}, False),                      # level2 < 3
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/finance/y", "content": "x"}, True), # finance owns, level3>=2
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/eng/y", "content": "x"}, False),    # not owner dept
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/finance/frozen/y", "content": "x"}, False), # frozen forbids
    ("carol", "opa", "POST", "/storage/read",  {"key": "classified/x"}, True,  {"X-Break-Glass": "true"}),  # break-glass
    ("carol", "opa", "POST", "/storage/read",  {"key": "classified/x"}, False),                      # no flag → deny
```

- [ ] **Step 10: Build + unit tests green**

Run: `source ~/.bash_profile && dotnet test`
Expected: `Passed! - Failed: 0, Passed: 65`.

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "feat(authz): OPA/Rego policy-as-code paradigm end-to-end"
```

(The e2e run for OPA happens in Task 7 with the full stack, after the realm role is added.)

---

## Task 6: Cedar end-to-end

Same shape as OPA. Response is `{"decision":"Allow"|"Deny","diagnostics":{"reason":[…]}}`.

**Files:**
- Create: `src/Api/Authz/ICedarClient.cs`, `CedarAgentClient.cs`, `CedarProvisioner.cs`, `CedarEvaluator.cs`
- Modify: `src/Api/Program.cs`, `src/Api/Endpoints/AuthzConfigEndpoint.cs`,
  `src/Api/appsettings.Development.json`, `src/AppHost/AppHost.cs`, `scripts/dev-up.sh`,
  `scripts/verify-authz.py`
- Test: `tests/Api.Tests/CedarEvaluatorTests.cs`

- [ ] **Step 1: Client interface + HTTP client**

Create `src/Api/Authz/ICedarClient.cs`:

```csharp
namespace Api.Authz;

public interface ICedarClient
{
    // POSTs the is_authorized query; returns (allow, reason) where reason is the deciding policy id.
    Task<(bool Allow, string Reason)> IsAuthorizedAsync(
        string principal, string action, string resource, object context, CancellationToken ct);
}
```

Create `src/Api/Authz/CedarAgentClient.cs`:

```csharp
using System.Net.Http.Json;
using System.Text.Json;

namespace Api.Authz;

// ICedarClient over the cedar-agent REST API. Policies + the Action entity set are loaded at startup
// by CedarProvisioner; each call POSTs an is_authorized query whose principal/resource are readable
// (unregistered) uids and whose decision data rides in context.
public sealed class CedarAgentClient(HttpClient http) : ICedarClient
{
    public async Task<(bool Allow, string Reason)> IsAuthorizedAsync(
        string principal, string action, string resource, object context, CancellationToken ct)
    {
        var resp = await http.PostAsJsonAsync("/v1/is_authorized",
            new { principal, action, resource, context }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var allow = root.GetProperty("decision").GetString() == "Allow";
        var reason = root.TryGetProperty("diagnostics", out var diag)
            && diag.TryGetProperty("reason", out var reasons)
            && reasons.ValueKind == JsonValueKind.Array && reasons.GetArrayLength() > 0
                ? reasons[0].GetString() ?? "" : "";
        return (allow, reason);
    }
}
```

- [ ] **Step 2: Provisioner**

Create `src/Api/Authz/CedarProvisioner.cs`:

```csharp
using System.Text;

namespace Api.Authz;

// Startup provisioning of cedar-agent: PUT the policies and the entity (Action) set. Fail-fast.
// Returns a ready ICedarClient.
public static class CedarProvisioner
{
    public static async Task<ICedarClient> ProvisionAsync(
        string apiUrl, string policiesJson, string entitiesJson, CancellationToken ct)
    {
        var http = new HttpClient { BaseAddress = new Uri(apiUrl) };
        (await http.PutAsync("/v1/policies",
            new StringContent(policiesJson, Encoding.UTF8, "application/json"), ct)).EnsureSuccessStatusCode();
        (await http.PutAsync("/v1/data",
            new StringContent(entitiesJson, Encoding.UTF8, "application/json"), ct)).EnsureSuccessStatusCode();
        return new CedarAgentClient(http);
    }
}
```

- [ ] **Step 3: Evaluator**

Create `src/Api/Authz/CedarEvaluator.cs`:

```csharp
namespace Api.Authz;

// Policy-as-code via Cedar (cedar-agent). Because storage keys are dynamic, all decision data rides
// in the request context (proven in the spike); principal/resource are readable but unregistered
// uids. The policy logic lives in cedar-policies.json.
public sealed class CedarEvaluator(ICedarClient client) : IExternalEvaluator
{
    public string Paradigm => "cedar";

    public async Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct)
    {
        var p = PolicyInput.From(req);
        var context = new Dictionary<string, object>
        {
            ["classification"] = p.Classification,
            ["level"] = p.Level,
            ["caller_department"] = p.CallerDepartment,
            ["owner_department"] = p.OwnerDepartment,
            ["frozen"] = p.Frozen,
            ["roles"] = p.Roles,
            ["break_glass"] = p.BreakGlass,
        };
        var (allow, reason) = await client.IsAuthorizedAsync(
            $"User::\"{req.Caller.Name}\"", $"Action::\"{p.Action}\"", "Resource::\"obj\"", context, ct);
        var why = reason.Length > 0 ? $" [{reason}]" : "";
        return new AuthzDecision(allow, $"Cedar: {(allow ? "Allow" : "Deny")}{why}", "cedar");
    }
}
```

- [ ] **Step 4: Unit test (stub client)**

Create `tests/Api.Tests/CedarEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class CedarEvaluatorTests
{
    sealed class StubCedar(bool allow, string reason) : ICedarClient
    {
        public string? LastAction;
        public Task<(bool Allow, string Reason)> IsAuthorizedAsync(
            string principal, string action, string resource, object context, CancellationToken ct)
        {
            LastAction = action;
            return Task.FromResult((allow, reason));
        }
    }

    static AuthzRequest Req() => new(
        new CallerClaims("s", "bob", [],
            new Dictionary<string, string> { ["department"] = "engineering", ["level"] = "3" }, []),
        StorageAction.Read, "classified/x");

    [Fact]
    public void Paradigm_is_cedar() =>
        Assert.Equal("cedar", new CedarEvaluator(new StubCedar(true, "")).Paradigm);

    [Fact]
    public async Task Permit_and_reason_flow_through()
    {
        var d = await new CedarEvaluator(new StubCedar(true, "r1-read-clearance")).EvaluateAsync(Req(), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("cedar", d.Paradigm);
        Assert.Contains("r1-read-clearance", d.Reason);
    }

    [Fact]
    public async Task Deny_flows_through()
    {
        var d = await new CedarEvaluator(new StubCedar(false, "")).EvaluateAsync(Req(), CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Action_is_mapped_to_the_cedar_action_uid()
    {
        var stub = new StubCedar(true, "");
        await new CedarEvaluator(stub).EvaluateAsync(Req(), CancellationToken.None);
        Assert.Equal("Action::\"read\"", stub.LastAction);
    }
}
```

Run: `source ~/.bash_profile && dotnet test --filter CedarEvaluatorTests`
Expected: PASS (4 tests).

- [ ] **Step 5: Register in `Program.cs`**

In `src/Api/Program.cs`, add above the `IReadOnlyDictionary<...>` registration (next to OPA):

```csharp
var cedarUrl = builder.Configuration["Cedar:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(cedarUrl)
    ? new Api.Authz.UnconfiguredEvaluator("cedar")
    : new Api.Authz.CedarEvaluator(await Api.Authz.CedarProvisioner.ProvisionAsync(
        cedarUrl, Api.Authz.PolicyAssets.CedarPolicies, Api.Authz.PolicyAssets.CedarEntities, CancellationToken.None)));
```

- [ ] **Step 6: Config surface**

In `src/Api/Endpoints/AuthzConfigEndpoint.cs`, add before `_ => null`:

```csharp
            "cedar" => new
            {
                engine = "cedar",
                note = "config is a set of Cedar permit/forbid policies; decision data rides in context",
                policies = System.Text.Json.JsonDocument.Parse(PolicyAssets.CedarPolicies).RootElement,
            },
```

- [ ] **Step 7: Config URLs (appsettings + AppHost)**

In `src/Api/appsettings.Development.json`, add:

```json
  "Cedar": { "ApiUrl": "http://172.30.0.40:8180" },
```

In `src/AppHost/AppHost.cs`, add the constant:

```csharp
const string cedarUrl = "http://172.30.0.40:8180";
```

and on the `api` resource:

```csharp
    .WithEnvironment("Cedar__ApiUrl", cedarUrl)
```

- [ ] **Step 8: Infra — cedar-agent container in `dev-up.sh`**

In `scripts/dev-up.sh`, after the OPA block, add:

```bash
echo ">> cedar-agent (cedar-agent, 172.30.0.40) — Cedar policy engine"
if exists cedar-agent; then docker start cedar-agent >/dev/null; else
  docker run -d --name cedar-agent --network "$NET" --ip 172.30.0.40 \
    permitio/cedar-agent >/dev/null
fi
```

After the OPA `wait_http` line, add:

```bash
wait_http "http://172.30.0.40:8180/v1/policies" cedar-agent
```

Add to the summary heredoc:

```
   Cedar    : http://172.30.0.40:8180  (Cedar policies pushed by the API at startup)
```

- [ ] **Step 9: verify-authz.py — Cedar cases**

Add to `CASES` (mirroring the OPA cases so the two engines are proven to agree):

```python
    # Cedar (policy-as-code): identical scenario, judged by cedar-agent.
    ("bob",   "cedar", "POST", "/storage/read",  {"key": "classified/x"}, True),
    ("alice", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, False),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/finance/y", "content": "x"}, True),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/eng/y", "content": "x"}, False),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/finance/frozen/y", "content": "x"}, False),
    ("carol", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, True,  {"X-Break-Glass": "true"}),
    ("carol", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, False),
```

- [ ] **Step 10: Build + unit tests green**

Run: `source ~/.bash_profile && dotnet test`
Expected: `Passed! - Failed: 0, Passed: 69`.

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "feat(authz): Cedar policy-as-code paradigm end-to-end"
```

---

## Task 7: Realm role, full e2e verify, run note

Add the `incident_responder` role (assigned to carol so break-glass is demonstrable — her level 1
fails rule 1, so only the flag permits), run the whole matrix against real engines, document it.

**Files:**
- Modify: `src/AppHost/realms/authn-authz-realm.json`
- Create: `docs/superpowers/notes/2026-07-03-policy-as-code-run.md`

- [ ] **Step 1: Add the realm role + assignment**

In `src/AppHost/realms/authn-authz-realm.json`:

Add to `roles.realm` (the array currently holding `reader`, `writer`):

```json
      { "name": "incident_responder" }
```

Add a `realmRoles` field to the `carol` user object:

```json
      "realmRoles": ["incident_responder"],
```

- [ ] **Step 2: Re-import the realm (realm JSON does not hot-reload)**

Run: `docker rm -f kc-spike >/dev/null 2>&1; bash scripts/dev-up.sh`
Expected: the script brings up Keycloak (fixed IP 172.30.0.20 preserved), Ceph, OpenFGA, OPA,
cedar-agent, and prints all five infra URLs plus "first token written".

- [ ] **Step 3: Confirm the role reaches the token**

Run:
```bash
T=$(curl -s -d 'client_id=webapp&grant_type=password&username=carol&password=carol&scope=openid' \
  http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
python3 -c "import base64,json,sys; p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p)).get('realm_access'))" "$T"
```
Expected: the printed `realm_access.roles` list contains `incident_responder`.

- [ ] **Step 4: Run the API (standalone fast-verify) against the full stack**

Per the ReBAC run note pattern — temp Postgres + the AppHost env, API on a fixed port:

```bash
docker rm -f sp4-pg >/dev/null 2>&1
docker run -d --name sp4-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16 >/dev/null

source ~/.bash_profile
ASPNETCORE_ENVIRONMENT=Development \
ConnectionStrings__appdb="Host=localhost;Port=5433;Database=appdb;Username=postgres;Password=postgres" \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198 &
```

Wait for `Now listening on: http://127.0.0.1:5198`, and for the startup log to show no provisioning
error (Cedar + OPA + OpenFGA all provisioned).

- [ ] **Step 5: Run the full verify matrix**

Run: `python3 scripts/verify-authz.py http://127.0.0.1:5198`
Expected: every line `PASS`, final `ALL PASS`. This includes the SP1–3 cases plus 7 OPA + 7 Cedar
cases — the OPA and Cedar rows over the same scenario must agree row-for-row.

If any case fails: STOP, read the API log and the `reason` in the verify output, root-cause it (do
not wrap or mask). Cedar/OPA disagreement on a row is a real policy-translation bug to fix in the
`.rego` / `cedar-policies.json`, re-provision (restart the API), re-run.

- [ ] **Step 6: Tear down fast-verify scaffolding**

```bash
kill %1 2>/dev/null; docker rm -f sp4-pg >/dev/null 2>&1
```
Leave the fixed infra (kc-spike, ceph-demo, openfga, opa, cedar-agent, webid-refresher) up.

- [ ] **Step 7: Run note**

Create `docs/superpowers/notes/2026-07-03-policy-as-code-run.md` documenting: what SP4 adds (two PaC
paradigms, one scenario), the run commands (full stack + fast-verify), the verified result
(`dotnet test` count + `verify-authz.py` ALL PASS with the OPA/Cedar head-to-head), and the gotchas
(realm re-import for `incident_responder`; in-memory engines re-provisioned by the API at startup;
policy edits need the API restarted to re-push).

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "test+docs: SP4 realm role, full e2e verify, run note"
```

---

## Self-review (author)

**Spec coverage:** two paradigms cedar+opa (Tasks 5,6) ✓; shared 4-rule scenario in both policy
assets (Task 4) ✓; IExternalEvaluator seam (Task 1) ✓; request context/break-glass (Task 2) ✓;
PolicyInput derivation (Task 3) ✓; fixed-IP containers + startup provisioning (Tasks 5,6) ✓;
`/authz/{opa,cedar}/config` (Tasks 5,6) ✓; verify head-to-head (Tasks 5–7) ✓; realm dependency
(Task 7) ✓.

**Type consistency:** `IExternalEvaluator{Paradigm, EvaluateAsync}`, `PolicyInput.From`, `IOpaClient.DecideAsync(object)`,
`ICedarClient.IsAuthorizedAsync(principal,action,resource,context,ct)`, `AuthzContext(BreakGlass)`,
`DecideAsync(paradigm,req,cfg,IReadOnlyDictionary<string,IExternalEvaluator>,ct)` — used identically
across tasks.

**Out of scope (deferred):** persistent stores / policy hot-reload, full apples-to-apples across all
paradigms, playground UI, list-action coverage under PaC (`list` has no scenario rule → denies).

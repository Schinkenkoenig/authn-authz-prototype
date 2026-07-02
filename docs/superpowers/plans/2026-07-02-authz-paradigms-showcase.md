# Authorization Paradigms Showcase — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authorize object-storage operations over arbitrary prefixes under four in-process paradigms (RBAC, ABAC, claim-based, ACL), selectable per request, each seeded to show its sweet-spot scenario.

**Architecture:** A thin data seam — `AuthzRequest{Caller,Action,Resource}` → `AuthzDecision` — dispatched by a paradigm selector to one of four **pure static evaluators**. Config for RBAC/ABAC/ACL is seeded in Postgres and loaded once at startup into an in-memory `AuthzConfigStore` singleton; claim-based reads grants straight off the token. Storage I/O reuses SP1's service-identity `S3Gateway`. Decision logic never touches `DbContext`, HTTP, or S3, so it is unit-tested as pure functions.

**Tech Stack:** .NET 10, FastEndpoints 8.2, EF Core 10 + Npgsql, AWSSDK.S3 4.0, Keycloak (realm import), Ceph RGW, xUnit. Dev dotnet is user-local — every build/test/ef command is prefixed `source ~/.bash_profile &&`.

**Working directory:** the sub-project-2 worktree, branch `subproject-2-file-storage-authz`. All paths below are relative to the repo root.

---

## File Structure

**Create (Api):**
- `src/Api/Authz/AuthzModel.cs` — `StorageAction` enum, `AuthzRequest`, `AuthzDecision` records
- `src/Api/Authz/PrefixMatch.cs` — the one prefix-coverage rule shared by all paradigms
- `src/Api/Authz/RbacEvaluator.cs` — `RbacConfig`, `RolePermission`, pure evaluator
- `src/Api/Authz/AbacEvaluator.cs` — `AbacConfig`, `AbacRule`, `AttrPredicate`, pure evaluator
- `src/Api/Authz/ClaimsEvaluator.cs` — pure evaluator over `CallerClaims.StorageGrants`
- `src/Api/Authz/AclEvaluator.cs` — `AclConfig`, `AclEntry`, pure evaluator
- `src/Api/Authz/AuthzDispatcher.cs` — `AuthzConfig` bundle, paradigm list, `Resolve` + `Decide`
- `src/Api/Authz/AuthzConfigStore.cs` — DB→in-memory config loader (singleton) + pure parsers
- `src/Api/Authz/AuthzSeeder.cs` — idempotent seed of the §4 shared world
- `src/Api/Data/AuthzConfigEntities.cs` — EF row types for RBAC/ABAC/ACL config
- `src/Api/Endpoints/StorageReadEndpoint.cs`, `StorageWriteEndpoint.cs`, `StorageListEndpoint.cs`
- `src/Api/Endpoints/AuthzParadigmsEndpoint.cs`, `AuthzConfigEndpoint.cs`
- `scripts/verify-authz.py` — scripted integration verify against the live stack

**Modify:**
- `src/Api/Auth/CallerClaims.cs` — add `Attributes` + `StorageGrants`
- `src/Api/Storage/S3Gateway.cs` — add `ListAsync`
- `src/Api/Data/AppDbContext.cs` — add the four config `DbSet`s
- `src/Api/Program.cs` — register `AuthzConfigStore`; seed + load after `Migrate()`
- `src/AppHost/realms/authn-authz-realm.json` — users + attributes + `storage_grants`/`department`/`level` mappers + direct-access grant for scripted verify
- `tests/Api.Tests/CallerClaimsTests.cs` — cover the new claim extraction

**Delete:**
- `src/Api/Endpoints/StorageRoundtripEndpoint.cs` — replaced by read/write/list (its `prefix == username` rule is exactly what SP2 removes)

**Test:** `tests/Api.Tests/` — one test file per evaluator plus dispatcher/parser tests.

---

## Task 1: Extend CallerClaims with attributes and storage grants

**Files:**
- Modify: `src/Api/Auth/CallerClaims.cs`
- Test: `tests/Api.Tests/CallerClaimsTests.cs`

- [ ] **Step 1: Write the failing test** — append to `tests/Api.Tests/CallerClaimsTests.cs`:

```csharp
    [Fact]
    public void Extracts_attributes_and_storage_grants()
    {
        var caller = CallerClaims.FromPrincipal(Principal(
            new Claim("sub", "bob-sub"),
            new Claim("preferred_username", "bob"),
            new Claim("department", "engineering"),
            new Claim("level", "3"),
            new Claim("storage_grants", "rw:projects/apollo/"),
            new Claim("storage_grants", "r:shared/")));

        Assert.Equal("engineering", caller.Attributes["department"]);
        Assert.Equal("3", caller.Attributes["level"]);
        Assert.Equal(new[] { "rw:projects/apollo/", "r:shared/" }, caller.StorageGrants);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter Extracts_attributes_and_storage_grants`
Expected: FAIL to compile — `CallerClaims` has no `Attributes`/`StorageGrants`.

- [ ] **Step 3: Rewrite `src/Api/Auth/CallerClaims.cs`**

```csharp
using System.Security.Claims;
using System.Text.Json;

namespace Api.Auth;

// The validated identity, reduced to what the paradigms need. Realm roles stay nested under
// Keycloak's `realm_access` claim (informational — shown by /whoami; RBAC assignment lives in
// the DB, not the token). ABAC reads `Attributes`; claim-based reads `StorageGrants`.
public sealed record CallerClaims(
    string Subject,
    string Name,
    IReadOnlyList<string> Roles,
    IReadOnlyDictionary<string, string> Attributes,
    IReadOnlyList<string> StorageGrants)
{
    // The fixed attribute set the ABAC showcase reasons over. Adding an attribute the rules
    // need means adding its claim name here.
    static readonly string[] AttributeClaims = ["department", "level"];

    public static CallerClaims FromPrincipal(ClaimsPrincipal principal)
    {
        var subject = principal.FindFirstValue("sub") ?? "";
        var name = principal.FindFirstValue("preferred_username") ?? subject;

        var attributes = new Dictionary<string, string>();
        foreach (var claim in AttributeClaims)
        {
            var value = principal.FindFirstValue(claim);
            if (value is not null)
                attributes[claim] = value;
        }

        var grants = principal.FindAll("storage_grants").Select(c => c.Value).ToArray();

        return new CallerClaims(subject, name, RealmRoles(principal), attributes, grants);
    }

    static IReadOnlyList<string> RealmRoles(ClaimsPrincipal principal)
    {
        var realmAccess = principal.FindFirstValue("realm_access");
        if (string.IsNullOrEmpty(realmAccess))
            return [];

        using var doc = JsonDocument.Parse(realmAccess);
        if (!doc.RootElement.TryGetProperty("roles", out var roles))
            return [];

        return roles.EnumerateArray().Select(r => r.GetString() ?? "").ToArray();
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests`
Expected: PASS (both `CallerClaims` tests; the existing roles test still passes).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Auth/CallerClaims.cs tests/Api.Tests/CallerClaimsTests.cs
git commit -m "feat: CallerClaims carries attributes + storage grants"
```

---

## Task 2: Authz core data shapes + prefix matching

**Files:**
- Create: `src/Api/Authz/AuthzModel.cs`
- Create: `src/Api/Authz/PrefixMatch.cs`
- Test: `tests/Api.Tests/PrefixMatchTests.cs`

- [ ] **Step 1: Create `src/Api/Authz/AuthzModel.cs`**

```csharp
using Api.Auth;

namespace Api.Authz;

public enum StorageAction { Read, Write, List }

// The one request shape every paradigm evaluates. Resource is an object key (read/write) or a
// prefix (list).
public sealed record AuthzRequest(CallerClaims Caller, StorageAction Action, string Resource);

public sealed record AuthzDecision(bool Permit, string Reason, string Paradigm);
```

- [ ] **Step 2: Write the failing test** — create `tests/Api.Tests/PrefixMatchTests.cs`:

```csharp
using Api.Authz;

namespace Api.Tests;

public class PrefixMatchTests
{
    [Theory]
    [InlineData("finance/", "finance/q1.txt", true)]      // under the prefix
    [InlineData("finance/", "finance/2026/q1.txt", true)] // nested
    [InlineData("finance/", "finance", false)]            // the bare prefix name is not "under" it
    [InlineData("finance/", "engineering/x", false)]      // different prefix
    [InlineData("finance/", "financials/x", false)]       // not fooled by shared leading text
    [InlineData("finance/q1.txt", "finance/q1.txt", true)]// exact key grant
    [InlineData("*", "anything/at/all", true)]            // wildcard grants everything
    public void Covers(string grant, string resource, bool expected) =>
        Assert.Equal(expected, PrefixMatch.Covers(grant, resource));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter PrefixMatchTests`
Expected: FAIL to compile — `PrefixMatch` undefined.

- [ ] **Step 4: Create `src/Api/Authz/PrefixMatch.cs`**

```csharp
namespace Api.Authz;

// The single resource-coverage rule shared by every prefix-granting paradigm, so decisions
// differ because of config shape — not matching quirks. A grant covers a resource when it is
// "*" (all), an exact key match, or a directory prefix the resource sits strictly under.
public static class PrefixMatch
{
    public static bool Covers(string grant, string resource)
    {
        if (grant == "*") return true;
        if (grant == resource) return true;
        var prefix = grant.EndsWith('/') ? grant : grant + "/";
        return resource.StartsWith(prefix, StringComparison.Ordinal);
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter PrefixMatchTests`
Expected: PASS (all 7 cases).

- [ ] **Step 6: Commit**

```bash
git add src/Api/Authz/AuthzModel.cs src/Api/Authz/PrefixMatch.cs tests/Api.Tests/PrefixMatchTests.cs
git commit -m "feat: authz decision shapes + shared prefix-match rule"
```

---

## Task 3: RBAC evaluator

**Files:**
- Create: `src/Api/Authz/RbacEvaluator.cs`
- Test: `tests/Api.Tests/RbacEvaluatorTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/RbacEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class RbacEvaluatorTests
{
    static CallerClaims User(string name) =>
        new("sub-" + name, name, [], new Dictionary<string, string>(), []);

    static readonly RbacConfig Config = new(
        UserRoles: new Dictionary<string, IReadOnlyList<string>>
        {
            ["erin"] = ["editor"],
            ["carol"] = ["viewer"],
        },
        Permissions:
        [
            new RolePermission("editor", "projects/", [StorageAction.Read, StorageAction.Write]),
            new RolePermission("viewer", "shared/", [StorageAction.Read]),
        ]);

    [Fact]
    public void Role_grants_write_under_its_prefix()
    {
        var d = RbacEvaluator.Evaluate(User("erin"), StorageAction.Write, "projects/apollo/x.txt", Config);
        Assert.True(d.Permit);
    }

    [Fact]
    public void Viewer_cannot_write()
    {
        var d = RbacEvaluator.Evaluate(User("carol"), StorageAction.Write, "shared/x.txt", Config);
        Assert.False(d.Permit);
    }

    [Fact]
    public void Unknown_user_denied()
    {
        var d = RbacEvaluator.Evaluate(User("mallory"), StorageAction.Read, "shared/x.txt", Config);
        Assert.False(d.Permit);
        Assert.Contains("no roles", d.Reason);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter RbacEvaluatorTests`
Expected: FAIL to compile — `RbacConfig`/`RbacEvaluator` undefined.

- [ ] **Step 3: Create `src/Api/Authz/RbacEvaluator.cs`**

```csharp
using Api.Auth;

namespace Api.Authz;

// RBAC config lives in the DB (role→permission and user→role), keyed by username for legible
// seed data. Sweet spot: many users share few roles, so onboarding is one user_roles row.
public sealed record RolePermission(string Role, string Prefix, IReadOnlyList<StorageAction> Actions);

public sealed record RbacConfig(
    IReadOnlyDictionary<string, IReadOnlyList<string>> UserRoles,
    IReadOnlyList<RolePermission> Permissions);

public static class RbacEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, RbacConfig cfg)
    {
        if (!cfg.UserRoles.TryGetValue(caller.Name, out var roles) || roles.Count == 0)
            return new(false, $"no roles assigned to '{caller.Name}'", "rbac");

        foreach (var perm in cfg.Permissions)
            if (roles.Contains(perm.Role) && perm.Actions.Contains(action) && PrefixMatch.Covers(perm.Prefix, resource))
                return new(true, $"role '{perm.Role}' grants {action} on '{perm.Prefix}'", "rbac");

        return new(false, $"role(s) [{string.Join(", ", roles)}] grant no {action} on '{resource}'", "rbac");
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter RbacEvaluatorTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/RbacEvaluator.cs tests/Api.Tests/RbacEvaluatorTests.cs
git commit -m "feat: RBAC evaluator (role→permission, user→role in DB)"
```

---

## Task 4: ABAC evaluator

**Files:**
- Create: `src/Api/Authz/AbacEvaluator.cs`
- Test: `tests/Api.Tests/AbacEvaluatorTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/AbacEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AbacEvaluatorTests
{
    static CallerClaims User(string dept, string level) =>
        new("sub", "u", [], new Dictionary<string, string> { ["department"] = dept, ["level"] = level }, []);

    // Rule 1: anyone may read+write under their own department prefix (templated).
    // Rule 2: level >= 3 may read hr/.
    static readonly AbacConfig Config = new(
    [
        new AbacRule([], "{department}/", [StorageAction.Read, StorageAction.Write]),
        new AbacRule([new AttrPredicate("level", "gte", "3")], "hr/", [StorageAction.Read]),
    ]);

    [Fact]
    public void Department_template_grants_own_prefix()
    {
        var d = AbacEvaluator.Evaluate(User("finance", "2"), StorageAction.Write, "finance/q1.txt", Config);
        Assert.True(d.Permit);
    }

    [Fact]
    public void Department_template_denies_other_prefix()
    {
        var d = AbacEvaluator.Evaluate(User("finance", "2"), StorageAction.Write, "engineering/x", Config);
        Assert.False(d.Permit);
    }

    [Fact]
    public void Level_condition_gates_hr_read()
    {
        Assert.True(AbacEvaluator.Evaluate(User("engineering", "3"), StorageAction.Read, "hr/records.txt", Config).Permit);
        Assert.False(AbacEvaluator.Evaluate(User("engineering", "2"), StorageAction.Read, "hr/records.txt", Config).Permit);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AbacEvaluatorTests`
Expected: FAIL to compile — ABAC types undefined.

- [ ] **Step 3: Create `src/Api/Authz/AbacEvaluator.cs`**

```csharp
using Api.Auth;

namespace Api.Authz;

// ABAC derives access from caller attributes. A rule applies when all its conditions hold and its
// prefix template (which may reference attributes, e.g. "{department}/") resolves. Sweet spot:
// onboarding needs zero authz change — a new finance user is covered by the department rule.
public sealed record AttrPredicate(string Attribute, string Op, string Value); // Op: "eq" | "gte"

public sealed record AbacRule(
    IReadOnlyList<AttrPredicate> Conditions,
    string PrefixTemplate,
    IReadOnlyList<StorageAction> Actions);

public sealed record AbacConfig(IReadOnlyList<AbacRule> Rules);

public static class AbacEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, AbacConfig cfg)
    {
        foreach (var rule in cfg.Rules)
        {
            if (!rule.Actions.Contains(action)) continue;
            if (!rule.Conditions.All(c => Holds(c, caller.Attributes))) continue;
            if (!TryResolve(rule.PrefixTemplate, caller.Attributes, out var prefix)) continue;
            if (PrefixMatch.Covers(prefix, resource))
                return new(true, $"attributes satisfy rule → {action} on '{prefix}'", "abac");
        }
        return new(false, $"no attribute rule grants {action} on '{resource}'", "abac");
    }

    static bool Holds(AttrPredicate p, IReadOnlyDictionary<string, string> attrs)
    {
        if (!attrs.TryGetValue(p.Attribute, out var value)) return false;
        return p.Op switch
        {
            "eq" => value == p.Value,
            "gte" => int.TryParse(value, out var v) && int.TryParse(p.Value, out var t) && v >= t,
            _ => false,
        };
    }

    // Substitute {attr} placeholders from caller attributes. A referenced attribute that is
    // missing means the rule does not apply to this caller.
    static bool TryResolve(string template, IReadOnlyDictionary<string, string> attrs, out string resolved)
    {
        resolved = template;
        var open = resolved.IndexOf('{');
        while (open >= 0)
        {
            var close = resolved.IndexOf('}', open);
            if (close < 0) break;
            var name = resolved[(open + 1)..close];
            if (!attrs.TryGetValue(name, out var value)) { resolved = ""; return false; }
            resolved = resolved[..open] + value + resolved[(close + 1)..];
            open = resolved.IndexOf('{');
        }
        return true;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AbacEvaluatorTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/AbacEvaluator.cs tests/Api.Tests/AbacEvaluatorTests.cs
git commit -m "feat: ABAC evaluator (attribute conditions + templated prefixes)"
```

---

## Task 5: Claim-based evaluator

**Files:**
- Create: `src/Api/Authz/ClaimsEvaluator.cs`
- Test: `tests/Api.Tests/ClaimsEvaluatorTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/ClaimsEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class ClaimsEvaluatorTests
{
    static CallerClaims User(params string[] grants) =>
        new("sub", "u", [], new Dictionary<string, string>(), grants);

    [Fact]
    public void Rw_grant_permits_write()
    {
        var d = ClaimsEvaluator.Evaluate(User("rw:projects/apollo/"), StorageAction.Write, "projects/apollo/x");
        Assert.True(d.Permit);
    }

    [Fact]
    public void Read_grant_does_not_permit_write()
    {
        var d = ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.Write, "finance/x");
        Assert.False(d.Permit);
    }

    [Fact]
    public void Read_grant_permits_read_and_list()
    {
        Assert.True(ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.Read, "finance/x").Permit);
        Assert.True(ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.List, "finance/").Permit);
    }

    [Fact]
    public void Wildcard_grant_permits_everything()
    {
        Assert.True(ClaimsEvaluator.Evaluate(User("rw:*"), StorageAction.Write, "anything/x").Permit);
    }

    [Fact]
    public void No_grant_denied()
    {
        Assert.False(ClaimsEvaluator.Evaluate(User(), StorageAction.Read, "finance/x").Permit);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter ClaimsEvaluatorTests`
Expected: FAIL to compile — `ClaimsEvaluator` undefined.

- [ ] **Step 3: Create `src/Api/Authz/ClaimsEvaluator.cs`**

```csharp
using Api.Auth;

namespace Api.Authz;

// Claim-based: the IdP issues the grants in the token and the app trusts them. There is NO app
// config — the admin surface is the Keycloak claim mapper. Grants look like "r:finance/",
// "rw:projects/apollo/", "rw:*". Contrast: revocation waits for token expiry.
public static class ClaimsEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource)
    {
        foreach (var grant in caller.StorageGrants)
        {
            var colon = grant.IndexOf(':');
            if (colon < 0) continue;
            var caps = grant[..colon];
            var prefix = grant[(colon + 1)..];
            if (!Allows(caps, action)) continue;
            if (PrefixMatch.Covers(prefix, resource))
                return new(true, $"token grant '{grant}' permits {action}", "claims");
        }
        return new(false, $"no token grant permits {action} on '{resource}'", "claims");
    }

    static bool Allows(string caps, StorageAction action) => action switch
    {
        StorageAction.Write => caps.Contains('w'),
        StorageAction.Read => caps.Contains('r'),
        StorageAction.List => caps.Contains('r'), // read implies list
        _ => false,
    };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter ClaimsEvaluatorTests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/ClaimsEvaluator.cs tests/Api.Tests/ClaimsEvaluatorTests.cs
git commit -m "feat: claim-based evaluator (IdP-issued token grants)"
```

---

## Task 6: ACL evaluator

**Files:**
- Create: `src/Api/Authz/AclEvaluator.cs`
- Test: `tests/Api.Tests/AclEvaluatorTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/AclEvaluatorTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AclEvaluatorTests
{
    static CallerClaims User(string name) =>
        new("sub", name, [], new Dictionary<string, string>(), []);

    static readonly AclConfig Config = new(
    [
        new AclEntry("shared/", "*", [StorageAction.Read]),
        new AclEntry("projects/apollo/", "bob", [StorageAction.Read, StorageAction.Write]),
    ]);

    [Fact]
    public void Wildcard_principal_grants_everyone_read()
    {
        Assert.True(AclEvaluator.Evaluate(User("carol"), StorageAction.Read, "shared/notes.txt", Config).Permit);
    }

    [Fact]
    public void Named_principal_grants_only_that_user()
    {
        Assert.True(AclEvaluator.Evaluate(User("bob"), StorageAction.Write, "projects/apollo/x", Config).Permit);
        Assert.False(AclEvaluator.Evaluate(User("carol"), StorageAction.Write, "projects/apollo/x", Config).Permit);
    }

    [Fact]
    public void No_matching_entry_denied()
    {
        Assert.False(AclEvaluator.Evaluate(User("carol"), StorageAction.Write, "shared/notes.txt", Config).Permit);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AclEvaluatorTests`
Expected: FAIL to compile — ACL types undefined.

- [ ] **Step 3: Create `src/Api/Authz/AclEvaluator.cs`**

```csharp
using Api.Auth;

namespace Api.Authz;

// ACL: each prefix carries an explicit who-can-do-what list; "*" principal means everyone. The
// dumb baseline — obvious for small ad-hoc sharing, but grows linearly and offers no reuse.
public sealed record AclEntry(string Prefix, string Principal, IReadOnlyList<StorageAction> Actions);

public sealed record AclConfig(IReadOnlyList<AclEntry> Entries);

public static class AclEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, AclConfig cfg)
    {
        foreach (var e in cfg.Entries)
        {
            if (e.Principal != "*" && e.Principal != caller.Name) continue;
            if (!e.Actions.Contains(action)) continue;
            if (PrefixMatch.Covers(e.Prefix, resource))
                return new(true, $"ACL on '{e.Prefix}' grants {action} to '{e.Principal}'", "acl");
        }
        return new(false, $"no ACL entry grants {action} on '{resource}' to '{caller.Name}'", "acl");
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AclEvaluatorTests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/AclEvaluator.cs tests/Api.Tests/AclEvaluatorTests.cs
git commit -m "feat: ACL evaluator (per-prefix access lists)"
```

---

## Task 7: Dispatcher — paradigm selection + routing

**Files:**
- Create: `src/Api/Authz/AuthzDispatcher.cs`
- Test: `tests/Api.Tests/AuthzDispatcherTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/AuthzDispatcherTests.cs`:

```csharp
using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AuthzDispatcherTests
{
    static readonly AuthzConfig Config = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>> { ["bob"] = ["editor"] },
            [new RolePermission("editor", "projects/", [StorageAction.Write])]),
        new AbacConfig([]),
        new AclConfig([]));

    static AuthzRequest Req(string resource) =>
        new(new CallerClaims("sub", "bob", [], new Dictionary<string, string>(), []), StorageAction.Write, resource);

    [Theory]
    [InlineData(null, "rbac")]        // absent → default
    [InlineData("", "rbac")]          // empty → default
    [InlineData("nonsense", "rbac")]  // unknown → default
    [InlineData("acl", "acl")]        // known → itself
    public void Resolve_falls_back_to_default(string? selector, string expected) =>
        Assert.Equal(expected, AuthzDispatcher.Resolve(selector));

    [Fact]
    public void Decide_routes_to_named_paradigm()
    {
        var d = AuthzDispatcher.Decide("rbac", Req("projects/apollo/x"), Config);
        Assert.True(d.Permit);
        Assert.Equal("rbac", d.Paradigm);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AuthzDispatcherTests`
Expected: FAIL to compile — `AuthzConfig`/`AuthzDispatcher` undefined.

- [ ] **Step 3: Create `src/Api/Authz/AuthzDispatcher.cs`**

```csharp
namespace Api.Authz;

// The in-memory config bundle the store loads once at startup (claim-based needs none — it reads
// the token).
public sealed record AuthzConfig(RbacConfig Rbac, AbacConfig Abac, AclConfig Acl);

// The thin data seam: pick an evaluator by selector, route the request. No engine hierarchy.
public static class AuthzDispatcher
{
    public const string Default = "rbac";
    public static readonly IReadOnlyList<string> Paradigms = ["rbac", "abac", "claims", "acl"];

    public static string Resolve(string? selector) =>
        selector is not null && Paradigms.Contains(selector) ? selector : Default;

    public static AuthzDecision Decide(string paradigm, AuthzRequest req, AuthzConfig cfg) => paradigm switch
    {
        "rbac" => RbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Rbac),
        "abac" => AbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Abac),
        "claims" => ClaimsEvaluator.Evaluate(req.Caller, req.Action, req.Resource),
        "acl" => AclEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Acl),
        _ => new(false, $"unknown paradigm '{paradigm}'", paradigm),
    };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AuthzDispatcherTests`
Expected: PASS (5 cases).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/AuthzDispatcher.cs tests/Api.Tests/AuthzDispatcherTests.cs
git commit -m "feat: authz dispatcher — selector resolution + routing"
```

---

## Task 8: EF config entities + migration

**Files:**
- Create: `src/Api/Data/AuthzConfigEntities.cs`
- Modify: `src/Api/Data/AppDbContext.cs`

- [ ] **Step 1: Create `src/Api/Data/AuthzConfigEntities.cs`**

```csharp
namespace Api.Data;

// Seeded authorization config, read into in-memory structs at startup. Multi-value fields are
// stored as simple strings (Actions CSV like "Read,Write"; ABAC conditions as JSON) so the
// schema stays flat and the parsing lives in AuthzConfigStore.
public sealed class RbacUserRoleRow
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Role { get; set; } = "";
}

public sealed class RbacRolePermissionRow
{
    public int Id { get; set; }
    public string Role { get; set; } = "";
    public string Prefix { get; set; } = "";
    public string Actions { get; set; } = ""; // CSV of StorageAction
}

public sealed class AbacRuleRow
{
    public int Id { get; set; }
    public string ConditionsJson { get; set; } = "[]"; // JSON array of {Attribute,Op,Value}
    public string PrefixTemplate { get; set; } = "";
    public string Actions { get; set; } = ""; // CSV of StorageAction
}

public sealed class AclEntryRow
{
    public int Id { get; set; }
    public string Prefix { get; set; } = "";
    public string Principal { get; set; } = ""; // username or "*"
    public string Actions { get; set; } = ""; // CSV of StorageAction
}
```

- [ ] **Step 2: Add DbSets** — edit `src/Api/Data/AppDbContext.cs`, replacing the `AppDbContext` class body:

```csharp
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<RbacUserRoleRow> RbacUserRoles => Set<RbacUserRoleRow>();
    public DbSet<RbacRolePermissionRow> RbacRolePermissions => Set<RbacRolePermissionRow>();
    public DbSet<AbacRuleRow> AbacRules => Set<AbacRuleRow>();
    public DbSet<AclEntryRow> AclEntries => Set<AclEntryRow>();
}
```

- [ ] **Step 3: Verify the project builds**

Run: `source ~/.bash_profile && dotnet build src/Api`
Expected: build succeeds.

- [ ] **Step 4: Add the EF migration**

Run: `source ~/.bash_profile && dotnet ef migrations add AuthzConfig --project src/Api`
Expected: a new migration under `src/Api/Migrations/` creating the four tables. (If `dotnet ef` is missing: `dotnet tool install --global dotnet-ef --version 10.*` then re-run.)

- [ ] **Step 5: Commit**

```bash
git add src/Api/Data/AuthzConfigEntities.cs src/Api/Data/AppDbContext.cs src/Api/Migrations/
git commit -m "feat: EF entities + migration for RBAC/ABAC/ACL config"
```

---

## Task 9: Config store — DB→in-memory loader + pure parsers

**Files:**
- Create: `src/Api/Authz/AuthzConfigStore.cs`
- Test: `tests/Api.Tests/AuthzConfigParseTests.cs`

- [ ] **Step 1: Write the failing test** — create `tests/Api.Tests/AuthzConfigParseTests.cs`:

```csharp
using Api.Authz;

namespace Api.Tests;

public class AuthzConfigParseTests
{
    [Fact]
    public void Parses_action_csv()
    {
        var actions = AuthzConfigStore.ParseActions("Read, Write");
        Assert.Equal(new[] { StorageAction.Read, StorageAction.Write }, actions);
    }

    [Fact]
    public void Parses_empty_actions_to_empty()
    {
        Assert.Empty(AuthzConfigStore.ParseActions(""));
    }

    [Fact]
    public void Parses_conditions_json()
    {
        var conds = AuthzConfigStore.ParseConditions("""[{"Attribute":"level","Op":"gte","Value":"3"}]""");
        Assert.Single(conds);
        Assert.Equal("level", conds[0].Attribute);
        Assert.Equal("gte", conds[0].Op);
        Assert.Equal("3", conds[0].Value);
    }

    [Fact]
    public void Parses_empty_conditions_to_empty()
    {
        Assert.Empty(AuthzConfigStore.ParseConditions("[]"));
        Assert.Empty(AuthzConfigStore.ParseConditions(""));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AuthzConfigParseTests`
Expected: FAIL to compile — `AuthzConfigStore` undefined.

- [ ] **Step 3: Create `src/Api/Authz/AuthzConfigStore.cs`**

```csharp
using System.Text.Json;
using Api.Data;
using Microsoft.EntityFrameworkCore;

namespace Api.Authz;

// Loads seeded config once at startup into an immutable in-memory bundle the evaluators read.
// Keeping the load here (not in the evaluators) is what lets decision logic stay pure and
// DbContext-free. Read-only this spec; a reload path arrives with the config-editing playground.
public sealed class AuthzConfigStore
{
    public AuthzConfig Current { get; private set; } = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>>(), []),
        new AbacConfig([]),
        new AclConfig([]));

    public void Load(AppDbContext db)
    {
        var userRoles = db.RbacUserRoles.AsNoTracking().ToList()
            .GroupBy(r => r.Username)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.Role).ToList());

        var permissions = db.RbacRolePermissions.AsNoTracking().ToList()
            .Select(p => new RolePermission(p.Role, p.Prefix, ParseActions(p.Actions)))
            .ToList();

        var rules = db.AbacRules.AsNoTracking().ToList()
            .Select(r => new AbacRule(ParseConditions(r.ConditionsJson), r.PrefixTemplate, ParseActions(r.Actions)))
            .ToList();

        var acl = db.AclEntries.AsNoTracking().ToList()
            .Select(a => new AclEntry(a.Prefix, a.Principal, ParseActions(a.Actions)))
            .ToList();

        Current = new AuthzConfig(new RbacConfig(userRoles, permissions), new AbacConfig(rules), new AclConfig(acl));
    }

    public static IReadOnlyList<StorageAction> ParseActions(string csv) =>
        csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Select(Enum.Parse<StorageAction>)
           .ToList();

    public static IReadOnlyList<AttrPredicate> ParseConditions(string json) =>
        string.IsNullOrWhiteSpace(json)
            ? []
            : JsonSerializer.Deserialize<List<AttrPredicate>>(json) ?? [];
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source ~/.bash_profile && dotnet test tests/Api.Tests --filter AuthzConfigParseTests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/AuthzConfigStore.cs tests/Api.Tests/AuthzConfigParseTests.cs
git commit -m "feat: config store loads seeded authz config into memory"
```

---

## Task 10: Seeder — the §4 shared world

**Files:**
- Create: `src/Api/Authz/AuthzSeeder.cs`

- [ ] **Step 1: Create `src/Api/Authz/AuthzSeeder.cs`**

```csharp
using Api.Data;

namespace Api.Authz;

// The one shared world (spec §4): one prefix namespace + one roster, each paradigm's sweet-spot
// scenario a slice of it. Idempotent — seeds only when empty. Usernames are the principal keys
// for RBAC/ACL so seed data reads clearly; ABAC/claims key off attributes/token grants.
public static class AuthzSeeder
{
    public static void Seed(AppDbContext db)
    {
        if (db.RbacUserRoles.Any()) return;

        // RBAC — few reusable roles; bob & erin share 'editor' (role reuse is the sweet spot).
        db.RbacUserRoles.AddRange(
            new RbacUserRoleRow { Username = "alice", Role = "auditor" },
            new RbacUserRoleRow { Username = "bob", Role = "editor" },
            new RbacUserRoleRow { Username = "carol", Role = "viewer" },
            new RbacUserRoleRow { Username = "dave", Role = "admin" },
            new RbacUserRoleRow { Username = "erin", Role = "editor" });

        db.RbacRolePermissions.AddRange(
            new RbacRolePermissionRow { Role = "viewer", Prefix = "shared/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "editor", Prefix = "projects/", Actions = "Read,Write,List" },
            new RbacRolePermissionRow { Role = "editor", Prefix = "shared/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "finance/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "hr/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "engineering/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "admin", Prefix = "*", Actions = "Read,Write,List" });

        // ABAC — rw under your own department; level >= 3 may read hr/.
        db.AbacRules.AddRange(
            new AbacRuleRow { ConditionsJson = "[]", PrefixTemplate = "{department}/", Actions = "Read,Write,List" },
            new AbacRuleRow
            {
                ConditionsJson = """[{"Attribute":"level","Op":"gte","Value":"3"}]""",
                PrefixTemplate = "hr/",
                Actions = "Read,List",
            });

        // ACL — explicit per-prefix lists + a wildcard.
        db.AclEntries.AddRange(
            new AclEntryRow { Prefix = "shared/", Principal = "*", Actions = "Read,List" },
            new AclEntryRow { Prefix = "shared/announcements/", Principal = "dave", Actions = "Read,Write,List" },
            new AclEntryRow { Prefix = "projects/apollo/", Principal = "bob", Actions = "Read,Write,List" },
            new AclEntryRow { Prefix = "finance/", Principal = "erin", Actions = "Read,Write,List" });

        db.SaveChanges();
    }
}
```

- [ ] **Step 2: Verify the project builds**

Run: `source ~/.bash_profile && dotnet build src/Api`
Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/Api/Authz/AuthzSeeder.cs
git commit -m "feat: seed the shared authz world (roster + per-paradigm config)"
```

---

## Task 11: Wire DI + startup seed/load; add S3 list

**Files:**
- Modify: `src/Api/Program.cs`
- Modify: `src/Api/Storage/S3Gateway.cs`

- [ ] **Step 1: Add `ListAsync` to `src/Api/Storage/S3Gateway.cs`** — insert after `GetAsync`:

```csharp
    public async Task<IReadOnlyList<string>> ListAsync(string prefix, CancellationToken ct)
    {
        var resp = await _client.ListObjectsV2Async(new ListObjectsV2Request
        {
            BucketName = ceph.Bucket,
            Prefix = prefix,
        }, ct);
        return resp.S3Objects?.Select(o => o.Key).ToList() ?? [];
    }
```

- [ ] **Step 2: Register the config store** — in `src/Api/Program.cs`, after the `AddSingleton<S3Gateway>()` line:

```csharp
builder.Services.AddSingleton<Api.Authz.AuthzConfigStore>();
```

- [ ] **Step 3: Seed + load at startup** — in `src/Api/Program.cs`, replace the existing migrate block:

```csharp
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
    Api.Authz.AuthzSeeder.Seed(db);
    app.Services.GetRequiredService<Api.Authz.AuthzConfigStore>().Load(db);
}
```

- [ ] **Step 4: Verify build + existing tests**

Run: `source ~/.bash_profile && dotnet build src/Api && dotnet test tests/Api.Tests`
Expected: build succeeds; all unit tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/Api/Program.cs src/Api/Storage/S3Gateway.cs
git commit -m "feat: wire config store; seed+load at startup; S3 list"
```

---

## Task 12: Storage endpoints — read/write/list gated by the PDP

**Files:**
- Create: `src/Api/Endpoints/StorageReadEndpoint.cs`
- Create: `src/Api/Endpoints/StorageWriteEndpoint.cs`
- Create: `src/Api/Endpoints/StorageListEndpoint.cs`
- Delete: `src/Api/Endpoints/StorageRoundtripEndpoint.cs`

- [ ] **Step 1: Delete the old roundtrip endpoint**

```bash
git rm src/Api/Endpoints/StorageRoundtripEndpoint.cs
```

- [ ] **Step 2: Create `src/Api/Endpoints/StorageReadEndpoint.cs`**

```csharp
using Amazon.S3;
using Api.Auth;
using Api.Authz;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record ReadRequest(string Key);
public sealed record StorageResult(string Paradigm, bool Permit, string Reason, string Key, string? Content);

// Read is gated by the selected paradigm, then served with the service identity. The paradigm
// comes from the X-Authz-Paradigm header (default when absent/unknown).
public sealed class StorageReadEndpoint(AuthzConfigStore store, S3Gateway s3)
    : Endpoint<ReadRequest, StorageResult>
{
    public override void Configure()
    {
        Post("/storage/read");
        Policies("authenticated");
    }

    public override async Task HandleAsync(ReadRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var decision = AuthzDispatcher.Decide(paradigm, new AuthzRequest(caller, StorageAction.Read, req.Key), store.Current);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new StorageResult(paradigm, false, decision.Reason, req.Key, null), 403, ct);
            return;
        }

        string content;
        try { content = await s3.GetAsync(req.Key, ct); }
        catch (AmazonS3Exception ex) { content = $"(read failed: {ex.ErrorCode})"; }

        await Send.OkAsync(new StorageResult(paradigm, true, decision.Reason, req.Key, content), ct);
    }
}
```

- [ ] **Step 3: Create `src/Api/Endpoints/StorageWriteEndpoint.cs`**

```csharp
using Api.Auth;
using Api.Authz;
using Api.Data;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record WriteRequest(string Key, string Content);

public sealed class StorageWriteEndpoint(AuthzConfigStore store, S3Gateway s3, AppDbContext db)
    : Endpoint<WriteRequest, StorageResult>
{
    public override void Configure()
    {
        Post("/storage/write");
        Policies("authenticated");
    }

    public override async Task HandleAsync(WriteRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var decision = AuthzDispatcher.Decide(paradigm, new AuthzRequest(caller, StorageAction.Write, req.Key), store.Current);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new StorageResult(paradigm, false, decision.Reason, req.Key, null), 403, ct);
            return;
        }

        await s3.PutAsync(req.Key, req.Content, ct);
        db.AuditEntries.Add(new AuditEntry
        {
            At = DateTimeOffset.UtcNow,
            Subject = caller.Subject,
            RoleArn = paradigm,
            ObjectKey = req.Key,
        });
        await db.SaveChangesAsync(ct);

        await Send.OkAsync(new StorageResult(paradigm, true, decision.Reason, req.Key, req.Content), ct);
    }
}
```

- [ ] **Step 4: Create `src/Api/Endpoints/StorageListEndpoint.cs`**

```csharp
using Api.Auth;
using Api.Authz;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

// GET has no body — FastEndpoints instantiates this and binds from the query string, which needs
// a settable property (NOT an init-only positional record, which fails to bind at runtime).
public sealed class ListRequest { public string Prefix { get; set; } = ""; }

public sealed record ListResult(string Paradigm, bool Permit, string Reason, string Prefix, IReadOnlyList<string> Keys);

public sealed class StorageListEndpoint(AuthzConfigStore store, S3Gateway s3)
    : Endpoint<ListRequest, ListResult>
{
    public override void Configure()
    {
        Get("/storage/list");
        Policies("authenticated");
    }

    public override async Task HandleAsync(ListRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var decision = AuthzDispatcher.Decide(paradigm, new AuthzRequest(caller, StorageAction.List, req.Prefix), store.Current);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new ListResult(paradigm, false, decision.Reason, req.Prefix, []), 403, ct);
            return;
        }

        var keys = await s3.ListAsync(req.Prefix, ct);
        await Send.OkAsync(new ListResult(paradigm, true, decision.Reason, req.Prefix, keys), ct);
    }
}
```

- [ ] **Step 5: Verify build + tests**

Run: `source ~/.bash_profile && dotnet build src/Api && dotnet test tests/Api.Tests`
Expected: build succeeds; unit tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/Api/Endpoints/StorageReadEndpoint.cs src/Api/Endpoints/StorageWriteEndpoint.cs src/Api/Endpoints/StorageListEndpoint.cs
git commit -m "feat: storage read/write/list endpoints gated by selected paradigm"
```

- [ ] **Step 7: Smoke-test the FastEndpoints runtime paths early**

The per-task `dotnet build` only catches compile errors; the FE usages here (`Send.ResponseAsync(dto, 403, ct)`, header-selector binding, GET query binding) first execute at runtime. Confirm them now — before more endpoints depend on them — rather than discovering them all at Task 15. Requires the stack + API running (`bash scripts/dev-up.sh`; `dotnet run --project src/AppHost` in another shell; note the API base URL from the Aspire dashboard resource view).

```bash
source ~/.bash_profile
KC=http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token
API=<api-base-url-from-aspire-dashboard>
BOB=$(curl -s -d client_id=webapp -d grant_type=password -d username=bob -d password=bob -d scope=openid "$KC" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
# permit (bob editor writes projects/apollo/ under rbac) -> 200
curl -s -o /dev/null -w "write permit -> %{http_code}\n" -X POST "$API/storage/write" -H "Authorization: Bearer $BOB" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"projects/apollo/smoke.txt","content":"x"}'
# deny (bob has no finance write under rbac) -> 403
curl -s -o /dev/null -w "write deny   -> %{http_code}\n" -X POST "$API/storage/write" -H "Authorization: Bearer $BOB" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"finance/smoke.txt","content":"x"}'
# GET query binding on list -> 200
curl -s -o /dev/null -w "list        -> %{http_code}\n" "$API/storage/list?prefix=projects/apollo/" -H "Authorization: Bearer $BOB" -H "X-Authz-Paradigm: rbac"
```
Expected: `write permit -> 200`, `write deny -> 403`, `list -> 200`. If `list` is not 200, the `ListRequest` query binding is wrong — recheck it is a class with a settable `Prefix` (not a positional record).

(This is an interactive verification, not a commit step.)

Note for the future playground: the SP1 CORS policy only allows the `Authorization`/`Content-Type` request headers. `X-Authz-Paradigm` is server-side only in this spec (verify is curl/python), so no change is needed now — but a browser playground will need it added to the CORS `WithHeaders(...)`.

---

## Task 13: Config-surface endpoints

**Files:**
- Create: `src/Api/Endpoints/AuthzParadigmsEndpoint.cs`
- Create: `src/Api/Endpoints/AuthzConfigEndpoint.cs`

- [ ] **Step 1: Create `src/Api/Endpoints/AuthzParadigmsEndpoint.cs`**

```csharp
using Api.Authz;
using FastEndpoints;

namespace Api.Endpoints;

public sealed class AuthzParadigmsEndpoint : EndpointWithoutRequest<IReadOnlyList<string>>
{
    public override void Configure()
    {
        Get("/authz/paradigms");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct) =>
        await Send.OkAsync(AuthzDispatcher.Paradigms, ct);
}
```

- [ ] **Step 2: Create `src/Api/Endpoints/AuthzConfigEndpoint.cs`**

```csharp
using Api.Auth;
using Api.Authz;
using FastEndpoints;

namespace Api.Endpoints;

// Exposes the admin's config artifact for a paradigm — the "burden" the showcase points at. The
// three DB-backed paradigms return their seeded config; claim-based returns a pointer to Keycloak
// plus the caller's live grant claim, because its config lives in the IdP, not our DB.
public sealed class AuthzConfigEndpoint(AuthzConfigStore store) : EndpointWithoutRequest<object>
{
    public override void Configure()
    {
        Get("/authz/{paradigm}/config");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var paradigm = Route<string>("paradigm") ?? "";
        object? body = paradigm switch
        {
            "rbac" => store.Current.Rbac,
            "abac" => store.Current.Abac,
            "acl" => store.Current.Acl,
            "claims" => new
            {
                source = "keycloak",
                note = "config lives in the IdP claim mapper; the app trusts the token",
                callerGrants = CallerClaims.FromPrincipal(User).StorageGrants,
            },
            _ => null,
        };

        if (body is null)
        {
            await Send.NotFoundAsync(ct);
            return;
        }

        await Send.OkAsync(body, ct);
    }
}
```

- [ ] **Step 3: Verify build + tests**

Run: `source ~/.bash_profile && dotnet build src/Api && dotnet test tests/Api.Tests`
Expected: build succeeds; unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/Api/Endpoints/AuthzParadigmsEndpoint.cs src/Api/Endpoints/AuthzConfigEndpoint.cs
git commit -m "feat: /authz/paradigms + /authz/{paradigm}/config surface endpoints"
```

---

## Task 14: Extend the Keycloak realm (users, attributes, claim mappers)

**Files:**
- Modify: `src/AppHost/realms/authn-authz-realm.json`

Goal: the §4 roster (alice, bob, carol, dave, erin) each with `department` + `level` attributes and a `storage_grants` attribute; protocol mappers on the `webapp` client that put `department`, `level`, and the multivalued `storage_grants` into the **access token**; and `directAccessGrantsEnabled: true` on `webapp` so the verify script can fetch tokens by password grant.

- [ ] **Step 1: Read the current realm file** to see the exact `users`, `clients`, and `protocolMappers` shapes.

Run: `source ~/.bash_profile && sed -n '1,200p' src/AppHost/realms/authn-authz-realm.json` — locate the `webapp` client block and the `users` array.

- [ ] **Step 2: On the `webapp` client**, set `"directAccessGrantsEnabled": true` and add these entries to its `protocolMappers` array (keep the existing audience mapper):

```json
{
  "name": "department",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "department",
    "claim.name": "department",
    "jsonType.label": "String",
    "access.token.claim": "true",
    "id.token.claim": "false",
    "userinfo.token.claim": "false"
  }
},
{
  "name": "level",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "level",
    "claim.name": "level",
    "jsonType.label": "String",
    "access.token.claim": "true",
    "id.token.claim": "false",
    "userinfo.token.claim": "false"
  }
},
{
  "name": "storage_grants",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "storage_grants",
    "claim.name": "storage_grants",
    "jsonType.label": "String",
    "multivalued": "true",
    "access.token.claim": "true",
    "id.token.claim": "false",
    "userinfo.token.claim": "false"
  }
}
```

- [ ] **Step 3: Replace the `users` array** so all five exist with credentials + attributes. Attributes are arrays (Keycloak stores multivalued attributes); `storage_grants` carries the per-user grants (spec §4):

```json
"users": [
  {
    "username": "alice", "enabled": true, "email": "alice@example.com",
    "credentials": [{ "type": "password", "value": "alice", "temporary": false }],
    "attributes": { "department": ["finance"], "level": ["2"], "storage_grants": ["r:finance/"] }
  },
  {
    "username": "bob", "enabled": true, "email": "bob@example.com",
    "credentials": [{ "type": "password", "value": "bob", "temporary": false }],
    "attributes": { "department": ["engineering"], "level": ["3"], "storage_grants": ["rw:projects/apollo/"] }
  },
  {
    "username": "carol", "enabled": true, "email": "carol@example.com",
    "credentials": [{ "type": "password", "value": "carol", "temporary": false }],
    "attributes": { "department": ["hr"], "level": ["1"], "storage_grants": ["r:hr/"] }
  },
  {
    "username": "dave", "enabled": true, "email": "dave@example.com",
    "credentials": [{ "type": "password", "value": "dave", "temporary": false }],
    "attributes": { "department": ["it"], "level": ["4"], "storage_grants": ["rw:*"] }
  },
  {
    "username": "erin", "enabled": true, "email": "erin@example.com",
    "credentials": [{ "type": "password", "value": "erin", "temporary": false }],
    "attributes": { "department": ["finance"], "level": ["3"], "storage_grants": ["rw:finance/"] }
  }
]
```

> Note: preserve the realm's existing `clientScopes`/`roles`/`storage-service` client. Realm roles are informational here (evaluators use DB assignments), so existing `realmRoles` on users may be dropped or kept — keep them if present to avoid import churn.

- [ ] **Step 4: Restart the stack so Keycloak re-imports** and confirm a token carries the new claims:

```bash
bash scripts/dev-up.sh
# fetch an access token for bob via direct grant and inspect its claims:
source ~/.bash_profile
BOB=$(curl -s -d client_id=webapp -d grant_type=password -d username=bob -d password=bob -d scope=openid \
  http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
python3 -c "import base64,json,sys;p=sys.argv[1].split('.')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'==')),indent=2))" "$BOB"
```
Expected: the decoded payload shows `"department": "engineering"`, `"level": "3"`, `"storage_grants": ["rw:projects/apollo/"]`, and `aud` including `api`.

- [ ] **Step 5: Commit**

```bash
git add src/AppHost/realms/authn-authz-realm.json
git commit -m "feat: realm — roster attributes + storage_grants/department/level access-token mappers"
```

---

## Task 15: Scripted integration verify against the live stack

**Files:**
- Create: `scripts/verify-authz.py`

Follows SP1's committed-script verification pattern (real Keycloak tokens, real Ceph — no mocks). Asserts each paradigm's sweet-spot scenario end to end.

- [ ] **Step 1: Ensure the stack + API are up**

```bash
bash scripts/dev-up.sh
source ~/.bash_profile && dotnet run --project src/AppHost   # in a separate shell
# Read the API base URL from the Aspire dashboard's resource view (the "api" resource endpoint) —
# Aspire assigns a dynamic port, so don't assume :5000.
```

- [ ] **Step 2: Create `scripts/verify-authz.py`** (set `API` to the API base URL Aspire assigns):

```python
#!/usr/bin/env python3
"""End-to-end authz verify: each paradigm's sweet-spot scenario against the live stack."""
import json, sys, urllib.request

KC = "http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token"
API = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

def token(user):
    data = f"client_id=webapp&grant_type=password&username={user}&password={user}&scope=openid".encode()
    req = urllib.request.Request(KC, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    return json.load(urllib.request.urlopen(req))["access_token"]

def call(method, path, tok, paradigm, body=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                 "X-Authz-Paradigm": paradigm})
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

# (user, paradigm, method, path, body, expect_permit)
CASES = [
    # RBAC: editor writes projects/, viewer cannot
    ("bob",   "rbac",   "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, True),
    ("carol", "rbac",   "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, False),
    # ABAC: rw under own department; deny another department
    ("alice", "abac",   "POST", "/storage/write", {"key": "finance/a.txt", "content": "x"}, True),
    ("alice", "abac",   "POST", "/storage/write", {"key": "engineering/a.txt", "content": "x"}, False),
    ("bob",   "abac",   "POST", "/storage/read",  {"key": "hr/records.txt"}, True),   # level 3
    ("alice", "abac",   "POST", "/storage/read",  {"key": "hr/records.txt"}, False),  # level 2
    # Claims: token grant governs
    ("bob",   "claims", "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, True),
    ("bob",   "claims", "POST", "/storage/write", {"key": "finance/a.txt", "content": "x"}, False),
    # ACL: named principal + wildcard read
    ("bob",   "acl",    "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, True),
    ("carol", "acl",    "POST", "/storage/read",  {"key": "shared/notes.txt"}, True),  # wildcard read
    ("carol", "acl",    "POST", "/storage/write", {"key": "shared/notes.txt", "content": "x"}, False),
]

fails = 0
for user, paradigm, method, path, body, expect in CASES:
    status, resp = call(method, path, token(user), paradigm, body)
    permit = resp.get("permit", status == 200)
    ok = permit == expect and (status == 200 if expect else status == 403)
    print(f"{'PASS' if ok else 'FAIL'}  {user:6} {paradigm:6} {path:16} -> {status} permit={permit} (want {expect}) :: {resp.get('reason','')}")
    fails += 0 if ok else 1

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
```

- [ ] **Step 3: Seed a couple of read targets** the READ cases expect to exist (writes create their own targets; reads need seeded objects). Using dave (rw:* / admin) to place them:

```bash
source ~/.bash_profile
DAVE=$(curl -s -d client_id=webapp -d grant_type=password -d username=dave -d password=dave -d scope=openid "$KC" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST "$API/storage/write" -H "Authorization: Bearer $DAVE" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"hr/records.txt","content":"seed"}'
curl -s -X POST "$API/storage/write" -H "Authorization: Bearer $DAVE" -H "X-Authz-Paradigm: rbac" -H "Content-Type: application/json" -d '{"key":"shared/notes.txt","content":"seed"}'
```
(Set `KC` and `API` env vars to match the script constants first.)

- [ ] **Step 4: Run the verify script**

Run: `python3 scripts/verify-authz.py <API-base-url>`
Expected: every line `PASS`, final line `ALL PASS`.

- [ ] **Step 5: Commit**

```bash
git add scripts/verify-authz.py
git commit -m "test: scripted end-to-end authz verify across all four paradigms"
```

---

## Task 16: Update run docs

**Files:**
- Modify: `docs/superpowers/notes/` (add a short SP2 run note) or the existing run doc if one exists.

- [ ] **Step 1: Write `docs/superpowers/notes/2026-07-02-authz-paradigms-run.md`** capturing: how to run (`scripts/dev-up.sh` + `dotnet run --project src/AppHost`; read the API URL from the Aspire dashboard resource view), the four paradigms + the `X-Authz-Paradigm` selector header (default `rbac`), the seeded roster/config, how to run `scripts/verify-authz.py`, and the note that a future browser playground must add `X-Authz-Paradigm` to the API's CORS `WithHeaders(...)` (server-side callers don't need it). Keep it short and factual.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/notes/2026-07-02-authz-paradigms-run.md
git commit -m "docs: SP2 run + verify notes"
```

---

## Self-Review

**Spec coverage:**
- §1 arbitrary prefixes / kill username coupling — Task 12 deletes `StorageRoundtripEndpoint`; endpoints take caller-supplied keys. ✓
- §3 thin seam + pure evaluators + separate config-load seam — Tasks 2–7, 9. ✓
- §4 one shared world (roster + namespace) — Task 10 seed + Task 13 realm. ✓
- §5 four paradigms + config homes + one prefix-match rule — Tasks 2 (match), 3–6 (evaluators), 10 (seed), 13 (claims in Keycloak). ✓
- §6 read/write/list + `/authz/paradigms` + `/authz/{paradigm}/config` + selector default + 403+reason — Tasks 11–13. ✓
- §7 EF entities seeded on migrate; repositories→structs; realm mapper — Tasks 8–11, 13. ✓
- §8 DoD: selectable per request, sweet-spot enforcement end-to-end, config surface, unit + scripted integration — Tasks 7, 12, 13, 15. ✓
- §9 pure-data unit tests, no DbContext; scripted integration — Tasks 3–7, 9 (unit), 15 (integration). ✓

**Placeholder scan:** No TBD/TODO. Task 13 realm edits reference reading the current file first (its exact surrounding JSON isn't reproduced because it's environment state to preserve, not code to author) — the mapper/user JSON to add is given in full. Task 14/15 `API` base URL is a runtime value from Aspire, passed as an argument, not a placeholder.

**Type consistency:** `StorageAction{Read,Write,List}`, `AuthzRequest(Caller,Action,Resource)`, `AuthzDecision(Permit,Reason,Paradigm)`, `RbacConfig(UserRoles,Permissions)`, `RolePermission(Role,Prefix,Actions)`, `AbacConfig(Rules)`, `AbacRule(Conditions,PrefixTemplate,Actions)`, `AttrPredicate(Attribute,Op,Value)`, `AclConfig(Entries)`, `AclEntry(Prefix,Principal,Actions)`, `AuthzConfig(Rbac,Abac,Acl)`, `AuthzConfigStore.Current/Load/ParseActions/ParseConditions`, `AuthzDispatcher.Resolve/Decide/Paradigms/Default` — all used consistently across tasks. Evaluator signatures match dispatcher calls (claims takes no config; the other three take their config slice). `StorageResult` shared by read/write; `ListResult` for list.

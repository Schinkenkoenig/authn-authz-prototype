# Authz Phase 2 Review Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the ReBAC silent-deny observability gap (SP3 open point #4), then extend the live
verify matrix with edge/negative cases and a cross-paradigm consistency table, per
`docs/superpowers/specs/2026-07-05-authz-review-pass-design.md`.

**Architecture:** No new paradigms, endpoints, or seam changes. One small pure-code change
(`RebacSeeder`/`RebacEvaluator`) unit-tested with TDD, then two additions to the existing
`scripts/verify-authz.py` e2e script (more `CASES`, plus a new observational `COMPARISON` block),
verified against the live stack.

**Tech Stack:** C#/.NET 10 (xunit), Python 3 (`scripts/verify-authz.py`), real Keycloak + Ceph +
OpenFGA + OPA + cedar-agent (no mocks in the e2e layer).

---

### Task 1: `RebacSeeder.ModeledPrefixes`

**Files:**
- Modify: `src/Api/Authz/RebacSeeder.cs`
- Test: `tests/Api.Tests/RebacMappingTests.cs`

- [ ] **Step 1: Write the failing test**

Add to `tests/Api.Tests/RebacMappingTests.cs` (inside the existing `RebacMappingTests` class, after
`User_name_maps_to_user_object`):

```csharp
    [Fact]
    public void ModeledPrefixes_contains_every_prefix_wired_into_a_tuple()
    {
        var expected = new HashSet<string>
        {
            "prefix:projects/",
            "prefix:projects/apollo/",
            "prefix:projects/apollo/specs/",
            "prefix:shared/",
        };
        Assert.Equal(expected, RebacSeeder.ModeledPrefixes);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --filter "FullyQualifiedName~RebacMappingTests"`
Expected: FAIL (compile error) — `'RebacSeeder' does not contain a definition for 'ModeledPrefixes'`.

- [ ] **Step 3: Write minimal implementation**

In `src/Api/Authz/RebacSeeder.cs`, add after the `Tuples` property (`ImplicitUsings` is enabled,
so `System.Linq` needs no `using`):

```csharp
    // Every prefix object that appears anywhere in the seeded graph (either side of a tuple).
    // A resource whose containing prefix falls outside this set was never wired into the graph —
    // its Check() result is a coverage gap, not a policy decision. See RebacEvaluator.
    public static readonly IReadOnlySet<string> ModeledPrefixes = Tuples
        .SelectMany(t => new[] { t.User, t.Object })
        .Where(s => s.StartsWith("prefix:", StringComparison.Ordinal))
        .ToHashSet();
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test --filter "FullyQualifiedName~RebacMappingTests"`
Expected: PASS (5 tests now, all green).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/RebacSeeder.cs tests/Api.Tests/RebacMappingTests.cs
git commit -m "feat: compute the set of ReBAC prefixes actually wired into the seeded graph"
```

---

### Task 2: `RebacEvaluator` distinguishes unmodeled-depth denies

**Files:**
- Modify: `src/Api/Authz/RebacEvaluator.cs`
- Test: `tests/Api.Tests/RebacMappingTests.cs`

- [ ] **Step 1: Write the failing tests**

Add to `tests/Api.Tests/RebacMappingTests.cs`. First add `using Api.Auth;` to the top of the file
(alongside the existing `using Api.Authz;`). Then add, inside the `RebacMappingTests` class:

```csharp
    sealed class StubRebac(bool allowed) : IRebacClient
    {
        public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
            Task.FromResult(allowed);
    }

    static CallerClaims Caller(string name) =>
        new("sub", name, [], new Dictionary<string, string>(), []);

    [Fact]
    public async Task Deny_reason_for_a_modeled_prefix_says_the_user_lacks_the_relation()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("carol"), StorageAction.Write, "projects/apollo/a.txt",
            new StubRebac(false), CancellationToken.None);

        Assert.False(d.Permit);
        Assert.Equal("OpenFGA: user:carol lacks editor on prefix:projects/apollo/", d.Reason);
    }

    [Fact]
    public async Task Deny_reason_for_an_unmodeled_prefix_flags_it_as_a_coverage_gap()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("bob"), StorageAction.Write, "projects/apollo/specs/deep/nested.txt",
            new StubRebac(false), CancellationToken.None);

        Assert.False(d.Permit);
        Assert.Equal(
            "OpenFGA: prefix:projects/apollo/specs/deep/ has no seeded tuple at this depth (unmodeled — not a policy decision)",
            d.Reason);
    }

    [Fact]
    public async Task Permit_reason_is_unchanged()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("carol"), StorageAction.Read, "projects/apollo/a.txt",
            new StubRebac(true), CancellationToken.None);

        Assert.True(d.Permit);
        Assert.Equal("OpenFGA: user:carol has viewer on prefix:projects/apollo/", d.Reason);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test --filter "FullyQualifiedName~RebacMappingTests"`
Expected: FAIL — `Deny_reason_for_an_unmodeled_prefix_flags_it_as_a_coverage_gap` fails because the
current reason string is `"OpenFGA: user:bob lacks editor on prefix:projects/apollo/specs/deep/"`
(no "unmodeled" wording yet). The other two should already pass against current code — that's
expected; only the new branch is under test.

- [ ] **Step 3: Write minimal implementation**

Replace the body of `EvaluateAsync` in `src/Api/Authz/RebacEvaluator.cs`:

```csharp
    public static async Task<AuthzDecision> EvaluateAsync(
        CallerClaims caller, StorageAction action, string resource, IRebacClient client, CancellationToken ct)
    {
        var user = UserObject(caller.Name);
        var relation = RelationFor(action);
        var obj = PrefixObject(resource);

        var allowed = await client.CheckAsync(user, relation, obj, ct);
        if (allowed)
            return new(true, $"OpenFGA: {user} has {relation} on {obj}", "rebac");

        var reason = RebacSeeder.ModeledPrefixes.Contains(obj)
            ? $"OpenFGA: {user} lacks {relation} on {obj}"
            : $"OpenFGA: {obj} has no seeded tuple at this depth (unmodeled — not a policy decision)";
        return new(false, reason, "rebac");
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test --filter "FullyQualifiedName~RebacMappingTests"`
Expected: PASS (8 tests now, all green).

- [ ] **Step 5: Commit**

```bash
git add src/Api/Authz/RebacEvaluator.cs tests/Api.Tests/RebacMappingTests.cs
git commit -m "fix: distinguish ReBAC denies at unmodeled path depths from real policy denies"
```

---

### Task 3: Full unit-test suite regression check

**Files:** none (verification only)

- [ ] **Step 1: Run the full suite**

Run: `dotnet test`
Expected: PASS, 72/72 (69 existing + 3 new).

- [ ] **Step 2: If anything other than the 3 new tests changed status, stop and investigate**

Do not proceed to Task 4 until the full suite is clean — this is the regression gate before
touching the e2e script.

---

### Task 4: `verify-authz.py` — edge/negative cases

**Files:**
- Modify: `scripts/verify-authz.py`

- [ ] **Step 1: Add the new cases**

In `scripts/verify-authz.py`, insert the following block into the `CASES` list, immediately before
the closing `]` (i.e. after the existing `list has no scenario rule...` cases):

```python
    # --- Phase 2 review pass: edge/negative cases ---
    # (see docs/superpowers/specs/2026-07-05-authz-review-pass-design.md)
    # Correct-prefix-wrong-action: the resource matches, the specific action doesn't.
    ("carol", "rbac",  "POST", "/storage/write", {"key": "shared/notes.txt", "content": "x"}, False),  # viewer: Read,List on shared/, not Write
    ("dave",  "abac",  "POST", "/storage/read",  {"key": "hr/records.txt"}, True),                      # level 4 >= 3 grants Read
    ("dave",  "abac",  "POST", "/storage/write", {"key": "hr/records.txt", "content": "x"}, False),     # level rule has no Write; dept 'it' != hr/
    # Prefix-subtree boundary: same top segment, different subtree.
    ("bob",   "claims", "POST", "/storage/read", {"key": "projects/other/x.txt"}, False),               # grant is rw:projects/apollo/, not projects/
    # Identity-vs-attribute divergence: alice's department matches finance/ but she is not on the ACL.
    ("alice", "acl",   "POST", "/storage/write", {"key": "finance/a.txt", "content": "x"}, False),      # only erin is listed for finance/
    # Unmodeled depth: exercises the ReBAC observability fix (reason should say "unmodeled").
    ("bob",   "rebac", "POST", "/storage/write", {"key": "projects/apollo/specs/deep/nested.txt", "content": "x"}, False),
    # Header-without-role: the break-glass flag alone isn't enough without the incident_responder
    # role. NOTE: must use a caller who ALSO fails plain clearance (level < 3) — otherwise the
    # ordinary clearance rule permits regardless of the header, and the case tests nothing. alice
    # is level 2 with no incident_responder role, so both rule 1 (clearance) and rule 3
    # (break-glass) correctly fail here. (dave is level 4 and would wrongly permit via rule 1
    # alone, masking whether the header/role combination is doing anything.)
    ("alice", "opa",   "POST", "/storage/read", {"key": "classified/x"}, False, {"X-Break-Glass": "true"}),
    ("alice", "cedar", "POST", "/storage/read", {"key": "classified/x"}, False, {"X-Break-Glass": "true"}),
    # Untested classification tier: 'internal' (level 2) had no read case at all.
    ("alice", "opa",   "POST", "/storage/read", {"key": "internal/x"}, True),                           # level 2 >= 2, exact boundary
    ("carol", "opa",   "POST", "/storage/read", {"key": "internal/x"}, False),                          # level 1 < 2
    ("alice", "cedar", "POST", "/storage/read", {"key": "internal/x"}, True),
    ("carol", "cedar", "POST", "/storage/read", {"key": "internal/x"}, False),
```

- [ ] **Step 2: Syntax-check the script**

Run: `python3 -m py_compile scripts/verify-authz.py`
Expected: no output, exit code 0. **Then run `git status` before the next commit** — `py_compile`
writes `scripts/__pycache__/`, which must NOT be staged (this bit SP4; `.gitignore` now excludes
it, but verify with `git status` anyway).

- [ ] **Step 3: Commit**

```bash
git status
git add scripts/verify-authz.py
git commit -m "test: add edge/negative authz cases (action boundaries, unmodeled ReBAC depth, break-glass without role)"
```

(Running the new cases against the live stack happens in Task 6, once Task 5's comparison block
is also in place — one live run covers both additions.)

---

### Task 5: `verify-authz.py` — cross-paradigm consistency table

**Files:**
- Modify: `scripts/verify-authz.py`

- [ ] **Step 1: Add the comparison block**

Insert this block into `scripts/verify-authz.py` after the `print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")` line and before `sys.exit(1 if fails else 0)`:

```python
# Cross-paradigm consistency (informational only — does not affect the exit code). Same
# (user, action, resource) tuple run through every paradigm's OWN existing demo data — NOT the
# apples-to-apples scenario (that's separate future work, one fixed scenario authored identically
# under every paradigm). Differences here are expected; each row is annotated with why, so a
# difference can be checked against that paradigm's own model instead of assumed to be a bug.
COMPARISON = [
    ("alice", "POST", "/storage/write", {"key": "finance/a.txt", "content": "x"},
     "alice: finance dept, level 2. Only ABAC permits (own-department rule). RBAC (auditor is "
     "read-only), Claims (grant is r:finance/, read-only), ACL (only erin is listed for "
     "finance/), ReBAC (finance/ was never modeled here), and OPA/Cedar (the department derived "
     "from this path shape doesn't match alice's) all deny."),
    ("carol", "POST", "/storage/read", {"key": "shared/notes.txt"},
     "carol: hr dept, level 1. RBAC (viewer covers shared/), ACL (wildcard * on shared/), ReBAC "
     "(user:* viewer wildcard tuple), and OPA/Cedar (default public classification, level 1 >= "
     "1) all permit. ABAC (no rule covers shared/) and Claims (grant is r:hr/) deny — neither "
     "has a concept of public access outside its own modeled prefixes."),
]

print("\n=== Cross-paradigm consistency (informational, not pass/fail) ===")
for user, method, path, body, annotation in COMPARISON:
    print(f"\n{user} {method} {path} {body}\n  {annotation}")
    tok = token(user)
    for paradigm in ["rbac", "abac", "claims", "acl", "rebac", "opa", "cedar"]:
        status, resp = call(method, path, tok, paradigm, body)
        permit = resp.get("permit", status == 200)
        print(f"  {paradigm:8} permit={permit!s:5} {resp.get('reason', '')}")
```

- [ ] **Step 2: Syntax-check the script**

Run: `python3 -m py_compile scripts/verify-authz.py`
Expected: no output, exit code 0. **Run `git status` before committing** (same `__pycache__`
caveat as Task 4).

- [ ] **Step 3: Commit**

```bash
git status
git add scripts/verify-authz.py
git commit -m "test: add cross-paradigm consistency table to verify-authz.py"
```

---

### Task 6: Live verification against the real stack

**Files:**
- Create: `docs/superpowers/notes/2026-07-05-authz-review-pass-run.md`

- [ ] **Step 1: Bring up infra**

Run: `bash scripts/dev-up.sh`
Expected: Keycloak, Ceph, OpenFGA, OPA, cedar-agent, webid-refresher all report healthy.

- [ ] **Step 2: Start a temp Postgres + the API standalone (fast-verify pattern)**

```bash
docker run -d --name sp5-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16
```

Then, in a separate terminal/background process:

```bash
ASPNETCORE_ENVIRONMENT=Development \
ConnectionStrings__appdb="Host=localhost;Port=5433;Database=appdb;Username=postgres;Password=postgres" \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198
```

Expected: API starts cleanly, logs show successful provisioning against OpenFGA/OPA/cedar-agent
(fail-fast on any provisioning error — if it throws, stop and root-cause before continuing).

- [ ] **Step 3: Run the verify script**

Run: `python3 scripts/verify-authz.py http://127.0.0.1:5198`
Expected: every `CASES` row prints `PASS`, ending in `ALL PASS`. Then the
`=== Cross-paradigm consistency ===` section prints both rows across all 7 paradigms.

- [ ] **Step 4: Check the two new things by hand**

1. Find the `bob rebac write .../deep/nested.txt` line in the `CASES` output — confirm its printed
   reason contains `unmodeled`.
2. Compare the `COMPARISON` output against the expected spread in Task 5's annotations (and the
   design spec's Section 3). If any paradigm's actual decision doesn't match the annotation,
   **stop and root-cause it** — either the annotation's reasoning was wrong (fix the annotation,
   it's just a comment) or the paradigm's behavior is a real bug (do not paper over it; raise it).

- [ ] **Step 5: Tear down the fast-verify scaffolding**

```bash
docker rm -f sp5-pg
```
Kill the standalone `dotnet run` process. Leave the fixed-IP infra (kc-spike, ceph-demo, openfga,
opa, cedar-agent, webid-refresher) up.

- [ ] **Step 6: Write the run note**

Create `docs/superpowers/notes/2026-07-05-authz-review-pass-run.md`:

```markdown
# Authz Phase 2 review pass — run & verify note

## What it adds

Fixes the SP3-flagged ReBAC silent-deny sharp edge (a resource at a path depth never wired into
the seeded relationship graph denied indistinguishably from a real policy deny) — the deny reason
now says so explicitly. Adds edge/negative test cases across all 7 paradigms and a cross-paradigm
consistency table to `scripts/verify-authz.py`. See the
[design spec](../specs/2026-07-05-authz-review-pass-design.md).

## Run (full stack)

\`\`\`bash
bash scripts/dev-up.sh
dotnet run --project src/AppHost
\`\`\`

## Fast verify (standalone API, no Aspire)

\`\`\`bash
bash scripts/dev-up.sh
docker run -d --name sp5-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb postgres:16

ASPNETCORE_ENVIRONMENT=Development \
ConnectionStrings__appdb="Host=localhost;Port=5433;Database=appdb;Username=postgres;Password=postgres" \
AWS_ROLE_ARN=arn:aws:iam:::role/DemoService AWS_WEB_IDENTITY_TOKEN_FILE=/tmp/webid/token \
AWS_ROLE_SESSION_NAME=storage-service AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL_STS=http://172.30.0.10:8080 \
dotnet run --project src/Api --no-launch-profile --urls http://127.0.0.1:5198

python3 scripts/verify-authz.py http://127.0.0.1:5198
\`\`\`

## Result (2026-07-05)

- `dotnet test` → **[fill in actual count]/[fill in actual count]** (3 new: ModeledPrefixes,
  modeled-vs-unmodeled deny reason, permit reason regression).
- `verify-authz.py` → **[fill in actual count]/[fill in actual count] ALL PASS**, including the 12
  new edge/negative cases, against real Keycloak + Ceph + OpenFGA + OPA + cedar-agent.
- Cross-paradigm consistency table: [fill in — confirm both rows matched the expected spread in
  the design spec, or note what didn't and how it was resolved].

## Notes / gotchas

- [fill in anything encountered during this run that isn't already covered by prior run notes]

## Teardown

\`\`\`bash
docker rm -f sp5-pg
\`\`\`
Fixed-IP infra (kc-spike, ceph-demo, openfga, opa, cedar-agent, webid-refresher) left up.
```

Fill in the bracketed placeholders with the actual results from Steps 3–4 before committing — this
is the one place in this plan where the content depends on live output that doesn't exist until
you run it.

- [ ] **Step 7: Commit**

```bash
git add docs/superpowers/notes/2026-07-05-authz-review-pass-run.md
git commit -m "docs: Phase 2 authz review-pass run note"
```

---

### Task 7: Update memory

**Files:** none in the repo — this updates the persistent memory store, not tracked by git.

- [ ] **Step 1: Update `subproject-3-rebac-status.md`**

Mark open point #4 as resolved: the deny reason now distinguishes unmodeled path depths from real
policy denies (still denies either way — behavior unchanged, diagnosability improved). Link to
this plan's spec and run note.

- [ ] **Step 2: Create or update a `subproject-5-authz-review-pass-status.md` memory**

Summarize: what shipped (ReBAC fix + edge cases + consistency table), verified counts, and that
Phase 2 is done. Note Phase 3 (dynamic config + provisioning-during-deployment,
wiki/playground) is next per the standing plan.

- [ ] **Step 3: Update `MEMORY.md` index and `authz-followons-and-learnings.md`**

Add the new status memory to the index; mark Phase 2 as done in the phased-plan note.

---

## Self-review notes

- Every spec section (1: ReBAC fix, 2: edge cases, 3: comparison table) maps to a task (2, 4, 5).
  Out-of-scope items are explicitly not tasked.
- Type/signature consistency checked against current code: `RebacEvaluator.EvaluateAsync` params,
  `CallerClaims` constructor order, `IRebacClient.CheckAsync` signature, and `AuthzDecision`
  field order (`Permit, Reason, Paradigm`) all match what's actually in the repo, not assumed.
- All expected values (RBAC roles/permissions, ABAC rules, ACL entries, Keycloak user attributes,
  ReBAC tuples, PaC classification/department derivation) were checked against the real seed data
  (`AuthzSeeder.cs`, `RebacSeeder.cs`, `authn-authz-realm.json`, `PolicyInput.cs`) rather than
  invented, so Task 4/5's expected outcomes should hold on the first live run — but Task 6 Step 4
  is the actual gate, not this plan's arithmetic.

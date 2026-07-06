#!/usr/bin/env python3
"""End-to-end authz verify: each paradigm's sweet-spot scenario against the live stack.

Usage: python3 scripts/verify-authz.py <API-base-url>
The API base URL is assigned dynamically by Aspire — read it from the dashboard resource view.
Requires the stack (scripts/dev-up.sh) + the API (dotnet run --project src/AppHost) to be up,
and the seed read-targets to exist (see the run note)."""
import json, sys, urllib.request, urllib.error

KC = "http://172.30.0.20:8080/realms/authn-authz/protocol/openid-connect/token"
API = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

def token(user):
    data = f"client_id=webapp&grant_type=password&username={user}&password={user}&scope=openid".encode()
    req = urllib.request.Request(KC, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    return json.load(urllib.request.urlopen(req))["access_token"]

def call(method, path, tok, paradigm, body=None, extra=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    # Only advertise a JSON body when one is sent: a bodyless GET with Content-Type: application/json
    # makes FastEndpoints attempt (and fail) body binding → 400.
    headers = {"Authorization": f"Bearer {tok}", "X-Authz-Paradigm": paradigm}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
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
    # ReBAC (OpenFGA): relationship graph — inheritance + group membership are the character.
    ("carol", "rebac",  "POST", "/storage/read",  {"key": "projects/apollo/specs/design.md"}, True),        # viewer on projects/ inherited down the hierarchy
    ("carol", "rebac",  "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, False),  # viewer only, not editor
    ("bob",   "rebac",  "POST", "/storage/write", {"key": "projects/apollo/a.txt", "content": "x"}, True),   # eng team editor, inherited
    ("dave",  "rebac",  "POST", "/storage/read",  {"key": "projects/apollo/a.txt"}, False),                 # no grant, not in team
    ("alice", "rebac",  "POST", "/storage/write", {"key": "projects/apollo/x.txt", "content": "x"}, True),   # owner of apollo => editor
    ("dave",  "rebac",  "POST", "/storage/read",  {"key": "shared/notes.txt"}, True),                       # public read (user:*)
    # OPA/Rego (policy-as-code): clearance, department, frozen-deny-override, break-glass.
    ("bob",   "opa", "POST", "/storage/read",  {"key": "classified/x"}, True),                       # level3 >= 3
    ("alice", "opa", "POST", "/storage/read",  {"key": "classified/x"}, False),                      # level2 < 3
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/finance/y", "content": "x"}, True), # finance owns, level3>=2
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/eng/y", "content": "x"}, False),    # not owner dept
    ("erin",  "opa", "POST", "/storage/write", {"key": "internal/finance/frozen/y", "content": "x"}, False), # frozen forbids
    ("carol", "opa", "POST", "/storage/read",  {"key": "classified/x"}, True,  {"X-Break-Glass": "true"}),  # break-glass
    ("carol", "opa", "POST", "/storage/read",  {"key": "classified/x"}, False),                      # no flag → deny
    # Cedar (policy-as-code): identical scenario, judged by cedar-agent.
    ("bob",   "cedar", "POST", "/storage/read",  {"key": "classified/x"}, True),
    ("alice", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, False),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/finance/y", "content": "x"}, True),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/eng/y", "content": "x"}, False),
    ("erin",  "cedar", "POST", "/storage/write", {"key": "internal/finance/frozen/y", "content": "x"}, False),
    ("carol", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, True,  {"X-Break-Glass": "true"}),
    ("carol", "cedar", "POST", "/storage/read",  {"key": "classified/x"}, False),
    # list has no scenario rule under policy-as-code → deny (403 before touching S3, no unknown-action 500).
    ("bob",   "opa",   "GET",  "/storage/list",  None, False),
    ("bob",   "cedar", "GET",  "/storage/list",  None, False),
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
    ("alice", "cedar", "POST", "/storage/read", {"key": "internal/x"}, True),                            # level 2 >= 2, exact boundary
    ("carol", "cedar", "POST", "/storage/read", {"key": "internal/x"}, False),                           # level 1 < 2
]

fails = 0
for case in CASES:
    user, paradigm, method, path, body, expect = case[:6]
    extra = case[6] if len(case) > 6 else None
    status, resp = call(method, path, token(user), paradigm, body, extra)
    permit = resp.get("permit", status == 200)
    ok = permit == expect and (status == 200 if expect else status == 403)
    print(f"{'PASS' if ok else 'FAIL'}  {user:6} {paradigm:6} {path:16} -> {status} permit={permit} (want {expect}) :: {resp.get('reason','')}")
    fails += 0 if ok else 1

print(f"\n{'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")

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

sys.exit(1 if fails else 0)

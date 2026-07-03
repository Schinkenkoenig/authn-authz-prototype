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
sys.exit(1 if fails else 0)

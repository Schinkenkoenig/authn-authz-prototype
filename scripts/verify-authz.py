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

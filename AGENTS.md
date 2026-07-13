# authn-authz

A testbed that implements the **same** storage-access decision under **seven interchangeable
authorization paradigms**, so their configuration burden and expressiveness can be compared
hands-on. The caller picks a paradigm per request; the decision gates real object I/O against a real
Ceph S3 backend, behind a real Keycloak login.

This is a **comparison showcase, not a production access-control system.** Read
[ADR 0005](docs/adr/0005-caller-selected-paradigm-union-access.md) before you reason about its
security posture — effective access is the UNION across paradigms by design.

## Where to look

- **Domain vocabulary** → [CONTEXT.md](CONTEXT.md) — the glossary. Read it before naming things.
- **Why it's shaped this way** → [docs/adr/](docs/adr/) — the architectural decisions and their trade-offs.
- **What each paradigm is and how it's configured** → [docs/authz-paradigms.md](docs/authz-paradigms.md).
- **Per-subproject history** (specs, plans, run notes) → [docs/superpowers/](docs/superpowers/).
- **The SPA** has its own [src/web/AGENTS.md](src/web/AGENTS.md) — heed it; that Next.js is not the one you know.

## Merging → pull requests only

**All merges to `main` go through a pull request** — never merge locally into `main` or push to it
directly, even for docs-only changes. Branch, push, `gh pr create`, merge the PR.

## Agent memory → collector issue

The agent keeps project memory in a private, per-user store outside the repo. A single tracker issue —
**[Agent memory collector #7](https://github.com/Schinkenkoenig/authn-authz-prototype/issues/7)** —
holds a lightweight **index** of it (one line per memory), so what the memory covers is visible in the
repo. **When you add, rename, or delete a memory, add/update/remove its line in #7 in the same
session.** Content edits that don't change a memory's one-line hook need no update there. The local
memory files stay the source of truth; #7 is only the index.

## Feature tracking → milestones + linked projects

A **feature** is a full capability that spans multiple issues/tasks (e.g. the *comparison wiki*). The
tracking flow is fixed:

1. **One milestone per feature** — every issue/task for the feature is assigned to it, so the
   milestone's open/closed rollup is the feature's progress. Create with
   `gh api repos/Schinkenkoenig/authn-authz-prototype/milestones -f title="<feature>"`.
2. **One Project (v2) per milestone** — the Kanban board that tracks that feature's issues. The board
   and its milestone share the feature name. `gh project create --owner Schinkenkoenig --title "<feature>"`.
3. **Link the project to this repo** — so it shows under the repo's *Projects* tab:
   `gh project link <n> --owner Schinkenkoenig --repo Schinkenkoenig/authn-authz-prototype`.

Worked example: the milestone **Full comparison wiki** + its linked project
[users/Schinkenkoenig/projects/1](https://github.com/users/Schinkenkoenig/projects/1).

Gotchas (all cost time once):
- **Projects v2 are user/org-owned, never repo-owned.** Creating one does *not* attach it to the repo —
  the explicit `gh project link` in step 3 is what makes it appear under the repo's Projects tab.
- **The `project` token scope is required** for any `gh project` write. The default token lacks it:
  `gh auth refresh -s project` (interactive device login).
- **`gh` can't set a view's layout.** A fresh project opens in *Table* layout; flip the view to *Board*
  grouped by **Status** in the UI once. The CLI *can* set the Status field per item
  (`gh project item-edit … --single-select-option-id`, options Todo / In Progress / Done).

## Layout

```
src/Api/           FastEndpoints API — the PDP + PEP. Authenticates the caller, decides, enforces.
  Auth/            caller-claims extraction from the JWT
  Authz/           the seam: AuthzDispatcher + 7 evaluators + external-engine clients/provisioners
  Storage/         S3Gateway — one service identity, dumb/broad backend access
  Endpoints/       storage/{read,write,list}, authz/paradigms, authz/{paradigm}/config, whoami
  Data/            EF Core (Postgres) — authz config rows, seeded read-only at startup
src/AppHost/       .NET Aspire orchestrator — runs Postgres + API + SPA; holds realm + Ceph init
src/ServiceDefaults/  shared Aspire wiring (OTel, health)
src/web/           Next.js SPA (Auth Code + PKCE via react-oidc-context)
src/wiki/          Astro + Starlight comparison wiki — serves docs/wiki/ markdown; dev server only
tests/Api.Tests/   unit tests — the pure evaluators + dispatch + claims parsing
scripts/           dev-up.sh (infra) + verify-authz.py (the paradigm matrix)
```

## Running it

Two tiers. **Infra** (Keycloak, Ceph, the three external engines, the token sidecar) runs on a
fixed-IP Docker bridge — see [ADR 0006](docs/adr/0006-fixed-ip-oidc-issuer-app-tier-aspire.md) for
why. **App tier** (Postgres + API + SPA) runs under Aspire.

```bash
source ~/.bash_profile          # get the user-local dotnet (~/.dotnet, SDK 10)
bash scripts/dev-up.sh          # fixed-IP infra; prints the endpoint map when ready
dotnet run --project src/AppHost   # Aspire: Postgres + API + SPA; open the dashboard + SPA at :3000
```

Fixed infra endpoints (Docker bridge `cephnet`, 172.30.0.0/16):

| Service    | Address              | Notes                                                    |
|------------|----------------------|----------------------------------------------------------|
| Keycloak   | `172.30.0.20:8080`   | realm `authn-authz`; the pinned OIDC issuer              |
| Ceph RGW   | `172.30.0.10:8080`   | bucket `demo`; service role `DemoService`                |
| OpenFGA    | `172.30.0.30:8080`   | ReBAC; in-memory, provisioned by the API at startup      |
| cedar-agent| `172.30.0.40:8180`   | Cedar; policies pushed by the API at startup             |
| OPA        | `172.30.0.50:8181`   | Rego; policy pushed by the API at startup                |
| token file | `/tmp/webid/token`   | web-identity token, kept fresh by the `webid-refresher` sidecar |

## Verifying

`scripts/verify-authz.py <api-url>` runs the full paradigm matrix against real Keycloak tokens +
real Ceph + the real engines. This is the end-to-end truth check — not a mock in sight.

**Fast verify without full Aspire:** run the API standalone (env from `src/AppHost/AppHost.cs` + a
throwaway Postgres) and point the script at it. Caveat: `dotnet run --project src/Api` binds the
`launchSettings.json` `applicationUrl` (**:5198**), which overrides `ASPNETCORE_URLS`. Under AppHost,
read the API's dynamic port from the Aspire dashboard.

`dotnet test` runs the unit suite (the pure evaluators, dispatch, claims parsing).

## Gotchas that cost time

- **Keycloak realm JSON does not hot-reload.** `--import-realm` only imports into a *fresh*
  container. To pick up a realm edit: `docker rm -f kc-spike && bash scripts/dev-up.sh` (the fixed IP
  is preserved, so Ceph's OIDC trust is unaffected). The same applies to a `model.fga` edit against a
  reused OpenFGA store — `docker rm -f openfga` to force a re-provision.
- **Keycloak 26 users MUST have `firstName` + `lastName`** or the password grant fails
  `"Account is not fully set up"`.
- **`dotnet-ef` lives at `~/.dotnet/tools`** — not on the profile PATH. Prepend it for
  `dotnet ef migrations add`.
- **`ceph-demo` state is not durable indefinitely.** It accretes a writable layer while sitting in
  `HEALTH_WARN`; under host disk pressure its monitor can refuse to start. Fix: `docker rm -f
  ceph-demo` + free disk + re-run `dev-up.sh`. Its demo data is reproducible — the read-target seed
  keys are listed in the SP5 run note (`docs/superpowers/notes/2026-07-05-authz-review-pass-run.md`).
- **`git status` before `git add -A`.** A `py_compile` check leaves `__pycache__/*.pyc` that has been
  committed by accident before (now `.gitignore`d).

## Prove external payloads before writing C#

For every external engine (OpenFGA, cedar-agent, OPA), the request/response shapes were proven with
`curl` against the live container *before* any C# was written. Cheaper than a failing e2e case, and it
has caught real surprises (cedar-agent tolerates unregistered uids; OPA needs `default allow := false`
or a deny returns `{}`). Do the same for any new engine.

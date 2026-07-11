# Enterprise-IdP leverage per paradigm (Microsoft Entra ID)

**Question:** for each of the seven paradigms, how much of its configuration burden is absorbed by
data an enterprise IdP — Microsoft Entra ID — *already maintains* (security groups, departments,
user profile attributes), and how easily does the paradigm tap it?

**Framing: leverage, not migration.** Enterprises already run a directory: HR feeds keep
`department` current, IT keeps security-group membership current, group-based app assignment is a
practiced motion. The paradigm that can ride that existing data has a structurally lower config
burden than one that needs its own parallel store. Keycloak stays the live IdP in this testbed;
this is a documentation axis for the comparison wiki, verified against Microsoft/engine primary
docs — no live Entra tenant involved.

Two numbers to keep in mind throughout (verified against Microsoft Learn):

- **Groups claim limit: 200 groups in a JWT, 150 in a SAML assertion, 5 via the implicit flow**,
  including nested groups. Exceed it and Entra **omits the groups claim entirely** and emits an
  overage indication instead — the app must call Microsoft Graph to enumerate memberships.
  ([Configure group claims](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims))
- **Custom security attributes are never emitted in tokens** — explicitly unsupported for both SAML
  and JWT claims; they're Graph-only.
  ([Custom security attributes overview](https://learn.microsoft.com/en-us/entra/fundamentals/custom-security-attributes-overview))

## Summary table

| Paradigm | Absorbed for free | Stays app-side | Mechanism | Friction |
|---|---|---|---|---|
| **rbac** | user→role assignment (security groups assigned to app roles) | role→(prefix, actions) rows | app roles + `roles` claim | per-app role assignment is still admin work; raw groups claim = GUIDs + 200-group overage |
| **abac** | caller attributes (`department` HR-maintained; `level` as directory extension) | the rules (conditions, template, actions) | claims mapping (`user.department`) / directory-extension optional claims (`extn.*`) | needs `acceptMappedClaims` or custom signing key; custom security attributes can't be claims; ≤10 extension attrs as claims |
| **claims** | almost nothing — `storage_grants` isn't pre-existing directory data | grant data must be authored somewhere (extension attr or external store) | directory extensions or custom claims provider (external REST at token issuance) | new per-user data, no reuse; token bloat; revocation waits for expiry |
| **acl** | only the principal identifier (`oid`); group-principals if entries name groups | every ACL entry | `oid`/`sub` from the token; groups claim if entries reference groups | entries keyed by GUIDs; per-resource entries inherently app-local |
| **rebac** | group-membership edges (`user→member→team` ≙ security groups) | model, hierarchy tuples, team→resource role edges | SCIM/Graph sync → Write API tuples, or contextual tuples from the token's groups claim | continuous sync = staleness window + custom reconciler; contextual tuples don't persist, Check-family only |
| **cedar** | principal attributes + group parents (from token or Graph) | policy text, schema, entity/context marshalling | app builds entities/context per request from claims (or Graph pull) | Cedar never talks to the IdP — the app is the ETL, every request |
| **opa** | same caller data; JWT-as-input is a documented first-class pattern | Rego policy, input construction, data plumbing for big datasets | `input` from token claims; bundle API / push / `http.send` for directory snapshots | bundle staleness + memory; `http.send` latency; OPAL (third-party) for realtime push |

Rough leverage ranking: **rbac ≈ abac > opa ≈ cedar ≈ rebac > acl > claims** — with the caveat that
rebac's leverage comes bundled with the most plumbing.

---

## RBAC

**Absorbed for free.** The `user_roles` table — the half of RBAC's config that churns with every
hire and reorg — maps directly onto data Entra already holds. You declare app roles (`editor`,
`viewer`, `admin`) on the app registration and assign **existing security groups** to them; every
member inherits the role, and Entra emits a `roles` claim listing the role *values* in the ID/access
token ([Add app roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)).
Onboarding stays what it already is in the enterprise: add the user to the group. Microsoft's own
docs recommend exactly this pattern — app roles as an indirection layer over groups — because role
values are strings the app controls, portable across tenants, instead of tenant-specific group IDs.

**Stays app-side regardless.** `role_permissions` — `editor → projects/ (Read,Write,List)`. Entra
has no concept of this app's prefixes or actions; an app role is just a named string. The
role→permission mapping is and remains the app's DB rows (or code).

**Mechanism.** App roles are declared in the app registration manifest; users *and groups* are
assigned under Enterprise applications → Users and groups; the token carries
`"roles": ["editor"]` ([Add app roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)).
The evaluator's `user_roles` lookup collapses to reading one claim. Alternative: skip app roles and
consume the raw `groups` claim (`groupMembershipClaims` in the manifest,
[Configure group claims](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)) —
then the app maps group IDs to roles itself.

**Friction.** The `roles` claim path is clean — strings, no overage (a user holds few app roles).
The raw-groups path is worse: groups arrive as **object-ID GUIDs** by default (names only for
AD-synced groups via `sAMAccountName`, or cloud-group display names restricted to
groups-assigned-to-the-app, because display names aren't unique); and the 200-group JWT limit means
a heavily-grouped user's token silently drops the claim, forcing a Graph call. Both docs recommend
the "groups assigned to the application" filter to stay under the limit. The number of app roles
counts toward application-manifest limits; Microsoft doesn't state a dedicated per-app role cap in
the app-roles doc, so we don't quote one. Net: **highest leverage of the seven** — the churny half
of RBAC's config rides existing group hygiene.

## ABAC

**Absorbed for free.** The paradigm's entire value proposition is IdP-maintained attributes, and
Entra genuinely maintains the flagship one: `department` is a standard user-profile attribute,
typically fed by HR sync, selectable as a claim source (`user.department`) in the enterprise app's
Attributes & Claims editor
([Customize JWT claims](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization)).
The `alice (department=finance) → finance/` rule needs zero per-user authz config — exactly the
zero-touch-onboarding pitch, and Entra's HR-fed directory is what makes the attribute trustworthy.
`level` has no standard directory equivalent; it becomes a **directory (schema) extension**, which
Entra can also emit in tokens.

**Stays app-side regardless.** The rules themselves — `(conditions, prefix-template, actions)`.
Entra stores attributes, not this app's interpretation of them.

**Mechanism.** Two token paths, one API path:
1. *Claims mapping* — add `user.department` as a custom claim on the enterprise app. Catch: an app
   consuming mapped claims must either set `acceptMappedClaims: true` in its manifest
   (single-tenant only) or configure a **custom signing key**; otherwise Entra returns error
   AADSTS50146. Microsoft warns explicitly: "Do not set the acceptMappedClaims property to true for
   multi-tenant apps, which can allow malicious actors to create claims-mapping policies for your
   app." ([Customize JWT claims](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization))
2. *Directory extensions as optional claims* — emitted as `extn.<attributename>` in the JWT; an app
   can request **at most 10 extension attributes** as optional claims
   ([Configure optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)).
3. *Custom claims provider* — a custom authentication extension that calls an external REST API on
   the **token issuance start** event to fetch attributes from systems that can't be synced into
   the directory ([Custom claims provider](https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview)).

**Friction.** The custom-security-attributes trap: they look purpose-built for this ("use for
authorization scenarios", usable in Azure ABAC role-assignment conditions) but are **explicitly not
supported in SAML or JWT claims** — Graph-only
([overview](https://learn.microsoft.com/en-us/entra/fundamentals/custom-security-attributes-overview)).
So a "clearance level" stored there needs a Graph pull or a custom claims provider, not a mapper.
Plus the signing-key/`acceptMappedClaims` ceremony, and the paradigm's standing caveat: decision
quality equals attribute quality. Net: **high leverage** — the data is the directory's day job; the
plumbing is a one-time claims-config exercise.

## Claim-based

**Absorbed for free.** Almost nothing — and this is the interesting inversion. The paradigm is
"the IdP does everything," so it leans on the IdP *maximally*, but on **pre-existing** IdP data
*minimally*: no security group or HR attribute encodes `rw:projects/apollo/`. The grant list is new,
app-specific, per-user data that someone has to author, whichever IdP hosts it. The only free parts
are identity itself and the emission machinery.

**Stays app-side regardless.** Nothing at decision time (that's the point) — but the *authoring
burden* doesn't vanish; it relocates. In Keycloak it's a claim mapper per user; in Entra the grant
data must live in directory extensions or an external store, and populating it is exactly the
per-user work ACL does, minus the app database.

**Mechanism.** Two Entra options for a `storage_grants`-style claim:
1. *Directory extension* per user (`extension_<appid>_storageGrants`), emitted via optional claims
   as `extn.storageGrants` — subject to the 10-extension-attribute-claims limit
   ([Configure optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)).
2. *Custom claims provider* — fetch grants from your own grants service at token issuance
   ([Custom claims provider](https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview)).
   Note what that implies: you're running a grants database anyway; the IdP is just the courier.

**Friction.** No reuse of existing enterprise config at all; rich grant sets bloat every token (the
paradigm's own documented trade-off); revocation waits for token expiry; option 2 adds an external
REST dependency inside the token-issuance path. Net: **lowest leverage** of pre-existing config,
despite being the most IdP-coupled paradigm. "The IdP holds the config" and "the enterprise already
maintains the config" are different claims — this axis measures the second.

## ACL

**Absorbed for free.** Only the principal identifier. Entra gives you a stable `oid` (Microsoft
warns against `email`/`upn` for authorization since both are mutable —
[optional claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference));
the ACL's principal column can key on it. If you extend entries to accept *group* principals
(`finance-team → finance/ (rw)`), group membership evaluation comes free via the groups claim —
that's a real, if partial, absorption: one entry covers a team the enterprise already curates.

**Stays app-side regardless.** Every entry. `(prefix, principal, actions)` triples are the whole
paradigm and are inherently app-local — Entra has no per-resource grant store for your prefixes.

**Mechanism.** Trivial: `oid` from the validated token matches the entry's principal. For
group-principal entries: the `groups` claim (GUIDs, 200-JWT-group limit, overage → Graph call), or
a Graph `transitiveMemberOf` lookup server-side
([Configure group claims](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)).

**Friction.** Entries end up keyed by GUIDs instead of the readable `bob`/`erin` this testbed
seeds — auditability degrades unless you store display names alongside. The linear users×resources
growth that makes ACL buckle is precisely the part Entra can't absorb. Net: **minimal leverage**;
group-principals are the one worthwhile borrowing.

## ReBAC (OpenFGA)

**Absorbed for free.** The group-membership tuples. `user:bob --member--> team:eng` *is* an Entra
security group membership — the enterprise already maintains that edge, with joiner/leaver
processes attached. That's the highest-churn slice of the tuple set.

**Stays app-side regardless.** The authorization model (the `type prefix` schema), the hierarchy
tuples (`parent` edges — Entra knows nothing of your prefix tree), and the team→resource role edges
(`team:eng#member --editor--> prefix:projects/`). Those are the paradigm's actual authoring surface
and stay yours.

**Mechanism.** Two documented routes:
1. *Sync memberships into tuples.* Entra's provisioning service pushes users and groups to a SCIM
   2.0 endpoint, tracking changes via Graph delta query, with an initial cycle then periodic
   incremental cycles ([How provisioning works](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/how-provisioning-works));
   your SCIM receiver translates membership changes into OpenFGA Write API calls (transactional,
   max 100 tuples per request, `on_duplicate: "ignore"` for idempotent imports —
   [Update tuples](https://openfga.dev/docs/getting-started/update-tuples)). Alternatively a
   Graph-pull reconciler using the same delta queries. Microsoft's current docs describe incremental
   cycle intervals as app-specific ("at intervals defined in the tutorial specific to each
   application"); the commonly cited ~40-minute figure is **not verifiable in the current docs**, so
   treat the staleness window as "minutes to an hour", not a guaranteed constant.
2. *Contextual tuples from the token.* OpenFGA explicitly documents deriving group tuples from OIDC
   token claims at Check time, "avoiding the need to persist user-directory relationships in the
   store" and eliminating "a synchronization mechanism to keep the user directory data up to date
   with tuples in the store"
   ([Token claims as contextual tuples](https://openfga.dev/docs/modeling/token-claims-contextual-tuples)).
   Feed the Entra `groups` claim in as `user:X member team:Y` per request.

**Friction.** Route 1: a staleness window plus a reconciler you write and operate — OpenFGA's docs
don't ship one. Route 2 trades that for token-lifetime staleness ("if those relationships change
while the token has not expired, users will still get access") and inherits the 200-group
JWT/overage problem wholesale; contextual tuples also "do not persist" and only work for
Check/ListObjects/ListUsers — no read/expand, so no permission-aware indexing off them. Either way,
team IDs are group GUIDs unless you map them. Net: **medium leverage with the highest plumbing
bill** — the memberships are free, the pipeline is not.

## Cedar

**Absorbed for free.** The principal's attributes and group memberships — as *data*. Cedar
policies over `principal.department` or group-typed principals consume exactly what Entra
maintains. In Cedar's model, "all entities with the same parent can be considered members of that
group", so an Entra group maps naturally onto a Cedar group entity
([Cedar terminology](https://docs.cedarpolicy.com/overview/terminology.html)).

**Stays app-side regardless.** The policy text, the schema, and — critically — the marshalling.
Cedar has no data-fetch machinery: "Your application must gather all of the relevant information
and provide it to Cedar's authorization engine when making the request" (same source). The engine
never talks to Entra.

**Mechanism.** The app (PEP) builds the entities/context payload per request from the validated
token: `roles` claim (app roles), `groups` claim → parent entities, mapped `department` claim →
principal attribute; anything not token-borne comes from a Graph pull the app performs. This
testbed already works this way — all decision data rides in `context` because storage keys are
dynamic — so the Entra integration point is exactly the claims configuration described under ABAC
(claims mapping + `acceptMappedClaims`/signing key, directory extensions, custom claims provider),
then a dumb copy into the request.

**Friction.** The app is the ETL on every request: token→entities translation is app code you own,
including GUID→entity-ID mapping if the typed schema wants readable group names. Overage or missing
mapped claims degrade into per-request Graph calls inside the decision path. Net: **medium
leverage** — the *data* is absorbed to the same degree as ABAC; the delivery is manual and
per-request.

## OPA / Rego

**Absorbed for free.** Same caller data as Cedar — and OPA is the engine most explicit about
consuming it: JWT claims are a documented first-class external-data pattern ("JWT tokens": updates
only at login, limited size, high performance/availability —
[External data](https://www.openpolicyagent.org/docs/latest/external-data/)). Entra's `roles`,
`groups`, and mapped attribute claims drop straight into `input.caller` with no impedance.

**Stays app-side regardless.** The Rego module, the `input` document construction, and — if
policies need directory data beyond the token — the data-delivery plumbing.

**Mechanism.** OPA documents five patterns, four relevant here
([External data](https://www.openpolicyagent.org/docs/latest/external-data/)):
1. *JWT/input overload* — the PEP copies token claims into `input`; cheapest, what this testbed does.
2. *Bundle API* — periodically pull a snapshot (e.g. group→user map exported from Graph or fed by
   SCIM) into OPA's memory; "maximum lag combines data replication and bundle pull intervals";
   whole dataset in memory; suited to "static, medium-sized data".
3. *Push data* — delta updates via OPA's data API; "requires custom replicator implementation".
4. *Pull during evaluation* — `http.send` to Graph mid-policy; "perfectly current", network-bound.
OPAL delivers realtime pushed updates but is a **third-party ecosystem project**, not core OPA —
OPA's docs list it under ecosystem integrations.

**Friction.** Pattern-dependent: bundles add a staleness window and memory ceiling; `http.send`
puts Graph latency and availability inside every decision; push needs a replicator you build. Group
GUIDs again unless transformed upstream. Net: **medium leverage, most flexible mechanism menu** —
for token-sized data it's as effortless as it gets; for directory-scale data you pick your
staleness/complexity trade-off explicitly.

---

## Where this leaves the comparison

- **rbac** and **abac** convert Entra's existing config most directly: security groups → app-role
  assignments, HR attributes → mapped claims. Their app-side remainder (role→permission rows, rule
  text) is the low-churn part.
- **cedar** and **opa** absorb the same *data* but make the app carry it to the engine — one-time
  plumbing for token-borne facts, an explicit sync/pull decision beyond that.
- **rebac** absorbs the churniest data (memberships) but demands the most machinery: a sync
  pipeline you operate, or contextual tuples with token-staleness and no persistence.
- **acl** leverages only identity (plus optional group-principals); its defining artifact can't be
  absorbed by construction.
- **claims** leverages the least *pre-existing* config despite being the most IdP-coupled paradigm:
  grants are new data wherever they're stored. IdP-hosted ≠ enterprise-pre-existing.

## Sources

Microsoft Learn (first-party):
- Optional claims reference — https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference
- Configure optional claims (directory extensions, `extn.*`, 10-attr limit, groups config) — https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims
- Add app roles and get them from a token — https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps
- Configure group claims (150 SAML / 200 JWT / 5 implicit, formats, overage, filtering) — https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims
- Customize JWT claims (claims mapping, `acceptMappedClaims`, custom signing key) — https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization
- Custom security attributes overview (no token emission; Graph-only) — https://learn.microsoft.com/en-us/entra/fundamentals/custom-security-attributes-overview
- Custom claims provider overview (token issuance start event) — https://learn.microsoft.com/en-us/entra/identity-platform/custom-claims-provider-overview
- How application provisioning works (SCIM 2.0, delta query, cycles) — https://learn.microsoft.com/en-us/entra/identity/app-provisioning/how-provisioning-works
- What is automated app user provisioning — https://learn.microsoft.com/en-us/entra/identity/app-provisioning/user-provisioning

Engine docs (first-party):
- OpenFGA: token claims as contextual tuples — https://openfga.dev/docs/modeling/token-claims-contextual-tuples
- OpenFGA: update relationship tuples (Write API) — https://openfga.dev/docs/getting-started/update-tuples
- Cedar: terminology (entities, context, app supplies data) — https://docs.cedarpolicy.com/overview/terminology.html
- OPA: external data patterns (JWT, input, bundles, push, pull; OPAL = third-party ecosystem) — https://www.openpolicyagent.org/docs/latest/external-data/

Unverified numbers, flagged rather than guessed: the ~40-minute incremental provisioning interval
(current docs say interval is app-specific) and any per-app cap on the number of app roles (docs
say only that roles count toward manifest limits).

# Service-level storage IAM, application-level authorization

The API authorizes every request itself (it is both PDP and PEP) and reaches storage through a
**single service identity** with broad access — rather than brokering per-user, prefix-scoped
temporary credentials from the storage backend.

## Context

The original walking skeleton did the opposite: each user's token was exchanged for scoped Ceph
credentials via `AssumeRoleWithWebIdentity`, with an inline session policy, so the storage backend
enforced authorization per user. Two forces killed that design:

1. The testbed must support **multiple storage backends**. Authorization can't live inside one
   backend's IAM if it has to hold across several.
2. Ceph's role-permission-policy actions were **not reliably enforced** for the owner account, so the
   per-user scoping wasn't trustworthy anyway (walking-skeleton verdicts §5).

## Decision

Move authorization *up*, into the application:

- The API validates the access token and runs the selected paradigm — it is the Policy Decision Point.
- The API enforces its own decision before any object I/O — it is the Policy Enforcement Point.
- Storage is reached with **one broad service identity** (the AWS SDK's web-identity credential
  provider assumes a service role); the backend is dumb, broad, and swappable.

## Consequences

- `StsBroker`, `SessionPolicy`, and per-user role-ARN resolution were removed; the SPA no longer sends
  an ID token.
- Storage sees only the service identity, so a bug in the API's authorization is a real breach — there
  is no second enforcement layer beneath it. This is accepted for a comparison testbed.
- The Ceph role becomes a broad `DemoService` role. Backend-enforced authorization remains possible in
  principle (a role in a separate tenant would honor role policies) but is explicitly not used.

# Web-identity token supplied by a refresher sidecar

The service identity's OIDC token (see [ADR 0001](0001-service-iam-app-level-authz.md)) is produced by
a **separate sidecar container** that fetches it from Keycloak on an interval and writes it to a shared
file; the API only reads `AWS_WEB_IDENTITY_TOKEN_FILE`. The API writes no token-acquisition or STS code.

## Context

The AWS SDK's web-identity credential provider (the IRSA / Pod-Identity mechanism) reads a token from a
file and does `AssumeRoleWithWebIdentity` + refresh itself. Something has to keep that file fresh. The
options were: an in-app refresher, a static long-lived token, an external host script, or a sidecar.

## Decision

Use a **sidecar** (`webid-refresher` in `dev-up.sh`): it does client-credentials against Keycloak for
the `storage-service` client and rewrites `/tmp/webid/token` on an interval. The API stays a pure
credential *consumer*.

This mirrors production IRSA/Pod-Identity exactly, which is the point — the API code is identical to
what it would be in a real cluster. Rejected alternatives were each less faithful: an in-app refresher
is un-IRSA-like and couples token lifecycle into the app; a static token doesn't refresh; a host script
doesn't containerize.

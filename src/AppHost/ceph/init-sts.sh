#!/usr/bin/env bash
# Idempotently configure Ceph RGW STS + Keycloak OIDC federation for the
# AssumeRoleWithWebIdentity flow. Captures the exact recipe proven in the
# walking-skeleton spike (see docs/superpowers/notes/2026-07-01-ceph-sts-verdicts.md).
#
# Assumes: `ceph-demo` (ceph/demo:latest-squid) and a Keycloak with the
# authn-authz realm are running on docker network `cephnet`, with Keycloak's
# issuer at a network-reachable fixed IP so token `iss` == provider Url.
set -euo pipefail

CEPH_CONTAINER="${CEPH_CONTAINER:-ceph-demo}"
NET="${NET:-cephnet}"
RGW_ENDPOINT="${RGW_ENDPOINT:-http://172.30.0.10:8080}"
ISSUER_HOST="${ISSUER_HOST:-172.30.0.20:8080}"           # host:port of Keycloak, used in iss
ISSUER_URL="http://${ISSUER_HOST}/realms/authn-authz"
CLIENT_ID="${CLIENT_ID:-webapp}"                          # == ID token aud
# RBAC selects the role (RoleResolver: reader->DemoReader, writer->DemoWriter). In the
# walking skeleton both carry the same broad permission policy — the per-caller inline
# session policy is what scopes to a prefix (ABAC). Read-vs-write action semantics are
# deferred to sub-project 2's real policy model.
ROLE_NAMES="${ROLE_NAMES:-DemoReader DemoWriter}"
ADMIN_KEY="${ADMIN_KEY:-demoaccess}"
ADMIN_SECRET="${ADMIN_SECRET:-demosecret123}"
POLICY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

iam() { docker run --rm -i --network "$NET" -v "${POLICY_DIR}:/policies:ro" \
  -e AWS_ACCESS_KEY_ID="$ADMIN_KEY" -e AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET" -e AWS_DEFAULT_REGION=us-east-1 \
  amazon/aws-cli --endpoint-url "$RGW_ENDPOINT" "$@"; }

echo ">> enable STS on RGW"
docker exec "$CEPH_CONTAINER" ceph config set client.rgw rgw_sts_key "abcdef0123456789"
docker exec "$CEPH_CONTAINER" ceph config set client.rgw rgw_s3_auth_use_sts true

echo ">> grant oidc-provider/roles/user-policy caps to the admin user"
for cap in "oidc-provider=*" "roles=*" "user-policy=*"; do
  docker exec "$CEPH_CONTAINER" radosgw-admin caps add --uid=demo --caps="$cap" >/dev/null
done

echo ">> (re)create OIDC provider for issuer ${ISSUER_URL}"
iam iam create-open-id-connect-provider \
  --url "$ISSUER_URL" --client-id-list "$CLIENT_ID" \
  --thumbprint-list ffffffffffffffffffffffffffffffffffffffff >/dev/null 2>&1 || echo "   (provider already exists)"

for ROLE_NAME in $ROLE_NAMES; do
  echo ">> (re)create role ${ROLE_NAME} with trust policy"
  iam iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document file:///policies/trust-policy.json >/dev/null 2>&1 || echo "   (role already exists)"

  echo ">> attach storage permission policy to ${ROLE_NAME}"
  iam iam put-role-policy --role-name "$ROLE_NAME" --policy-name StorageAccess \
    --policy-document file:///policies/permission-policy.json >/dev/null
done

echo ">> NOTE: RGW must be restarted once after enabling STS (docker restart ${CEPH_CONTAINER})"
echo ">> done. Roles: ${ROLE_NAMES// /, } (arn:aws:iam:::role/<name>)"

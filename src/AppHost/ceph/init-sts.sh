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
# RBAC: RoleResolver maps realm role -> Ceph IAM role (reader->DemoReader, writer->DemoWriter),
# which selects the assumed IDENTITY. Both roles carry the SAME broad permission policy: on
# this owner-account setup the role's permission-policy actions are NOT enforced (owner bypass,
# see the STS verdicts note). The API's inline SESSION policy is the sole enforcer of BOTH the
# action set (reader vs writer) and the prefix. The role's broad policy just makes the role a
# usable identity vehicle.
ROLE_NAMES="${ROLE_NAMES:-DemoReader DemoWriter DemoService}"
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

PROVIDER_ARN="arn:aws:iam:::oidc-provider/${ISSUER_HOST}/realms/authn-authz"
SERVICE_CLIENT_ID="${SERVICE_CLIENT_ID:-storage-service}"   # == service token aud (client-credentials)

# Ceph RGW has no add-client-id-to-open-id-connect-provider, so to guarantee both client
# ids are present we delete (if any) and recreate the provider. The ARN is derived from the
# issuer URL, so it stays stable and existing role trust policies remain valid.
echo ">> (re)create OIDC provider for issuer ${ISSUER_URL} (clients: ${CLIENT_ID}, ${SERVICE_CLIENT_ID})"
iam iam delete-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN" >/dev/null 2>&1 || true
iam iam create-open-id-connect-provider \
  --url "$ISSUER_URL" --client-id-list "$CLIENT_ID" "$SERVICE_CLIENT_ID" \
  --thumbprint-list ffffffffffffffffffffffffffffffffffffffff >/dev/null 2>&1 \
  || echo "   (provider create failed — check RGW STS config)"

# The user roles (reader/writer) trust the SPA client (aud=webapp); the service role trusts
# the service client (aud=storage-service). The service identity assumes DemoService; per-user
# authorization is enforced in the API (app-level), not by these roles.
trust_for() { case "$1" in
  DemoService) echo trust-policy-service.json ;;
  *)           echo trust-policy.json ;;
esac; }

for ROLE_NAME in $ROLE_NAMES; do
  TRUST_FILE="$(trust_for "$ROLE_NAME")"
  echo ">> (re)create role ${ROLE_NAME} (trust: ${TRUST_FILE})"
  iam iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file:///policies/${TRUST_FILE}" >/dev/null 2>&1 \
    || iam iam update-assume-role-policy --role-name "$ROLE_NAME" \
         --policy-document "file:///policies/${TRUST_FILE}" >/dev/null 2>&1 \
    || echo "   (could not set trust policy)"

  echo ">> attach broad permission policy to ${ROLE_NAME} (identity vehicle; not the enforcer)"
  iam iam put-role-policy --role-name "$ROLE_NAME" --policy-name StorageAccess \
    --policy-document "file:///policies/permission-policy.json" >/dev/null
done

echo ">> ensure bucket demo exists"
iam s3 mb s3://demo >/dev/null 2>&1 || echo "   (bucket already exists)"

echo ">> seed a readable welcome object under each user prefix (so read-only roles have something to read)"
SEED_DIR="$(mktemp -d)"
for u in alice bob; do
  echo "Hello ${u}. Any signed-in user with a read capability can GET this object." > "${SEED_DIR}/${u}.txt"
done
docker run --rm -i --network "$NET" -v "${SEED_DIR}:/seed:ro" \
  -e AWS_ACCESS_KEY_ID="$ADMIN_KEY" -e AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET" -e AWS_DEFAULT_REGION=us-east-1 \
  amazon/aws-cli --endpoint-url "$RGW_ENDPOINT" s3 cp /seed/alice.txt s3://demo/alice/welcome.txt >/dev/null
docker run --rm -i --network "$NET" -v "${SEED_DIR}:/seed:ro" \
  -e AWS_ACCESS_KEY_ID="$ADMIN_KEY" -e AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET" -e AWS_DEFAULT_REGION=us-east-1 \
  amazon/aws-cli --endpoint-url "$RGW_ENDPOINT" s3 cp /seed/bob.txt s3://demo/bob/welcome.txt >/dev/null
rm -rf "$SEED_DIR"

echo ">> NOTE: RGW must be restarted once after enabling STS (docker restart ${CEPH_CONTAINER})"
echo ">> done. Roles: ${ROLE_NAMES// /, } (arn:aws:iam:::role/<name>); reader/writer capability is enforced by the API's inline session policy, not the role"

#!/usr/bin/env bash
# Bring up the walking-skeleton dev stack: fixed-IP Keycloak (realm imported), Ceph
# RGW+STS, and Postgres — all on the `cephnet` bridge. This is a deliberate WORKAROUND
# for full Aspire orchestration (Task 4b): Aspire hands Keycloak a random host port,
# but Ceph's OIDC trust is pinned to one issuer string that must also be reachable from
# the browser (host) and the API. A fixed bridge IP satisfies all three at once on
# Linux. Replacing this with a proper Aspire issuer strategy is deferred.
#
# Idempotent: re-running starts existing containers and re-applies STS init.
# Run the API and SPA separately (see the printed hints).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPHOST_DIR="$SCRIPT_DIR/../src/AppHost"
NET=cephnet
KC=http://172.30.0.20:8080
RGW=http://172.30.0.10:8080

exists() { docker ps -a --format '{{.Names}}' | grep -qx "$1"; }

echo ">> ensure network $NET"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet 172.30.0.0/16 "$NET" >/dev/null

echo ">> Keycloak (kc-spike, 172.30.0.20)"
if exists kc-spike; then docker start kc-spike >/dev/null; else
  docker run -d --name kc-spike --network "$NET" --ip 172.30.0.20 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_HOSTNAME="$KC" -e KC_HTTP_ENABLED=true \
    -v "$APPHOST_DIR/realms:/opt/keycloak/data/import:ro" \
    quay.io/keycloak/keycloak:26.6 start-dev --import-realm >/dev/null
fi

echo ">> Ceph RGW+STS (ceph-demo, 172.30.0.10)"
FRESH_CEPH=false
if exists ceph-demo; then docker start ceph-demo >/dev/null; else
  FRESH_CEPH=true
  docker run -d --name ceph-demo --network "$NET" --ip 172.30.0.10 \
    -e MON_IP=172.30.0.10 -e CEPH_PUBLIC_NETWORK=172.30.0.0/16 \
    -e CEPH_DEMO_UID=demo -e CEPH_DEMO_ACCESS_KEY=demoaccess -e CEPH_DEMO_SECRET_KEY=demosecret123 \
    -e CEPH_DEMO_BUCKET=firstbucket -e RGW_NAME=localhost -e RGW_FRONTEND_PORT=8080 \
    quay.io/ceph/demo:latest-squid >/dev/null
fi

echo ">> Postgres (pg-spike, localhost:5433)"
if exists pg-spike; then docker start pg-spike >/dev/null; else
  docker run -d --name pg-spike -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=appdb \
    -p 5433:5432 postgres:18.3 >/dev/null
fi

wait_http() { # url label
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true)
    [ -n "$code" ] && [ "$code" != "000" ] && { echo "   $2 ready ($code)"; return 0; }
    sleep 2
  done
  echo "   !! $2 not ready after 120s" >&2; return 1
}

echo ">> waiting for services"
wait_http "$KC/realms/authn-authz/.well-known/openid-configuration" Keycloak
wait_http "$RGW" "Ceph RGW"

echo ">> configure STS (idempotent)"
bash "$APPHOST_DIR/ceph/init-sts.sh"

if [ "$FRESH_CEPH" = true ]; then
  echo ">> fresh Ceph — restart RGW so STS config takes effect, then wait"
  docker restart ceph-demo >/dev/null
  wait_http "$RGW" "Ceph RGW"
fi

cat <<EOF

>> dev stack up.
   Keycloak : $KC  (realm authn-authz; alice/alice reader, bob/bob writer)
   Ceph RGW : $RGW  (bucket demo; role arn:aws:iam:::role/DemoReader)
   Postgres : localhost:5433 (db appdb, postgres/postgres)

   Run the API:
     ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS=http://127.0.0.1:5080 \\
       dotnet run --project src/Api --no-launch-profile
EOF

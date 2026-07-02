#!/usr/bin/env bash
# Run the API against the dev stack (scripts/dev-up.sh must be up first).
#
# Storage credentials are NOT in the app — the AWS SDK's web-identity provider resolves
# them from these AWS_* env vars (IRSA/Pod-Identity style): it does AssumeRoleWithWebIdentity
# against Ceph using the token the refresher sidecar keeps fresh in the shared file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
RGW="${RGW:-http://172.30.0.10:8080}"
TOKEN_DIR="${TOKEN_DIR:-/tmp/webid}"

export ASPNETCORE_ENVIRONMENT=Development
export ASPNETCORE_URLS="${ASPNETCORE_URLS:-http://localhost:5080}"

# AWS SDK web-identity credential resolution (service identity):
export AWS_ROLE_ARN="arn:aws:iam:::role/DemoService"
export AWS_WEB_IDENTITY_TOKEN_FILE="${TOKEN_DIR}/token"
export AWS_ROLE_SESSION_NAME="storage-service"
export AWS_REGION="us-east-1"
export AWS_DEFAULT_REGION="us-east-1"
export AWS_ENDPOINT_URL_STS="$RGW"

exec dotnet run --project "$ROOT/src/Api" --no-launch-profile

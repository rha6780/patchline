#!/bin/sh
# Turns on the Trivy analyzer in Dependency-Track through its REST API.
#
#   DT_URL=http://localhost:8081 DT_ADMIN_KEY=odt_... TRIVY_TOKEN=... ./scripts/enable-trivy.sh
#
# DT_ADMIN_KEY needs the SYSTEM_CONFIGURATION permission. Use a temporary key
# and delete it afterwards; Patchline's own key must stay read-only.
set -eu

: "${DT_URL:?set DT_URL, e.g. http://localhost:8081}"
: "${DT_ADMIN_KEY:?set DT_ADMIN_KEY (SYSTEM_CONFIGURATION)}"
: "${TRIVY_TOKEN:?set TRIVY_TOKEN (same value as in .env)}"
TRIVY_URL="${TRIVY_URL:-http://trivy:8080}"
TRIVY_IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-false}"

curl -sSf -X POST "$DT_URL/api/v1/configProperty/aggregate" \
  -H "X-Api-Key: $DT_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data @- >/dev/null <<JSON
[
  {"groupName": "scanner", "propertyName": "trivy.enabled",         "propertyValue": "true"},
  {"groupName": "scanner", "propertyName": "trivy.base.url",        "propertyValue": "$TRIVY_URL"},
  {"groupName": "scanner", "propertyName": "trivy.api.token",       "propertyValue": "$TRIVY_TOKEN"},
  {"groupName": "scanner", "propertyName": "trivy.ignore.unfixed",  "propertyValue": "$TRIVY_IGNORE_UNFIXED"}
]
JSON

echo "Trivy analyzer enabled in Dependency-Track ($TRIVY_URL)"

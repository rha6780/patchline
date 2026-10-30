#!/bin/sh
# Wires the compose demo together and loads sample data, i.e. steps 2, 3
# and 5 of README.md:
#
#   1. signs in to Dependency-Track as admin (changing the first-start
#      password to DT_ADMIN_PASSWORD, default "patchline-demo")
#   2. gives the Automation team the permissions Patchline needs and
#      creates its API key (saved as PATCHLINE_DT_API_KEY in .env)
#   3. creates the "Patchline" alert that sends findings to Patchline
#   4. turns on the Trivy analyzer (the compose file runs a Trivy server):
#      without it Dependency-Track finds nothing in the sample SBOM
#   5. restarts Patchline with the key and uploads the sample SBOM as
#      storefront-api@main and storefront-api@prod
#
# Run it after `make demo-up`, once Dependency-Track answers (first start
# takes a few minutes). It is safe to run again. Needs curl and jq.
#
# Demo only: it changes Dependency-Track's admin password and writes the
# API key to .env.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
env_file="$here/.env"
[ -f "$env_file" ] || cp "$here/.env.example" "$env_file"
# shellcheck disable=SC1090
. "$env_file"

DT="http://localhost:${DT_API_PORT:-18081}"
PL="http://localhost:${PATCHLINE_PORT:-18080}"
TOKEN="${PATCHLINE_WEBHOOK_TOKEN:-change-me}"
TRIVY_TOKEN="${TRIVY_TOKEN:-patchline-demo-trivy}"
DT_ADMIN_PASSWORD="${DT_ADMIN_PASSWORD:-patchline-demo}"
compose="docker compose -f $here/docker-compose.yml"

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "seed: $tool is required" >&2; exit 1; }
done

step() { printf '\n==> %s\n' "$*"; }

step "Waiting for Dependency-Track at $DT"
i=0
until curl -sf "$DT/api/version" >/dev/null; do
  i=$((i + 1))
  [ "$i" -le 60 ] || { echo "seed: Dependency-Track did not answer; check: make demo-logs" >&2; exit 1; }
  sleep 5
done

step "Signing in to Dependency-Track as admin"
login() { curl -s -o /tmp/patchline-seed.$$ -w '%{http_code}' -X POST "$DT/api/v1/user/login" \
  --data-urlencode username=admin --data-urlencode "password=$1"; }
code=$(login "$DT_ADMIN_PASSWORD")
if [ "$code" != 200 ]; then
  code=$(login admin)
  if [ "$code" = 401 ] && grep -q FORCE_PASSWORD_CHANGE /tmp/patchline-seed.$$; then
    curl -sf -X POST "$DT/api/v1/user/forceChangePassword" --data-urlencode username=admin \
      --data-urlencode password=admin --data-urlencode "newPassword=$DT_ADMIN_PASSWORD" \
      --data-urlencode "confirmPassword=$DT_ADMIN_PASSWORD" >/dev/null
    echo "    Dependency-Track admin password set to: $DT_ADMIN_PASSWORD"
    code=$(login "$DT_ADMIN_PASSWORD")
  fi
fi
if [ "$code" != 200 ]; then
  rm -f /tmp/patchline-seed.$$
  cat >&2 <<EOF
seed: cannot sign in to Dependency-Track as admin (tried "$DT_ADMIN_PASSWORD" and "admin").
      The admin password was changed: pass the current one, for example
        DT_ADMIN_PASSWORD='your-password' make demo-seed
EOF
  exit 1
fi
JWT=$(cat /tmp/patchline-seed.$$)
rm -f /tmp/patchline-seed.$$
api() { curl -sf -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' "$@"; }

step "Granting permissions to the Automation team"
team=$(api "$DT/api/v1/team" | jq -r '.[] | select(.name == "Automation") | .uuid')
[ -n "$team" ] || { echo "seed: no Automation team in Dependency-Track" >&2; exit 1; }
for perm in VIEW_PORTFOLIO VIEW_VULNERABILITY BOM_UPLOAD PROJECT_CREATION_UPLOAD VULNERABILITY_ANALYSIS; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $JWT" "$DT/api/v1/permission/$perm/team/$team")
  case "$code" in 200|304) echo "    $perm" ;; *) echo "seed: adding $perm: HTTP $code" >&2; exit 1 ;; esac
done

KEY="${PATCHLINE_DT_API_KEY:-}"
if [ -z "$KEY" ]; then
  step "Creating an API key for Patchline"
  KEY=$(api -X PUT "$DT/api/v1/team/$team/key" | jq -r '.key')
  tmp="$env_file.tmp"
  if grep -q '^PATCHLINE_DT_API_KEY=' "$env_file"; then
    sed "s|^PATCHLINE_DT_API_KEY=.*|PATCHLINE_DT_API_KEY=$KEY|" "$env_file" > "$tmp"
  else
    { cat "$env_file"; echo "PATCHLINE_DT_API_KEY=$KEY"; } > "$tmp"
  fi
  mv "$tmp" "$env_file"
  echo "    saved as PATCHLINE_DT_API_KEY in deploy/compose/.env"
fi

step "Creating the Patchline alert in Dependency-Track"
rule=$(api "$DT/api/v1/notification/rule" | jq -c '[.[] | select(.name == "Patchline")][0] // empty')
if [ -z "$rule" ]; then
  publisher=$(api "$DT/api/v1/notification/publisher" | jq -r '.[] | select(.publisherClass | endswith("WebhookPublisher")) | .uuid')
  rule=$(api -X PUT "$DT/api/v1/notification/rule" \
    -d "{\"name\":\"Patchline\",\"scope\":\"PORTFOLIO\",\"notificationLevel\":\"INFORMATIONAL\",\"publisher\":{\"uuid\":\"$publisher\"}}")
fi
destination="http://patchline:8080/webhooks/dependency-track?token=$TOKEN"
echo "$rule" | jq --arg d "$destination" '.enabled = true
  | .notifyOn = ["NEW_VULNERABILITY","NEW_VULNERABLE_DEPENDENCY","BOM_PROCESSED","PROJECT_AUDIT_CHANGE"]
  | .publisherConfig = ({destination: $d} | tojson)' \
  | api -X POST "$DT/api/v1/notification/rule" -d @- >/dev/null
echo "    sends to $destination"

step "Turning on the Trivy analyzer"
$compose up -d trivy >/dev/null
i=0
printf '    waiting for the Trivy database'
until $compose logs trivy 2>/dev/null | grep -q 'Listening'; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo
    echo "seed: Trivy did not start; check: docker compose -f $here/docker-compose.yml logs trivy" >&2
    exit 1
  fi
  printf '.'; sleep 3
done
echo
jq -n --arg t "$TRIVY_TOKEN" '[
  {groupName: "scanner", propertyName: "trivy.enabled", propertyValue: "true"},
  {groupName: "scanner", propertyName: "trivy.base.url", propertyValue: "http://trivy:8080"},
  {groupName: "scanner", propertyName: "trivy.api.token", propertyValue: $t}]' \
  | api -X POST "$DT/api/v1/configProperty/aggregate" -d @- >/dev/null
echo "    Dependency-Track now also analyzes with http://trivy:8080"

step "Restarting Patchline with the API key"
$compose up -d patchline >/dev/null
i=0
until curl -sf "$PL/readyz" >/dev/null; do
  i=$((i + 1)); [ "$i" -le 30 ] || { echo "seed: Patchline did not start; check: make demo-logs" >&2; exit 1; }
  sleep 2
done

step "Uploading the sample SBOM as storefront-api@main and @prod"
for version in main prod; do
  curl -sf -X POST "$DT/api/v1/bom" -H "X-Api-Key: $KEY" \
    -F autoCreate=true -F projectName=storefront-api -F "projectVersion=$version" \
    -F "bom=@$root/examples/sbom/storefront-api.cdx.json" >/dev/null
  echo "    $version"
done

step "Waiting for findings in Patchline (up to 3 minutes)"
i=0
while :; do
  n=$(curl -sf "$PL/api/v1/findings" | jq '.findings | length')
  [ "${n:-0}" -gt 0 ] && break
  i=$((i + 1))
  if [ "$i" -gt 36 ]; then
    echo
    echo "seed: no findings yet. Check that Dependency-Track ran Trivy:" >&2
    echo "        docker compose -f $here/docker-compose.yml logs dtrack-apiserver | grep -i trivy" >&2
    echo "      (expect \"Trivy vulnerability analysis complete\"), then run this again." >&2
    exit 1
  fi
  printf '.'; sleep 5
done
echo
echo "    $n findings"

cat <<EOF

Done. Open $PL
  - read without signing in, or sign in as admin / admin to assign findings,
    request and approve exceptions (you will be asked for a new password)
  - Dependency-Track UI: http://localhost:${DT_UI_PORT:-18082} (admin / $DT_ADMIN_PASSWORD)
  - to see a fix resolve on main but stay open in prod, see step 7 in README.md
EOF

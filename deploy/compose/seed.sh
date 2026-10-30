#!/bin/sh
# Loads the compose demo with sample data.
#
#   seed.sh        Patchline's own detection (default): waits for the OSV
#                  mirror, then uploads the sample SBOMs to /ingest/sbom:
#                  storefront-api@main and @prod (Maven, npm: OSV) and
#                  storefront-api-image@prod (Debian packages: Trivy)
#   seed.sh dt     Dependency-Track as well (make demo-up PROFILE=dependency-track):
#                  signs in as admin (changing the first-start password to
#                  DT_ADMIN_PASSWORD, default "patchline-demo"), gives the
#                  Automation team the permissions Patchline needs, saves its
#                  API key in .env, adds the Patchline alert, turns on the
#                  Trivy analyzer and uploads the sample SBOM there
#
# Safe to run again. Needs curl and jq. Demo only: "dt" changes
# Dependency-Track's admin password and writes the API key to .env.
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
ECOSYSTEMS="${PATCHLINE_OSV_ECOSYSTEMS:-Maven,npm}"
compose="docker compose -f $here/docker-compose.yml"

for tool in curl jq; do
  command -v "$tool" >/dev/null || { echo "seed: $tool is required" >&2; exit 1; }
done

step() { printf '\n==> %s\n' "$*"; }

# set_env writes KEY=VALUE into .env, replacing an earlier value.
set_env() {
  tmp="$env_file.tmp"
  if grep -q "^$1=" "$env_file"; then
    sed "s|^$1=.*|$1=$2|" "$env_file" > "$tmp"
  else
    { cat "$env_file"; echo "$1=$2"; } > "$tmp"
  fi
  mv "$tmp" "$env_file"
}

wait_patchline() {
  i=0
  until curl -sf "$PL/readyz" >/dev/null; do
    i=$((i + 1)); [ "$i" -le 60 ] || { echo "seed: Patchline did not start; check: make demo-logs" >&2; exit 1; }
    sleep 2
  done
}

upload() { # project version file
  curl -sf -X POST "$PL/ingest/sbom?project=$1&version=$2" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' --data-binary "@$root/examples/sbom/$3" | jq -r '"    \($ARGS.positional[0]): \(.components) components"' --args "$1@$2"
}

wait_findings() { # what to check when nothing arrives
  i=0
  while :; do
    n=$(curl -sf "$PL/api/v1/findings?limit=10000" | jq '.findings | length')
    [ "${n:-0}" -gt 0 ] && break
    i=$((i + 1))
    if [ "$i" -gt 36 ]; then
      echo
      echo "seed: no findings yet. $1" >&2
      exit 1
    fi
    printf '.'; sleep 5
  done
  sleep 3
  echo
  curl -sf "$PL/api/v1/findings?limit=10000" | jq -r '.findings | group_by(.service + "@" + .environment)[]
    | "    \(.[0].service)/\(.[0].environment): \(length) findings"'
}

seed_native() {
  step "Waiting for Patchline at $PL"
  wait_patchline

  step "Waiting for the OSV mirror ($ECOSYSTEMS; npm is about 220 MB the first time)"
  want=$(echo "$ECOSYSTEMS" | tr ',' '\n' | grep -c .)
  i=0
  until [ "$($compose logs patchline 2>/dev/null | grep -c 'osv synced')" -ge "$want" ]; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo
      echo "seed: the OSV mirror did not sync; check: make demo-logs (look for \"osv sync failed\")" >&2
      exit 1
    fi
    printf '.'; sleep 5
  done
  echo

  step "Waiting for the Trivy database"
  i=0
  until $compose logs trivy 2>/dev/null | grep -q 'Listening'; do
    i=$((i + 1)); [ "$i" -le 60 ] || { echo "seed: Trivy did not start; check: $compose logs trivy" >&2; exit 1; }
    printf '.'; sleep 3
  done
  echo

  step "Uploading the sample SBOMs to Patchline"
  upload storefront-api main storefront-api.cdx.json
  upload storefront-api prod storefront-api.cdx.json
  upload storefront-api-image prod storefront-api-image.cdx.json

  step "Waiting for findings"
  wait_findings "Check: make demo-logs (look for \"sbom analyzed\")."

  cat <<EOF

Done. Open $PL
  - Findings, and Components: search "log4j" or open /vulnerabilities/CVE-2021-44228
  - Integrations: each project's commit and its VEX
  - sign in as admin / admin to assign findings, request and approve decisions
    (you will be asked for a new password)
  - see a fix resolve on main but stay open in prod: step 4 in README.md
  - add Dependency-Track: make demo-up PROFILE=dependency-track && make demo-seed-dt
EOF
}

seed_dt() {
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
          DT_ADMIN_PASSWORD='your-password' make demo-seed-dt
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
    set_env PATCHLINE_DT_API_KEY "$KEY"
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

  set_env PATCHLINE_DT_UI_URL "http://localhost:${DT_UI_PORT:-18082}"

  step "Restarting Patchline with the API key"
  $compose up -d patchline >/dev/null
  i=0
  until curl -sf "$PL/readyz" >/dev/null; do
    i=$((i + 1)); [ "$i" -le 30 ] || { echo "seed: Patchline did not start; check: make demo-logs" >&2; exit 1; }
    sleep 2
  done

  step "Uploading the sample SBOM to Dependency-Track as storefront-api@main and @prod"
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
}

case "${1:-native}" in
  native) seed_native ;;
  dt)
    seed_dt
    cat <<EOF

Done. Dependency-Track UI: http://localhost:${DT_UI_PORT:-18082} (admin / $DT_ADMIN_PASSWORD)
Findings Dependency-Track reports join the ones Patchline found itself; a finding both report shows both under "Reported by".
EOF
    ;;
  *) echo "usage: seed.sh [native|dt]" >&2; exit 2 ;;
esac

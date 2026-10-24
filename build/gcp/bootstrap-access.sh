#!/usr/bin/env bash
# Run in the authenticated owner session (e.g. Cloud Shell), not as root.
# Dependencies: bash, gcloud, jq. No cwd assumptions; no credentials are printed.
# Default: inspect only. --apply creates/validates the inspector access setup.
# No VMs, resource roles, image IAM, keys, or user impersonation grants.
set -euo pipefail
apply=false
for arg in "$@"; do
  case "$arg" in
    --apply) apply=true ;;
    --share-source-image)
      echo 'Image IAM changes require a separately reviewed access phase.' >&2
      exit 2 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
for tool in gcloud jq; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done
: "${LABAPP_BUILD_PROJECT:?Set the existing Labapp project ID}"
[[ "$LABAPP_BUILD_PROJECT" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
  echo 'Expected a GCP project ID, not a project number.' >&2; exit 2;
}
pool=labapp-github
provider=trusted-main
workflow='afewell-hh/labapp/.github/workflows/labapp-cloud.yml@refs/heads/main'
inspector="labapp-inspector@${LABAPP_BUILD_PROJECT}.iam.gserviceaccount.com"
number=$(gcloud projects describe "$LABAPP_BUILD_PROJECT" \
  --format='value(projectNumber)')
[[ "$number" =~ ^[0-9]+$ ]] || { echo 'No project number returned.' >&2; exit 1; }
base="projects/${number}/locations/global/workloadIdentityPools/${pool}"
mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.repository_owner_id=assertion.repository_owner_id,attribute.ref=assertion.ref,attribute.workflow_ref=assertion.workflow_ref,attribute.event_name=assertion.event_name'
condition="assertion.repository_id == '1089062808' && assertion.repository_owner_id == '193945001' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == '${workflow}' && assertion.event_name == 'workflow_dispatch'"
principal="principalSet://iam.googleapis.com/${base}/attribute.repository_id/1089062808"
printf 'BUILD_PROJECT=%s\nWIF_PROVIDER=%s/providers/%s\nINSPECTOR_SA=%s\n' \
  "$LABAPP_BUILD_PROJECT" "$base" "$provider" "$inspector"
if ! "$apply"; then
  echo 'Inspect only: no APIs, resources or IAM policies will be changed.'
  gcloud iam service-accounts list --project="$LABAPP_BUILD_PROJECT" \
    --filter="email=$inspector" --format=json
  gcloud iam workload-identity-pools list --project="$LABAPP_BUILD_PROJECT" \
    --location=global --format=json
  echo 'Use --apply only after reviewing the runbook and target project.'
  exit 0
fi
# Project-scoped review for public-image metadata only. Inherited/platform
# administrators may still impersonate this account; see the runbook boundary.
[[ "${LABAPP_PROJECT_ACCESS_REVIEWED:-}" == yes ]] || {
  echo 'Set LABAPP_PROJECT_ACCESS_REVIEWED=yes after the runbook review.' >&2
  exit 1
}
policy=$(gcloud projects get-iam-policy "$LABAPP_BUILD_PROJECT" --format=json)
jq -e --arg member "serviceAccount:$inspector" '
  [.bindings[]? | select(any(.members[]?; . == $member))] | length == 0
' <<<"$policy" >/dev/null || {
  echo 'Inspector already has project roles; resolve before federation.' >&2
  exit 1
}
# Enable only access/metadata APIs in the Labapp project. Errors stop the run.
gcloud services enable compute.googleapis.com iam.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com \
  --project="$LABAPP_BUILD_PROJECT" --quiet
accounts=$(gcloud iam service-accounts list --project="$LABAPP_BUILD_PROJECT" \
  --format=json)
account=$(jq -c --arg email "$inspector" \
  '[.[] | select(.email == $email)]' <<<"$accounts")
if [[ $(jq length <<<"$account") == 0 ]]; then
  gcloud iam service-accounts create labapp-inspector \
    --project="$LABAPP_BUILD_PROJECT" --display-name='Labapp image inspector'
else
  jq -e 'length == 1 and (.[0].disabled != true)' <<<"$account" >/dev/null || {
    echo 'Existing inspector is disabled or unexpected; inspect manually.' >&2
    exit 1
  }
fi
# Audit credentials held by others before extending this identity's access.
# Read IAM and key metadata only; never request private key material.
sa_policy=$(gcloud iam service-accounts get-iam-policy "$inspector" \
  --project="$LABAPP_BUILD_PROJECT" --format=json)
jq -e --arg principal "$principal" '
  all(.bindings[]?;
    .role == "roles/iam.workloadIdentityUser" and
    (.condition // null) == null and .members == [$principal])
' <<<"$sa_policy" >/dev/null || {
  echo 'Unexpected inspector IAM binding; no trust/access grant attempted.' >&2
  exit 1
}
keys=$(gcloud iam service-accounts keys list --iam-account="$inspector" \
  --project="$LABAPP_BUILD_PROJECT" --managed-by=user --format=json)
jq -e 'type == "array" and length == 0' <<<"$keys" >/dev/null || {
  echo 'Inspector has user-managed key credentials; inspect manually.' >&2
  exit 1
}
pools=$(gcloud iam workload-identity-pools list --project="$LABAPP_BUILD_PROJECT" \
  --location=global --show-deleted --format=json)
existing=$(jq -c --arg name "$base" '[.[] | select(.name == $name)]' <<<"$pools")
if [[ $(jq length <<<"$existing") == 0 ]]; then
  gcloud iam workload-identity-pools create "$pool" --location=global \
    --project="$LABAPP_BUILD_PROJECT" --display-name='Labapp trusted GitHub'
else
  jq -e 'length == 1 and .[0].state == "ACTIVE" and (.[0].disabled != true)' \
    <<<"$existing" >/dev/null || {
    echo 'Existing pool is disabled/deleted; resolve manually.' >&2; exit 1;
  }
fi
providers=$(gcloud iam workload-identity-pools providers list \
  --workload-identity-pool="$pool" --location=global \
  --project="$LABAPP_BUILD_PROJECT" --show-deleted --format=json)
# A pool-level principalSet also trusts other providers in this pool.
# Refuse unexpected providers rather than silently broadening access.
jq -e --arg name "$base/providers/$provider" \
  'all(.[]; .name == $name)' <<<"$providers" >/dev/null || {
  echo 'Unexpected provider in reserved labapp pool; inspect manually.' >&2; exit 1;
}
if [[ $(jq length <<<"$providers") == 0 ]]; then
  gcloud iam workload-identity-pools providers create-oidc "$provider" \
    --workload-identity-pool="$pool" --location=global \
    --project="$LABAPP_BUILD_PROJECT" \
    --issuer-uri='https://token.actions.githubusercontent.com' \
    --attribute-mapping="$mapping" --attribute-condition="$condition"
else
  expected=$(jq -Rn --arg mapping "$mapping" \
    '$mapping | split(",") | map(split("=") | {key: .[0], value: .[1]}) | from_entries')
  jq -e --arg condition "$condition" --argjson mapping "$expected" '
    length == 1 and .[0].state == "ACTIVE" and
    (.[0].disabled != true) and .[0].attributeCondition == $condition and
    .[0].attributeMapping == $mapping and
    .[0].oidc.issuerUri == "https://token.actions.githubusercontent.com" and
    ((.[0].oidc.jwksJson // "") == "") and
    ((.[0].oidc.allowedAudiences // []) | length == 0)
  ' <<<"$providers" >/dev/null || {
    echo 'Existing provider differs from reviewed trust; no update attempted.' >&2
    exit 1
  }
fi
gcloud iam service-accounts add-iam-policy-binding "$inspector" \
  --project="$LABAPP_BUILD_PROJECT" --member="$principal" \
  --role=roles/iam.workloadIdentityUser --condition=None --quiet

echo 'Inspector setup complete. No VM/build capabilities were granted.'
echo 'Set Actions Variables, then dispatch the fixed public-image metadata workflow.'

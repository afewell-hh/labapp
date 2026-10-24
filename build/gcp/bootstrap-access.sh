#!/usr/bin/env bash
# Run as an authenticated project administrator (e.g. Cloud Shell), not root.
# Dependencies: bash, gcloud, jq. No cwd assumptions; no credentials are printed.
# Default: inspect only. --apply creates/validates the inspector access setup.
# No VMs, builder roles, networks, quotas, keys, or user impersonation grants.
set -euo pipefail
apply=false
share=false
for arg in "$@"; do
  case "$arg" in
    --apply) apply=true ;;
    --share-source-image) share=true ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
  esac
done
if "$share" && ! "$apply"; then
  echo '--share-source-image requires --apply.' >&2; exit 2
fi
for tool in gcloud jq; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done
: "${LABAPP_BUILD_PROJECT:?Set the existing dedicated build project ID}"
[[ "$LABAPP_BUILD_PROJECT" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
  echo 'Expected a GCP project ID, not a project number.' >&2; exit 2;
}
[[ "$LABAPP_BUILD_PROJECT" != teched-473722 ]] || {
  echo 'The source/production project cannot be the build project.' >&2; exit 2;
}
source_project=teched-473722
source_image=hedgehog-vaidc-v20260114
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
# Validate effective access before exposing the identity through federation.
# This catches direct project grants, but not folder/org/group policy effects.
[[ "${LABAPP_EFFECTIVE_ACCESS_AUDITED:-}" == yes ]] || {
  echo 'Set LABAPP_EFFECTIVE_ACCESS_AUDITED=yes after the runbook audit.' >&2
  exit 1
}
policy=$(gcloud projects get-iam-policy "$LABAPP_BUILD_PROJECT" --format=json)
jq -e --arg member "serviceAccount:$inspector" '
  [.bindings[]? | select(any(.members[]?; . == $member))] | length == 0
' <<<"$policy" >/dev/null || {
  echo 'Inspector already has project roles; resolve before federation.' >&2
  exit 1
}
# Enable only access/metadata APIs in the dedicated project. Errors stop the run.
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
    ((.[0].oidc.allowedAudiences // []) | length == 0)
  ' <<<"$providers" >/dev/null || {
    echo 'Existing provider differs from reviewed trust; no update attempted.' >&2
    exit 1
  }
fi
gcloud iam service-accounts add-iam-policy-binding "$inspector" \
  --project="$LABAPP_BUILD_PROJECT" --member="$principal" \
  --role=roles/iam.workloadIdentityUser --condition=None --quiet
if "$share"; then
  # Explicit opt-in only, after metadata access was denied. This role allows
  # image read/use; it does not mean a metadata-only IAM role.
  gcloud compute images add-iam-policy-binding "$source_image" \
    --project="$source_project" --member="serviceAccount:$inspector" \
    --role=roles/compute.imageUser --condition=None --quiet
fi
echo 'Inspector setup complete. No VM/build capabilities were granted.'
echo 'Audit effective access, set Actions Variables, then dispatch metadata workflow.'

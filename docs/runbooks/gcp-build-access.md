# Keyless GCP access for trusted runner work

Use the existing, billing-enabled Labapp project `teched-473722`, which the
owner created for this work. It also holds the published production VM image;
that image and all other preexisting resources remain protected. The selected
source is
`projects/teched-473722/global/images/hedgehog-vaidc-v20260114`.
Its current accessibility and metadata must be verified, not assumed.

## Access boundary

The owner bootstraps GitHub OIDC → Google Workload Identity Federation (WIF)
→ `labapp-inspector` in the same Labapp project. The provider requires all of:

- Repository ID `1089062808`, owner ID `193945001`.
- Ref `refs/heads/main` and event `workflow_dispatch`.
- Workflow ref
  `afewell-hh/labapp/.github/workflows/labapp-cloud.yml@refs/heads/main`.

The checked-in workflow has no inputs and only reads the selected image's
metadata. Action revisions and Cloud CLI version are pinned. It checks out
trusted main; it does not execute repository scripts or accept commands, SHAs,
image names, or service accounts from a task comment. General Claude jobs and
Codex environments receive no cloud credentials. Protect main and review changes
to this workflow, because reviewed main code is this trust boundary.

The inspector has no build-project resource roles from this bootstrap. A
per-image `roles/compute.imageUser` grant, if needed, permits **read and use** of
that image; it is broader than metadata access. The workflow itself performs
only a metadata read. No builder/runtime identities or build privileges are
created here. Do not attach the inspector identity to a VM. In this shared
project, future builder IAM must protect the published/source image and all
preexisting resources; broad Compute/storage administration is not approved.

## Owner setup in Cloud Shell

The project administrator needs permissions to enable the listed APIs, create
service accounts and WIF pools/providers, and edit the inspector's IAM policy.
Only the optional source-image step requires source-image IAM administration.
Do not solve missing permissions by granting Owner/Editor or production project
roles to an agent. Use the owner's existing administrative session; do not copy
Cloud Shell credentials or tokens into agent sessions.

After reviewing and merging the access change, obtain a trusted main checkout:

```bash
git clone https://github.com/afewell-hh/labapp.git
cd labapp
export LABAPP_BUILD_PROJECT='teched-473722'
# Default is read-only inspection; failure is not permission to mutate.
bash build/gcp/bootstrap-access.sh
# First audit effective access as described below; then acknowledge it.
export LABAPP_EFFECTIVE_ACCESS_AUDITED=yes
# Explicit setup: APIs, inspector, dedicated pool/provider, WIF binding.
bash build/gcp/bootstrap-access.sh --apply
```

The script validates the project ID format and prints nonsecret identifiers.
It accepts `teched-473722`; a separate or empty project is not required.
It never creates keys, VMs, networks, disks, quota changes, or user Token Creator
grants. It describes existing configuration before reuse: disabled/deleted
resources, unexpected providers, uploaded OIDC signing keys, or mismatched
provider trust stop the script
rather than being overwritten. The reserved pool must contain only the one
reviewed provider. Failed partial setup can be rerun; inspect failures before
retrying. IAM/API propagation may require waiting.

Before `--apply`, the administrator must verify both sides of effective access:
roles held by the inspector, and principals that can impersonate or attach it,
including inherited project/folder/organization roles and group membership.
Record that audit in #152, then set `LABAPP_EFFECTIVE_ACCESS_AUDITED=yes`.
The script rejects direct project roles held by the inspector. It reads the
service account's own IAM policy and rejects every binding except the exact,
unconditional reviewed WIF role/member; an empty policy is also valid for first
setup. It rejects any user-managed keys, including disabled keys, by listing
key metadata only. It never reads key material, deletes keys, or removes IAM
bindings. Unexpected configuration requires administrator investigation before
retrying. These checks cannot establish all inherited effective access offline;
do not reuse an inspector with builder/administrative access or alternate
impersonators.

Set these repository **Actions Variables** (identifiers, not secrets), using
Settings → Secrets and variables → Actions → Variables, or an authenticated `gh`:

```bash
gh variable set LABAPP_BUILD_PROJECT --repo afewell-hh/labapp \
  --body "$LABAPP_BUILD_PROJECT"
# Copy WIF_PROVIDER and INSPECTOR_SA from the script's output.
gh variable set LABAPP_WIF_PROVIDER --repo afewell-hh/labapp \
  --body 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/labapp-github/providers/trusted-main'
gh variable set LABAPP_INSPECTOR_SA --repo afewell-hh/labapp \
  --body "labapp-inspector@${LABAPP_BUILD_PROJECT}.iam.gserviceaccount.com"
```

Do not put a JSON service-account key or an access token in GitHub Secrets.
The auth action creates a temporary runner credentials file and removes it at
job completion; do not upload the workspace or that file as an artifact.

## Verify access and record evidence

The lead can request the fixed workflow with its existing GitHub access:

```bash
gh workflow run labapp-cloud.yml --ref main --repo afewell-hh/labapp
gh run list --workflow labapp-cloud.yml --repo afewell-hh/labapp --limit 5
gh run view RUN_ID --repo afewell-hh/labapp --log
```

Only this named workflow on `main` is approved for cloud dispatch here. Do not
broaden a worker's general shell permissions to run arbitrary workflows. Record
the run URL, commit, selected image's immutable ID and metadata result in #152.
A successful setup or auth step alone does not prove image access.

First try without changing production image IAM: it may already be shared with
all authenticated users. If the metadata read is denied, distinguish auth/API
errors from image permission errors. An authorized source-image administrator
may then explicitly grant this inspector read/use of **only that image**:

```bash
bash build/gcp/bootstrap-access.sh --apply --share-source-image
```

This option updates source-image IAM and is not required if access already
works. Never grant source-project Owner, Editor or broad Compute roles. Rerun
the same metadata workflow and record its actual result. Do not grant builder
roles or start VM jobs to diagnose an image metadata failure.

Optional local impersonation is a separate access decision: it would require
`roles/iam.serviceAccountTokenCreator` on this inspector for a named human and
an independently authenticated local session. It is not needed for the lead to
dispatch this workflow and is not granted by the script.

## VM lifecycle gates (before any later build workflow)

The owner permits at most **three simultaneous build/test VM slots**, counting
stopped VMs, reservations, and cleanup-pending resources. Default to one active
cloud job; use parallelism only when useful. A slot is reusable only after its
VM and all owned temporary child resources are confirmed absent.

Default VM bounds are 60 minutes for inspection/component work and 120 minutes
for a full build, with no silent extension. Set cloud-side termination limits
at creation with DELETE where supported. Workflow deadlines must leave cleanup
time. Runtime termination is not complete cleanup: Packer disks can have
`autoDelete=false`; account for disks, addresses, temporary images/snapshots,
and failed/cancelled jobs. Require scoped project/run/issue/slot ownership and
immutable IDs, success/failure/cancellation cleanup, and independent expiry
cleanup. Never delete source/published/preexisting or unowned resources in this
shared project. Accepted release images need a separate retention decision.

Check CPU/storage quotas before allocation; the historical 500 GB disk quota
may prevent three appliance VMs. Do not raise quotas or machine sizes
implicitly. No GPUs are needed. These are policy requirements, **not yet an
enforced VM lifecycle implementation**. GitHub concurrency only serializes this
metadata workflow. No VMs may start until the allocation, runtime and cleanup
gates in #153 have been reviewed and tested, with builder IAM separately
reviewed. This access phase neither grants nor implements VM creation.

## Sources and validation scope

Official sources consulted 2026-10-24:

- [Google WIF deployment pipelines](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines):
  numeric repository/owner attributes and conditions, service-account federation.
- [Google auth action v3](https://github.com/google-github-actions/auth):
  short-lived credentials, checkout ordering, cleanup and permissions.
- [Google setup-gcloud v3](https://github.com/google-github-actions/setup-gcloud):
  pinned CLI version; WIF requires CLI ≥363.0.0.
- [CLI 540.0.0 release announcement](https://groups.google.com/g/google-cloud-sdk-announce/c/pRR1RNN3_AM):
  selected known released CLI version, not a claim it is latest.
- [Custom image access](https://docs.cloud.google.com/compute/docs/images/managing-access-custom-images):
  per-image `roles/compute.imageUser`, avoiding project-wide grants.

- [Service-account IAM policy](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/get-iam-policy)
  and [key metadata listing](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list):
  account resource policy and `--managed-by=user` credential checks.

Offline shell/YAML checks cannot establish effective IAM, organization policy,
API propagation, image availability or successful federation. Those require the
actual authorized setup and trusted metadata workflow; record results in GitHub.

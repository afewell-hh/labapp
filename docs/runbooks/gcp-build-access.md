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
metadata. Action revisions and Cloud CLI version are pinned. It executes the
trusted main workflow without checking out repository files. It creates the
workspace directory before auth so the pinned auth action can write temporary
credentials; no later checkout can delete that file. It does not execute
repository scripts or accept commands, SHAs,
image names, or service accounts from a task comment. General Claude jobs and
Codex environments receive no cloud credentials. Protect main and review changes
to this workflow, because reviewed main code is this trust boundary.

This phase reads metadata for the image already shared with authenticated
users. The inspector receives no project/resource roles or image IAM grants.
The workflow performs only the fixed image metadata read. Project/platform
administrators and inherited permissions may still provide other impersonation
paths: this setup does not promise exclusive workflow access to the inspector.
No builder/runtime identities or build privileges are
created here. Do not attach the inspector identity to a VM. In this shared
project, future builder IAM must protect the published/source image and all
preexisting resources; broad Compute/storage administration is not approved.

## Owner setup in Cloud Shell

The owner uses their existing project access to enable the listed APIs, create
service accounts and WIF pools/providers, and edit the inspector's IAM policy.
No separate administrator or organization-wide policy access is required for
this metadata-only phase.
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
# Review project access and its visibility limits below; then acknowledge it.
export LABAPP_PROJECT_ACCESS_REVIEWED=yes
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

Before `--apply`, the owner reviews the visible project policy and records in
#152 the inspector's intended scope, known privileged project/platform paths,
and any inherited-policy visibility limits. Then set
`LABAPP_PROJECT_ACCESS_REVIEWED=yes`. This acknowledgment is limited to fixed
public-image metadata with no project/resource grants; it is not certification
that every inherited impersonation or group path has been audited.

A visible organization name does not prove access to its IAM policy. If
organization/folder policy reads are denied, record that limit rather than
claiming the project has no organization or that inherited access is absent.
Existing owners, default service accounts or platform service agents can have
privileged paths. The lead accepts those known paths and visibility limits for
this narrowly scoped phase; do not remove existing platform bindings. Any
builder privileges or access to private resources require a separate review of
effective roles and impersonation/attachment paths before being granted.
The script rejects direct project roles held by the inspector. It reads the
service account's own IAM policy and rejects every binding except the exact,
unconditional reviewed WIF role/member; an empty policy is also valid for first
setup. It rejects any user-managed keys, including disabled keys, by listing
key metadata only. It never reads key material, deletes keys, or removes IAM
bindings. Unexpected configuration requires administrator investigation before
retrying. These direct checks remain mandatory; the limited acknowledgment
does not waive them or permit direct alternate impersonators, keys, or
builder/administrative roles on the inspector.

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

If the metadata read is denied, distinguish authentication/API errors from
image permissions and report the evidence. Do not change image IAM to diagnose
this phase: `--share-source-image` is rejected. Source-image read/use grants,
private-image access and builder roles require separately reviewed scope; the
limited project acknowledgment cannot authorize them.

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

Offline lease primitives for these gates (single reusable slot, CAS
transitions, shared normal/janitor cleanup) are in
[`build/gcp/README.md`](../../build/gcp/README.md). They are library code and
tests only: they do not enable a workflow, adapter, IAM setup or VM execution.

## Lifecycle identity and ledger bootstrap

`build/gcp/bootstrap-lifecycle-access.py` prepares access separately from the
metadata inspector. It does not modify `labapp-inspector` or its pool. This is
access setup only: no controller adapter, workflow, VM, attached service account,
slot object or resource cleanup is executed. Keep the existing image and all
preexisting resources protected. Review/merge this bootstrap before applying it;
review the controller and fixed workflows separately before launching anything.

Run from the authenticated owner's session with Python 3 and Google Cloud CLI;
the Compute, IAM, STS, IAM Credentials and Storage APIs must already be enabled.
The target is fixed to project `teched-473722` / number `22685701361`:

```bash
# Offline plan, requires no gcloud/credentials and makes no network calls.
python3 build/gcp/bootstrap-lifecycle-access.py
# Optional read-only inventory/validation; missing resources are not created.
python3 build/gcp/bootstrap-lifecycle-access.py --inspect
# After reviewing the documented privilege scope and visibility limits:
export LABAPP_LIFECYCLE_ACCESS_REVIEWED=yes
python3 build/gcp/bootstrap-lifecycle-access.py --apply
```

`--apply` creates/reuses these exact resources, validates reused configuration
instead of overwriting it, and fails on unexpected direct roles, account trust,
keys, pool providers, signing keys, audiences, or ledger policy. Failed partial
setup can be rerun after investigation; it never removes unexpected resources,
keys or bindings. The script requires existing APIs rather than automatically
resolving access/API errors. Existing organization/platform administration and
inherited impersonation remain possible; record visible project policy and
known limits in #153. The acknowledgment means this new privilege scope was
reviewed, not that workflow-exclusive identity or complete inherited visibility
has been proven. No separate organization-administrator handoff is required.

| Identity | Dedicated pool | Allowed future workflow / events |
|---|---|---|
| `labapp-lc-creator` | `labapp-lc-creator` | `labapp-lifecycle-inspect.yml`, dispatch only |
| `labapp-lc-cleanup` | `labapp-lc-cleanup` | `labapp-lifecycle-cleanup.yml`, completed creator run, schedule or dispatch |

Both require the existing numeric repository/owner IDs, `refs/heads/main`, and
the exact workflow ref. Each SA binding also selects that workflow ref within
its own pool. Keeping separate pools prevents a provider intended for one
identity from impersonating the other through a pool-wide repository selector.
No generic worker job gets these credentials. The referenced workflows are not
installed by this bootstrap; future workflow implementation must preserve these
fixed refs and contain no arbitrary input/command execution.

The cleanup provider also allows `workflow_run` for immediate cleanup after the
trusted creator finishes, including cancellation, without giving the creator
Actions-write or delete privileges. The future cleanup workflow must trigger on
`completed` runs of the fixed creator workflow, then validate its expected
workflow name/path, head repository, `head_branch == main`, and original event
`workflow_dispatch` before using lifecycle credentials. Its own workflow code
must come from trusted main. Read the durable ledger and validate ownership;
never execute triggering-run code, commands, artifacts or event-supplied scripts.
Schedule and manual dispatch remain fallback paths. Provider event permission
alone does not implement or prove these trigger checks; the actual workflows
still require independent review before enabling cloud work.

Custom IAM roles separate creation/read from deletion:

- Creator: instance/disk creation, inline metadata/labels, inventory/operations,
  serial read and quota/subnet metadata. These project grants are **not**
  prefix-limited creation: they do not enforce VM count, shape, runtime, no-SA,
  no-external-IP or ownership. Metadata/label permissions can affect other VMs
  or disks, so fixed trusted code, preflight and lifecycle review are essential.
- Cleanup: instance/disk/zone-operation reads and the project-wide operation
  list needed for census, plus a separate delete-only role
  conditioned on Compute Instance/Disk type and the exact `us-central1-a`
  `labapp-lc-` name prefixes. The creator has no delete role; normal cleanup
  and the janitor must both run under the cleanup identity. Prefix IAM alone
  does not prove ownership: deletion still requires ledger and immutable-ID
  checks, and no preexisting resource may be deleted.
- Creator subnet use: only `default` in `us-central1`, via a separate subnet-level
  custom role. No network, firewall, external-IP, snapshot, image administration,
  service-account attachment/`actAs`, or service-account-key privilege is granted.
  Public Ubuntu/source images supply image read/use; no image IAM is changed.

The private ledger is exactly
`gs://labapp-lifecycle-ledger-22685701361`, regional `us-central1`, STANDARD,
with uniform bucket access and enforced public-access prevention. Each identity
gets `roles/storage.objectUser` **on this bucket only**. This pragmatic predefined
role includes object create/get/delete/list/update and more; it is not claimed
to be a minimal custom role. Overwriting a CAS ledger object requires create
and delete. No project-wide Storage role, bucket administration or automatic
slot expiry is granted. A reused bucket must belong to this project, remain
private, and have no object lifecycle deletion or retention hold that could
invalidate slot semantics. Existing owner/editor/viewer legacy bucket bindings
are recognized platform paths; inherited access is not disproven by this check.

The later controller starts with one persistent slot object and generation-matched
CAS for **every** transition; it must not release a slot before confirmed VM and
both disk deletion. This bootstrap deliberately does not initialize or delete
slot objects. A private bucket and IAM setup are not a capacity/runtime/cleanup
implementation; #153 still requires reviewed adapters, fixed workflows, quota
checks and live evidence before any VM starts. Conditional deletion is sourced
from supported Compute resource attributes, but actual IAM sufficiency and
allowed/denied behavior must be verified without attempting production deletes.

Offline checks:

```bash
python3 -m py_compile build/gcp/bootstrap-lifecycle-access.py
python3 -m unittest discover -s build/gcp -p 'test_bootstrap_lifecycle_access.py' -v
```

## Sources and validation scope

Official sources consulted 2026-10-24:

- [GA aggregated operation list](https://docs.cloud.google.com/compute/docs/reference/rest/v1/globalOperations/aggregatedList#iam-permissions):
  project-wide census requires `compute.globalOperations.list`; both lifecycle
  read sets include it, without adding region-operation permissions.
- [GA instance insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert):
  field-specific creation/metadata/label permissions; actual complete pilot
  sufficiency remains to be verified.
- [Compute prefix access conditions](https://docs.cloud.google.com/iam/docs/configuring-resource-based-access)
  and [resource attributes](https://docs.cloud.google.com/iam/docs/conditions-resource-attributes):
  supported existing Instance/Disk type and name conditions; no claim that they
  constrain resource creation.
- [Subnet IAM binding CLI](https://docs.cloud.google.com/sdk/gcloud/reference/compute/networks/subnets/add-iam-policy-binding):
  the subnet command accepts member/role/region but no condition flag; the one
  subnet-use grant is unconditional at that subnet, unlike the conditional
  project delete binding. Also checked with local CLI `--help` (no API call).
- [Storage IAM roles](https://docs.cloud.google.com/storage/docs/access-control/iam-roles):
  bucket-level Object User permissions and overwrite requirements.
- [Bucket creation](https://docs.cloud.google.com/sdk/gcloud/reference/storage/buckets/create)
  and [raw metadata](https://docs.cloud.google.com/sdk/gcloud/reference/storage/buckets/describe):
  region, uniform access, public-access prevention and raw ownership validation.

- [Google WIF deployment pipelines](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines):
  numeric repository/owner attributes and conditions, service-account federation.
- [Google auth action v3](https://github.com/google-github-actions/auth):
  short-lived credentials, cleanup and permissions. The
  [pinned auth source](https://github.com/google-github-actions/auth/blob/7c6bc770dae815cd3e89ee6cdf493a5fab2cc093/src/main.ts#L150-L157)
  explicitly supports legitimate use without checkout; the workspace directory
  must exist for its temporary credentials file.
- [Google setup-gcloud v3](https://github.com/google-github-actions/setup-gcloud):
  pinned CLI version; WIF requires CLI ≥363.0.0.
- [CLI 540.0.0 release announcement](https://groups.google.com/g/google-cloud-sdk-announce/c/pRR1RNN3_AM):
  selected known released CLI version, not a claim it is latest.
- [Custom image access](https://docs.cloud.google.com/compute/docs/images/managing-access-custom-images):
  authenticated-user image sharing; no additional image grant in this phase.

- [Service-account IAM policy](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/get-iam-policy)
  and [key metadata listing](https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list):
  account resource policy and `--managed-by=user` credential checks.

Offline shell/YAML checks cannot establish effective IAM, organization policy,
API propagation, image availability or successful federation. Those require the
actual authorized setup and trusted metadata workflow; record results in GitHub.

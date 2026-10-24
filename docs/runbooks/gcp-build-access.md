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

Use this named workflow on `main` for the metadata-only scope described above.
The separately scoped [fixed lifecycle runner](../../build/gcp/README.md#fixed-lifecycle-runner)
supports lead-dispatched serial VM pilots and independent cleanup. Neither path
permits arbitrary workflows/commands or general worker cloud credentials. Record
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

The lifecycle inspector's source-copy disk stays `READ_ONLY` and must use
`autoDelete: false`: Compute forbids auto-delete for read-only attachments.
Its boot disk uses `READ_WRITE` with `autoDelete: true`. VM termination with
`DELETE` therefore requests boot-disk deletion but leaves the 300GB source copy.
Normal cleanup or the independent janitor must explicitly delete that owned
copy using the recorded scope/name/immutable ID, wait for the disk operation
and confirm 404. A missing VM alone never releases capacity. The VM's absolute
deadline does not bound data-disk retention; independent scheduled cleanup is
best-effort, and failed cleanup remains capacity-blocking until resolved.

Check current CPU/storage quotas before allocation; quota reads are snapshots,
not reservations. Do not raise quotas or machine sizes implicitly. No GPUs are
needed. The [fixed lifecycle runner](../../build/gcp/README.md#fixed-lifecycle-runner)
implements one reusable CAS slot, project-wide census, absolute expiry and
shared verified normal/janitor cleanup through GCS/Compute adapters. GitHub
concurrency is only a workflow throttle, not capacity enforcement. The metadata
workflow remains read-only and grants no VM creation capability.

The fixed creator/cleanup workflows support the serial lifecycle pilot, not
routine Packer builds, a three-slot allocator or guest recovery. New scope
requires its own reviewed/tested lifecycle and IAM gates. Keep overall #153/#161
acceptance and live evidence in GitHub rather than inferring them from access
setup or these instructions.

## Lifecycle identity and ledger bootstrap

`build/gcp/bootstrap-lifecycle-access.py` prepares access separately from the
metadata inspector. It does not modify `labapp-inspector` or its pool. This is
access setup only: no controller adapter, workflow, VM, attached service account,
slot object or resource cleanup is executed. Keep the existing image and all
preexisting resources protected. Apply only the reviewed bootstrap from trusted
main under the lead's authorized scope; access setup does not authorize a VM
launch. Controller/workflow changes require separate review and validation.

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

| Identity | Dedicated pool | Allowed trusted-main workflow / events |
|---|---|---|
| `labapp-lc-creator` | `labapp-lc-creator` | `labapp-lifecycle-inspect.yml`, dispatch only |
| `labapp-lc-cleanup` | `labapp-lc-cleanup` | `labapp-lifecycle-cleanup.yml`, completed creator run, schedule or dispatch |

Both require the existing numeric repository/owner IDs, `refs/heads/main`, and
the exact workflow ref. Each SA binding also selects that workflow ref within
its own pool. Keeping separate pools prevents a provider intended for one
identity from impersonating the other through a pool-wide repository selector.
No generic worker job gets these credentials. The referenced workflows are not
installed by this bootstrap; their checked-in implementations preserve these
fixed refs and contain no arbitrary input/command execution. See the
[fixed runner contract](../../build/gcp/README.md#fixed-lifecycle-runner).

The cleanup provider also allows `workflow_run` for immediate cleanup after the
trusted creator finishes, including cancellation, without giving the creator
Actions-write or delete privileges. The checked-in cleanup workflow triggers on
`completed` runs of the fixed creator workflow, then validates its expected
workflow name/path, head repository, `head_branch == main`, and original event
`workflow_dispatch` before using lifecycle credentials. It fetches allowlisted
code at its own trusted-main SHA, reads the durable ledger and requires the
triggering run ID/attempt to match before forced cleanup. It never executes
triggering-run code, commands, artifacts or event-supplied scripts. Manual
main dispatch forces the current lease; scheduled cleanup handles due leases
and remains best-effort. Provider event permission alone does not establish
these checks; retain them and independent review when changing the workflows.

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
invalidate slot semantics. Existing own-project owner/editor legacy bucket
and object owner bindings, and viewer legacy bucket and object reader bindings,
are recognized platform defaults for uniform bucket access. This does not
disprove inherited access; public, foreign-project, extra-user, unknown-role
and conditional direct bindings remain rejected.

The controller uses one persistent slot object and generation-matched CAS for
**every** transition; it does not release a slot before confirmed VM and both
disk deletion. This bootstrap deliberately does not initialize or delete
slot objects. A private bucket and IAM setup are not a capacity/runtime/cleanup
implementation. The fixed runner supplies reviewed adapters, trusted workflows
and quota checks; live acceptance evidence and any wider #153 scope remain
separate requirements. Conditional deletion is sourced
from supported Compute resource attributes, but actual IAM sufficiency and
allowed/denied behavior must be verified without attempting production deletes.

Offline checks:

```bash
python3 -m py_compile build/gcp/bootstrap-lifecycle-access.py
python3 -m unittest discover -s build/gcp -p 'test_bootstrap_lifecycle_access.py' -v
```

## Owner IAP access to an owned inspector

This is a lead-run access plan for #173/#170/#151, not an automated bootstrap
or permission to access a preexisting appliance. The shared create request and
creator/cleanup roles stay unchanged. Current lifecycle-only pilots stay
untagged. Only the existing owner `art@githedgehog.com`, using the current
trusted lead host, prepares access to a separately authorized inspector after
its creation and ownership checks. No new principal, receiver, VM service
account, external IP, metadata SSH key or worker credential is needed.

Before setup, verify the authenticated account and its effective permissions.
Google documents that project Owner can use IAP TCP forwarding; this is not
evidence that an account currently has Owner or that deny/organization policies
permit access. Check `iap.tunnelInstances.accessViaIAP`, Compute instance
get/list and project get, plus OS Login and `compute.instances.osAdminLogin`
for the later privileged mount wrapper. Prove OS Login/admin access in the
synthetic pilot instead of automatically granting IAP/OS Admin Login roles.
Service Account User is unnecessary for this no-SA VM. Keep instance
`enable-oslogin=TRUE` and `block-project-ssh-keys=TRUE`; never fall back to
project/instance SSH metadata keys. Source collector content remains private.

### Dedicated access firewall infrastructure

The lead owns one dedicated rule, configured once for the inspection series,
with explicit teardown at series end. It is **access infrastructure, not a
per-lease child**: the current controller/janitor owns only VM/boot/data disk
cleanup and cannot claim firewall deletion. Record the rule's name, immutable
ID, creation operation and exact configuration in a nonsecret issue receipt,
with the lead responsible for teardown even on failure/cancellation. Do not
silently leave a temporary rule for the controller to collect.

Fixed contract: project `teched-473722`, existing VPC `global/networks/default`,
rule and target network tag `labapp-inspector-iap-ssh`, ingress allow only
`tcp:22` from `35.235.240.0/20`, priority 1000. The default VPC and its
`us-central1/default` subnet are **preexisting protected infrastructure**, not
owned resources. Verify that subnet's actual network link matches this VPC;
the name `default` alone proves neither identity nor ownership. Inventory all
VMs in the project and confirm no preexisting/unowned VM has the reserved tag.
Review effective firewall policy: this narrow allow does not negate broader
existing rules or override denies. Report conflicting rules without modifying
them. Network tags scope this firewall, not IAP IAM authorization.

The following are documented commands for the lead's reviewed setup, not
commands executed by this change:

```bash
gcloud compute firewall-rules describe labapp-inspector-iap-ssh \
  --project=teched-473722 --format=json
# Only after confirmed absence, verified VPC/subnet/tag inventory and recorded intent:
gcloud compute firewall-rules create labapp-inspector-iap-ssh \
  --project=teched-473722 --network=default --direction=INGRESS \
  --priority=1000 --action=ALLOW --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=labapp-inspector-iap-ssh \
  --description='Lead-managed inspector IAP SSH access; teardown after inspection series'
gcloud compute firewall-rules describe labapp-inspector-iap-ssh \
  --project=teched-473722 --format=json
```

Authentication/API errors are not absence. A same-name rule without the prior
ownership receipt, or with any conflicting ID/configuration, blocks setup;
never overwrite or adopt it by name. On readback require the exact network,
direction, priority, source range, target tag and TCP22-only allow; no extra
ports/protocols, source tags/service accounts, target service accounts or deny
entries, and `disabled=false`. Broader fields or incomplete visibility block
the access pilot. This plan does not enable APIs or change firewall/IAM policy
automatically.

### Owner adds the tag after creation

Do not add tags to the shared creation body: the v1 insert API requires
`compute.instances.setTags` for that field, which the creator role lacks.
No creator role expansion or generic transport endpoint is proposed here.
The existing owner performs this separate administrative access mutation only
after insert is terminal, controller confirmation has persisted all three IDs,
and there is sufficient time before the unchanged absolute deadline. Do not
mutate an in-flight or superseded lease, change its saved body hash, or renew
its deadline. Coordinate with normal/janitor cleanup; cleanup retains priority.

Use the exact instance name from the current ledger, never a prefix-selected
or preexisting VM. Immediately before mutation, get the instance and verify
project/zone, immutable VM ID, lease/run/owner labels, unchanged deadline,
no service account/external IP, OS Login metadata and exactly the two intended
attachments and immutable disk IDs (boot read-write/auto-delete, source copy
read-only/retained). Verify both disks' pinned source-image IDs. Require the
existing tag list empty; unexpected tags block rather than being removed.
Record only nonsecret identities/configuration in the access receipt.

Use the **current** `tags.fingerprint` from that same instance read for the
reviewed owner-authenticated Compute v1 request. This is a request template,
not a command that supplies credentials or bypasses the preceding checks:

```text
GET https://compute.googleapis.com/compute/v1/projects/teched-473722/zones/us-central1-a/instances/EXACT_LEDGER_INSTANCE
# Verify response.id equals the ledger's confirmed VM ID and all checks above.
POST https://compute.googleapis.com/compute/v1/projects/teched-473722/zones/us-central1-a/instances/EXACT_LEDGER_INSTANCE/setTags
{
  "items": ["labapp-inspector-iap-ssh"],
  "fingerprint": "CURRENT_FINGERPRINT_FROM_VERIFIED_GET"
}
```

Await the returned operation's terminal success, bind its target ID/link to
that exact VM, then re-read and require unchanged ID/lease/deadline/attachments
and exactly the dedicated tag. A fingerprint conflict means stop and
re-evaluate ownership, not unconditional retry. The fingerprint protects tag
updates, **not an atomic immutable-VM-ID precondition**. Serialize owner actions;
an ID replacement or concurrent lifecycle change blocks access and requires
lead adjudication. A tag is a VM field, not a separate cloud resource; it goes
away when the VM is deleted. It does not establish ownership or weaken any
existing protected-resource census/deletion check.

### Synthetic access, transfer and teardown

Before any raw extraction, the owner proves SSH/OS Login/admin access and
private transfer using harmless synthetic marker data only. Bind SSH host-key
evidence to the exact confirmed inspector incarnation using a trusted channel
before connection; unresolved host identity blocks the pilot. Use IAP and
`--strict-host-key-checking=yes` explicitly (gcloud's first-connection default
is `no`). Do not use unauthenticated keyscan or first-use acceptance as proof.
Keep owner SSH keys/credentials on the trusted host and out of the VM, repo,
GitHub artifacts and general worker sessions.

Pull only the known bounded synthetic file by authenticated SFTP/SCP into an
exclusive-create mode0600 file in the lead's mode0700 temporary directory.
Verify recipient UID, size and checksum, with only fixed status/count/hash
receipts; no raw content, shell tracing or stdout transfer. Same-UID trusted
contributors are not adversarially isolated by these modes. Synthetic success
does not authorize an unreviewed mount or collector change. Delete private
staging promptly and invoke the existing lifecycle cleanup on success/failure/
cancellation; require VM and both disks 404 before slot reuse.

At series end, the lead re-reads the dedicated firewall and compares its
immutable ID and complete configuration with the recorded owned receipt.
Confirm no remaining inspector uses it, then delete only that exact rule:

```bash
# Only after the immediately preceding ownership/configuration checks:
gcloud compute firewall-rules delete labapp-inspector-iap-ssh \
  --project=teched-473722
gcloud compute firewall-rules describe labapp-inspector-iap-ssh \
  --project=teched-473722 --format=json
```

Wait for the deletion operation and require confirmed not-found; errors are
not successful cleanup. Firewall deletion is name-addressed, with no atomic
ID guard: serialize teardown, stop on replacement/mismatch and record any
cleanup failure. Do not delete the default VPC/subnet, preexisting rules or
another VM's tags. Firewall teardown, private-file cleanup and VM/disk cleanup
have separate receipts; none implies the others succeeded.

Sources read 2026-10-24 (documented, not live-tested here):
[IAP TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding),
[OS Login setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin),
[network tags](https://docs.cloud.google.com/vpc/docs/add-remove-network-tags),
[v1 insert tags permission](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert),
[v1 setTags fingerprint](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/setTags),
[firewall create flags](https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/create),
and [gcloud SSH host checks](https://docs.cloud.google.com/sdk/gcloud/reference/compute/ssh).
Effective owner permissions, firewall reachability, host-key binding, OS Login
and private transfer still need the separately authorized synthetic pilot.

## Sources and validation scope

Official sources consulted 2026-10-24:

- [Disk auto-delete settings](https://docs.cloud.google.com/compute/docs/disks/modify-persistent-disk#autodelete):
  read-only attachments cannot auto-delete; retained disks incur cost until
  explicitly deleted. This constraint is stated in the disk guide, beyond the
  `instances.insert` boolean field schema.
- [Cloud Storage basic-role convenience values](https://docs.cloud.google.com/storage/docs/access-control/iam-roles):
  a new uniform-access bucket gives project owners/editors both legacy bucket
  owner and object owner roles, and viewers both legacy bucket reader and object
  reader roles. These are existing platform access paths, not bootstrap grants.
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
actual authorized setup and the relevant fixed metadata/lifecycle workflows;
record results in GitHub.

# Manual Lab VM Image Build (historical fallback runbook)

This is the documented way to build a Lab VM image until an automated Packer
build exists. It is a historical manual fallback, not the default development
iteration process; for day-to-day changes use the cheapest-representative
testing layers in
[agent-workflow.md](../contributing/agent-workflow.md#testing-cheapest-representative-first).
It was moved here from the former root `AGENTS.md`/`CLAUDE.md`
without changing the commands. An automated Packer build does **not** exist
yet; progress is tracked in issue #145.

These steps create cloud resources and images. Run them only as the
lead/owner or when a task explicitly authorizes cloud commands. Workers must
not run them otherwise. Delete test VMs when done.
Check current CPU and storage quotas before launch; never increase them implicitly.
Never commit secrets or credentials.

## Reviewed immutable-source baseline

The saved image `teched-473722/hedgehog-vaidc-v20260114`, immutable image ID
`7638370619126112785`, has a reviewed read-only inventory. The
[published candidate and separate lead source attestation](https://github.com/afewell-hh/labapp/issues/151#issuecomment-6388996007)
identify the collector/candidate revisions and each captured file hash. The
accepted canonical candidate SHA-256 is
`44e5454ab21f75d69b4bfd59ab77d378e1611a86161456f03e2de7441b7aa290`.
These installed versions describe that source; they are observations, not
recommended upgrade targets or new-build pins.

| Installed packages | Observed versions, in matching order |
| --- | --- |
| `docker-ce`, `docker-ce-cli`, `containerd.io` | `5:29.1.3-1~ubuntu.24.04~noble`, `5:29.1.3-1~ubuntu.24.04~noble`, `2.2.1-1~ubuntu.24.04~noble` |
| `qemu-system-x86`, `qemu-utils` | Both `1:8.2.2+ds-0ubuntu1.11` |
| `xfce4`, `xfce4-session`, `xrdp` | `4.18`, `4.18.3-1build2`, `0.9.24-4` |
| `git`, `curl`, `jq` | `1:2.43.0-1ubuntu7.3`, `8.5.0-2ubuntu10.6`, `1.7.1-3ubuntu0.24.04.1` |
| `openssh-server` | `1:9.6p1-3ubuntu13.14` |
| `python3` | `3.12.3-0ubuntu2.1` |
| `cloud-init` | `25.2-0ubuntu1~24.04.1` |
| `ubuntu-minimal` | `1.539.2` |

### Persisted startup literals

The [accepted startup candidate and separate lead attestation](https://github.com/afewell-hh/labapp/issues/151#issuecomment-6389492802)
add selected persisted settings for the same immutable image ID
`7638370619126112785`. Candidate SHA-256:
`a1962de0ecd47b8baf0bb1ab37629b3557ad72407800fd25137835d472e2827a`.
The canonical os-release check verifies exactly `ID=ubuntu`,
`VERSION_ID=24.04` and `VERSION_CODENAME=noble`; it does not verify other
os-release fields. The original inventory skipped the `/etc/os-release`
symlink; canonical verification does not turn skipped paths into inspected
ones.

The five captured files are under `/etc/systemd/system/`. The table records
recognized literal settings, not complete units to install. All five contain
`RemainAfterExit=yes`; the first four also contain
`WantedBy=multi-user.target`, which does not establish that they are enabled.

| Unit | Recognized persisted settings | Literal recovery limits |
| --- | --- | --- |
| `argocd-port-fix.service` | `Requires=docker.service`; `Type=oneshot`; `ExecStart=/usr/local/bin/fix-argocd-port.sh`; `TimeoutStartSec=180` (180 seconds) | Unsupported directive and value withheld. |
| `hhbr-ip.service` | `After=hhfab-vlab-resume.service`; `Wants=hhfab-vlab-resume.service`; `Type=oneshot`; `ExecStart=/usr/local/bin/hhbr-ip-setup.sh`; `Restart=on-failure`; `RestartSec=30` (30 seconds) | Only unit with a complete recognized literal subset; helper implementation remains unknown. |
| `hhfab-vlab-resume.service` | `After=network-online.target`; `Wants=network-online.target`; `Type=forking`; `ExecStart=/usr/local/bin/hhfab-vlab-resume.sh`; `User=ubuntu`; `Group=ubuntu`; `WorkingDirectory=/home/ubuntu/hhfab`; `TimeoutStartSec=120` (120 seconds) | Unsupported directive withheld. |
| `kubeconfig-merge.service` | `After=network-online.target hhfab-vlab-resume.service`; `Wants=network-online.target`; `Type=oneshot`; `Restart=no` | Unsupported value withheld; no command recovered in the accepted subset. |
| `vlab-netfilter.service` | `DefaultDependencies=no`; `Type=oneshot` | Repeated assignment and unsupported value withheld; no command or install target recovered in the accepted subset. |

Supplemental observed literals approved in
[#201](https://github.com/afewell-hh/labapp/issues/201) add three facts for the
same immutable source, based on the lead's private complete-line comparison
and independent approval of the public literal associations:

- `hhfab-vlab-resume.service`: `[Service] Environment="TERM=xterm-256color"`.
- `argocd-port-fix.service`: `[Service] StandardOutput=journal`.
- `argocd-port-fix.service`: `[Service] StandardError=journal`.

These supplements were not in the startup candidate identified by the hash
above; the table describes that earlier candidate's recovery limits. A newly
derived candidate still requires independent approval before publication.
These three facts do not establish complete or effective units.

All three referenced helpers have presence/hash receipts, but their
implementations and behavior remain unknown: `/usr/local/bin/fix-argocd-port.sh`,
`/usr/local/bin/hhbr-ip-setup.sh` and `/usr/local/bin/hhfab-vlab-resume.sh`.
The [historical public recipe in #131](https://github.com/afewell-hh/labapp/issues/131)
did not exactly match the source hhbr helper and must not substitute for it.

Even the complete recognized hhbr literal subset does not establish complete
or effective configuration, enablement, runtime state or successful startup.
Drop-ins were not composed, masks and aliases were not resolved, generators
and runtime were not inspected, and unknown fields were withheld. The
collector skipped symlinked `/lib` paths; skipped paths remain unknown, not
absent. Missing fixed paths do not prove no equivalent component exists
elsewhere. These subsets must not be deployed as production-ready unit files.

### Persisted CLI identity and VLAB topology

The [approved host candidate and separate lead provenance attestation](https://github.com/afewell-hh/labapp/issues/208#issuecomment-6391555177)
extend this baseline for the same source image
`teched-473722/hedgehog-vaidc-v20260114`, immutable ID
`7638370619126112785`. The capture used accepted main revision
[`57b920b67dfa2ff769d76f54e3761e41ddbdd962`](https://github.com/afewell-hh/labapp/commit/57b920b67dfa2ff769d76f54e3761e41ddbdd962).
The lead bound the private source to the derived candidate; the independent
reviewer approved the exact derived candidate and provenance without inspecting
raw source. These are observed persisted facts, not new-build or upgrade pins.

- The captured `hhfab` binary is byte-identical to the official
  `hhfab-v0.43.1-linux-amd64` release member. No guest application was executed.
  The other recorded binary identities were subsequently resolved as follows.

| Binary / version (linux/amd64) | Source bytes | Source SHA-256 | Identity evidence |
| --- | ---: | --- | --- |
| `helm` 3.19.4 | 60,182,712 | `ea22096683b9b61005584501e36168a1eadc5b6883a89df299f5a55e4e2dd283` | [Accepted official archive-member comparison and independent audit](https://github.com/afewell-hh/labapp/issues/314#issuecomment-6430812209); acquired archive verified before member hashing. |
| `k3d` 5.7.4 | 24,215,704 | `1ac1da365236736a8df8c32107b54aca208384ab1d9a06771443c85ad698a5eb` | [Accepted publisher checksum/asset-size metadata match](https://github.com/afewell-hh/labapp/issues/313#issuecomment-6428750111); no binary acquired. |
| `kubectl` 1.35.0 | 58,597,560 | `a2e984a18a0c063279d692533031c1eff93a262afcc0afdc517375432d060989` | [Accepted publisher checksum/asset-size metadata match](https://github.com/afewell-hh/labapp/issues/313#issuecomment-6428750111); no binary acquired. |

These identities retain the approved source receipt's lengths and hashes.
The Helm archive digest covers a different object from the binary digest above.
HTTPS/checksum provenance does not establish verified signatures; these matches
establish neither runtime behavior nor full appliance equivalence, and select
no new installation or upgrade pins. Oras presence, hash and version remain
unknown.

- The complete captured wiring matches the parsed documents of the existing
  root [`wiringd.yaml`](../../wiringd.yaml), SHA-256
  `c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a`:
  7 switches (2 spines and 5 server-leaves), 10 servers, 21 connections,
  3 switch groups, one VLAN namespace spanning 1000–2999 and one IPv4
  namespace containing `10.0.0.0/16`. The public fixture is unchanged.
  Parsed-document equality does not establish full graph semantics or
  effective/hydrated Fabric validity.
- The persisted VLAB configuration contains 1 control, 7 switch and 10 server
  VM entries. Its selected size settings are below. Gateway and external
  size settings do not establish that VMs of those types are configured or
  running.

| VLAB size type | CPU (cores) | RAM (MB) | Disk (GB) |
| --- | --- | --- | --- |
| `control` | 6 | 6144 | 100 |
| `switch` | 4 | 5120 | 50 |
| `server` | 2 | 768 | 10 |
| `gateway` | 8 | 6144 | 50 |
| `external` | 4 | 5120 | 50 |

Field units follow the versioned upstream
[`VMSize` definition in Fabricator v0.43.1](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/vlabconfig.go#L163-L167)
(accessed 2026-10-25): cores, MB and GB. These labels retain upstream's
terminology; they do not measure runtime allocation or host capacity.

The fabric file was rejected during YAML parsing, so no Fabric settings were
recovered from it; secret-bearing text was neither repaired nor published.
That historical refusal does not establish malformed source YAML: the public
official hhfab 0.43.1 template includes a separation tab accepted by libyaml
but refused by the earlier pure-Python parser. The actual cause of the source
refusal remains unverified; the original private report was deleted. The
trusted host deriver now requires libyaml-backed CSafeLoader and a supported
PyYAML version (see [parser requirements](../../build/gcp/README.md)); this
change recovers no additional historical source facts.
The captured generic modules and sysctl files yielded no selected settings;
the selected bridge-specific modules and sysctl files were missing. These
bounded observations do not prove that equivalent settings are absent elsewhere.
All shell recipes remain unknown, including captured system bashrc/profile
and user bashrc; MOTD, user aliases and user profile were missing at the selected
paths. All original helper implementations remain unknown.

Chart/app versions, GitOps/seed inputs, network/shell behavior and runtime/student
compatibility remain gaps; see [#151](https://github.com/afewell-hh/labapp/issues/151).
These recovery limits describe historical evidence, not defaults for a future
image or a diagnosis of current production. Persisted inputs do not establish
effective/hydrated configuration, enabled/running services, a complete automated
build or student acceptance. Reproducing the image still requires reviewed
configuration recovery and clean build, boot/reboot and student acceptance.
The historical commands below are a separate manual workflow, not evidence
that they reproduce this immutable source.

## Step 1: Launch VM with cloud-config

```bash
# See gcp_vm_launch_command.txt for the full command
gcloud compute instances create hedgehog-lab-YYYYMMDD \
  --project=YOUR_PROJECT \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=400GB \
  --boot-disk-type=pd-ssd \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Cascade Lake" \
  --metadata-from-file=user-data=cloud-config.yaml
```

## Step 2: Verify cloud-init completion

```bash
# SSH in and check cloud-init status
gcloud compute ssh hedgehog-lab-YYYYMMDD --zone=us-central1-a

# On the VM:
cloud-init status --wait
cat /var/log/cloud-init-output.log
```

## Step 3: Manual VLAB installation

Complete any steps that cloud-config cannot handle:

- Verify all dependencies installed correctly (Docker, KVM/QEMU, hhfab, etc.)
- Run `hhfab init` and configure fab.yaml
- Run `hhfab vlab up` and wait for VLAB to be ready

## Step 4: Save VM as image

```bash
# Stop the VM first
gcloud compute instances stop hedgehog-lab-YYYYMMDD --zone=us-central1-a

# Create image from the VM's boot disk
gcloud compute images create hedgehog-lab-vYYYYMMDD \
  --source-disk=hedgehog-lab-YYYYMMDD \
  --source-disk-zone=us-central1-a \
  --family=hedgehog-labapp \
  --description="Hedgehog VLAB pre-configured lab environment"
```

## Step 5: Test the image

```bash
gcloud compute instances create test-from-image \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image=hedgehog-lab-vYYYYMMDD \
  --boot-disk-size=400GB \
  --enable-nested-virtualization
```

## Known issues and troubleshooting

### QEMU/KVM not installed after cloud-init

The `qemu-kvm` package in cloud-config may fail silently. Verify with:

```bash
which qemu-system-x86_64
kvm --version
```

If missing, install manually:

```bash
sudo apt-get update
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
```

### Checking cloud-init logs

```bash
# Full output log
cat /var/log/cloud-init-output.log

# Cloud-init status
cloud-init status
cloud-init status --long

# Per-module logs
cat /var/log/cloud-init.log
```

### Updating cloud-config.yaml

- Test with the cheapest representative layer first (schema/syntax and
  component tests; see
  [testing layers](../contributing/agent-workflow.md#testing-cheapest-representative-first)).
  Launch a fresh VM and monitor cloud-init logs when the changed behavior
  requires an actual boot or VM check. Final clean image build, boot/reboot
  and student gates remain required for appliance releases.
- Keep installations idempotent where possible.
- Document any packages that consistently fail in cloud-init (in the
  relevant GitHub issue until a stable limit is confirmed, then here).

## Quick reference

```bash
# Launch new VM with cloud-config
# Historical recipes only; select and adapt ONE command:
cat gcp_vm_launch_command.txt

# SSH into VM
gcloud compute ssh INSTANCE_NAME --zone=us-central1-a

# Check cloud-init status
cloud-init status --wait

# Stop VM for imaging
gcloud compute instances stop INSTANCE_NAME --zone=us-central1-a

# Create image
gcloud compute images create IMAGE_NAME \
  --source-disk=INSTANCE_NAME \
  --source-disk-zone=us-central1-a \
  --family=hedgehog-labapp

# List images
gcloud compute images list --filter="family:hedgehog-labapp"

# Delete old test VMs
gcloud compute instances delete INSTANCE_NAME --zone=us-central1-a
```

## GCP Marketplace publishing (future, not a current objective)

Marketplace publication is not the current primary objective (decisions
recorded in #136 and #137). If it is revisited once the image is stable:

1. Create image in GCP project
2. Set up Cloud Marketplace Partner account
3. Create product listing with VM image
4. Submit for review

## Candidate VLAB core guest integration

The fixed [`vlab_core.py` contract](../../build/provision/README.md#dedicated-guest-vlab-core-assembly-and-preserved-state-resume)
provides fresh import, foreground systemd startup, canonical readiness and
preserved-state resume in a dedicated appliance guest. It consumes explicit
private FAB plus already provisioned baseline tools/packages, including QEMU
`.11`; it does not install packages or launch a provider VM. Its source tests do
not authorize or prove an actual eighteen-node trial. The existing small builder
fixture is insufficient for this profile.

This candidate intentionally records unknown original FAB/helper/startup values
and direct service versus historical tmux as differences. It uses the generated
private VLAB kubeconfig explicitly and does not merge student contexts or claim
desktop/EMC/GitOps/telemetry/course equivalence. Preserve the published source image
and existing student procedures until a separately reviewed candidate passes
runtime/persistence and owner acceptance. A bounded service stop contains owned
processes; it is not evidence of graceful guest OS shutdown or disk quiescence.

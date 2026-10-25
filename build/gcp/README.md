# GCP build access and VM lease primitives

## Offline private filesystem collector

`inspection/collector.py` is a Python 3.12+ standard-library command for an
**already mounted, stable, read-only guest root on Linux**. It does not mount,
repair, chroot, execute/source guest code, or use cloud credentials. No workflow
invokes it against a guest. Mounting, private authenticated transfer/storage,
reviewer access, deletion deadlines and lifecycle authorization must be reviewed
separately before actual guest use; this module does not supply those gates.

Invoke unchanged from the repository root as an inspector user with read access
to the mount and an existing, owned mode-0700 private output directory:

```bash
python3 -m build.gcp.inspection.collector \
  --root /mnt/guest --private-output /private/inspection/inventory.json
python3 -m unittest discover -s build/gcp/inspection -t build/gcp -v
```

The new output file is exclusive-create, mode 0600, outside the guest root,
limited to 8 MiB. Never upload or print it. stdout contains only status counts
and a report hash; errors do not include guest content. Raw units/helpers can
contain secrets even at allowlisted paths. Private output still requires a
separate reviewed transfer and field-redaction pass before any public use;
neither allowlisting nor a future pattern scanner proves publication safety.

Schema 1 records guest path, kind, status and (for captured files) SHA-256.
OS release at both fixed `/etc/os-release` and `/usr/lib/os-release` paths,
six named units and their `.conf` drop-ins are captured privately.
The names are `hhfab-vlab-resume`, `vlab-netfilter`, `hhbr-ip`,
`kubeconfig-merge`, `argocd-port-fix`, `hhfab-vlab`; these are historical leads,
not evidence that the saved image has them. Installed package name/version
pairs come from the guest `/var/lib/dpkg/status` via a bounded stdlib parser,
never the inspector's package database. Other dpkg fields are not copied.

Helper discovery accepts only a simple first executable from `ExecStart`,
`ExecStartPre` or `ExecStartPost`, with a fixed basename matching those six
names (optionally `.sh`), `hhfab-vlab-runner`, `hhbr-ip-setup.sh` or
`fix-argocd-port.sh` (the last two are historical #138 candidates), in `/usr/local/bin`,
`/usr/local/sbin`, `/opt/hedgehog/bin`, `/home/ubuntu/bin` or `/home/hhlab/bin`.
It does not interpret shell wrappers, expand systemd specifiers or recursively
follow helpers. Unsupported references remain in private unit text for review.
No arbitrary home/opt directory traversal, environment-file reads, token files,
kubeconfigs, SSH keys, histories, databases, container data or VM disks occur.
Legitimate helper names containing `kubeconfig` are allowed by exact name.

Every guest path component is opened relative to a pinned directory fd with
`O_NOFOLLOW`; **all symlinks are skipped and reported**, including legitimate
`/etc/os-release` or `/lib` guest links. Files must be regular UTF-8 text, at
most 256 KiB (16 MiB for dpkg). Drop-in enumeration is nonrecursive and bounded
to 128 entries per directory; the report has a 256-capture ceiling. A gap is
not evidence that a component is absent. This is filesystem evidence, not
systemd effective configuration or runtime verification. It assumes a trusted
inspector host and no concurrent mount replacement.

The report explicitly marks network/sysctl/modules, fabric/wiring sanitization,
shell profiles, binary versions, charts, environment files, recursive helpers,
effective systemd configuration and runtime recovery unimplemented. These need
separate slices; this command cannot recover the complete appliance baseline.

### Private inventory candidate

After the separately authorized transfer, the lead can derive a smaller private
candidate on the trusted lead host without executing any report content:

```bash
python3 -m build.gcp.inspection.candidate \
  --private-input /private/inspection/inventory.json \
  --private-output /private/inspection/candidate.json
```

Both parent directories must already be owned mode0700; input must be an owned
regular mode0600 file, and output is exclusive-create0600. No raw file body,
execution/environment string, OS release body, unknown package name or dynamic
drop-in filename is copied. The candidate contains fixed kind/status counts,
installed versions only for the fixed `candidate.PACKAGES` catalog, and status/
SHA-256 entries only for compile-time named unit/helper paths. Captured text
hashes are checked against their private bodies before releasing hash metadata.
OS release is represented by status counts only; gaps are not proof of absence.

Schema1, exact keys/types, known paths/statuses, bounded sizes and duplicate JSON
keys are validated before output. Unknown data fails closed. The source image
is **not** inferred from guest claims: provenance remains
`lead-verification-required` until the lead separately binds the accepted cloud
image/disk/lease evidence. stdout contains only fixed status, counts and candidate
hash. No automatic GitHub publication or credential scanner is supplied. The
candidate remains private until lead and independent review approve its exact
hash; this tool does not claim arbitrary version strings or hashes are safe
for publication without that review. Keep raw/intermediate retention and cleanup
under the private-transfer contract; delete promptly after accepted recovery or
an abandoned attempt. Unit/helper configuration recovery is a separate reviewed
slice; metadata inventory does not recover effective settings or runtime.

### Private persisted startup candidate

The lead can derive reusable selected startup configuration using the same
private file/mode/hash checks and review/publication boundary:

```bash
python3 -m build.gcp.inspection.startup \
  --private-input /private/inspection/inventory.json \
  --private-output /private/inspection/startup.json
```

This preserves the inventory fields and adds `persisted_startup` schema1.
Named base units yield selected `[Unit]`, `[Service]` and `[Install]` settings
plus a pure formatted unit containing only those recovered settings. Dependency,
identity, directory, boolean and service-mode values use compile-time public
catalogs. Literal second values are integers from 0 through3600. Startup
commands must match complete public literal commands in `startup.COMMANDS`,
including the historical #130 inline netfilter command. No arbitrary command
arguments, environment values, descriptions, documentation URLs or unknown
directive/section names enter the output. The sole environment exception is
the complete quoted
`Environment="TERM=xterm-256color"` assignment in `[Service]`, approved in
[#201](https://github.com/afewell-hh/labapp/issues/201). `StandardOutput` and
`StandardError` accept only `journal`. Other environment assignments,
`EnvironmentFile`, specifiers and output targets remain withheld.
Unknown directives/values/syntax, duplicate assignments and resets produce
fixed gap codes. Repeated/reset directives are omitted rather than assigning
invented precedence. Backslashes
refuse the entire unit's settings because continuation/escape semantics are
unsupported; this is deliberately not a systemd parser.
CRLF is normalized to LF; lone CR and Unicode whitespace/separators refuse
the unit subset rather than creating apparent directives inside private text.

Captured helpers yield a reusable script only when the whole body matches a
public checked-in recipe: currently `hhbr_ip_131.txt`, from issue#131. Only
CRLF and one final newline are normalized; comments, shebang, quoted content
and whitespace remain significant. A mismatch yields `recipe: unknown`.
Historical recipes are not proof of saved-image configuration until matched.

`literal_subset_complete` means no unrecognized execution-related assignment
was encountered in that base file; it does not mean the formatted subset is a
complete effective service. Description/documentation are intentionally omitted.
Drop-ins are not composed; aliases/masks, generators, enabled state and runtime
remain unknown, and `effective` is always false. Correct recovered fields can
still be reviewed and reused with these limits; gaps require further recovery.
No guest code or systemd command executes. The optional canonical os-release
record is recognized by both candidate commands; older schema1 reports still
derive the original inventory without changes. `/lib` aliases are not followed;
the existing fixed `/usr/lib/systemd/system` reads provide canonical evidence.

The offline discovery suite above tests known reusable unit/script output,
mixed secret/unknown input, reset/repetition, unsupported quoting/specifiers,
canonical symlink refusal and old/new inventory compatibility. These tests
cannot prove actual image configuration, boot behavior or helper equivalence
outside the exact recipe match.

### Opt-in fixed host baseline

`inspection/host_baseline.py` is a separate `host-baseline-v1` profile; the
original collector, candidate and startup schemas stay unchanged. The inspector
uses Linux/Python stdlib only. Its fixed selection is:

- SHA256/length only for `/usr/local/bin/{hhfab,k3d,kubectl,helm}` (384MiB each).
- Private UTF-8 text from `/home/ubuntu/hhfab/fab.yaml`,
  `/home/ubuntu/hhfab/vlab/config.yaml`, `/etc/sysctl.d/99-vlab-bridge.conf`,
  `/etc/modules-load.d/br_netfilter.conf`, `/etc/sysctl.conf`, `/etc/modules`.
- Direct, case-sensitive `.yaml` children of `/home/ubuntu/hhfab/include`,
  including dot-prefixed names. No recursion or symlink following. Enumeration
  stops at129 entries; over128 entries or32 selected names makes the entire
  selection incomplete without reading a truncated sample.
- Hash/length only for `/home/ubuntu/{.profile,.bashrc,.bash_aliases}` and
  `/etc/{profile,bash.bashrc,motd}` (256KiB each). Unknown shell hashes and
  bodies never enter the derived candidate; the initial shell recipe catalog
  is empty.

All text is limited to256KiB/file and1MiB aggregate. All binary/shell reads
share512MiB. Failed reads spend their bytes; a timed-out reader spends its
maximum possible remaining allowance. Files are hashed in64KiB blocks with
pinned-FD size/device/inode/mtime/ctime checks and an independent no-follow
reopen check. Inspector operators still supply an immutable, read-only source.
The total source-operation deadline is120s, per binary60s, other inputs and
enumeration10s. Linux fork-owned children cover root/component opens, reads,
enumeration and the output-containment check. On timeout/cancellation the parent
kills only its owned child and allows at most1s to reap it. Failed reaping is a
cleanup blocker. Deadline expiry produces explicit gaps; it never extends the
VM lease. These bounds do not promise real-time host scheduling.

The private report has an exact separate discriminator, all16 fixed IDs in
manifest order, one include summary, at most32 private child records, and a
collection-complete flag. All summary/success/gap records count toward the
existing256-record/8MiB ceilings. It retains the exclusive0600 file in an
owned0700 directory outside the guest. Names/text remain private. Errors and
stdout summaries contain only fixed diagnostics/counts/digests.

After separate mount/lifecycle authorization, add exactly
`--profile host-baseline-v1` to the fixed mounted-wrapper command below. The
default remains the old collector; no arbitrary profile/path manifest is read.
For synthetic trusted trees only, the same collector can also run directly:

```bash
python3 -m build.gcp.inspection.host_baseline \
  --root /mnt/guest --private-output /private/inspection/host-report.json
# Trusted LEAD host only, with distribution python3-yaml already installed:
python3 -m build.gcp.inspection.host_derive \
  --private-report /private/inspection/host-report.json \
  --private-output /private/inspection/host-candidate.json
python3 -m unittest discover -s build/gcp/inspection -t build/gcp -v
```

`host_derive.py` validates every nested record, status/reason, byte count/hash,
selection count/completeness and aggregate budget before projection. Trusted
PyYAML is an explicit CI dependency, never installed on the inspector by this
code. Both new command entrypoints turn SIGTERM into bounded owned cleanup;
a cancelled derivation removes its exclusive partial candidate and prints only
the fixed refusal. YAML event preflight rejects tags, anchors/aliases, nonstring/duplicate/
merge keys, ambiguous scalar forms, unsupported scalar types and resource
excesses; only SafeLoader nodes are composed, without object constructors.
CRLF is normalized for parsing; lone CR/control characters refuse. Limits are
depth32, scalar4096UTF-8 bytes,64documents/file,256documents and100,000events
aggregate. Integer/bool/string/null types remain distinct; quoted values never
satisfy integer/boolean fields. Malformed YAML becomes a fixed projection gap.

The narrow candidate includes only:

- Four binary identities (unknown SHA/length stays private pending exact-hash
  review); known hhfab release-member comparisons for0.43.1/0.47.4. Provenance
  is the [public bounded archive-member receipt](https://github.com/afewell-hh/labapp/issues/203#issuecomment-6391084882).
  Archive SHA is not binary SHA. These versions are comparisons, not target pins.
- Selected Fabricatorv1beta1 network/ASN/mode fields and ControlNode/FabNode
  counts; credentials, users, overrides and status stay withheld. Canonical
  IPv4 types, ranges and DNS/VIP/DHCP membership are checked when their
  corresponding persisted subnets exist. Missing values remain unknown.
- Wiring GVK/role counts and narrow VLAN/IPv4 namespace ranges for Fabric
  APIv0.96.2. Full parsed-object equality uses the unchanged repository
  `wiringd.yaml`, pinned SHA256
  `c522c64d80515c7484a67c27646acebf86073192f0f6ff9597497b990548806a`.
  Mapping/document order is ignored, sequence order/scalar types/absent values
  are retained. Catalog equality requires complete selected input; seven
  switches in that public fixture are comparison data, not observed facts.
- VLAB type counts and integer cpu/ram/disk sizes, selected per-file sysctl/
  module booleans, and six shell catalog statuses. Duplicate/malformed/reset/
  glob/slash selected network assignments withhold affected keys. Other active
  content yields an incomplete gap; no effective sysctl precedence is inferred.

Candidate lists are sorted and contain no source basenames, arbitrary names,
NIC/endpoint graph, secret-adjacent strings or unknown shell hashes. All derived
results retain `effective:false`, `runtime:"unknown"`, separate collection and
projection coverage, and fixed gaps. Runtime Helm/Argo/Gitea/Grafana state,
actual traffic/telemetry, source existence/version and image integration remain
unproved. Neither successful parsing nor exact public matching is privacy
approval: provenance and independent exact-hash candidate review remain required
before publication/general use. No workflow launches a capture with this code.

Primary version-scoped references: [Fabricator fields0.43.1](https://github.com/githedgehog/fabricator/blob/v0.43.1/api/fabricator/v1beta1/fabricator_types.go),
[VLAB fields0.43.1](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/vlabconfig.go),
[include loader0.43.1](https://github.com/githedgehog/fabricator/blob/v0.43.1/pkg/hhfab/hydrate.go),
[Fabric API0.96.2](https://github.com/githedgehog/fabric/tree/v0.96.2/api).
The typed profile does not claim the newer Fabric0.120.3 API. Public sources
were read2026-10-24/25; offline tests use only public/synthetic fixtures.

### Fixed mount wrapper

`inspection/mounted_collect.py` adds local ext4 mount/collect/unmount only.
It has no cloud, SSH, transfer, IAM or firewall behavior. The lead first binds
the local source-copy disk/partition and their major:minor device numbers to
the exact lease/cloud disk incarnation. It does not guess device names or make
that cloud identity binding itself. Caller-supplied numbers are an assertion
to verify against local evidence, not cloud provenance proof.

On the trusted clean Linux inspector, from the reviewed code directory, run as
root in a fresh mount namespace. These are example device identities, **not
values to assume for an appliance**:

```bash
sudo unshare --mount --propagation private -- \
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  /usr/bin/python3 -E -s -m build.gcp.inspection.mounted_collect \
  --disk /dev/sdb --partition /dev/sdb1 \
  --disk-number 8:16 --partition-number 8:17 \
  --private-dir /run/labapp-inspection-output
```

The output directory must already exist, be empty, nonsymlink, owned by the
caller and mode0700. Prepare private staging and its cleanup before running;
the wrapper does not create a tmpfs or configure swap/core-dump policy. The
collector writes only `inventory.json` there, mode0600 and bounded to8MiB.
Use a private0700/0600 lead-host destination for later authenticated transfer.
Same-UID permissions are not isolation from other same-UID processes: general
workers are trusted contributors instructed not to read raw data, and the lead
does not share raw paths/content with them. No separate recipient/account or
arbitrary retention interval is required. Remove raw/intermediate data promptly
after reviewed recovery or abandonment; publish only reviewed sanitized output.

The wrapper requires a private namespace different from PID1's and private
propagation for both the root and the mount containing the private output
directory, checked before any mount. Fixed inspector tools (`findmnt`, `lsblk`, `dumpe2fs`,
`mount`, `umount`) must already exist. Device paths must be direct nonsymlink
block nodes under `/dev`, with the supplied exact numbers. Structured `lsblk`
evidence must show one read-only disk with at most four unmounted partitions,
exactly one ext4 candidate matching the supplied partition by default, and only
empty or vfat filesystems on other partitions. A boot-filesystem match,
LVM/RAID/encryption, unexpected layout, dirty ext4 state or `needs_recovery`
refuses collection.

For a separately verified Ubuntu root plus separate ext4 boot layout, supply
both `--boot-partition /dev/EXACT_BOOT_PARTITION` and
`--boot-partition-number MAJOR:MINOR`. This accepts exactly two ext4 partitions
matching the explicit root and boot identities under the same read-only parent;
all existing partition-count, mounted-child, protected inspector-boot and
identity guards remain. Both ext4 filesystems must be clean without
`needs_recovery`. Existing trusted `/usr/sbin/debugfs` is additionally required;
there is no install fallback.

Before mounting either filesystem, the wrapper invokes only fixed default-RO
`debugfs -R 'stat PATH'` requests. The root must have `/etc` and `/usr`
directories plus regular `/var/lib/dpkg/status`, and positively lack `/grub`
and `/grub/grub.cfg`. The companion must have `/grub` directory and regular
`/grub/grub.cfg`, and positively lack every root marker. Missing lookup is
accepted only as the exact known diagnostic; IO, corruption, unknown banners,
unparsed metadata, symlinks or ambiguous roles refuse. Exit0 alone is not
existence evidence. No contents, arbitrary labels or commands are used for
role identification. Names, sizes and filesystem labels alone do not choose
root. Device numbers/RO/layout are rechecked after probes. Only root is mounted;
the verified boot companion stays unmounted and its contents are not collected.

It mounts only explicit ext4 with `ro,noload,nodev,nosuid,noexec`, disables
external mount helpers, and verifies resulting source/number/type/options/private
propagation before calling the unchanged collector. It neither uses guest fstab
nor repairs, activates, replays journals or executes guest code. Every attempted
mount gets an unmount attempt; collector failure/cancellation removes the known
partial report. Unmount failure refuses success and leaves the private mountpoint
for lead cleanup. It never recursively deletes a guest mount. Diagnostics never
relay command output. SIGTERM/SIGINT trigger cleanup; SIGKILL or VM loss still
requires the existing independent resource cleanup and lead staging cleanup.

The offline suite uses mocked commands and synthetic files, including an
unchanged collector run against a fake mount. It establishes command/validation/
cleanup behavior, not kernel mount semantics or source-image layout. Actual
execution is separate evidence: see the [inspector kernel and private-transfer
proof](https://github.com/afewell-hh/labapp/issues/170#issuecomment-6388863729) and
[whole-wrapper source collection](https://github.com/afewell-hh/labapp/issues/170#issuecomment-6389012668).
The resulting [reviewed source inventory](https://github.com/afewell-hh/labapp/issues/151#issuecomment-6388996007)
is a separate metadata-only publication.
The synthetic loop proof does not establish whole-wrapper source-layout
acceptance; each source inspection still requires its own identity/layout and
clean-state validation. Never use a public workflow artifact or serial output
for raw transfer. Existing lifecycle deadlines are never extended by this wrapper.

Sources consulted2026-10-24: [kernel ext4](https://docs.kernel.org/admin-guide/ext4.html)
(RO alone may replay journals; `noload`/`norecovery` skips replay),
[util-linux mount](https://man7.org/linux/man-pages/man8/mount.8.html) and
[unshare](https://man7.org/linux/man-pages/man1/unshare.1.html), and
[Ubuntu24.04 debugfs](https://manpages.ubuntu.com/manpages/noble/man8/debugfs.8.html)
(e2fsprogs1.47.0; default read-only and fixed inode stat). These describe
upstream behavior. Offline tests do not establish Ubuntu tool/kernel
compatibility; the linked real inspector evidence records its actual tool/kernel
scope and cannot guarantee compatibility with every Ubuntu revision.

### Synthetic inspector kernel proof

Before source-copy mounting, the lead can run the fixed-profile
`inspection/synthetic_ext4.py` on the separately authorized clean inspector:

```bash
sudo unshare --mount --propagation private -- \
  /usr/bin/python3 -E -s -m build.gcp.inspection.synthetic_ext4
```

Add `--profile host-baseline-v1` to exercise the same host collector with
its fixed harmless fixture; omitting it preserves the original fixture/proof.
The offline suite tests selection/fixture/cleanup behavior with fake mounts;
new host-profile kernel execution requires separate lead authorization and is
not established by those tests.

Use Python3.12+ and already-present trusted `mkfs.ext4`, `losetup`, `blockdev`,
`udevadm` plus the wrapper tools above, from the exact reviewed code SHA. No
install/download fallback. It creates its own0700 `/run` directory,32MiB file
and harmless fixture, formats that file before read-only loop attachment, and
verifies the exact backing inode/device, zero offset, size limit, loop device
number and RO state. It neither accepts source paths nor scans/adopts disks.

This separately proves actual private ext4 `ro,noload,nodev,nosuid,noexec`
mount semantics and runs the unchanged collector. The production validator
must refuse the observed `TYPE=loop`; its `TYPE=disk` requirement stays intact.
Thus success is **not** positive whole-wrapper integration or source-layout
acceptance. Dirty-state refusal in this clean harness uses synthetic evidence;
it does not generate an actual dirty journal. Use the separate pending-journal
proof below for real on-disk refusal. Source-copy layout and clean
state remain separate gates, including an unformatted BIOS boot partition
(which normally has no filesystem type); unexpected types still refuse.

The harness unmounts and verifies no exact-target mount, revalidates ownership
before detach, waits for udev, requires the owned loop mapping absent and the
backing-file hash unchanged, then deletes only explicit generated files and
empty directories. The complete fixture manifest is declared before writes, so
preparation errors/cancellation also remove exact owned partial entries without
recursion. Uncertain cleanup preserves evidence and fails; the lead
must resolve it before source inspection or slot reuse. It never recursively
deletes through a mountpoint. Output is fixed status/count/hash evidence only.
Offline tests cover mapping-identity refusal, not actual kernel mounts or all
cleanup failure paths. Record actual execution/tool versions and remaining
limits in the issue; no live execution is implied by this module's presence.

### Actual pending-journal refusal proof

On the same separately authorized clean inspector, before source inspection,
the lead can run the fixed no-input proof from reviewed code:

```bash
sudo unshare --mount --propagation private -- \
  /usr/bin/python3 -E -s -m build.gcp.inspection.dirty_ext4
```

It requires Python3.12+ and already-present trusted `mkfs.ext4`, `debugfs`,
`dumpe2fs`, `losetup`, `blockdev`, `lsblk`, `findmnt` and `udevadm`; no downloads
or install fallback. It creates only a new owned32MiB regular file in a0700
`/run` directory. Preparation formats4096-byte blocks, then fixed debugfs
`journal_open`, `journal_write -b 7000 /dev/zero`, `journal_close` commands write
one committed journal transaction to that file. `/dev/zero` supplies one fixed
block of harmless data. No superblock flag is forged, no original/source image
is accepted and no filesystem is mounted writable or snapshotted.

After preparation it hashes the file and attaches only that exact file as a
read-only loop. The existing loop verifier binds backing inode/device, offset,
size limit, kernel device number and RO state. Actual `dumpe2fs -h` must report
`needs_recovery` and nonzero journal start; default-read-only `debugfs logdump`
must show the expected pending descriptor and commit. Then the unchanged
production `validate_clean` must refuse that actual evidence. The fixture is
**never mounted**, repaired or replayed; journal_run/fsck are absent. This
proves the cleanliness guard against a real userspace-generated transaction,
not whole-wrapper disk-layout acceptance or a kernel-crash scenario. Production
loop-device refusal remains unchanged.

Cleanup revalidates exact owned read-only/unmounted loop identity, detaches it,
waits for udev, confirms its mapping absent and post-preparation hash unchanged,
then removes only explicit generated files and the empty owned directory.
Unknown mapping or failed cleanup preserves evidence and refuses success. Lead
must resolve it before source collection or slot reuse. Signals get the same
cleanup; SIGKILL/VM loss still need lead/resource cleanup. Output is fixed
status only. Offline mocks cover success, failed probe and failed detach;
the actual loop/kernel path requires separate lead execution on the existing
bounded inspector. No additional VM or lease extension is implied.

Primary recipe checked 2026-10-24: e2fsprogs
[j_short_trans_64bit](https://github.com/tytso/e2fsprogs/blob/8fd79523d051d5ea881237f27eb1c664486e0078/tests/j_short_trans_64bit/script)
uses jo/jw/jc; its later fsck/replay steps are deliberately excluded.
[do_journal.c](https://github.com/tytso/e2fsprogs/blob/8fd79523d051d5ea881237f27eb1c664486e0078/debugfs/do_journal.c)
marks recovery required after committing the transaction, and
[debugfs manual](https://man7.org/linux/man-pages/man8/debugfs.8.html) documents
these journal commands. Actual userspace preparation/probe/refusal/hash/cleanup
passed with e2fsprogs1.47.2 in a credential-free Debian13 container without
host devices or mount capability; that is not kernel-loop proof.

Primary references consulted 2026-10-24: Python
[3.12 descriptor-relative filesystem APIs](https://docs.python.org/3.12/library/os.html),
[dpkg-query database/installed package fields](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)
(Debian bookworm manual, not an Ubuntu guest version claim), and
[systemd.service command syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
(current upstream 262; the collector deliberately implements only discovery,
not that parser). Synthetic tests establish isolation and bounds. Real mount
and immutable-source inventory evidence is linked above; neither proves runtime
behavior of the saved appliance.

- `bootstrap-access.sh`: owner-run keyless access setup (see
  [`docs/runbooks/gcp-build-access.md`](../../docs/runbooks/gcp-build-access.md)).
- `lifecycle/`: single-slot controller, GCS/Compute adapters and trusted-runner
  CLI used by the [fixed lifecycle workflows](#fixed-lifecycle-runner).
  Offline tests inject fake storage/cloud transports and require no credentials.
  Real execution uses separate creator/cleanup identities configured by
  `bootstrap-lifecycle-access.py`; the CLI does not create IAM or the bucket.

For separately authorized owner access to an inspector, see the
[IAP access plan](../../docs/runbooks/gcp-build-access.md#owner-iap-access-to-an-owned-inspector).
The create body stays untagged. Reuse an effective protected existing SSH rule
without adopting, modifying or deleting it; do not add a redundant firewall or
tag. Bind the clean inspector public host key through privately captured
authenticated owner guest-attribute evidence and its exact confirmed immutable
ID, then use strict host checking and short-lived owner OS Login keys. This plan adds no
creator/cleanup IAM or API capability, guest execution or raw-data publication path.

## Lifecycle module contract

Python 3.12+ standard library only. The controller/spec and offline tests need
no network or credentials. State and cloud access are injected; real adapters
perform network access only when explicitly called.

| File | Role |
|---|---|
| `spec.py` | Three fixed profiles (Ubuntu profiles described below). Inspector: `e2-standard-2`, `us-central1-a`, 10 GB boot + 300 GB copy of the selected source image (both `pd-standard`; boot `READ_WRITE`/`autoDelete: true`, copy `READ_ONLY`/`autoDelete: false`), no external IP, no service account, absolute `scheduling.terminationTime` with `DELETE` (60 minutes by default). Builds, validates and hashes the exact `instances.insert` body |
| `store.py` | `SlotStore` protocol: generation-matched writes (`if_generation_match`, 0 = must not exist), **no delete**. `MemoryStore` models Cloud Storage generation semantics |
| `cloud.py` | `PolicyCloud`: the controller's mutation/inventory call surface. Allows only `instances.{insert,get,list,delete}`, `disks.{get,list,delete}`, `zoneOperations.{get,list}` in the fixed project/zone, plus read-only `{instances,disks,globalOperations}.aggregatedList` for the census. The constructor rejects any project/zone other than the approved constants. One fixed read-only Ubuntu image GET is also allowed; image mutations, arbitrary image reads, snapshots, addresses, stop/start/setScheduling/setMetadata, IAM and quota calls are rejected before reaching any transport |
| `cli.py` | Trusted-runner entrypoint for the fixed workflows; validates events and performs fixed read-only project/region/image preflight requests separately from `PolicyCloud`, then invokes creator or cleanup transitions |
| `controller.py` | State machine `FREE → RESERVED → ACTIVE → FREE`, plus `CLEANUP_FAILED`, on **one persistent slot object** |
| `fakes.py`, `test_lifecycle.py` | Fake cloud with failure injection and the invariant tests |

### Safety contract

- `Config.lease_minutes` defaults to 60 and may shorten the lease to an
  integer from 1 to 60 for the inspector. The Ubuntu component defaults to 30
  and accepts only 1 through 30. The library-only Ubuntu base-build defaults
  to 120 and accepts 1 through 120; its first fixture explicitly selects 45.
  `min_submit_minutes` must be shorter than that lease;
  the fixed thirty-minute inspector uses a one-minute submission margin. Admission
  rechecks these bounds before writing intent; an existing deadline is never
  extended.
- **Every** transition (admit, submit, ID capture, failure, release) is a
  compare-and-swap on the slot generation, for the creator, normal cleanup
  and the janitor alike. The slot object is never deleted, so a released slot
  is reusable; a stale actor loses its write instead of overwriting a newer
  lease.
- `admit` persists the UUID (`requestId`), the exact body hash, the intended
  profile, exact intended child initialization, names and the immutable deadline
  **before** the insertion call. Read-only census/image preflight happens first. Identity fields
  and the deadline cannot change while a lease is held.
- `submit` records the attempt before sending, reuses the persisted UUID and
  body, and never mints a new UUID. Default is one attempt
  (`max_submit_attempts`); retry semantics for `requestId` are not verified.
- Admission fails closed over the **whole project** (every zone, all pages of
  `aggregatedList`; a failed page, unreachable scope or runaway paging blocks):
  any instance or disk not in the lead-supplied `baseline` (name → immutable
  id), or any non-DONE operation, blocks the lease. Baseline VMs are protected
  but still count: total VMs (running or stopped, any zone) plus the new lease
  must not exceed `max_vm_slots` (3), so four baseline VMs never admit a fifth.
  Prefix lookalikes are unknown, not owned. This is a serial one-slot gate, not
  a multi-slot allocator.
- `reconcile` is the only path to `FREE`. Before any delete it runs an
  all-or-nothing preflight: every existing resource must match name, lease
  label, zone and immutable id, and an existing VM must have **exactly** the
  intended disks attached (one boot for either Ubuntu profile; boot plus source
  copy for the inspector). Boot is `READ_WRITE`, with `autoDelete: true` for
  inspector/component and `false` for base-build; the inspector
  source copy is `READ_ONLY`/`autoDelete: false`. Any
  unexpected or mismatched child blocks the VM delete too, because VM delete
  also removes `autoDelete` disks. An id not yet recorded is adopted only with
  proof (a completed insert whose `clientOperationId` is this lease's UUID,
  whose `targetId` matches the VM incarnation, and a creation time not before
  the reservation); labels alone never suffice. Then
  it deletes the VM, then each disk, by exact name, waits for the delete
  operation, and requires a 404 for **every intended resource** before release.
  - Compute forbids auto-delete on a read-only attachment. VM deletion, whether
    explicit or at the absolute deadline, auto-deletes the inspector/component
    boot but retains the base-build boot. The inspector source copy remains billable until the cleanup identity explicitly deletes
    it. Independent janitor cleanup is required; the VM deadline alone cannot
    bound data-disk retention. A failed or pending disk delete keeps capacity
    occupied, even when the VM is absent.
  - An error, identity mismatch, still-existing resource or foreign pending
    operation keeps the slot occupied (`CLEANUP_FAILED` or `blocked`).
  - A 404, timeout or HTTP error on create is not proof the create failed. A
    lease with submit attempts but no insert operation for **its own request
    id** and no VM is held (an operation that only targets the same name does
    not count) is held. Elapsed time and the deadline never release it: past
    the deadline it reports `blocked` until a terminal current-request insert
    operation is seen and VM and all intended disks are verified absent. If the
    operation has aged out of the list, the slot stays blocked for manual
    review (conservative; whether Compute rejects a late create after
    `terminationTime` is an unverified assumption, not relied on).
  - `reconcile(request_id)` is the owner's forced cleanup and leaves a newer
    lease alone (`superseded`). `reconcile()` is the janitor: it acts only on
    expired, stopped or previously failed leases.

### Fixed Ubuntu component library profile

`Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_COMPONENT)`
selects `ubuntu-component-v1`: pinned Ubuntu 24.04 amd64
`ubuntu-2404-noble-amd64-v20261024`, immutable image ID
`4575951068918267275`, `n2-standard-2` (2 vCPU / 8 GiB), one 20 GB
`pd-standard` writable auto-delete boot disk in `us-central1-a`, nested
virtualization enabled and minimum CPU `Intel Cascade Lake`. Maintenance
uses `TERMINATE` with automatic restart disabled, a conservative component-test
choice rather than a claim that nested VMs cannot migrate. The initial absolute
`terminationTime` uses `DELETE` and defaults to 30 minutes; it cannot exceed 30.
There is no appliance source disk, guest service account, external address,
startup code or image capture. This small shape is for prerequisites, not the
complete VLAB.

The library checks the fixed public image name, immutable ID, readiness,
architecture and 10 GB image minimum at admission and again before submission;
no arbitrary image/project read is accepted. Before adoption or deletion it also
checks the boot disk's actual `sourceImage` and `sourceImageId`. Image-read
failure blocks creation; provenance mismatch blocks adoption and cleanup for
lead review. Cleanup does not require the upstream image still to exist.
Records persist profile, fixed child intent and component image ID before
insertion. Missing profile/child-intent fields are accepted only as the original
two-disk inspector schema; mixed or unknown inventories fail closed. All
profiles share the same serial slot and request/operation/immutable-ID rules.

The trusted creator now selects this profile through fixed CLI mode `component`;
its legacy workflow filename is retained because WIF pins that path. The old
inspector library and CLI mode remain compatible, including old-ledger cleanup,
but the active creator no longer dispatches an inspector. Workflow support is
not live proof: guest access, transport/dependency delivery and each live task
still need their own reviewed scope. Offline tests prove request/state-machine
behavior, not capacity, image boot, systemd, KVM or VLAB operation.

Sources checked 2026-10-25: Google's [nested restrictions](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview#restrictions)
exclude E2; [direct enablement](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/enabling#enable_nested_virtualization_directly_on_a_new_vm)
uses `advancedMachineFeatures.enableNestedVirtualization` without a custom
VMX image; [N2 shapes](https://docs.cloud.google.com/compute/docs/general-purpose-machines#n2_machine_types)
document the 2 vCPU / 8 GiB machine. The fixed image/zone/shape were separately
read-only verified by the lead; quota snapshots do not reserve capacity.

### Retained-boot Ubuntu base-build library profile

`Config(boot_image=spec.COMPONENT_IMAGE, profile=spec.UBUNTU_BASE_BUILD,
lease_minutes=spec.BASE_BUILD_FIRST_LEASE_MINUTES)` explicitly selects the
45-minute first fixture of `ubuntu-base-build-v1`. The profile defaults to a
120-minute cap, measured absolutely from admission with no renewal; it leaves
inspector 60-minute/component 30-minute limits unchanged. The proposed first-fixture allocation
of 30 minutes work and 15 minutes cleanup reserve is a future runner budget,
not enforced guest work/capture scheduling. The existing submission margin is
still enforced, including refusal after expiry.

This uses the exact component public Ubuntu name/ID, small nested machine,
CPU minimum, single 20 GB disk, fixed metadata/labels, no external IP and no
service account/scopes. The sole resource-body difference is boot
`autoDelete: false`. Fixed preflight reads the public Ubuntu image and quotas
for two CPUs/N2 CPUs, one instance and 20 GB; it never reads/copies the protected
appliance image or requires the inspector's 310 GB. Actual boot provenance and
persisted profile/body hash remain required before adoption or deletion.

The existing reconciler disposes of the VM followed by its exact retained boot
on normal cleanup, failure, cancellation and expiry. Cloud VM deletion leaves
that disk billable: independently scheduled cleanup must still verify the disk's
immutable ID, terminal operations and absence before `FREE`, including when the
VM has already disappeared. Unknown inserts, foreign replacements, unexpected
children and pending operations continue to hold capacity. Image capture is an explicit library opt-in described below; ordinary cleanup
still disposes of the retained boot. This profile adds no CLI mode, dispatch,
identity or IAM grant.
The active component workflow is unchanged. A live build needs separately
reviewed capture/retention, IAM, fixed runner/staging/sealing and boot/reboot gates.

Required lifecycle CI discovers `test_base_build.py` alongside the existing
suite using the command below. Its fake HTTP/controller tests cover retained
requests, absolute bounds, disposal after cloud expiry, pending/error/no-op
operations, collision/provenance/cancellation and old-profile compatibility.
They prove offline policy behavior, not live API/IAM, boot or capture readiness.

Sources checked 2026-10-25 (Compute REST v1):
[instances.insert autoDelete](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert)
defines deletion behavior for attached disks;
[absolute VM termination](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)
documents initial `terminationTime` plus `DELETE`. These are documented API
semantics, not a live build test.

### Explicit candidate capture and quarantine library contract

The retained base-build controller exposes `prepare_capture(lease_uuid,
capture_uuid, retain_until=None)` and `capture(lease_uuid)` as separate opt-in
library actions. They require the current confirmed build, a distinct nonzero
UUID, and more than fifteen minutes remaining before its original absolute
lease deadline. No CLI or workflow invokes them. Guest staging/sealing, runner
integration, scoped IAM and separately authorized live capture/boot/reboot
remain required gates; these methods establish no sealing result.

Preparation persists the exact unique `labapp-candidate-<capture UUID>` name,
labels, request/body hash, immutable boot disk ID, original deadline and a
preflight snapshot of all existing image names/IDs before mutation. Those IDs
are protected, including the eleven saved images in the accepted project
baseline; offline tests use synthetic IDs. UUID tombstones persist through
FREE and later admissions, so deleted output names cannot be reused. History
is bounded at 512 intents and then fails closed pending a reviewed migration.
Existing VM/boot names are unchanged. The candidate and retained-build
namespaces still require alignment with the separately reviewed IAM proposal;
these library changes do not establish compatibility with future grants.

Capture verifies the terminal request-correlated VM insertion and exact child
inventory, deletes the builder while retaining its sole boot, confirms the
delete operation and VM absence, and rechecks the immutable unattached boot and
remaining budget before recording submission and calling `images.insert` once.
The source must be unattached and no `forceCreate` is sent.
The source ID is checked again after a returned insertion response.
`sourceDiskId` is output-only, so immutable provenance is also checked on the
resulting image. The image must match its request-correlated terminal global
operation target ID, recorded source disk ID/path and exact labels. Names,
labels, elapsed time, API errors or 404 alone never resolve a lost insertion.
Uncertainty keeps the boot and slot occupied. CAS fences cancellation before
cleanup: cleanup resolves an already submitted capture but never starts one.

Normal/failure/cancel/expiry reconciliation checks capture/global operations
before disposing of the exact candidate and retained boot. It persists image
delete intent/UUID before submission, verifies terminal request/target-ID proof
and exact absence, then disposes of the boot. Pending operations, foreign
incarnations, extra children and ambiguous writes/deletes hold capacity. Compute
has no immutable-ID precondition on image delete; isolated owned namespaces,
restricted writers and independently reviewed IAM remain live safety gates.
There is no family, promotion, publication, IAM mutation or force replacement.

An explicit `retain_until` can preserve a READY candidate for at most 24 hours
from preparation. After VM/boot absence and terminal operations, the same CAS
that releases the VM slot durably transfers its exact image/operation/source
identity and deletion deadline to a separate `quarantine` inventory in the
existing ledger object. This inventory survives FREE/reserve/release, rejects
duplicates/malformed entries and does not hide foreign resources from admission.
Expired quarantine blocks admission. Independent `reconcile_quarantine()` works
while a newer VM lease occupies the slot and deletes only the exact expired
image; it never disposes of that VM or its disks. Without retention, cleanup
deletes the candidate before release.

No independent capture-expiry runner, schedule, monitoring or escalation is
installed by this library change. Before live retention is enabled, a separate
trusted cleanup runner must invoke quarantine reconciliation independently of
creator completion, monitor overdue/blocked records and failed/missing runs,
and alert the lead for exact-identity investigation. A best-effort cron cadence
is not a deletion deadline guarantee; only terminal operations plus verified
absence establish deletion. The VM's cloud deadline deletes neither retained
boot nor candidate image.

Required lifecycle CI discovers `test_capture.py` with controller ordering,
lost responses, cancellation/CAS races, HTTP paths/bodies, wire-level GCS
round trips, protected image collisions and independent quarantine expiry.
These offline tests do not prove live API/IAM, scheduling, sealing or image boot.

Sources checked 2026-10-25 (Compute REST v1, documentation 2026-09-01):
[images.insert](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/insert)
(request UUID, forceCreate parameter and output-only sourceDiskId),
[globalOperations.aggregatedList](https://docs.cloud.google.com/compute/docs/reference/rest/v1/globalOperations/aggregatedList)
(project-wide operations including global scope),
[globalOperations.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/globalOperations/get)
(terminal operation, clientOperationId and targetId), and
[images.delete](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/delete)
(name and request UUID; no immutable-ID precondition).

### Own-key access records (offline library only)

`Controller(..., access_records=records).register_access(...)` lets the trusted
controller register one A producer run/attempt, canonical SELF identity and
public-key hash against a confirmed retained base build. It reserves the last
fifteen minutes for cleanup. It does not enable access or launch a workflow.
`Context.from_slot` captures that occupied lease; `GcsAccessRecords` exposes only
an exact slot read and four immutable, <=16KiB versioned records:
`access/slot-1/<captured lease UUID>/{intent,import,seal,removed}.json`.
Paths come from the validated slot, never caller-supplied object names.
Reads pair metadata with generation-pinned media. Uploads use
`ifGenerationMatch=0`, then exact canonical read-back; lost replies and 412
require equality verification, without replaying the upload. A has no exposed
list, overwrite, delete or slot-write operation. No private key is accepted.

`SelfLogin` takes an explicitly supplied token provider for the same minimal A
identity and an expected canonical SELF name. It only addresses that profile,
one public-key import and exact server-fingerprint deletion. These inputs are
trusted runner configuration; matching the returned profile name is not token
introspection or proof of deployed WIF. A newly dedicated identity might lack a
POSIX profile/account before its first import. Missing/ambiguous profile or
nonroot project POSIX identity refuses access; no key/bootstrap repair is
attempted. Live SELF/account behavior remains an explicit deployment gate.

`OwnKeyImport(..., producer_run_id=..., producer_attempt=..., now=...)` checks
that captured producer and the canonical public-key baseline, writes intent
before import, and holds a process-bound single-use capability only when its
fresh internal nonce wins intent creation. A 412, restart, repeated call,
copied session, different process or rerun cannot reconstruct the capability.
The capability is consumed before POST. The key expiration is at most twenty
minutes and never beyond the work deadline. Only an unambiguous successful
import response can produce `import.json`; canonical wire bytes and exact TTL
must match. Server-returned fingerprint/name are kept separately from the
locally computed public-key hash. No refresh, replacement or retry exists.
A crash before a durable import receipt sacrifices availability. Profile
re-observation, TTL, workflow termination or VM404 cannot settle a lost import;
that lease stays occupied pending a separately reviewed authoritative resolution.

Independent `cleanup_own_key` uses A again, never Compute cleanup's identity.
It requires durable successful-import evidence, preserves unrelated keys,
deletes only the exact intended key and requires a complete authenticated SELF
profile proving absence. After an uncertain DELETE, exact absence may yield
`absence-verified-after-uncertain-delete`; this does not claim a successful
HTTP response. This narrow safety inference relies on a completed sole import
and a never-reused key: a delayed DELETE cannot recreate that key or affect a
distinct new key. Profile errors/conflicts block. Expired absence is recorded
separately. An existing removal receipt is reused only after fresh exact-absence
verification. Cleanup has no import path.

Once all existing VM/disk/operation gates pass, reconciliation CAS-transitions
through occupied `finalizing` and `archived` access phases. It validates bound
intent/import/removal evidence and archives exact generations/hashes before
FREE. A missing seal is recorded only as absent at observation, not permanently
never-created. Access-enabled capture additionally requires seal/removal records
and currently refuses even syntactically valid seal hashes: trusted pre-login
ownership provenance and a supported installed sealing manifest have not been
implemented/accepted. Legacy capture, component and inspector behavior is
preserved. There is no sealer, executable SSH integration or live entry point.

Access objects are retained after release. Late old uploads remain confined to
the old UUID namespace and cannot authorize or occupy the next lease's paths.
Separate `access_history` accounting survives reuse, prevents key/UUID reuse,
and stops new access registration after sixteen completed access leases; nothing
is silently pruned. Eventual exact-generation deletion, late-upload accounting,
soft-deleted/noncurrent versions and migration at the bound need a separately
reviewed policy before unattended enablement. No complete deletion/physical
erasure or old-producer-quiescence claim is made.

Proposed A permissions remain **ungranted**: exact slot `get`, and `get/create`
under the entire `access/slot-1/` object namespace in the configured existing
ledger bucket with UBLA. This is broader than four exact object grants: IAM
would cover arbitrary suffixes and historical/future objects. UUID/four-name,
epoch/body and producer restrictions are trusted-code constraints. No A
list/delete/update/slot-write, TokenCreator or impersonation is implied.
Namespace/profile alignment, initial metadata authorization, inherited-grant
review, effective IAM, supported guest provenance/sealing and all live pilots
remain separate gates. Required CI discovers a nonzero `test_access.py` suite
alongside all existing lifecycle tests; fake HTTP/CAS evidence proves none of
these cloud or guest behaviors.

Sources checked 2026-10-25, GCS JSON API and OS Login v1:
[GCS generation preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
[GCS IAM conditions](https://docs.cloud.google.com/storage/docs/access-control/iam),
[SELF profile](https://docs.cloud.google.com/compute/docs/oslogin/rest/v1/users/getLoginProfile),
[key import](https://docs.cloud.google.com/compute/docs/oslogin/rest/v1/users/importSshPublicKey),
[public-key fields](https://docs.cloud.google.com/compute/docs/oslogin/rest/Shared.Types/SshPublicKey),
and [exact key deletion](https://docs.cloud.google.com/compute/docs/oslogin/rest/v1/users.sshPublicKeys/delete).
The DELETE recovery rule above is an inference about content-bound deletion,
not a documented general timeout-settlement guarantee.

### Run the tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s build/gcp/lifecycle -t build/gcp -v
```

## GCS slot adapter

`lifecycle/gcs.py` implements `SlotStore`; construct
`GcsSlotStore(bucket, token_provider=...)` with an existing private ledger
bucket. Only `slots/slot-1.json` is allowed by default. The shared
`auth_http.py` transport gets short-lived credentials from the trusted runner's
existing `gcloud` identity; it never logs tokens, follows redirects or retries
writes. Tests inject fake HTTP and credentials and make no cloud calls.

Reads fetch metadata then the body pinned to that generation. A revision lost
between requests triggers a bounded fresh read; it never becomes absence in
that call. Writes use `ifGenerationMatch`; HTTP 412 raises `PreconditionFailed`.
Other HTTP, malformed-data or network failures raise `StoreError`, blocking
progress. After an uncertain write, re-read and re-evaluate the controller
state; do not blindly repeat a transition. The adapter cannot delete objects
or manage buckets/IAM. See its module docstring for official API references.

The lifecycle discovery command above includes the HTTP-contract tests.
Mocked tests establish request/response handling, not live bucket/IAM behavior.

## Validation scope and remaining integrations

- Offline tests do not prove successful live creation or cleanup:
  `requestId` retention/idempotence, `terminationTime` plus
  `DELETE` removing the boot disk, explicit deletion of the retained data copy,
  whether disk labels from
  `initializeParams` propagate, whether an inline source-image disk is
  accepted with `READ_ONLY` mode (no writable fallback exists; if the API
  rejects it the design must change, not the check), the shape of
  `aggregatedList` warnings, org-policy effects, quota behavior and operation listing latency.
  The fake is a model, not evidence.
- Changes to the fixed workflows require independent review and authorized
  live evidence. They perform lifecycle/resource checks only; the offline
  collector and mount wrapper are not invoked by these workflows. Guest
  access, private transfer and recovery require separately reviewed integration.
- The separately reviewed lifecycle-access bootstrap must be applied and
  verified before dispatch; workflow files do not create IAM or the bucket.
- The fixed boot image is checked by immutable ID. Any later guest stage
  requires its tools verified in that image because the VM has no internet
  access; this lifecycle-only pilot runs no guest commands.
- Three-slot allocation is intentionally absent; the counter would need its
  own race tests first.

## Fixed lifecycle runner

The creator's display name is **Labapp bounded Ubuntu component**. Its path
remains `labapp-lifecycle-inspect.yml` because the existing WIF trust pins that
path; renaming the file would require a separately reviewed trust migration.
It accepts only a dispatch on `main`, with no inputs, and invokes the fixed
`component` CLI mode. It selects the Ubuntu profile above: a thirty-minute
initial absolute `DELETE` deadline, `n2-standard-2`, and one 20GB standard boot
disk. It never reads or clones the source appliance. No service account,
external IP, startup payload, package download, SSH or guest execution is added.
Initial access-only metadata and the existing serial CAS gate remain unchanged.

Preflight reads only the fixed project, region and public Ubuntu pin. It
requires exact project/region identity, image name/immutable ID, `READY`,
`X86_64`, and the 10GB image minimum, then checks global CPU and regional
`CPUS`, `N2_CPUS`, `INSTANCES` and standard-disk headroom. Inherited execution
metadata (startup/shutdown scripts or cloud-init user-data) blocks creation.
These reads are snapshots, not reservations or zonal capacity guarantees.
The fixed shape/zone were reviewed separately; the creator does not add
`machineTypes.get` or `zones.get` permissions or probe their endpoints. A live
scope must refresh owner-side shape/zone support checks. Unknown resources
continue to block admission through the project census. No quota, networking
or IAM change is made by dispatch.

Google documents `compute.instances.create` for enabling nested virtualization
at creation; the existing creator already has that permission. No image-creation
permission or legacy special virtualization image/license is needed for this
request. Public Ubuntu image read/use follows its supplier IAM; actual identity
sufficiency and kernel behavior require a separately authorized live pilot.
See [nested creation permissions](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/enabling#enable_nested_virtualization_directly_on_a_new_vm)
and [REST insert field permissions](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances/insert),
checked 2026-10-25 for Compute REST v1.

The thirty-minute fixed window has no duration input or environment override;
normal cleanup can end it early and it never changes an existing lease. Owner
access and module/runtime checks require their separately reviewed scope.
Historical two-disk inspectors remain supported by the library and cleanup,
including their read-only source-copy disk. Their Debian root/ESP identity,
source mount and private collection gates above remain required if a future
separately reviewed source-inspection task is authorized; this workflow does
not dispatch that profile.

The runner fetches only the nine required Python module files through GitHub's
Contents API at the trusted workflow's `github.sha`, before WIF authentication.
It does not check out archived gitlinks, execute triggering-run code, download
artifacts or overwrite auth credentials. The CLI is invoked from that temporary
module directory as `python3 -m lifecycle.cli component` or `cleanup`; these entry
points require trusted GitHub event context and accept no cloud parameters.

Creator confirmation polls the insert operation for up to six elapsed minutes,
with at most 72 polls at five-second intervals. Time spent in requests counts
against that polling budget, and CAS conflicts do not restart it. The budget is
checked between requests: one in-flight read can finish after it, and subsequent
ownership/provenance reads take additional time. The creator job has a thirty-six-
minute timeout, leaving four minutes beyond the thirty-minute lease plus two-minute
absence grace for setup and preflight; that overhead is allowance, not a
provisioning-time guarantee. No deadline is extended. Slow or uncertain creation
still fails closed and independent cleanup retains the occupied lease.

The controller's optional `confirm_created(..., timeout_seconds=...)` argument
sets this elapsed polling budget. Calls that omit it and all cleanup operation
waits retain their existing attempt/interval defaults. Creator uses 72 attempts;
the cleanup CLI retains 30 attempts at five-second intervals. The absence wait
also has an iteration ceiling covering the full thirty-minute lease plus two-minute
grace, so early provisioning does not exhaust its observation window first.

Creator and cleanup use distinct fixed WIF pools and service accounts. Creator
cannot delete; cleanup cannot create. After confirming the insert and persisting
the profile's resource IDs, creator checks each actual disk's `sourceImageId`
(and the component source-image path), then promptly prints a sanitized receipt
containing names, immutable IDs, request UUID, profile and deadline. It polls
read-only for VM absence, refusing a changed VM ID or absolute deadline,
until the immutable deadline plus two minutes. That observation does not release
the ledger or establish disk cleanup. The independent cleanup workflow handles
completed creator runs, including failure/cancellation, only after validating
either the new component or historical inspector name with the same fixed
path, original dispatch, repository/owner, main branch, and the
ledger's run ID and attempt. Late completions cannot force another lease's
cleanup. Manual cleanup dispatch forces the current lease; scheduled cleanup
only handles due leases, on an offset ten-minute schedule. This interval is
best-effort and gives no ten-minute completion guarantee. Both use the same CAS reconciliation and verify the VM
and every intended disk absent before release. Schedules remain best-effort; initial
Compute `terminationTime` plus `DELETE` is the independent cloud-side bound.
That bound requests VM deletion and boot-disk auto-deletion. For a historical
inspector it does not delete the `READ_ONLY` source-copy disk; cleanup must
delete that exact owned disk explicitly. Every profile still requires verified
VM/child absence and terminal operations before releasing the ledger.

The lead can exercise normal cleanup by dispatching manual cleanup after the
creator logs confirmed IDs; cancellation by cancelling the creator and checking
its independent completed-run cleanup; and expiry by allowing the fixed lease
to expire. Run these serially and inspect cleanup/ledger evidence before another
dispatch. Missing confirmation, API/IAM failure or ambiguous cleanup keeps capacity
blocked. This module's offline tests do not prove live identity federation,
image availability, Compute expiry behavior, cancellation delivery or disk
removal. Those require the separately authorized lead-run pilots after review.

Sources checked 2026-10-24 (Compute REST v1, API version 2026-09-01):
[Compute asynchronous operation polling](https://docs.cloud.google.com/compute/docs/api/how-tos/api-requests-responses#handling_api_responses),
[GitHub job timeout](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes),
[Python monotonic clock](https://docs.python.org/3/library/time.html#time.monotonic)
(stable since Python 3.3; local tests use Python 3.10, CI uses Ubuntu 24.04),
[disk auto-delete settings](https://docs.cloud.google.com/compute/docs/disks/modify-persistent-disk#autodelete)
(explicit read-only restriction; the REST boolean schema alone does not express it),
[GitHub Contents API](https://docs.github.com/en/rest/repos/contents#get-repository-content),
[workflow_run trust and default-branch semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run),
[CPU quota pools](https://docs.cloud.google.com/compute/resource-usage#cpu_quota),
[projects.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/projects/get),
[images.get](https://docs.cloud.google.com/compute/docs/reference/rest/v1/images/get),
[disks.get sourceImageId](https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/get),
[project-level startup scripts](https://docs.cloud.google.com/compute/docs/instances/startup-scripts/linux),
and Google's [current discovery schema](https://github.com/googleapis/google-api-python-client/blob/main/googleapiclient/discovery_cache/documents/compute.v1.json)
for regions.get and numeric quota fields (the regions reference page timed out).

Inspector identity sources checked 2026-10-24: Google's
[Debian OS details](https://docs.cloud.google.com/compute/docs/images/os-details#debian)
(10GB/GPT/ESP, guest environment and OS Login), Debian cloud-image
[AMD64 fstab](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/files/etc/fstab/AMD64),
[UUID generation](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/class/BASE.var)
and [GRUB selectors](https://salsa.debian.org/cloud-team/debian-cloud-images/-/blob/9ea44ee81fd04d1944127f33f07adf15a3608136/config_space/13/files/etc/default/grub.d/10_cloud.cfg/SYSTEM_BOOT).
Supplier source describes the intended layout, not exact published-image
attestation; actual pinned-image identities and mount behavior require the
bounded lead proof. Guest-attribute sources and trust limits are in the access
runbook. The dirty-journal refusal fixture remains separate from this pin change.


## Standalone pre-login evidence

`prelogin/hook.py` is a self-contained Python 3.10+ stdlib root hook; it takes
no command-line or environment configuration. It is **not installed or enabled**
by any profile, controller or workflow. Its fixed production mode is
`inventory-only`; the reviewed installed-manifest registry is empty. Synthetic
tests inject a baseline mode and manifest solely to exercise readiness checks.
No Ubuntu/Noble guest layout is declared supported.

The hook reads only the fixed local metadata keys and selected local paths,
uses fixed bounded `dpkg-query`, `systemctl` and `cloud-init status --wait
--format=json` commands, and exports selected package tuples and typed path
facts/hashes. It never exports file bodies, parses caches, executes clean hooks,
changes packages or deletes files. It refuses direct startup/cloud-final ordering
cycles, unknown unit output and an activating cloud-final before waiting; these
conservative checks do not establish compatibility with an installed unit graph.
The entire run has a 210-second monotonic cap within the metadata deadline,
with at most 180 seconds waiting and 20 seconds for subsequent collection and
publication. Unknown layouts remain diagnostic evidence, never baseline approval.

It creates an exclusive root `0700` reservation at
`/var/lib/labapp-prelogin-LEASE/baseline.json` and a root `0700` directory at
`/run/labapp-prelogin-LEASE`, containing exclusive `0600` reservation and
`evidence.json` files. Existing, partial or reboot-persistent reservations refuse
reruns; they never rebaseline. The final evidence file is at most 64 KiB, with
its SHA and kernel boot UUID in the receipt. A future reviewed sealer must
verify and remove exactly these lease-owned files/directories before capture;
no blanket cleanup is implemented. Kernel-boot/controller checks remain required.

Inventory publication uses exactly four canonical ASCII JSON parts, each at
most 4096 bytes, with an ordered length/SHA descriptor in a 4096-byte summary.
The parts total at most 16 KiB. Lease/epoch/run/attempt, nonce, numeric VM ID,
kernel boot UUID and profile/hook digests repeat in every part. Unsupported
path types and inventory limits produce `incomplete`/`limit` diagnostic status,
never ready. Transport failures suppress the summary; partial/lost parts cannot
be accepted. PUTs are spaced at least one second apart, without retries.

`prelogin/receipt.py` separately parses one exact guest-attribute item and the
complete strict typed receipt/parts. Inventory cannot satisfy `ready=True`.
This parser performs no authenticated read, access import or controller CAS.
Future integration must check the occupied lease, immutable VM/disk/source
identity, metadata and deadline before and after authenticated reads, preserve
the exact accepted bytes/hash in the ledger, enforce the pre-import barrier,
and verify first-SSH boot UUID and `evidence.json` SHA before guest work.
Guest attributes are guest-writable interval evidence, not attestation.

Required offline CI command (owned synthetic files, injected metadata/process
transports; subprocess failure tests run only tiny Python fixtures):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s build/gcp/prelogin -t build/gcp -v
```

The fixed source is bounded to 20 KiB (lead-scoped revision from the original
16 KiB proposal to preserve readable code); output bounds are unchanged.
Current [Compute metadata limits](https://docs.cloud.google.com/compute/docs/metadata/setting-custom-metadata)
allow 256 KB per value and 512 KB total, including inline startup scripts.
[Guest attributes](https://docs.cloud.google.com/compute/docs/metadata/manage-guest-attributes)
allow 256 KiB values, ten queries/minute and a three/second burst; other guest
writers can still cause loss, which the parser rejects. Sources checked
2026-10-25. [cloud-init CLI](https://docs.cloud-init.io/en/latest/reference/cli.html)
26.2 and [upstream startup unit](https://github.com/GoogleCloudPlatform/guest-agent/blob/main/google-startup-scripts.service)
are behavior references, not installed Noble payload proof. Offline tests do
not prove live metadata, systemd ordering, IAM, installed manifests, guest
access fencing, sealing, capture or boot/reboot behavior.

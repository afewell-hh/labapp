# Native course VLAB role

This is provisioning code, not a student CLI or a claim of native execution.
Root must review/test it before use. The role expects Ubuntu's `ubuntu` account,
Docker/KVM/QEMU, sudo access for native hhfab, OpenSSL, jq, kubectl and the
release-selected hhfab to be installed by the surrounding image playbook.

`tasks/main.yml` creates fresh lab-local credentials (not production values),
imports the versioned course topology and native Fabricator/ControlNode input,
validates with official hhfab and starts a foreground build service. Set
`vlab_start_build=false` for preparation without starting VMs. Credentials and
their inputs stay private on the guest, never in source or public task output.
Version0.43 requires SHA256-crypt `$5$` hashes despite an upstream error message
calling them bcrypt. Imported inputs are not force-overwritten on an existing
builder: a changed release uses a fresh builder. A standard sha256sum binding
covers the role's original inputs, not hhfab's normalized/hydrated output.

The initial FAB disables observability. After management and VLAB are running,
Root includes `tasks/finalize.yml`, which applies the declared final native
observability configuration to the live Fabricator. This is real desired state,
not a dummy switch edit or status patch. It does not rewrite the ISO's fab.yaml.
The merge patch removes the three default-derived observability subtrees so
the native mutating webhook regenerates enabled defaults; changing `defaults`
alone would leave the already-hydrated disabled metric settings in place.
Actual target URLs must appear on all seven Agent specs, with generation
convergence and the course's leaf-01 Applied condition observed. Old equal
generations before the final target update cannot pass this check. This ordering
does not guarantee reconciliation by itself.

Manifest inputs:

* `release.hedgehog.version_overrides: {}` and `ipv4_ranges` (R0's three ranges).
* `release.hedgehog.observability_targets`: native43 `alloy.Targets` mapping,
  e.g. `prometheus: {course: {url: http://172.30.0.2:9090/api/v1/write}}`
  and `loki: {course: {url: http://172.30.0.2:3100/loki/api/v1/push}}`.
* Optional `release.hedgehog.observability_labels`, e.g. `{env: labapp}`.

The role's wiring template is the accepted course-wiring.yaml topology from
0be780902e921e534cabfdfe11befe0a09ae675f, with only the default IPv4Namespace
ranges rendered from the release. Root must bind the rendered FAB/wiring and
final live telemetry configuration in the completed release evidence. The
historical owned576 override/cache and its strict projection engine are not used.

Native up arguments retain the known18VM sizes and ISO build mode. Controls
have unrestricted user networking explicitly for the selected R0 setup; servers
retain native restricted user networking (their fabric links/SSH still exist).
Verify required course reachability on the real guest. The only registry
credential location is `/run/labapp-build-registry` in the build service's
environment. Root supplies/removes that transient directory; resume has no
credential environment and must not depend on it or a user Docker login.

Resume uses the same foreground native command and preserved VM disks. Required
prepared files must exist; systemd mounts result/fab/registry/include/config/key
inputs read-only, so an attempted rebuild fails rather than silently replacing
them. Do not delete the hhfab work tree or required native cache as tool staging.
There is no invented `vlab up --no-create` flag, inode pinning or refusal merely
because the preceding stop was unclean. Restart is bounded to three starts per
boot; systemd owns the whole cgroup and gives native shutdown30seconds.
Build startup is capped at5400seconds (90minutes), with bridge creation and
API/native readiness inside one shared post-start timeout. Resume's post-start
step only sets the bridge address, bounded at900seconds; strict switch checks
cannot restart a working student's lab. Netfilter settings are applied by the
unit but the bridge helper does not assert them during boot.
These are maxima, not measured fit. Root's Packer100minute provisioning cap and
120minute provider ceiling remain external hard limits, never renewed here.

Build initial/final readiness retains native wait-switches. Strict inspection
is a bounded advisory check: its exit status and private diagnostic log are
retained under `~ubuntu/.local/state/labapp/inspect-{initial,final}.*`. A failed
inspection remains failed evidence, but does not kill the nested VMs. The
management pre-seal check separately requires actual Prometheus fabric-agent
series and a Loki hostname label; projecting targets alone cannot pass it.

After the image playbook's final checks, `tasks/prepare_capture.yml` stops the
build unit and enables (but does not start) resume. Outer image capture must
still stop the guest and verify nested VM/service behavior on a fresh clone and
normal stop/start. Service active and native wait/inspect are smoke checks, not
the release's approved pathway acceptance. No native command/test ran during authoring.

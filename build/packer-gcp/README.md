# Native GCP image build

This template selects `build/releases/<release>.yaml`, provisions the guest
through `build/ansible/image.yml`, and captures a private candidate image.
Packer is the VM/image owner; guest Ansible owns software and configuration.
No image family is assigned and no production image is used as the base.

Use Packer **1.16.2**, googlecompute **1.2.9** and ansible **1.1.6**. The Packer
engine pin already exists in `build/packer-qemu/stage_tools.py`; this builder
does not execute that path. `packer init` resolves the exact declared plugins.
The runner also needs the Google Cloud CLI for IAP and an explicitly selected,
reviewed build identity. Guest provisioning executes locally on the VM; it
does not run Ansible with the controller's cloud credentials.

Keep provider values in a private caller-owned `.pkrvars.hcl` file outside the
source tree. Supply `project_id`, `zone`, `subnetwork`,
`vm_service_account_email`, `builder_service_account_email`, `iap_network_tag`, `source_image`, `build_id`
and `ghcr_config_file`. The source image is an
exact Ubuntu 24.04 amd64 image name from `ubuntu-os-cloud`, not a mutable family.
Guest Ansible defaults to Ubuntu's verified `ansible-core=2.16.3-0ubuntu2`;
override `ansible_core_package_version` only with a reviewed exact package pin.
These operational inputs must be retained with the release record.

After preparing and validating the build environment, from this directory:

```sh
packer init .
packer validate -var-file=/private/build.pkrvars.hcl -var release=r0 .
timeout --signal=INT --kill-after=5m 115m packer build \
  -on-error=cleanup -parallel-builds=1 \
  -var-file=/private/build.pkrvars.hcl -var release=r0 .
```

Never use `-force` to replace an existing candidate. Choose a fresh `build_id`;
VM and disk are named `labapp-build-<release>-<build_id>`, and the image is
`labapp-candidate-<release>-<build_id>`. Match IAM resource conditions and owned
cleanup to these prefixes, rather than broadening Compute permissions.

The guest uses the manifest's N2/Cascade Lake/nested-virtualization/300GB build
profile, a balanced persistent disk, IAP SSH and an ephemeral external IP for
package/registry egress. SSH still uses IAP. The builder's sole network tag must
have an IAP-range TCP22 allow rule and a higher-priority deny than all other
applicable ingress allows; an IAP allow alone does not override public default
SSH/RDP rules. In the checked default VPC, the proposed rules use priorities
900 (allow35.235.240.0/20 TCP22) and901 (deny all other IPv4 ingress), targeting
only `labapp-r0-builder`. Verify effective rules again before launch. This
template creates no NAT, firewall rules, service accounts or IAM grants. The caller
and Cloud CLI must have coherent authentication for both Packer's Compute
requests and the IAP tunnel. The VM identity needs no cloud administration;
the explicit OAuth scopes avoid the plugin's broad defaults. Googlecompute
v1.2.9 shares `scopes` with its impersonated API token, so `compute` is required
alongside `userinfo.email`; the guest's separate identity still has no project roles.
Packer uses standard Application Default Credentials to impersonate the
dedicated builder identity; CLI login alone does not establish ADC. The plugin
also passes that impersonation target to its local gcloud IAP subprocess.
The builder's permissions must allow candidate creation and deletion of only
its owned VMs/disks, with no permission to delete or modify existing images.

Prefer a dedicated short-lived classic PAT with only `read:packages`, supplied
through a caller-owned mode-0600 file or stdin. An explicitly owner-authorized
existing GitHub credential can also supply the initial build. Verify its identity,
package scope and access to every artifact selected by the pinned recipe before
creating a VM. Remove temporary credential copies after the run; revoke a
dedicated PAT, but preserve the owner's existing login when that was selected.
Supply the GHCR Docker config as a mode-0600 file outside all uploaded source.
Do not pass its contents in a Packer variable, command argument, metadata or
log. The file provisioner transfers it directly into the guest's verified
`/run` tmpfs, in an ubuntu-owned mode-0700 directory. hhfab can use
`DOCKER_CONFIG=/run/labapp-build-registry` during the fresh build. Resume must
not depend on that directory. The image playbook must scrub it in its failure
and success paths; the final Packer step also removes it before capture. An
error-cleanup provisioner attempts removal after failure while SSH is available.
Lost SSH is not evidence of scrubbing; failed provisioning never captures an image.
The source stage and temporary Ansible wrapper are removed after success.

The final SSH step stops installed Google guest agents without disabling them,
cleans cloud-init identity/logs, and removes builder authorized keys and host SSH
keys. The new VM regenerates host identity and access on boot. Nested VLAB SSH
keys and the student's merged kubeconfig are preserved. This is source intent;
native clone acceptance must verify the resulting image and resumed services.

The instance insertion sets a **7200-second maximum runtime and DELETE action**.
Bootstrap is capped at 10 minutes, Ansible at 100 minutes and final cleanup at
2 minutes. The command-level timeout allows graceful Packer cleanup before its
hard stop. Use one builder at a time within quota. The plugin deliberately sets
the boot disk's AutoDelete to false: it deletes the builder VM before creating
the image from that disk, then deletes the disk during normal cleanup. Do not
turn on boot-disk auto-delete. A deadline or runner failure can leave the disk,
so independent expiry cleanup must explicitly delete the exact owned disk as
well as any remaining VM. Verified terminal VM/disk absence is required before
starting the N1 clone within quota. Do not silently extend a failed build's clock or restart old
attempt budgets. A successful capture still needs clone boot, stop/start and
the release's approved course acceptance before promotion. The acceptance record
binds the baseline course revision and the finite errata copy's patch/hash; it
does not turn original-course failures into unchanged-course passes.

Source references: [googlecompute v1.2.9 configuration](https://github.com/hashicorp/packer-plugin-googlecompute/blob/v1.2.9/builder/googlecompute/config.go)
(including native runtime/DELETE fields), [Ansible Local](https://developer.hashicorp.com/packer/integrations/hashicorp/ansible/latest/components/provisioner/ansible-local),
and [its v1.1.6 upload/execution code](https://github.com/hashicorp/packer-plugin-ansible/blob/v1.1.6/provisioner/ansible-local/provisioner.go).
Template validation checks schema; it does not establish cloud IAM, IAP
stability, image sealing or course acceptance.

The `native-r0-source` CI job runs selected Ansible syntax checks and
`packer fmt`/`packer validate` with dummy local inputs and
no cloud identity. It never invokes `packer build`; candidate boot and course
evidence remain separate release checks.

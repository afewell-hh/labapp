# Course-compatible image recipe

`image.yml` assembles a fresh Ubuntu 24.04 amd64 builder through ordinary Ansible
roles. The [native GCP Packer entrypoint](../packer-gcp/README.md) creates the
builder, uploads this `build/` directory, runs the playbook, and captures a
private candidate. It does not promote an image family.

Select a manifest with `-e release_file=/absolute/path/to/release.yaml`. The
top-level `release` mapping supplies tool and chart identities, course revision,
wiring and configuration. R0 uses official hhfab 0.43.1 / Fabric 0.96.2, with no
agent override. Its wiring is read from the manifest's checksum-verified file;
only the declared IPv4 namespace ranges are applied to that topology.

The image playbook provisions, in order:

1. Host packages, Docker/KVM, XFCE/XRDP, VS Code and the ordinary ubuntu account.
2. Verified native tools, six course dashboards and the sanitized teaching Git history.
3. Persistent k3d management services: Gitea, ArgoCD, Prometheus/Grafana and Loki.
4. Native hhfab VLAB build and readiness, followed by the actual telemetry
   configuration and reconciliation through the Fabricator API.
5. Gitea's `student/hedgehog-config` repository, the course's `hedgehog-config`
   Argo application, merged student kubeconfig and normal Argo CLI session.
6. VLAB/management shutdown, enabled boot units and owned download-cache cleanup.

The native VLAB process stays under systemd supervision. A failed build process
stops the build; student resume retries within the service limit. Boot's post-start
step only configures the bridge; diagnostic failures
cannot restart a usable lab. Resume uses prepared nested disks and prohibits rebuilding
the installer inputs. Management containers and volumes persist across stop/start.
The student's Argo session refreshes on boot and lasts the release-selected
2160hours (90days), covering course days without a daily login interruption.
Cloud-init preserves the selected ubuntu password on new clones. Unit
activation is not a substitute for live readiness. Before sealing, actual
fabric metrics and a Loki hostname label are required; bounded Argo sync
results are recorded as advisory evidence under `/var/lib/labapp/build-checks`.

XRDP uses a dedicated TLS identity generated before its listener starts on each
new VM. Capture removes the builder's dedicated XRDP identity and native RDP
security key; ordinary reboots retain the VM's generated identity. The Ubuntu
package's generic snakeoil key remains unused by XRDP and is not removed here.
Promotion requires a live clone check of boot ordering and distinct TLS public
keys across two clones, plus diagnosis of the observed later RDP logoffs.
The self-signed certificate lasts 3650 days; an interrupted pair installation
fails closed and needs an administrator to remove the incomplete owned pair.

Telemetry finalization waits up to 120 seconds each for `fab/fabricator-ctrl` to
be Available and `fab/fabricator-webhook-service` to have ready endpoints.
Each wait has a 135 second process bound. Availability is a precondition; a single
server-side dry-run of the exact merge patch tests admission before the single
write. Each patch command has a 30 second request timeout and 35 second process
bound. These commands are not retried. Their outer timeouts allow 5 seconds to kill.

On failure, the controller log retains the stage, original exit (or -1 when the
module supplied none), category, redacted stderr/message excerpts and selected
pod/endpoint/Fabricator status. The Ansible filter removes recognized credentials
before limiting each excerpt to 512 characters. Cluster specs, addresses, condition
messages and raw command stdout are omitted. Raw stderr and module message are
also bounded to 8192 characters each in a private 0600 guest file; that file disappears
with builder disposal. Do not publish it or a dry-run's returned Fabricator object.

The registry Docker config is supplied by Packer in `/run/labapp-build-registry`,
never in source or the image. The playbook removes it on success and failure.
Packer's final step also removes temporary source, build access and host identity
before capture. Newly generated lab-local credentials, nested SSH keys and
student kubeconfigs are image functionality; recovered production credentials
are never inputs. The teaching bundle retains its redactions, original metadata
and all 11 educational commits. Build-specific passwords do not enter Git.

`components.yml` remains a helper for base packages, verified tools, dashboards
and the bare Git seed. It does not deploy services or prove a usable image.
`finalize-tools.yml` removes its owned tool cache when used independently;
`image.yml` already includes that cleanup.

For syntax checking:

```sh
ansible-playbook -i INVENTORY build/ansible/image.yml \
  -e release_file=/absolute/path/to/r0.yaml --syntax-check
```

Native offline checks can initialize/hydrate hhfab inputs, render the actual
pinned Helm charts and verify source contracts. They cannot establish KVM,
IAP continuity, live GitOps/telemetry, image sealing, clone boot or stop/start.
Those require the bounded native GCP build and clone acceptance. Release
acceptance then requires the runnable Network Like a Hyperscaler steps as an
ordinary student against the finite errata-backed copy approved in the release's
acceptance contract. Record that copy's patch and hashes with the acceptance run.
Classify individual steps, retain original-course failures, and never waive a
whole module. Partial smoke success does not satisfy this gate. After stop/start,
repeat access, services, fresh telemetry and persisted-state checks. Full
unchanged-course acceptance remains withheld until the corresponding hh-learn
corrections land and the resulting curriculum is validated.

The exact Ubuntu base image and zone are explicit Packer caller inputs, retained
with the build. Ubuntu and VS Code packages resolve through their signed apt
repositories. The manifest's conditional 10.20 scenario is unresolved; this
recipe does not invent missing course scenarios or silently waive failed steps.
Clone acceptance must check `passwd -S ubuntu` after cloud-init and exercise
the RDP login. Course `gcloud compute ssh ... --command "kubectl ..."` can use
the caller's OS username rather than ubuntu; that user has no provisioned
kubeconfig. Record the exact user and result during course acceptance.

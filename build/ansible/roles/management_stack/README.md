# Native management deployment

Invoke this role as root after `vendor_tools`, Docker installation/startup and
`course_assets`. It needs working Docker, k3d, kubectl and Helm. It creates the
native `k3d-observability` cluster (context `k3d-k3d-observability`), installs
verified local chart archives and applies the rendered dashboard ConfigMaps.
No legacy port-patching wrapper or custom student CLI is used.

Release inputs under `services.management` are `cluster_name`, selected
`image` (`rancher/k3s:VERSION`, preferably resolved to its genuine digest), `api_port`, `bind_address`,
`prometheus_bind_address` and `storage_root`. The storage root is fixed to
`/var/lib/labapp/management-storage`; separate server/agent directories back
local-path volumes. `services.servers/agents` select the course's 1/2 topology.
`services.gitea.root_url` selects its externally visible URL.

`artifacts.management_charts` contains four records with `name`, `release_name`,
`namespace`, HTTPS `url` and `sha256`. Names are `kube-prometheus-stack`, `loki`,
`gitea`, `argo-cd`; versions come from `services.charts`. Select releases
`kube-prometheus-stack`/`loki` in monitoring, `gitea` in gitea and `argocd` in
argocd to match the course/native integration. Helm checks actual chart metadata
against the selected version before installation. Each Helm call waits up to
600s for resources/jobs; Ansible bounds the child to 660s. Chart upgrades run on
each invocation and may create Helm revisions; this is not a zero-change claim.

Host ports are 3000/Grafana, 3001/Gitea, 8080/ArgoCD, 9090/Prometheus and
3100/Loki, mapped
to declared NodePorts in the native cluster configuration. Bind addresses are
explicit release inputs, not authorization for external ingress. Prometheus's
bind must be reachable from the VLAB telemetry path. Loki is a single-binary
filesystem deployment at the direct `loki` service. Its separate declarative
`loki-telemetry` Service selects NodePort31000 because the pinned chart does not
support configuring its own single-binary Service's nodePort. The Gitea profile uses
persistent SQLite, not an additional PostgreSQL/Redis cluster. These are lab
deployment choices requiring actual chart rendering and VM validation.

Preserved Docker containers and host-mounted local-path data support ordinary
cluster stop/start; the role never deletes the cluster or storage. A config hash
refuses adoption/reconfiguration of an existing cluster with different inputs.
`labapp-management.service` starts the preserved cluster after Docker on VM boot
and stops it before Docker during shutdown. The oneshot's active state is not a
health check; node and service readiness still require observation. Image sealing
must stop this unit before capture; it stays enabled for the next boot.
Root owns normal student kubeconfig access.
The role keeps its kubeconfig root-only; no credentials are printed by Ansible.
Gitea users/seeds, ArgoCD external-cluster/course Application binding, telemetry
producers and actual browser/course acceptance remain separate integration.
Grafana/Prometheus/Loki/Gitea persistence sizes are explicit lab choices, not
proof of 300GB image fit or retained-state behavior across VM reboot.

Primary contracts: [k3d5.7.4 config](https://k3d.io/v5.7.4/usage/configfile/),
[Loki6.49.0 values](https://github.com/grafana/loki/blob/helm-loki-6.49.0/production/helm/loki/values.yaml),
[ArgoCD7.6.12 values](https://github.com/argoproj/argo-helm/blob/argo-cd-7.6.12/charts/argo-cd/values.yaml).
The Gitea10.4.1 upstream values URL was inaccessible during source preparation;
its proposed values need validation against the genuine selected chart archive.

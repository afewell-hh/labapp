# Course GitOps bootstrap

Run as root after management deployment, verified seed import and VLAB API
readiness. Supply `gitops_vlab_kubeconfig_path` as the absolute path of the
target's generated VLAB kubeconfig; this is not a controller/host file lookup.
The verified bare seed must exist at `/opt/labapp/seed/hedgehog-config.git`.

The role creates the selected organization/repository through the native Gitea
API, then pushes only original `main` history without force. An already matching
main is preserved. Different existing history is refused rather than overwritten;
do not run bootstrap over student work to reset it. Authentication uses selected
public-lab account inputs, no credentials in Git URLs/config/commits. A runtime
askpass script contains no password and is removed in `always`; actual credentials
exist only in the push environment. Authenticated API calls and push output use
`no_log`. The management Gitea chart consumes the same account fields.

Cluster registration uses ArgoCD's native Kubernetes cluster Secret instead of
an ArgoCD CLI login or retrieving its administrator password. The selected target
kubeconfig must contain embedded CA plus token or certificate/key authentication.
Exec plugins and external credential-provider configuration are not executed.
The API endpoint is the declared VLAB VIP `https://172.30.0.1:6443`; TLS verification
stays enabled. Root's network integration must make it reachable from k3d with a
certificate valid for that endpoint. No private kubeconfig or Secret is written
to Git or rendered to a public file.

The native Application selects the internal Gitea HTTP service, main/path active,
recursive manifests, the actual VLAB destination and release-selected prune/self
heal settings. This applies the initial selected seed; it does not invent faulty
scenario objects or alter course history. API connectivity, synchronization,
browser/CLI access and the release's approved course acceptance require actual validation.

With the native ArgoCD CLI installed, bootstrap also logs in as `ubuntu` to
`localhost:8080` using the newly deployed initial-admin Secret. The generated
normal server session lives at `/home/ubuntu/.config/argocd/config` mode0600,
so course `argocd app ...` commands use the actual server rather than core mode.
The password is neither source data nor written to Git/public files; the native
CLI receives it in transient process arguments under `no_log`. This is build
bootstrap, not password recovery: a missing initial Secret is a failure. The
session config is private lab credential material for subsequent image sealing
and student-access review, not a production credential export.

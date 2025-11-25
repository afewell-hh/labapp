#!/bin/bash
# 04-install-tools.sh
# Install kubectl, helm, and other Kubernetes/cloud-native tools
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing Kubernetes and cloud-native tools..."
echo "=================================================="

# Define versions
KUBECTL_VERSION="v1.31.1"
KIND_VERSION="v0.24.0"
ARGOCD_VERSION="v2.12.4"
K9S_VERSION="v0.32.5"
STERN_VERSION="1.30.0"
YQ_VERSION="v4.44.3"
BAT_VERSION="0.24.0"

# Create temporary directory for downloads
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Download all binaries in parallel for faster installation
echo "Downloading tools in parallel..."
(
  curl -sSL -o kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" &
  curl -sSL -o kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64" &
  curl -sSL -o argocd "https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-linux-amd64" &
  curl -sSL -o k9s.tar.gz "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz" &
  curl -sSL -o stern.tar.gz "https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_amd64.tar.gz" &
  curl -sSL -o yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" &
  curl -sSL -o bat.deb "https://github.com/sharkdp/bat/releases/download/v${BAT_VERSION}/bat_${BAT_VERSION}_amd64.deb" &
  wait
)

echo "Installing kubectl..."
chmod +x kubectl
mv kubectl /usr/local/bin/
kubectl version --client

echo "Installing Helm..."
curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version

echo "Installing kind..."
chmod +x kind
mv kind /usr/local/bin/kind
kind version

echo "Installing ArgoCD CLI..."
chmod +x argocd
mv argocd /usr/local/bin/
argocd version --client

echo "Installing kustomize..."
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
mv kustomize /usr/local/bin/
kustomize version

echo "Installing kubectx and kubens..."
rm -rf /opt/kubectx /usr/local/bin/kubectx /usr/local/bin/kubens
git clone --depth 1 https://github.com/ahmetb/kubectx /opt/kubectx
ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx
ln -s /opt/kubectx/kubens /usr/local/bin/kubens

echo "Installing k9s..."
tar -xzf k9s.tar.gz
chmod +x k9s
mv k9s /usr/local/bin/
k9s version

echo "Installing stern..."
tar -xzf stern.tar.gz
chmod +x stern
mv stern /usr/local/bin/
stern --version

echo "Installing yq..."
chmod +x yq
mv yq /usr/local/bin/
yq --version

echo "Installing bat..."
dpkg -i bat.deb

echo "Installing fzf..."
rm -rf /opt/fzf /usr/local/bin/fzf /usr/local/bin/fzf-tmux
git clone --depth 1 https://github.com/junegunn/fzf.git /opt/fzf
/opt/fzf/install --all --no-update-rc
ln -s /opt/fzf/bin/fzf /usr/local/bin/fzf

# Cleanup temporary directory
cd /
rm -rf "$TMPDIR"

# Set up bash completion for all tools
echo "Setting up bash completion..."
mkdir -p /etc/bash_completion.d/

kubectl completion bash > /etc/bash_completion.d/kubectl
helm completion bash > /etc/bash_completion.d/helm
kind completion bash > /etc/bash_completion.d/kind
argocd completion bash > /etc/bash_completion.d/argocd
k3d completion bash > /etc/bash_completion.d/k3d

echo "=================================================="
echo "Kubernetes and cloud-native tools installation complete!"
echo "=================================================="

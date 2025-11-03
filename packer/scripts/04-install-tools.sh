#!/bin/bash
# 04-install-tools.sh
# Install kubectl, helm, and other Kubernetes/cloud-native tools
# Part of Hedgehog Lab Appliance build pipeline

set -euo pipefail

echo "=================================================="
echo "Installing Kubernetes and cloud-native tools..."
echo "=================================================="

# Install kubectl
echo "Installing kubectl..."
KUBECTL_VERSION="v1.31.1"
curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/
kubectl version --client

# Install Helm
echo "Installing Helm..."
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version

# Install kind (Kubernetes in Docker) - useful for testing
echo "Installing kind..."
KIND_VERSION="v0.24.0"
curl -Lo ./kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
chmod +x ./kind
mv ./kind /usr/local/bin/kind
kind version

# Install argocd CLI
echo "Installing ArgoCD CLI..."
ARGOCD_VERSION="v2.12.4"
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-linux-amd64
chmod +x argocd
mv argocd /usr/local/bin/
argocd version --client

# Install kustomize
echo "Installing kustomize..."
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
mv kustomize /usr/local/bin/
kustomize version

# Install kubectx and kubens
echo "Installing kubectx and kubens..."
git clone https://github.com/ahmetb/kubectx /opt/kubectx
ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx
ln -s /opt/kubectx/kubens /usr/local/bin/kubens

# Install k9s (terminal UI for Kubernetes)
echo "Installing k9s..."
K9S_VERSION="v0.32.5"
wget -q https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz
tar -xzf k9s_Linux_amd64.tar.gz
chmod +x k9s
mv k9s /usr/local/bin/
rm k9s_Linux_amd64.tar.gz
k9s version

# Install stern (log tailing for Kubernetes)
echo "Installing stern..."
STERN_VERSION="1.30.0"
wget -q https://github.com/stern/stern/releases/download/v${STERN_VERSION}/stern_${STERN_VERSION}_linux_amd64.tar.gz
tar -xzf stern_${STERN_VERSION}_linux_amd64.tar.gz
chmod +x stern
mv stern /usr/local/bin/
rm stern_${STERN_VERSION}_linux_amd64.tar.gz
stern --version

# Install yq (YAML processor)
echo "Installing yq..."
YQ_VERSION="v4.44.3"
wget -q https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64 -O yq
chmod +x yq
mv yq /usr/local/bin/
yq --version

# Install bat (better cat with syntax highlighting)
echo "Installing bat..."
BAT_VERSION="0.24.0"
wget -q https://github.com/sharkdp/bat/releases/download/v${BAT_VERSION}/bat_${BAT_VERSION}_amd64.deb
dpkg -i bat_${BAT_VERSION}_amd64.deb
rm bat_${BAT_VERSION}_amd64.deb

# Install fzf (fuzzy finder)
echo "Installing fzf..."
git clone --depth 1 https://github.com/junegunn/fzf.git /opt/fzf
/opt/fzf/install --all --no-update-rc
ln -s /opt/fzf/bin/fzf /usr/local/bin/fzf

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

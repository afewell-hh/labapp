#!/bin/bash
# Hedgehog vAIDC Lab Deployment Script
# Usage: ./deploy-lab.sh YOUR_PROJECT_ID [ZONE]
#
# Example: ./deploy-lab.sh my-gcp-project us-west1-c

set -e

PROJECT_ID="${1:?Error: Please provide your GCP project ID as the first argument}"
ZONE="${2:-us-west1-c}"
VM_NAME="hedgehog-lab"
IMAGE_NAME="hedgehog-vaidc-v20260114"
IMAGE_PROJECT="teched-473722"

echo "=== Hedgehog vAIDC Lab Deployment ==="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo ""

# Set project
echo "[1/4] Setting project..."
gcloud config set project "$PROJECT_ID"

# Enable Compute API
echo "[2/4] Enabling Compute Engine API..."
gcloud services enable compute.googleapis.com --quiet

# Create VM
echo "[3/4] Creating VM instance (this may take 2-3 minutes)..."
gcloud compute instances create "$VM_NAME" \
  --zone="$ZONE" \
  --machine-type=n1-standard-32 \
  --image="$IMAGE_NAME" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size=300GB \
  --boot-disk-type=pd-balanced \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Cascade Lake" \
  --tags=http-server,https-server

# Create firewall rule (ignore if exists)
echo "[4/4] Creating firewall rules..."
gcloud compute firewall-rules create allow-vaidc-services \
  --allow=tcp:80,tcp:443,tcp:3000,tcp:3001,tcp:8080,tcp:9090 \
  --target-tags=http-server,https-server \
  --description="Allow access to Hedgehog vAIDC services" 2>/dev/null || echo "Firewall rule already exists"

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" \
  --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "=== Deployment Complete! ==="
echo ""
echo "VM External IP: $EXTERNAL_IP"
echo ""
echo "Wait 5-10 minutes for services to initialize, then access:"
echo ""
echo "  Grafana:    http://$EXTERNAL_IP:3000  (admin/admin)"
echo "  Gitea:      http://$EXTERNAL_IP:3001  (student01/hedgehog123)"
echo "  ArgoCD:     http://$EXTERNAL_IP:8080  (admin/retrieve via SSH)"
echo "  Prometheus: http://$EXTERNAL_IP:9090"
echo ""
echo "SSH to your VM:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE"
echo ""
echo "Get ArgoCD password:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE --command=\"kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d && echo\""
echo ""

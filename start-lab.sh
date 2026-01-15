#!/bin/bash
# Hedgehog vAIDC Lab Start Script
# Usage: ./start-lab.sh YOUR_PROJECT_ID [ZONE]
#
# Starts a previously stopped VM.
# Example: ./start-lab.sh my-gcp-project us-west1-c

PROJECT_ID="${1:?Error: Please provide your GCP project ID as the first argument}"
ZONE="${2:-us-west1-c}"
VM_NAME="hedgehog-lab"

echo "=== Starting Hedgehog vAIDC Lab ==="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo ""

gcloud config set project "$PROJECT_ID"

echo "Starting VM instance..."
gcloud compute instances start "$VM_NAME" --zone="$ZONE"

# Wait a moment for the instance to get an IP
sleep 5

# Get external IP
EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" \
  --zone="$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "=== Lab Started ==="
echo ""
echo "VM External IP: $EXTERNAL_IP"
echo ""
echo "Wait 2-3 minutes for services to initialize, then access:"
echo ""
echo "  Grafana:    http://$EXTERNAL_IP:3000"
echo "  Gitea:      http://$EXTERNAL_IP:3001"
echo "  ArgoCD:     http://$EXTERNAL_IP:8080"
echo "  Prometheus: http://$EXTERNAL_IP:9090"
echo ""
echo "SSH to your VM:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE"
echo ""

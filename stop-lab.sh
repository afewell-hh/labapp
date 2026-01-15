#!/bin/bash
# Hedgehog vAIDC Lab Stop Script
# Usage: ./stop-lab.sh YOUR_PROJECT_ID [ZONE]
#
# Stops the VM to save costs. Data is preserved.
# Example: ./stop-lab.sh my-gcp-project us-west1-c

PROJECT_ID="${1:?Error: Please provide your GCP project ID as the first argument}"
ZONE="${2:-us-west1-c}"
VM_NAME="hedgehog-lab"

echo "=== Stopping Hedgehog vAIDC Lab ==="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo ""

gcloud config set project "$PROJECT_ID"

echo "Stopping VM instance..."
gcloud compute instances stop "$VM_NAME" --zone="$ZONE"

echo ""
echo "=== Lab Stopped ==="
echo ""
echo "Your VM has been stopped. You will no longer be charged for compute,"
echo "but you will still be charged for disk storage (~\$51/month for 300GB)."
echo ""
echo "To restart your lab, run:"
echo "  ./start-lab.sh $PROJECT_ID $ZONE"
echo ""

#!/bin/bash
# Hedgehog vAIDC Lab Cleanup Script
# Usage: ./cleanup-lab.sh YOUR_PROJECT_ID [ZONE]
#
# This script removes all resources created by deploy-lab.sh
# Example: ./cleanup-lab.sh my-gcp-project us-west1-c

set -e

PROJECT_ID="${1:?Error: Please provide your GCP project ID as the first argument}"
ZONE="${2:-us-west1-c}"
VM_NAME="hedgehog-lab"
FIREWALL_RULE="allow-vaidc-services"

echo "=== Hedgehog vAIDC Lab Cleanup ==="
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo ""
echo "This will DELETE the following resources:"
echo "  - VM instance: $VM_NAME"
echo "  - Firewall rule: $FIREWALL_RULE"
echo ""
read -p "Are you sure you want to proceed? (y/N): " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""

# Set project
gcloud config set project "$PROJECT_ID"

# Delete VM instance
echo "[1/2] Deleting VM instance..."
if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" &>/dev/null; then
    gcloud compute instances delete "$VM_NAME" --zone="$ZONE" --quiet
    echo "  ✓ VM instance deleted"
else
    echo "  - VM instance not found (already deleted?)"
fi

# Delete firewall rule
echo "[2/2] Deleting firewall rule..."
if gcloud compute firewall-rules describe "$FIREWALL_RULE" &>/dev/null; then
    gcloud compute firewall-rules delete "$FIREWALL_RULE" --quiet
    echo "  ✓ Firewall rule deleted"
else
    echo "  - Firewall rule not found (already deleted?)"
fi

echo ""
echo "=== Cleanup Complete! ==="
echo ""
echo "All Hedgehog vAIDC lab resources have been removed from project: $PROJECT_ID"
echo ""
echo "Note: If you created any additional resources manually, you may need to"
echo "delete them separately through the GCP Console or gcloud CLI."
echo ""

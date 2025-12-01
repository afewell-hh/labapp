#!/usr/bin/env bash
set -euo pipefail

SCRIPT="packer/scripts/hhfab-vlab-runner"

echo ">> Ensuring hhfab-vlab-runner uses --ready wait"
if ! grep -q -- "--ready wait" "$SCRIPT"; then
    echo "❌ hhfab-vlab-runner missing --ready wait flag"
    exit 1
fi

echo ">> Ensuring skip-readiness message is removed"
if grep -q "Skipping switch readiness check" "$SCRIPT"; then
    echo "❌ hhfab-vlab-runner still skips readiness verification"
    exit 1
fi

echo ">> Ensuring switch verification function is present"
if ! grep -q "verify_switch_count()" "$SCRIPT"; then
    echo "❌ verify_switch_count function not found"
    exit 1
fi

echo "✅ VLAB readiness script checks passed"

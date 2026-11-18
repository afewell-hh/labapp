#!/usr/bin/env bash
# Keep the failure report limited to service state and kernel OOM notices.
# This runs only before Packer disposes an unsuccessful builder.
set +e
echo 'LABAPP_FAILURE_DIAGNOSTIC_BEGIN'
# Remove the builder credential before any optional diagnostic can stall.
if /usr/bin/timeout 5s /usr/bin/rm -rf -- /run/labapp-build-registry; then
  echo 'LABAPP_REGISTRY_CREDENTIAL_REMOVED=yes'
else
  echo 'LABAPP_REGISTRY_CREDENTIAL_REMOVED=no'
fi
for unit in labapp-vlab-build.service ssh.service; do
  echo "LABAPP_UNIT=$unit"
  /usr/bin/timeout 5s /usr/bin/systemctl show "$unit" --no-pager \
    --property=ActiveState,SubState,Result,ExecMainStatus,MainPID,NRestarts,ActiveEnterTimestamp,InactiveEnterTimestamp,ExecMainStartTimestamp \
    2>/dev/null
done
echo 'LABAPP_MEMORY_MIB'
/usr/bin/timeout 5s /usr/bin/free -m | /usr/bin/head -n 3
echo 'LABAPP_KERNEL_OOM'
/usr/bin/timeout 5s /usr/bin/journalctl -k --since='-10 minutes' --no-pager --output=cat 2>/dev/null \
  | /usr/bin/grep -Ei 'oom-kill|out of memory|killed process' \
  | /usr/bin/tail -n 12 \
  | /usr/bin/sed -E 's/[A-Za-z0-9_+\/=-]{40,}/[redacted]/g'
echo 'LABAPP_FAILURE_DIAGNOSTIC_END'

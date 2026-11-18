#!/usr/bin/env bash
# Keep the failure report limited to service state and kernel OOM notices.
# This runs only before Packer disposes an unsuccessful builder.
set +e
echo 'LABAPP_FAILURE_DIAGNOSTIC_BEGIN'
for unit in labapp-vlab-build.service ssh.service; do
  echo "LABAPP_UNIT=$unit"
  /usr/bin/systemctl show "$unit" --no-pager \
    --property=ActiveState,SubState,Result,ExecMainStatus,MainPID,NRestarts,ActiveEnterTimestamp,InactiveEnterTimestamp,ExecMainStartTimestamp \
    2>/dev/null
done
echo 'LABAPP_MEMORY_MIB'
/usr/bin/free -m | /usr/bin/head -n 3
echo 'LABAPP_KERNEL_OOM'
/usr/bin/journalctl -k --since='-10 minutes' --no-pager --output=cat 2>/dev/null \
  | /usr/bin/grep -Ei 'oom-kill|out of memory|killed process' \
  | /usr/bin/tail -n 12 \
  | /usr/bin/sed -E 's/[A-Za-z0-9_+\/=-]{40,}/[redacted]/g'
echo 'LABAPP_FAILURE_DIAGNOSTIC_END'
/usr/bin/rm -rf -- /run/labapp-build-registry

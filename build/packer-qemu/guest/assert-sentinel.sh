#!/usr/bin/env bash
# Sentinel guest assertions (see ../README.md "Fixed sentinel task"). Staged on the
# CD by stage_tools.py and run by guest-build.sh's plan as `<root|ubuntu> bash
# assert-sentinel.sh <root|ubuntu>` under `env -i`, cwd `/`, stdin /dev/null.
# Any failed assertion exits nonzero, so guest-build.sh emits status=fail.
# No network, package or VLAB operation. UNRUN in a guest.
set -Eeuo pipefail

want=${1:-}
case $want in
  root) uid=0; home=/root ;;
  ubuntu) uid=$(id -u ubuntu); home=/home/ubuntu ;;
  *) echo "usage: assert-sentinel.sh root|ubuntu" >&2; exit 2 ;;
esac

[[ $(id -u) == "$uid" ]]
[[ $want == root || $uid != 0 ]]
[[ $PWD == / && $(pwd -P) == / ]]
[[ $HOME == "$home" && $LC_ALL == C.UTF-8 && $DEBIAN_FRONTEND == noninteractive ]]
[[ $PATH == /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ]]
# Exactly the sanitized variables plus those bash itself maintains.
for name in $(compgen -e); do
  case $name in
    PATH|HOME|LC_ALL|DEBIAN_FRONTEND|PWD|OLDPWD|SHLVL|_) ;;
    *) echo "unexpected environment variable: $name" >&2; exit 1 ;;
  esac
done

if [[ $want == root ]]; then
  # Read the full bounded status, validate it, and emit only a fixed summary.
  # pipefail rejects a failed cloud-init command; overlong output is never truncated
  # into an accepted record. Only root runs this before guest-build.sh seals.
  # Both pipeline statuses are captured immediately and any nonzero one still fails; the
  # only output is one fixed token (producer/renderer numeric statuses, 0-255) left in
  # the reason file that guest-build.sh's LABAPP-DIAG line reads.
  set +e
  cloud-init status --format json | python3 -I "${BASH_SOURCE[0]%/*}/sentinel-evidence.py" >/dev/ttyS0
  st=("${PIPESTATUS[@]}")
  set -e
  if [[ ${st[0]} != 0 || ${st[1]} != 0 ]]; then
    (set -o noclobber; printf 'pipe-p%d-r%d' "${st[0]}" "${st[1]}" >/run/labapp-reason) 2>/dev/null || true
    exit 1
  fi
fi

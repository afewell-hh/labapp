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
  # Bounded evidence of the selected disk's cloud-init status; guest-build.sh's seal
  # runs `cloud-init clean --logs` later. The host observer currently ignores
  # non-receipt serial lines, so capturing this line is an UNMET gate (README).
  status=$(cloud-init status --format json | head -c 4096 | tr -d '\n')
  printf '\nLABAPP-EVIDENCE cloud-init-status %s\n' "$status" >/dev/ttyS0
fi

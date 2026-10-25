# Fixed sentinel runtime (README.md "Fixed sentinel task"). This directory is the ENTIRE
# Docker build context; nothing else is copied in. NOT built, NOT tested, NOT accepted:
# every package version below is a publisher-metadata CANDIDATE; availability and the
# dependency closure in the dated snapshot are unverified until the reviewed preparation
# workflow runs. The resulting image ID and RootFS DiffIDs, once accepted by the lead,
# become container_runner.SENTINEL_RUNTIME. Shared guest-module pins are untouched.
FROM ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

# Ambient sources are removed, then ONE dated Deb822 source (Canonical's documented
# Noble snapshot form) is written. Authentication stays on: the base image's own keyring
# and APT's signature, hash and Valid-Until checks; no key download, no trusted=yes, no
# allow-insecure/unauthenticated option. HTTP transport does not waive any of them.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && printf '%s\n' \
    'Types: deb' \
    'URIs: http://archive.ubuntu.com/ubuntu' \
    'Suites: noble noble-updates' \
    'Components: main universe' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    'Snapshot: 20261024T000000Z' \
    '' \
    'Types: deb' \
    'URIs: http://security.ubuntu.com/ubuntu' \
    'Suites: noble-security' \
    'Components: main universe' \
    'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
    'Snapshot: 20261024T000000Z' \
    > /etc/apt/sources.list.d/labapp-snapshot.sources

# Explicit roots only; native APT resolves dependencies against that exact base. QEMU
# versions equal build/provision/install-qemu.py PINS (not edited). Python is a plain
# root package, so no bootstrap interpreter is needed. No recommends, no socat.
# The record of the resolved set and signed-index hashes is baked into the image.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qemu-system-x86=1:8.2.2+ds-0ubuntu1.18 \
    qemu-utils=1:8.2.2+ds-0ubuntu1.18 \
    seabios=1.16.3-2 \
    python3=3.12.3-0ubuntu2.1 \
    python3.12=3.12.3-1ubuntu0.17 \
    xorriso=1:1.5.6-1.1ubuntu3 \
 && mkdir -p /usr/share/labapp-runtime \
 && dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' | sort \
    > /usr/share/labapp-runtime/packages.txt \
 && (cd /var/lib/apt/lists && sha256sum *InRelease) \
    > /usr/share/labapp-runtime/inrelease.sha256 \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

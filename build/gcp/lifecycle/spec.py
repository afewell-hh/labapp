"""Fixed, bounded inspection-VM specification and create-request builder.

Everything here is a constant or a pure function so the exact request body can
be hashed, persisted before submission and diffed in tests. Field names follow
the Compute Engine v1 ``instances.insert`` resource. A read-only attachment
cannot auto-delete; its owned disk requires explicit cleanup (see README gates).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

PROJECT = "teched-473722"
ZONE = "us-central1-a"
REGION = "us-central1"
MACHINE_TYPE = "e2-standard-2"
SOURCE_IMAGE = f"projects/{PROJECT}/global/images/hedgehog-vaidc-v20260114"
SOURCE_DISK_GB = 300  # verified source-image minimum (#151/#153)
BOOT_DISK_GB = 10
DISK_TYPE = "pd-standard"  # preferred; SSD quota is only 500 GB
LEASE_MINUTES = 60
SLOT_PREFIX = "labapp-lc-s1"
LABEL_OWNER = "labapp-owner"
LABEL_LEASE = "labapp-lease"
LABEL_RUN = "labapp-run"
OWNER_VALUE = "lifecycle-v1"

_NAME_RE = re.compile(r"^labapp-lc-s1-r[0-9]{1,15}-a[0-9]{1,3}(-boot|-src)?$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_owned_name(name: str) -> bool:
    return bool(_NAME_RE.match(name))


def names(run_id: int, attempt: int) -> dict:
    base = f"{SLOT_PREFIX}-r{run_id}-a{attempt}"
    out = {"instance": base, "boot": f"{base}-boot", "data": f"{base}-src"}
    for value in out.values():
        if not is_owned_name(value):
            raise ValueError(f"bad resource name {value!r}")
    return out


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_body(*, boot_image: str, request_id: str, run_id: int, attempt: int,
               deadline: datetime) -> dict:
    """Return the exact instances.insert body for one inspection lease."""
    if "/family/" in boot_image or "/global/images/" not in boot_image:
        raise ValueError("boot_image must be a pinned image, not a family")
    if not _UUID_RE.match(request_id):
        raise ValueError("request_id must be a lowercase UUID")
    n = names(run_id, attempt)
    labels = {LABEL_OWNER: OWNER_VALUE, LABEL_LEASE: request_id,
              LABEL_RUN: str(run_id)}
    zone = f"zones/{ZONE}"
    body = {
        "name": n["instance"],
        "machineType": f"{zone}/machineTypes/{MACHINE_TYPE}",
        "labels": labels,
        "disks": [
            {
                "boot": True, "autoDelete": True, "mode": "READ_WRITE",
                "deviceName": "boot", "type": "PERSISTENT",
                "initializeParams": {
                    "diskName": n["boot"], "sourceImage": boot_image,
                    "diskSizeGb": str(BOOT_DISK_GB),
                    "diskType": f"{zone}/diskTypes/{DISK_TYPE}",
                    "labels": labels,
                },
            },
            {
                # A copy created inline from the source image, attached
                # read-only; there is no writable fallback. The original
                # image is never attached. Compute rejects autoDelete on a
                # READ_ONLY attachment; reconciliation deletes this copy.
                "boot": False, "autoDelete": False, "mode": "READ_ONLY",
                "deviceName": "src", "type": "PERSISTENT",
                "initializeParams": {
                    "diskName": n["data"], "sourceImage": SOURCE_IMAGE,
                    "diskSizeGb": str(SOURCE_DISK_GB),
                    "diskType": f"{zone}/diskTypes/{DISK_TYPE}",
                    "labels": labels,
                },
            },
        ],
        # No accessConfigs (no external IP), no service account, no scopes.
        "networkInterfaces": [{
            "subnetwork": f"regions/{REGION}/subnetworks/default"}],
        "serviceAccounts": [],
        "canIpForward": False,
        "deletionProtection": False,
        "scheduling": {
            "provisioningModel": "STANDARD",
            "onHostMaintenance": "MIGRATE",
            "automaticRestart": False,
            # Absolute deadline: a stop/start cannot extend it.
            "terminationTime": rfc3339(deadline),
            "instanceTerminationAction": "DELETE",
        },
        "metadata": {"items": [
            {"key": "block-project-ssh-keys", "value": "TRUE"},
            {"key": "enable-oslogin", "value": "TRUE"},
            # Trusted stock guest agent publishes host PUBLIC keys on first
            # boot; owner-only authenticated reads bind subsequent SSH access.
            {"key": "enable-guest-attributes", "value": "TRUE"},
            # Guest extraction is a later, separately reviewed stage.
            {"key": "labapp-stage", "value": "none"},
        ]},
    }
    validate_body(body)
    return body


def validate_body(body: dict) -> None:
    """Reject any body outside the reviewed envelope (defence in depth)."""
    if not is_owned_name(body.get("name", "")):
        raise ValueError("instance name outside the owned pattern")
    for forbidden in ("guestAccelerators", "reservationAffinity",
                      "advancedMachineFeatures", "sourceMachineImage"):
        if forbidden in body:
            raise ValueError(f"forbidden field {forbidden}")
    if body.get("serviceAccounts") != []:
        raise ValueError("a service account must not be attached")
    if body.get("metadata") != {"items": [
            {"key": "block-project-ssh-keys", "value": "TRUE"},
            {"key": "enable-oslogin", "value": "TRUE"},
            {"key": "enable-guest-attributes", "value": "TRUE"},
            {"key": "labapp-stage", "value": "none"}]}:
        raise ValueError("metadata must match the fixed access-only settings")
    if not body.get("machineType", "").endswith(f"/machineTypes/{MACHINE_TYPE}"):
        raise ValueError("machine type outside the reviewed shape")
    nics = body.get("networkInterfaces", [])
    if len(nics) != 1 or "accessConfigs" in nics[0] or \
            "ipv6AccessConfigs" in nics[0]:
        raise ValueError("external addressing is forbidden")
    sched = body.get("scheduling", {})
    if sched.get("instanceTerminationAction") != "DELETE" or \
            not sched.get("terminationTime"):
        raise ValueError("absolute terminationTime with DELETE is required")
    if "maxRunDuration" in sched:
        raise ValueError("duration limits reset on restart; use terminationTime")
    disks = body.get("disks", [])
    if len(disks) != 2:
        raise ValueError("exactly boot and source-copy disks are allowed")
    boot, data = disks
    if boot.get("boot") is not True or boot.get("mode") != "READ_WRITE":
        raise ValueError("first disk must be the read-write boot disk")
    if data.get("boot") is not False or data.get("mode") != "READ_ONLY":
        raise ValueError("source copy must be a non-boot READ_ONLY attachment")
    if boot.get("autoDelete") is not True or data.get("autoDelete") is not False:
        raise ValueError("autoDelete must be true on boot and false on the READ_ONLY copy")
    sizes = []
    for disk in disks:
        init = disk.get("initializeParams", {})
        if not is_owned_name(init.get("diskName", "")):
            raise ValueError("disk name outside the owned pattern")
        if not init.get("diskType", "").endswith(f"/diskTypes/{DISK_TYPE}"):
            raise ValueError("disk type outside the reviewed shape")
        sizes.append(int(init.get("diskSizeGb", "0")))
    if sizes != [BOOT_DISK_GB, SOURCE_DISK_GB]:
        raise ValueError("disk sizes outside the reviewed shape")
    if disks[1]["initializeParams"].get("sourceImage") != SOURCE_IMAGE:
        raise ValueError("source copy must come from the selected image")


def body_hash(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

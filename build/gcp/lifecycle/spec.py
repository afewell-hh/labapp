"""Fixed, bounded VM specifications and create-request builder.

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
INSPECTOR = "inspector-v1"
UBUNTU_COMPONENT = "ubuntu-component-v1"
UBUNTU_BASE_BUILD = "ubuntu-base-build-v1"
UBUNTU_VLAB_CORE = "ubuntu-vlab-core-v1"
UBUNTU_PROFILES = (UBUNTU_COMPONENT, UBUNTU_BASE_BUILD, UBUNTU_VLAB_CORE)
VLAB_LEASE_MINUTES = 120
VLAB_MACHINE = "n2-standard-32"
VLAB_DISK_GB = 500
BASE_BUILD_LEASE_MINUTES = 120
BASE_BUILD_FIRST_LEASE_MINUTES = 45  # explicit first fixture; no runner enabled
COMPONENT_IMAGE = "projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20261024"
COMPONENT_IMAGE_ID = "4575951068918267275"
COMPONENT_MACHINE = "n2-standard-2"
COMPONENT_DISK_GB = 20
COMPONENT_LEASE_MINUTES = 30
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


def kinds(profile: str = INSPECTOR) -> tuple:
    if profile == INSPECTOR:
        return (("instance", "instances"), ("boot", "disks"), ("data", "disks"))
    if profile in UBUNTU_PROFILES:
        return (("instance", "instances"), ("boot", "disks"))
    raise ValueError("unknown fixed lifecycle profile")


def lease_limit(profile: str) -> int:
    """Absolute minutes from admission; profiles cannot renew a lease."""
    kinds(profile)
    if profile in (UBUNTU_BASE_BUILD, UBUNTU_VLAB_CORE):
        return BASE_BUILD_LEASE_MINUTES
    return COMPONENT_LEASE_MINUTES if profile == UBUNTU_COMPONENT else LEASE_MINUTES


def names(run_id: int, attempt: int, profile: str = INSPECTOR) -> dict:
    base = f"{SLOT_PREFIX}-r{run_id}-a{attempt}"
    out = {"instance": base, "boot": f"{base}-boot", "data": f"{base}-src"}
    out = {key: out[key] for key, _ in kinds(profile)}
    for value in out.values():
        if not is_owned_name(value):
            raise ValueError(f"bad resource name {value!r}")
    return out


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_body(*, boot_image: str, request_id: str, run_id: int, attempt: int,
               deadline: datetime, profile: str = INSPECTOR) -> dict:
    """Return the exact request for one fixed lifecycle profile."""
    if "/family/" in boot_image or "/global/images/" not in boot_image:
        raise ValueError("boot_image must be a pinned image, not a family")
    if not _UUID_RE.match(request_id):
        raise ValueError("request_id must be a lowercase UUID")
    kinds(profile)
    if profile in UBUNTU_PROFILES and boot_image != COMPONENT_IMAGE:
        raise ValueError("Ubuntu boot image must match the reviewed pin")
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
    if profile in UBUNTU_PROFILES:
        body["machineType"] = f"{zone}/machineTypes/{COMPONENT_MACHINE}"
        body["disks"] = body["disks"][:1]
        body["disks"][0]["autoDelete"] = profile != UBUNTU_BASE_BUILD
        body["disks"][0]["initializeParams"]["diskSizeGb"] = str(COMPONENT_DISK_GB)
        body["minCpuPlatform"] = "Intel Cascade Lake"
        body["advancedMachineFeatures"] = {"enableNestedVirtualization": True}
        # Stop rather than depending on nested-host migration compatibility.
        body["scheduling"]["onHostMaintenance"] = "TERMINATE"
        if profile == UBUNTU_VLAB_CORE:
            body["machineType"] = f"{zone}/machineTypes/{VLAB_MACHINE}"
            init = body["disks"][0]["initializeParams"]
            init["diskSizeGb"] = str(VLAB_DISK_GB)
            init["diskType"] = f"{zone}/diskTypes/pd-balanced"
    return body


def validate_body(body: dict) -> None:
    """Reject any body outside the reviewed envelope (defence in depth)."""
    if body.get("advancedMachineFeatures") is not None:
        try:
            label = body["labels"]
            match = re.fullmatch(r"labapp-lc-s1-r([0-9]{1,15})-a([0-9]{1,3})", body["name"])
            if match is None:
                raise ValueError()
            # Match a finite table, never infer a profile from one boolean.
            expected = [build_body(boot_image=COMPONENT_IMAGE,
                                   request_id=label[LABEL_LEASE],
                                   run_id=int(match[1]), attempt=int(match[2]),
                                   deadline=datetime.fromisoformat(body["scheduling"]["terminationTime"].replace("Z", "+00:00")),
                                   profile=p) for p in UBUNTU_PROFILES]
            if not any(body == candidate and body_hash(body) == body_hash(candidate)
                       for candidate in expected):
                raise ValueError()
        except (KeyError, IndexError, TypeError, ValueError, AttributeError):
            raise ValueError("body outside the fixed Ubuntu profile") from None
        return
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


CAPTURE_RESERVE_MINUTES = 15
MAX_QUARANTINE_HOURS = 24


def resource_link(path: str, value: str) -> bool:
    return value in (path, "https://www.googleapis.com/compute/v1/" + path,
                     "https://compute.googleapis.com/compute/v1/" + path)


def capture_body(capture: dict) -> dict:
    return {"name": capture["name"], "sourceDisk": capture["source_disk"],
            "labels": {LABEL_OWNER: OWNER_VALUE, LABEL_LEASE: capture["lease_id"],
                       LABEL_RUN: str(capture["run_id"]),
                       "labapp-capture": capture["request_id"]}}


def validate_capture(c: dict) -> None:
    """Validate fixed persisted capture intent, never an arbitrary image body.

    sourceDiskId is output-only: the controller also checks the immutable disk
    immediately before submission and verifies the returned image provenance.
    """
    try:
        import uuid
        for key in ("request_id", "lease_id", "delete_request_id"):
            if str(uuid.UUID(c[key])) != c[key] or uuid.UUID(c[key]).int == 0:
                raise ValueError()
        if len({c["request_id"], c["lease_id"], c["delete_request_id"]}) != 3:
            raise ValueError()
        n = names(c["run_id"], c["attempt"], UBUNTU_BASE_BUILD)
        expected_name = "labapp-candidate-" + c["request_id"]
        if (c["name"] != expected_name or c["source_disk"] !=
                f"projects/{PROJECT}/zones/{ZONE}/disks/{n['boot']}" or
                not re.fullmatch(r"[1-9][0-9]{0,19}", c["source_disk_id"]) or
                c["body_hash"] != body_hash(capture_body(c)) or
                c["name"] in c["preexisting_images"] or
                c.get("image_id") in c["preexisting_images"].values() or
                type(c["submitted"]) is not bool or type(c["delete_submitted"]) is not bool):
            raise ValueError()
        start = datetime.fromisoformat(c["prepared_at"].replace("Z", "+00:00"))
        deadline = datetime.fromisoformat(c["deadline"].replace("Z", "+00:00"))
        if not 0 < (deadline - start).total_seconds() <= BASE_BUILD_LEASE_MINUTES * 60:
            raise ValueError()
        if c["retain_until"] is not None:
            end = datetime.fromisoformat(c["retain_until"].replace("Z", "+00:00"))
            if not 0 < (end - start).total_seconds() <= MAX_QUARANTINE_HOURS * 3600:
                raise ValueError()
        if not isinstance(c["preexisting_images"], dict) or any(
                not isinstance(n, str) or not isinstance(i, str)
                for n, i in c["preexisting_images"].items()):
            raise ValueError()
        for field, request, kind in (("insert_receipt", c["request_id"], "insert"),
                                     ("delete_receipt", c["delete_request_id"], "delete")):
            op = c.get(field)
            if op is not None and (op.get("status") != "DONE" or op.get("error") or
                    op.get("operationType") != kind or op.get("clientOperationId") != request or
                    op.get("targetId") != c.get("image_id") or
                    not resource_link(f"projects/{PROJECT}/global/images/{c['name']}", op.get("targetLink"))):
                raise ValueError()
        if c.get("image_id") is not None and not re.fullmatch(r"[1-9][0-9]{0,19}", c["image_id"]):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("invalid fixed capture intent") from None

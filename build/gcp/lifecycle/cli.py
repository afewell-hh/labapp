"""Fixed trusted-runner lifecycle entrypoint. No freeform cloud parameters.

Official REST v1 projects.get, regions.get and images.get contracts checked
2026-10-24. Quota reads are preflight snapshots, not reservations. Creator and
cleanup identities remain separate; this module never switches identities.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
import math
import os
from pathlib import Path
import re
import sys
import uuid

from . import spec
from .auth_http import HttpTransport, bearer_headers, gcloud_token
from .cloud import NotFound, PolicyCloud
from .compute import ComputeRestTransport
from .controller import Config, Controller, Refused
from .gcs import GcsSlotStore
from .access_records import GcsAccessRecords, ReadOnlyAccessRecords

REPOSITORY = "afewell-hh/labapp"
REPOSITORY_ID = 1089062808
OWNER_ID = 193945001
CREATOR_NAME = "Labapp bounded Ubuntu component"
VLAB_CREATOR_NAME = "Labapp bounded canonical VLAB trial"
LEGACY_CREATOR_NAME = "Labapp bounded lifecycle inspection"
CREATOR_PATH = ".github/workflows/labapp-lifecycle-inspect.yml"
BUCKET = "labapp-lifecycle-ledger-22685701361"
BOOT_IMAGE = "projects/debian-cloud/global/images/debian-13-trixie-v20261023"
# Fixed reviewed budgets; no workflow or environment overrides.
PILOT_LEASE_MINUTES = 30
CONFIRM_TIMEOUT_SECONDS = 360
CONFIRM_POLL_ATTEMPTS = 72
POLL_SECONDS = 5
ABSENCE_GRACE_SECONDS = 120
ABSENCE_POLL_ATTEMPTS = (PILOT_LEASE_MINUTES * 60 + ABSENCE_GRACE_SECONDS) // POLL_SECONDS + 1
VLAB_ABSENCE_POLL_ATTEMPTS = (spec.VLAB_LEASE_MINUTES * 60 + ABSENCE_GRACE_SECONDS) // POLL_SECONDS + 1
COMPONENT_IMAGES = ((spec.COMPONENT_IMAGE, spec.COMPONENT_IMAGE_ID, 10),)
IMAGES = ((BOOT_IMAGE, "1840322579453583118", 10),
          (spec.SOURCE_IMAGE, "7638370619126112785", 300))


def trusted_event(mode, env, event):
    """Validate before credentials/cloud calls; return trusted completed run."""
    repo = event.get("repository", {})
    if (env.get("GITHUB_REPOSITORY") != REPOSITORY or
            env.get("GITHUB_REF") != "refs/heads/main" or
            repo.get("id") != REPOSITORY_ID or
            repo.get("full_name") != REPOSITORY or
            repo.get("owner", {}).get("id") != OWNER_ID):
        raise Refused("untrusted repository or ref")
    if event.get("inputs", {}):
        raise Refused("fixed workflow accepts no inputs")
    kind = env.get("GITHUB_EVENT_NAME")
    if mode in ("inspect", "component", "vlab-core"):
        if kind != "workflow_dispatch" or event.get("inputs", {}):
            raise Refused("creator requires fixed main dispatch without inputs")
        return None
    if kind in ("workflow_dispatch", "schedule"):
        if event.get("inputs", {}):
            raise Refused("cleanup accepts no inputs")
        return None
    run = event.get("workflow_run", {})
    head = run.get("head_repository", {})
    if (kind != "workflow_run" or event.get("action") != "completed" or
            run.get("status") != "completed" or
            run.get("name") not in (CREATOR_NAME, LEGACY_CREATOR_NAME, VLAB_CREATOR_NAME) or run.get("path") != CREATOR_PATH or
            run.get("event") != "workflow_dispatch" or
            run.get("head_branch") != "main" or
            head.get("id") != REPOSITORY_ID or head.get("full_name") != REPOSITORY or
            head.get("owner", {}).get("id") != OWNER_ID or
            type(run.get("id")) is not int or run["id"] <= 0 or
            type(run.get("run_attempt")) is not int or run["run_attempt"] <= 0 or
            not re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", ""))):
        raise Refused("untrusted completed creator run")
    return run


class Preflight:
    """Fixed project/region/image reads; no caller-supplied URL/path."""
    def __init__(self, http=None, token_provider=gcloud_token, profile=spec.INSPECTOR):
        spec.kinds(profile)
        self.profile = profile
        self.images = COMPONENT_IMAGES if profile in spec.UBUNTU_PROFILES else IMAGES
        self.http = http if http is not None else HttpTransport()
        self.token_provider = token_provider

    def check(self):
        base = "https://compute.googleapis.com/compute/v1/"
        paths = [f"projects/{spec.PROJECT}",
                 f"projects/{spec.PROJECT}/regions/{spec.REGION}"]
        paths.extend(path for path, _, _ in self.images)
        records = []
        for path in paths:
            response = self.http.request("GET", base + path,
                                         headers=bearer_headers(self.token_provider),
                                         timeout=20, max_bytes=1_048_576)
            if response.status != 200:
                raise Refused("fixed preflight read failed")
            try:
                record = json.loads(response.body)
                if not isinstance(record, dict):
                    raise ValueError()
            except (ValueError, TypeError):
                raise Refused("invalid preflight response") from None
            records.append(record)
        project, region, *images = records
        if project.get("name") != spec.PROJECT or region.get("name") != spec.REGION:
            raise Refused("preflight scope mismatch")
        metadata = project.get("commonInstanceMetadata", {}).get("items", [])
        if (not isinstance(metadata, list) or
                any(not isinstance(item, dict) or not isinstance(item.get("key"), str)
                    for item in metadata)):
            raise Refused("invalid inherited project metadata")
        executable = {"startup-script", "startup-script-url", "shutdown-script",
                      "shutdown-script-url", "user-data", "user-data-encoding"}
        if any(item["key"] in executable for item in metadata):
            raise Refused("inherited project execution metadata blocks pilot")
        self._quota(project, {"CPUS_ALL_REGIONS": 32 if self.profile == spec.UBUNTU_VLAB_CORE else 2})
        # E2 shares the regional CPUS pool with N1 (not E2_CPUS).
        self._quota(region, ({"N2_CPUS": 32, "INSTANCES": 1, "SSD_TOTAL_GB": 500}
                             if self.profile == spec.UBUNTU_VLAB_CORE else
                            {"CPUS": 2, "N2_CPUS": 2, "INSTANCES": 1,
                              "DISKS_TOTAL_GB": spec.COMPONENT_DISK_GB}
                             if self.profile in spec.UBUNTU_PROFILES else
                             {"CPUS": 2, "DISKS_TOTAL_GB": 310}))
        for actual, (path, image_id, minimum) in zip(images, self.images):
            if (actual.get("id") != image_id or
                    actual.get("name") != path.rsplit("/", 1)[-1] or
                    actual.get("status") != "READY" or
                    str(actual.get("diskSizeGb")) != str(minimum)):
                raise Refused("pinned image identity/status/minimum mismatch")
            if self.profile in spec.UBUNTU_PROFILES and actual.get("architecture") != "X86_64":
                raise Refused("component image architecture mismatch")

    @staticmethod
    def _quota(record, needs):
        quotas = record.get("quotas")
        if not isinstance(quotas, list):
            raise Refused("quota information missing")
        for metric, need in needs.items():
            matches = [q for q in quotas if isinstance(q, dict) and q.get("metric") == metric]
            if len(matches) != 1:
                raise Refused("required quota missing or ambiguous")
            quota = matches[0]
            limit, usage = quota.get("limit"), quota.get("usage")
            if (type(limit) not in (int, float) or type(usage) not in (int, float) or
                    not math.isfinite(limit) or not math.isfinite(usage) or
                    usage < 0 or limit < 0 or limit - usage < need):
                raise Refused("insufficient or invalid quota")


def verify_disk_provenance(controller, record):
    """Check actual cloned image IDs; names alone cannot pin incarnations."""
    profile = record.get("profile", spec.INSPECTOR)
    images = COMPONENT_IMAGES if profile in spec.UBUNTU_PROFILES else IMAGES
    kinds = [kind for kind, _ in spec.kinds(profile)[1:]]
    if set(record["ids"]) != {"instance", *kinds} or set(record["names"]) != {"instance", *kinds}:
        raise Refused("created disk inventory mismatch")
    for kind, (path, image_id, _) in zip(kinds, images):
        disk = controller.cloud.call("disks", "get", name=record["names"][kind])
        if (not record["ids"].get(kind) or disk.get("id") != record["ids"][kind] or
                disk.get("sourceImageId") != image_id or
                (profile in spec.UBUNTU_PROFILES and
                 disk.get("sourceImage") not in (path,
                     "https://www.googleapis.com/compute/v1/" + path,
                     "https://compute.googleapis.com/compute/v1/" + path))):
            raise Refused("created disk image provenance mismatch; independent cleanup required")


def wait_for_absence(controller, request_id):
    """Read-only bounded wait; deletion/release belongs to cleanup identity."""
    record, _ = controller.store.read(controller.cfg.key)
    if (not record or record.get("request_id") != request_id or
            not record.get("ids", {}).get("instance")):
        raise Refused("created lease identity unavailable")
    verify_disk_provenance(controller, record)
    # The fixed thirty-minute lease plus two-minute cloud convergence allowance.
    # An iteration bound also stops clock changes extending the wait.
    print(json.dumps({"status": "created", "ids": record["ids"],
                      "deadline": record["deadline"], "names": record["names"],
                      "request_id": request_id, "profile": record.get("profile", spec.INSPECTOR)}, sort_keys=True), flush=True)
    cutoff = datetime.fromisoformat(record["deadline"].replace("Z", "+00:00")) + timedelta(seconds=ABSENCE_GRACE_SECONDS)
    attempts = VLAB_ABSENCE_POLL_ATTEMPTS if record.get('profile') == spec.UBUNTU_VLAB_CORE else ABSENCE_POLL_ATTEMPTS
    for _ in range(attempts):
        if controller.cfg.now() >= cutoff:
            break
        try:
            instance = controller.cloud.call("instances", "get", name=record["names"]["instance"])
        except NotFound:
            return {"status": "vm-absent-awaiting-independent-disk-verification"}
        if instance.get("id") != record["ids"]["instance"]:
            raise Refused("instance identity changed during wait")
        try:
            observed = datetime.fromisoformat(instance["scheduling"]["terminationTime"].replace("Z", "+00:00"))
            expected = datetime.fromisoformat(record["deadline"].replace("Z", "+00:00"))
            if observed != expected:
                raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Refused("instance deadline changed during wait") from None
        controller.cfg.sleep(POLL_SECONDS)
    raise Refused("VM absence not confirmed within fixed wait bound")


def execute(mode, controller, preflight, env, event):
    run = trusted_event(mode, env, event)
    if mode in ("inspect", "component", "vlab-core"):
        # Verify before reserving capacity or issuing any mutation.
        preflight.check()
        run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
        if run_id <= 0 or attempt <= 0:
            raise Refused("invalid run identity")
        if mode == 'vlab-core' and attempt != 1:
            raise Refused('canonical creator is first-attempt only; dispatch a new run')
        lease = controller.admit(run_id, attempt, str(uuid.uuid4()))
        submitted = controller.submit(lease["request_id"])
        if submitted.status != "accepted":
            raise Refused("create not confirmed; independent cleanup required")
        confirmed = controller.confirm_created(lease["request_id"], timeout_seconds=CONFIRM_TIMEOUT_SECONDS)
        if confirmed.status != "created":
            raise Refused("creation not confirmed; independent cleanup required")
        # Deliberately no serial output, guest content, or raw API diagnostics.
        return wait_for_absence(controller, lease["request_id"])
    request_id = None
    if run is not None or env.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        record, _ = controller.store.read(controller.cfg.key)
        if record and record.get("state") != "FREE":
            if run is not None and (record.get("run_id"), record.get("attempt")) != (run["id"], run["run_attempt"]):
                return {"status": "superseded"}
            request_id = record["request_id"]
    outcome = controller.reconcile(request_id)
    if outcome.status not in {"released", "free", "not-due", "superseded"}:
        raise Refused("cleanup incomplete; capacity remains occupied")
    return {"status": outcome.status}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "component", "vlab-core", "cleanup"))
    args = parser.parse_args(argv)
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        # Trust validation precedes adapter construction and cloud access.
        trusted_event(args.mode, os.environ, event)
        profile = {"component": spec.UBUNTU_COMPONENT, "vlab-core": spec.UBUNTU_VLAB_CORE}.get(args.mode, spec.INSPECTOR)
        controller = Controller(GcsSlotStore(BUCKET),
                                PolicyCloud(ComputeRestTransport(), spec.PROJECT, spec.ZONE),
                                Config(boot_image=spec.COMPONENT_IMAGE if profile in spec.UBUNTU_PROFILES else BOOT_IMAGE,
                                       profile=profile, lease_minutes=spec.VLAB_LEASE_MINUTES if profile == spec.UBUNTU_VLAB_CORE else PILOT_LEASE_MINUTES,
                                       min_submit_minutes=1,
                                       poll_attempts=CONFIRM_POLL_ATTEMPTS if args.mode in ("inspect", "component", "vlab-core") else 30,
                                       poll_seconds=POLL_SECONDS),
                                access_records=(ReadOnlyAccessRecords(GcsAccessRecords(BUCKET, token_provider=gcloud_token))
                                                if args.mode == "cleanup" else None))
        result = execute(args.mode, controller, Preflight(profile=profile), os.environ, event)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # Never expose token provider/server payloads or raw ledger values.
        print("Lifecycle failed closed; inspect trusted ledger and cleanup status.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

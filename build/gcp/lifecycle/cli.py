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

REPOSITORY = "afewell-hh/labapp"
REPOSITORY_ID = 1089062808
OWNER_ID = 193945001
CREATOR_NAME = "Labapp bounded lifecycle inspection"
CREATOR_PATH = ".github/workflows/labapp-lifecycle-inspect.yml"
BUCKET = "labapp-lifecycle-ledger-22685701361"
BOOT_IMAGE = "projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20261024"
# Fixed reviewed budgets; no workflow or environment overrides.
PILOT_LEASE_MINUTES = 10
CONFIRM_TIMEOUT_SECONDS = 360
CONFIRM_POLL_ATTEMPTS = 72
POLL_SECONDS = 5
ABSENCE_GRACE_SECONDS = 120
ABSENCE_POLL_ATTEMPTS = (PILOT_LEASE_MINUTES * 60 + ABSENCE_GRACE_SECONDS) // POLL_SECONDS + 1
IMAGES = ((BOOT_IMAGE, "4575951068918267275", 10),
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
    kind = env.get("GITHUB_EVENT_NAME")
    if mode == "inspect":
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
            run.get("name") != CREATOR_NAME or run.get("path") != CREATOR_PATH or
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
    """Only four fixed read-only API requests; no caller-supplied URL/path."""
    def __init__(self, http=None, token_provider=gcloud_token):
        self.http = http if http is not None else HttpTransport()
        self.token_provider = token_provider

    def check(self):
        base = "https://compute.googleapis.com/compute/v1/"
        paths = [f"projects/{spec.PROJECT}",
                 f"projects/{spec.PROJECT}/regions/{spec.REGION}"]
        paths.extend(path for path, _, _ in IMAGES)
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
        self._quota(project, {"CPUS_ALL_REGIONS": 2})
        # E2 shares the regional CPUS pool with N1 (not E2_CPUS).
        self._quota(region, {"CPUS": 2, "DISKS_TOTAL_GB": 310})
        for actual, (path, image_id, minimum) in zip(images, IMAGES):
            if (actual.get("id") != image_id or
                    actual.get("name") != path.rsplit("/", 1)[-1] or
                    actual.get("status") != "READY" or
                    str(actual.get("diskSizeGb")) != str(minimum)):
                raise Refused("pinned image identity/status/minimum mismatch")

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
    for kind, (_, image_id, _) in zip(("boot", "data"), IMAGES):
        disk = controller.cloud.call("disks", "get", name=record["names"][kind])
        if (not record["ids"].get(kind) or disk.get("id") != record["ids"][kind] or
                disk.get("sourceImageId") != image_id):
            raise Refused("created disk image provenance mismatch; independent cleanup required")


def wait_for_absence(controller, request_id):
    """Read-only bounded wait; deletion/release belongs to cleanup identity."""
    record, _ = controller.store.read(controller.cfg.key)
    if (not record or record.get("request_id") != request_id or
            not record.get("ids", {}).get("instance")):
        raise Refused("created lease identity unavailable")
    verify_disk_provenance(controller, record)
    # The fixed ten-minute lease plus two-minute cloud convergence allowance.
    # An iteration bound also stops clock changes extending the wait.
    print(json.dumps({"status": "created", "ids": record["ids"],
                      "deadline": record["deadline"]}, sort_keys=True), flush=True)
    cutoff = datetime.fromisoformat(record["deadline"].replace("Z", "+00:00")) + timedelta(seconds=ABSENCE_GRACE_SECONDS)
    for _ in range(ABSENCE_POLL_ATTEMPTS):
        if controller.cfg.now() >= cutoff:
            break
        try:
            instance = controller.cloud.call("instances", "get", name=record["names"]["instance"])
        except NotFound:
            return {"status": "vm-absent-awaiting-independent-disk-verification"}
        if instance.get("id") != record["ids"]["instance"]:
            raise Refused("instance identity changed during wait")
        controller.cfg.sleep(POLL_SECONDS)
    raise Refused("VM absence not confirmed within fixed wait bound")


def execute(mode, controller, preflight, env, event):
    run = trusted_event(mode, env, event)
    if mode == "inspect":
        # Verify before reserving capacity or issuing any mutation.
        preflight.check()
        run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
        if run_id <= 0 or attempt <= 0:
            raise Refused("invalid run identity")
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
    parser.add_argument("mode", choices=("inspect", "cleanup"))
    args = parser.parse_args(argv)
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        # Trust validation precedes adapter construction and cloud access.
        trusted_event(args.mode, os.environ, event)
        controller = Controller(GcsSlotStore(BUCKET),
                                PolicyCloud(ComputeRestTransport(), spec.PROJECT, spec.ZONE),
                                Config(boot_image=BOOT_IMAGE, lease_minutes=PILOT_LEASE_MINUTES,
                                       min_submit_minutes=1,
                                       poll_attempts=CONFIRM_POLL_ATTEMPTS if args.mode == "inspect" else 30,
                                       poll_seconds=POLL_SECONDS))
        result = execute(args.mode, controller, Preflight(), os.environ, event)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        # Never expose token provider/server payloads or raw ledger values.
        print("Lifecycle failed closed; inspect trusted ledger and cleanup status.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Owner-run access bootstrap; default offline plan, no VM/controller execution.

Python 3 standard library; --inspect/--apply also require authenticated gcloud.
No cwd assumptions. Never creates credentials, attaches SAs, or touches images.
"""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

PROJECT = "teched-473722"
NUMBER = "22685701361"
BUCKET = f"labapp-lifecycle-ledger-{NUMBER}"
ZONE = "us-central1-a"
REGION = "us-central1"
MAPPING = {"google.subject": "assertion.sub", **{
    f"attribute.{key}": f"assertion.{key}" for key in (
        "repository_id", "repository_owner_id", "ref", "workflow_ref", "event_name")}}
READ = ["compute.instances.get", "compute.instances.list", "compute.disks.get",
        "compute.disks.list", "compute.zoneOperations.get", "compute.zoneOperations.list"]
ROLES = {
    "labappLifecycleCreator": READ + [
        "compute.instances.create", "compute.disks.create", "compute.instances.setMetadata",
        "compute.instances.setLabels", "compute.disks.setLabels",
        "compute.instances.getSerialPortOutput", "compute.projects.get",
        "compute.regions.get", "compute.subnetworks.get"],
    "labappLifecycleReader": READ,
    "labappLifecycleDelete": ["compute.instances.delete", "compute.disks.delete"],
    "labappLifecycleSubnet": ["compute.subnetworks.use"],
}
DELETE_CONDITION = {"title": "labapp_lifecycle_prefix_v1", "expression": (
    "resource.service == 'compute.googleapis.com' && ("
    "(resource.type == 'compute.googleapis.com/Instance' && "
    f"resource.name.startsWith('projects/{PROJECT}/zones/{ZONE}/instances/labapp-lc-')) || "
    "(resource.type == 'compute.googleapis.com/Disk' && "
    f"resource.name.startsWith('projects/{PROJECT}/zones/{ZONE}/disks/labapp-lc-')))"
)}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def role_name(key):
    return f"projects/{PROJECT}/roles/{key}"


def identity(kind):
    account = f"labapp-lc-{kind}"
    workflow = "inspect" if kind == "creator" else "cleanup"
    workflow_ref = (f"afewell-hh/labapp/.github/workflows/"
                    f"labapp-lifecycle-{workflow}.yml@refs/heads/main")
    base = f"projects/{NUMBER}/locations/global/workloadIdentityPools/{account}"
    condition = ("assertion.repository_id == '1089062808' && "
                 "assertion.repository_owner_id == '193945001' && "
                 "assertion.ref == 'refs/heads/main' && "
                 f"assertion.workflow_ref == '{workflow_ref}' && ")
    events = ("assertion.event_name == 'workflow_dispatch'" if kind == "creator" else
              "(assertion.event_name == 'schedule' || assertion.event_name == 'workflow_dispatch' || "
              "assertion.event_name == 'workflow_run')")
    return {"account": account, "email": f"{account}@{PROJECT}.iam.gserviceaccount.com",
            "pool": account, "base": base, "condition": condition + events,
            "principal": f"principalSet://iam.googleapis.com/{base}/attribute.workflow_ref/{workflow_ref}"}


def validate_sa(policy, keys, principal):
    for binding in policy.get("bindings", []):
        require(binding.get("role") == "roles/iam.workloadIdentityUser" and
                not binding.get("condition") and binding.get("members") == [principal],
                "Unexpected service-account trust; investigate without removing it")
    require(isinstance(keys, list) and not keys, "User-managed key metadata found")


def validate_provider(provider, ident):
    oidc = provider.get("oidc", {})
    require(provider.get("state") == "ACTIVE" and not provider.get("disabled") and
            provider.get("attributeMapping") == MAPPING and
            provider.get("attributeCondition") == ident["condition"] and
            oidc.get("issuerUri") == "https://token.actions.githubusercontent.com" and
            not oidc.get("jwksJson") and not oidc.get("allowedAudiences"),
            "Provider trust differs from reviewed configuration")


def expected_project_bindings(kind):
    key = "labappLifecycleCreator" if kind == "creator" else "labappLifecycleReader"
    bindings = [(role_name(key), None)]
    if kind == "cleanup":
        bindings.append((role_name("labappLifecycleDelete"), DELETE_CONDITION))
    return bindings


def validate_project_policy(policy, ident, kind):
    for binding in policy.get("bindings", []):
        if f"serviceAccount:{ident['email']}" in binding.get("members", []):
            require((binding["role"], binding.get("condition")) in expected_project_bindings(kind),
                    "Unexpected lifecycle identity project role/condition")


def validate_bucket(bucket):
    config = bucket.get("iamConfiguration", {})
    require(str(bucket.get("projectNumber")) == NUMBER and bucket.get("name") == BUCKET and
            bucket.get("location", "").upper() == "US-CENTRAL1" and
            config.get("uniformBucketLevelAccess", {}).get("enabled") is True and
            config.get("publicAccessPrevention") == "enforced" and
            not bucket.get("lifecycle", {}).get("rule") and
            not bucket.get("retentionPolicy") and not bucket.get("defaultEventBasedHold"),
            "Ledger bucket ownership/privacy/location/retention differs; no update attempted")


def validate_bucket_policy(policy):
    services = {f"serviceAccount:{identity(k)['email']}" for k in ("creator", "cleanup")}
    legacy = {"roles/storage.legacyBucketOwner": {f"projectOwner:{PROJECT}", f"projectEditor:{PROJECT}"},
              "roles/storage.legacyBucketReader": {f"projectViewer:{PROJECT}"}}
    for binding in policy.get("bindings", []):
        members = set(binding.get("members", []))
        allowed = services if binding.get("role") == "roles/storage.objectUser" else legacy.get(binding.get("role"), set())
        require(bool(members) and members <= allowed and not binding.get("condition"),
                "Unexpected direct ledger bucket access; no grant attempted")


class Gcloud:
    def __init__(self, apply):
        self.apply = apply

    def read(self, *args, optional=False):
        result = subprocess.run(["gcloud", *args, f"--project={PROJECT}", "--format=json"],
                                text=True, capture_output=True, check=False)
        if result.returncode:
            if optional and ("HTTPError 404" in result.stderr or "NOT_FOUND:" in result.stderr):
                return None
            raise RuntimeError(f"Read failed: {' '.join(args[:4])}: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def write(self, *args):
        require(self.apply, "Mutation requested in inspect mode")
        subprocess.run(["gcloud", *args, f"--project={PROJECT}", "--quiet"],
                       check=True, stdout=subprocess.DEVNULL)


def setup(gc):
    project = gc.read("projects", "describe", PROJECT)
    require(str(project.get("projectNumber")) == NUMBER, "Unexpected project number")
    policy = gc.read("projects", "get-iam-policy", PROJECT)
    accounts = gc.read("iam", "service-accounts", "list")
    roles = gc.read("iam", "roles", "list", "--show-deleted")
    # Validate existing roles before binding; never silently update custom roles.
    for key, permissions in ROLES.items():
        existing = next((r for r in roles if r["name"] == role_name(key)), None)
        if existing:
            role = gc.read("iam", "roles", "describe", key)
            require(not role.get("deleted") and role.get("stage") == "GA" and
                    set(role.get("includedPermissions", [])) == set(permissions),
                    f"Custom role differs: {key}")
        elif gc.apply:
            gc.write("iam", "roles", "create", key, f"--title={key}", "--stage=GA",
                     "--permissions=" + ",".join(permissions))
    subnet_policy = gc.read("compute", "networks", "subnets", "get-iam-policy", "default", f"--region={REGION}")
    for kind in ("creator", "cleanup"):
        ident = identity(kind)
        validate_project_policy(policy, ident, kind)
        # Only creator can use the one existing subnet; no network changes.
        for binding in subnet_policy.get("bindings", []):
            if f"serviceAccount:{ident['email']}" in binding.get("members", []):
                require(kind == "creator" and binding.get("role") == role_name("labappLifecycleSubnet") and
                        not binding.get("condition"), "Unexpected lifecycle subnet grant")
        account = next((a for a in accounts if a.get("email") == ident["email"]), None)
        if account:
            require(not account.get("disabled"), "Existing lifecycle account disabled")
        elif gc.apply:
            gc.write("iam", "service-accounts", "create", ident["account"])
        if account or gc.apply:
            validate_sa(gc.read("iam", "service-accounts", "get-iam-policy", ident["email"]),
                        gc.read("iam", "service-accounts", "keys", "list", f"--iam-account={ident['email']}", "--managed-by=user"),
                        ident["principal"])
        pools = gc.read("iam", "workload-identity-pools", "list", "--location=global", "--show-deleted")
        pool = next((p for p in pools if p["name"] == ident["base"]), None)
        if pool:
            require(pool.get("state") == "ACTIVE" and not pool.get("disabled"), "Existing pool disabled/deleted")
        elif gc.apply:
            gc.write("iam", "workload-identity-pools", "create", ident["pool"], "--location=global")
        if pool or gc.apply:
            providers = gc.read("iam", "workload-identity-pools", "providers", "list",
                                f"--workload-identity-pool={ident['pool']}", "--location=global", "--show-deleted")
            require(len(providers) <= 1 and all(p["name"] == ident["base"] + "/providers/trusted-main" for p in providers),
                    "Unexpected provider in reserved identity pool")
            if providers:
                validate_provider(providers[0], ident)
            elif gc.apply:
                gc.write("iam", "workload-identity-pools", "providers", "create-oidc", "trusted-main",
                         f"--workload-identity-pool={ident['pool']}", "--location=global",
                         "--issuer-uri=https://token.actions.githubusercontent.com",
                         "--attribute-mapping=" + ",".join(f"{k}={v}" for k, v in MAPPING.items()),
                         "--attribute-condition=" + ident["condition"])
    bucket = gc.read("storage", "buckets", "describe", f"gs://{BUCKET}", "--raw", optional=True)
    if bucket:
        validate_bucket(bucket)
    elif gc.apply:
        gc.write("storage", "buckets", "create", f"gs://{BUCKET}", f"--location={REGION}",
                 "--uniform-bucket-level-access", "--public-access-prevention", "--default-storage-class=STANDARD")
        validate_bucket(gc.read("storage", "buckets", "describe", f"gs://{BUCKET}", "--raw"))
    if bucket or gc.apply:
        validate_bucket_policy(gc.read("storage", "buckets", "get-iam-policy", f"gs://{BUCKET}"))
    if not gc.apply:
        print("Inspection completed; absent resources are not created.")
        return
    # All reused identities/trust/bucket settings validated before any grants.
    for kind in ("creator", "cleanup"):
        ident = identity(kind)
        gc.write("iam", "service-accounts", "add-iam-policy-binding", ident["email"],
                 "--member=" + ident["principal"], "--role=roles/iam.workloadIdentityUser", "--condition=None")
        for role, condition in expected_project_bindings(kind):
            with tempfile.TemporaryDirectory() as directory:
                args = ["projects", "add-iam-policy-binding", PROJECT,
                        f"--member=serviceAccount:{ident['email']}", "--role=" + role]
                if condition:
                    path = Path(directory) / "condition.json"
                    path.write_text(json.dumps(condition))
                    args.append("--condition-from-file=" + str(path))
                else:
                    args.append("--condition=None")
                gc.write(*args)
        gc.write("storage", "buckets", "add-iam-policy-binding", f"gs://{BUCKET}",
                 f"--member=serviceAccount:{ident['email']}", "--role=roles/storage.objectUser", "--condition=None")
    gc.write("compute", "networks", "subnets", "add-iam-policy-binding", "default", f"--region={REGION}",
             f"--member=serviceAccount:{identity('creator')['email']}",
             "--role=" + role_name("labappLifecycleSubnet"), "--condition=None")
    print("Access setup complete; no workflow, VM, slot object, image or key created.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inspect", action="store_true", help="read live metadata only")
    mode.add_argument("--apply", action="store_true", help="create reviewed access resources")
    args = parser.parse_args()
    print(json.dumps({"project": PROJECT, "ledger": f"gs://{BUCKET}", "roles": ROLES,
                      "deleteCondition": DELETE_CONDITION,
                      "identities": [identity(k) for k in ("creator", "cleanup")]}, indent=2))
    if args.inspect or args.apply:
        if args.apply:
            require(os.environ.get("LABAPP_LIFECYCLE_ACCESS_REVIEWED") == "yes",
                    "Review lifecycle privilege/impersonation limits; set LABAPP_LIFECYCLE_ACCESS_REVIEWED=yes")
        setup(Gcloud(args.apply))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error

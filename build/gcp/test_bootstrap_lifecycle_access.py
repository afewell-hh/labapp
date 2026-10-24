"""Offline contract tests; inject fake transport, never call gcloud."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("bootstrap-lifecycle-access.py")
spec = importlib.util.spec_from_file_location("access", SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def provider(kind):
    ident = a.identity(kind)
    return {"name": ident["base"] + "/providers/trusted-main", "state": "ACTIVE",
            "attributeMapping": a.MAPPING, "attributeCondition": ident["condition"],
            "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}


def bucket():
    return {"name": a.BUCKET, "projectNumber": a.NUMBER, "location": "US-CENTRAL1",
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                 "publicAccessPrevention": "enforced"}}


def default_bucket_policy():
    """Observed uniform-access bucket defaults; project convenience values."""
    return {"bindings": [
        {"role": "roles/storage.legacyBucketOwner", "members": [
            f"projectEditor:{a.PROJECT}", f"projectOwner:{a.PROJECT}"]},
        {"role": "roles/storage.legacyBucketReader", "members": [f"projectViewer:{a.PROJECT}"]},
        {"role": "roles/storage.legacyObjectOwner", "members": [
            f"projectEditor:{a.PROJECT}", f"projectOwner:{a.PROJECT}"]},
        {"role": "roles/storage.legacyObjectReader", "members": [f"projectViewer:{a.PROJECT}"]}]}


class FakeGcloud:
    """Model a complete previous bootstrap to test safe reuse/grant boundaries."""
    def __init__(self, apply=False):
        self.apply = apply
        self.writes = []
        self.bad_provider = False

    def read(self, *args, **kwargs):
        if args[:2] == ("projects", "describe"):
            return {"projectNumber": a.NUMBER}
        if args[:2] == ("projects", "get-iam-policy"):
            return {"bindings": [
                {"role": role, "members": [f"serviceAccount:{a.identity(kind)['email']}"],
                 **({"condition": condition} if condition else {})}
                for kind in ("creator", "cleanup")
                for role, condition in a.expected_project_bindings(kind)]}
        if args[:3] == ("iam", "roles", "list"):
            return [{"name": a.role_name(key)} for key in a.ROLES]
        if args[:3] == ("iam", "roles", "describe"):
            return {"stage": "GA", "includedPermissions": a.ROLES[args[3]]}
        if args[:3] == ("iam", "service-accounts", "list"):
            return [{"email": a.identity(kind)["email"]} for kind in ("creator", "cleanup")]
        if args[:3] == ("iam", "service-accounts", "get-iam-policy"):
            ident = next(a.identity(kind) for kind in ("creator", "cleanup") if a.identity(kind)["email"] == args[3])
            return {"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": [ident["principal"]]}]}
        if args[:4] == ("iam", "service-accounts", "keys", "list"):
            assert "--managed-by=user" in args
            return []
        if args[:3] == ("iam", "workload-identity-pools", "list"):
            return [{"name": a.identity(kind)["base"], "state": "ACTIVE"} for kind in ("creator", "cleanup")]
        if args[:4] == ("iam", "workload-identity-pools", "providers", "list"):
            kind = "creator" if "--workload-identity-pool=labapp-lc-creator" in args else "cleanup"
            result = copy.deepcopy(provider(kind))
            if self.bad_provider:
                result["oidc"]["jwksJson"] = '{"keys":[{"kid":"untrusted"}]}'
            return [result]
        if args[:4] == ("compute", "networks", "subnets", "get-iam-policy"):
            return {"bindings": []}
        if args[:3] == ("storage", "buckets", "describe"):
            assert "--raw" in args
            return bucket()
        if args[:3] == ("storage", "buckets", "get-iam-policy"):
            policy = default_bucket_policy()
            policy["bindings"].append({"role": "roles/storage.objectUser", "members": [
                f"serviceAccount:{a.identity(kind)['email']}" for kind in ("creator", "cleanup")]})
            return policy
        raise AssertionError(f"Unexpected read: {args}")

    def write(self, *args):
        assert self.apply
        if args[:4] == ("compute", "networks", "subnets", "add-iam-policy-binding"):
            assert args[4] == "default"
            assert all(arg.startswith(("--region=", "--member=", "--role=")) for arg in args[5:]), "Unsupported subnet IAM flag"
        if args[:2] == ("projects", "add-iam-policy-binding"):
            for arg in args:
                if arg.startswith("--condition-from-file="):
                    assert json.loads(Path(arg.split("=", 1)[1]).read_text()) == a.DELETE_CONDITION
        self.writes.append(args)


class AccessTests(unittest.TestCase):
    def test_optional_bucket_accepts_observed_cli_not_found(self):
        error = ("ERROR: (gcloud.storage.buckets.describe) "
                 f"gs://{a.BUCKET} not found: 404.\n")
        result = subprocess.CompletedProcess([], 1, stdout="", stderr=error)
        with mock.patch.object(a.subprocess, "run", return_value=result):
            self.assertIsNone(a.Gcloud(False).read(
                "storage", "buckets", "describe", f"gs://{a.BUCKET}",
                "--raw", optional=True))

    def test_optional_bucket_preserves_other_failures(self):
        errors = [
            f"ERROR: (gcloud.storage.buckets.describe) gs://{a.BUCKET} not found: 403.",
            f"ERROR: (gcloud.storage.buckets.describe) gs://{a.BUCKET} not found: 500.",
            f"ERROR: (gcloud.storage.buckets.describe) gs://{a.BUCKET} Permission denied: 403.",
            "ERROR: (gcloud.storage.buckets.describe) gs://other-bucket not found: 404.",
        ]
        for error in errors:
            with self.subTest(error=error):
                result = subprocess.CompletedProcess([], 1, stdout="", stderr=error)
                with mock.patch.object(a.subprocess, "run", return_value=result):
                    with self.assertRaises(RuntimeError):
                        a.Gcloud(False).read("storage", "buckets", "describe",
                                             f"gs://{a.BUCKET}", optional=True)

    def test_observed_bucket_404_requires_optional_and_exact_command(self):
        error = ("ERROR: (gcloud.storage.buckets.describe) "
                 f"gs://{a.BUCKET} not found: 404.")
        result = subprocess.CompletedProcess([], 1, stdout="", stderr=error)
        with mock.patch.object(a.subprocess, "run", return_value=result):
            with self.assertRaises(RuntimeError):
                a.Gcloud(False).read("storage", "buckets", "describe", f"gs://{a.BUCKET}")
            with self.assertRaises(RuntimeError):
                a.Gcloud(False).read("storage", "buckets", "get-iam-policy",
                                     f"gs://{a.BUCKET}", optional=True)

    def test_default_offline_plan_needs_no_gcloud(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], env={"PATH": ""},
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["project"], a.PROJECT)

    def test_apply_requires_specific_review(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--apply"],
                                env={"PATH": ""}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LABAPP_LIFECYCLE_ACCESS_REVIEWED", result.stderr)

    def test_inspect_never_mutates(self):
        gc = FakeGcloud()
        a.setup(gc)
        self.assertEqual(gc.writes, [])

    def test_rerun_has_scoped_roles_and_separate_cleanup(self):
        gc = FakeGcloud(True)
        a.setup(gc)
        project_grants = [x for x in gc.writes if x[:2] == ("projects", "add-iam-policy-binding")]
        self.assertEqual(len(project_grants), 3)
        deletion = next(x for x in project_grants if "--role=" + a.role_name("labappLifecycleDelete") in x)
        self.assertIn("--member=serviceAccount:" + a.identity("cleanup")["email"], deletion)
        self.assertTrue(any(x.startswith("--condition-from-file=") for x in deletion))
        self.assertNotIn("--condition=None", deletion)
        self.assertFalse(any("images" in x or "instances" in x or "disks" in x for x in gc.writes))

    def test_first_setup_creates_only_reviewed_access_resources(self):
        class Fresh(FakeGcloud):
            def read(self, *args, **kwargs):
                empty_lists = [("iam", "roles", "list"),
                               ("iam", "service-accounts", "list"),
                               ("iam", "workload-identity-pools", "list")]
                if args[:3] in empty_lists or args[:4] == ("iam", "workload-identity-pools", "providers", "list"):
                    return []
                if args[:2] == ("projects", "get-iam-policy") or args[:3] == ("iam", "service-accounts", "get-iam-policy"):
                    return {"bindings": []}
                if args[:3] == ("storage", "buckets", "describe") and kwargs.get("optional"):
                    return None
                return super().read(*args, **kwargs)
        gc = Fresh(True)
        a.setup(gc)
        self.assertEqual(sum(x[:3] == ("iam", "roles", "create") for x in gc.writes), 4)
        self.assertEqual(sum(x[:3] == ("iam", "service-accounts", "create") for x in gc.writes), 2)
        self.assertEqual(sum(x[:4] == ("iam", "workload-identity-pools", "providers", "create-oidc") for x in gc.writes), 2)
        self.assertEqual(sum(x[:3] == ("storage", "buckets", "create") for x in gc.writes), 1)

    def test_subnet_grant_matches_cli_without_condition_flag(self):
        gc = FakeGcloud(True)
        a.setup(gc)
        subnet = next(x for x in gc.writes if x[:4] == ("compute", "networks", "subnets", "add-iam-policy-binding"))
        self.assertEqual(subnet, ("compute", "networks", "subnets", "add-iam-policy-binding", "default",
                                 "--region=us-central1", "--member=serviceAccount:" + a.identity("creator")["email"],
                                 "--role=" + a.role_name("labappLifecycleSubnet")))
        with self.assertRaisesRegex(AssertionError, "Unsupported subnet IAM flag"):
            gc.write(*subnet, "--condition=None")

    def test_unexpected_provider_fails_before_any_grant(self):
        gc = FakeGcloud(True)
        gc.bad_provider = True
        with self.assertRaises(ValueError):
            a.setup(gc)
        self.assertEqual(gc.writes, [])

    def test_identity_pools_and_workflow_refs_are_distinct(self):
        creator, cleanup = (a.identity(k) for k in ("creator", "cleanup"))
        self.assertNotEqual(creator["pool"], cleanup["pool"])
        self.assertIn("attribute.workflow_ref/afewell-hh/labapp/", creator["principal"])
        self.assertNotIn("schedule", creator["condition"])
        self.assertIn("schedule", cleanup["condition"])
        self.assertIn("workflow_run", cleanup["condition"])
        self.assertNotIn("workflow_run", creator["condition"])
        self.assertNotIn("compute.instances.create", a.ROLES["labappLifecycleReader"])
        self.assertNotIn("compute.disks.create", a.ROLES["labappLifecycleReader"])
        self.assertEqual(a.expected_project_bindings("cleanup"), [
            (a.role_name("labappLifecycleReader"), None),
            (a.role_name("labappLifecycleDelete"), a.DELETE_CONDITION)])

    def test_existing_credentials_and_trust_fail_closed(self):
        ident = a.identity("creator")
        a.validate_sa({}, [], ident["principal"])
        for policy, keys in [({"bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:other@example.com"]}]}, []), ({}, [{"disabled": True}])]:
            with self.assertRaises(ValueError):
                a.validate_sa(policy, keys, ident["principal"])
        for field, value in [("jwksJson", "uploaded"), ("allowedAudiences", ["other"])]:
            obj = copy.deepcopy(provider("creator"))
            obj["oidc"][field] = value
            with self.assertRaises(ValueError):
                a.validate_provider(obj, ident)

    def test_unconditional_delete_and_extra_roles_rejected(self):
        for role, condition in [(a.role_name("labappLifecycleDelete"), None), ("roles/editor", None)]:
            policy = {"bindings": [{"role": role, "condition": condition,
                                    "members": ["serviceAccount:" + a.identity("cleanup")["email"]]}]}
            with self.assertRaises(ValueError):
                a.validate_project_policy(policy, a.identity("cleanup"), "cleanup")

    def test_private_bucket_has_no_slot_expiry_or_public_trust(self):
        a.validate_bucket(bucket())
        for change in [{"projectNumber": "999"}, {"lifecycle": {"rule": [{"action": {"type": "Delete"}}]}}]:
            with self.assertRaises(ValueError):
                a.validate_bucket({**bucket(), **change})
        with self.assertRaises(ValueError):
            a.validate_bucket_policy({"bindings": [{"role": "roles/storage.objectUser", "members": ["allAuthenticatedUsers"]}]})

    def test_observed_uniform_bucket_default_policy_is_accepted(self):
        a.validate_bucket_policy(default_bucket_policy())
        gc = FakeGcloud(True)
        a.setup(gc)
        self.assertEqual(sum(args[:3] == ("storage", "buckets", "add-iam-policy-binding")
                             for args in gc.writes), 2)

    def test_default_bucket_roles_reject_unexpected_members_and_conditions(self):
        for index in range(4):
            for member in ("allUsers", "allAuthenticatedUsers", "projectOwner:foreign",
                           "projectEditor:foreign", "projectViewer:foreign",
                           "user:other@example.com", f"serviceAccount:{a.identity('creator')['email']}"):
                with self.subTest(index=index, member=member):
                    policy = default_bucket_policy()
                    policy["bindings"][index]["members"].append(member)
                    with self.assertRaises(ValueError):
                        a.validate_bucket_policy(policy)
            for condition in ({"expression": "true"}, {}, None):
                with self.subTest(index=index, condition=condition):
                    policy = default_bucket_policy()
                    policy["bindings"][index]["condition"] = condition
                    with self.assertRaises(ValueError):
                        a.validate_bucket_policy(policy)
        for role, member in (("roles/storage.legacyObjectOwner", f"projectViewer:{a.PROJECT}"),
                             ("roles/storage.legacyObjectReader", f"projectOwner:{a.PROJECT}"),
                             ("roles/storage.admin", f"projectOwner:{a.PROJECT}")):
            with self.subTest(role=role, member=member), self.assertRaises(ValueError):
                a.validate_bucket_policy({"bindings": [{"role": role, "members": [member]}]})

    def test_invalid_bucket_default_blocks_all_grants_on_partial_setup(self):
        class Unexpected(FakeGcloud):
            def read(self, *args, **kwargs):
                result = super().read(*args, **kwargs)
                if args[:3] == ("storage", "buckets", "get-iam-policy"):
                    result["bindings"][2]["members"].append("projectOwner:foreign")
                return result
        gc = Unexpected(True)
        with self.assertRaises(ValueError):
            a.setup(gc)
        self.assertEqual(gc.writes, [])

    def test_project_wide_operation_census_has_only_required_read_addition(self):
        for key in ("labappLifecycleCreator", "labappLifecycleReader"):
            self.assertIn("compute.globalOperations.list", a.ROLES[key])
            self.assertNotIn("compute.regionOperations.list", a.ROLES[key])
        self.assertNotIn("compute.globalOperations.list", a.ROLES["labappLifecycleDelete"])

    def test_no_image_network_admin_actas_or_extra_deletes(self):
        permissions = {x for values in a.ROLES.values() for x in values}
        self.assertEqual({p for p in permissions if p.endswith(".delete")},
                         {"compute.instances.delete", "compute.disks.delete"})
        self.assertFalse(any(p.startswith(("compute.images.", "compute.snapshots.",
                                          "compute.addresses.", "compute.firewalls.", "iam.")) for p in permissions))
        self.assertIn(f"projects/{a.PROJECT}/zones/{a.ZONE}/instances/labapp-lc-", a.DELETE_CONDITION["expression"])


if __name__ == "__main__":
    unittest.main()

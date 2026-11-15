"""Safety mutations exercise actual catalog files without network or a cluster."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.validate_gitops import validate

ROOT = Path(__file__).resolve().parents[1]


class GitOpsSafety(unittest.TestCase):
    def setUp(self):
        cache = ROOT.parent / ".runtime"
        cache.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "source"
        shutil.copytree(
            ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__")
        )

    def change(self, path, mutate):
        file = self.root / path
        data = yaml.safe_load(file.read_text())
        mutate(data)
        file.write_text(yaml.safe_dump(data), encoding="utf-8", newline="\n")

    def reject(self):
        with self.assertRaises(ValueError):
            validate(self.root)

    def test_valid_offline_alternatives(self):
        report = validate(self.root)
        self.assertEqual(report["argo_objects"], 4)
        self.assertEqual(report["published_inputs_verified"], 0)
        self.assertFalse(report["deployable"])

    def test_branch_pin(self):
        self.change(
            "applications/collector-dev.yaml",
            lambda d: d["spec"]["sources"][0].update(targetRevision="main"),
        )
        self.reject()

    def test_fake_zero_pin(self):
        self.change(
            "releases/collector.json",
            lambda d: d["sources"]["chart"].update(commit="0" * 40),
        )
        self.reject()

    def test_automated_sync(self):
        self.change(
            "applications/collector-dev.yaml",
            lambda d: d["spec"]["syncPolicy"].update(
                automated={"prune": True, "selfHeal": True}
            ),
        )
        self.reject()

    def test_argo_namespace_destination(self):
        self.change(
            "applications/collector-dev.yaml",
            lambda d: d["spec"]["destination"].update(namespace="argocd"),
        )
        self.reject()

    def test_wildcard_source(self):
        self.change(
            "projects/collector-dev.yaml", lambda d: d["spec"].update(sourceRepos=["*"])
        )
        self.reject()

    def test_cluster_permission(self):
        self.change(
            "projects/collector-dev.yaml",
            lambda d: d["spec"].update(
                clusterResourceWhitelist=[{"group": "*", "kind": "*"}]
            ),
        )
        self.reject()

    def test_secret_permission(self):
        self.change(
            "projects/collector-dev.yaml",
            lambda d: d["spec"]["namespaceResourceWhitelist"].append(
                {"group": "", "kind": "Secret"}
            ),
        )
        self.reject()

    def test_unpinned_values_override(self):
        (self.root / "environments/dev/collector.yaml").write_text(
            "enabled: true\nprofile: qa\n", encoding="utf-8"
        )
        self.reject()

    def test_inline_values_bypass(self):
        self.change(
            "applications/collector-dev.yaml",
            lambda d: d["spec"]["sources"][0]["helm"].update(
                values="image: evil:latest"
            ),
        )
        self.reject()

    def test_delete_cascade_finalizer(self):
        self.change(
            "applications/collector-dev.yaml",
            lambda d: d["metadata"].update(
                finalizers=["resources-finalizer.argocd.argoproj.io"]
            ),
        )
        self.reject()

    def test_parallel_writers(self):
        self.change(
            "bootstrap/prepared-ownership.json",
            lambda d: d.update(active_writers=["bootstrap", "argo"]),
        )
        self.reject()

    def test_vendor_schema_tamper(self):
        (self.root / "vendor/argocd/Application.json").write_text(
            json.dumps({"type": "object"})
        )
        self.reject()

    def test_extra_manifest(self):
        (self.root / "applications/extra.yaml").write_text(
            "kind: Application\n", encoding="utf-8"
        )
        self.reject()

    def test_missing_values(self):
        (self.root / "environments/dev/collector.yaml").unlink()
        self.reject()

    def test_duplicate_yaml_key(self):
        file = self.root / "applications/collector-dev.yaml"
        file.write_text(file.read_text() + "kind: AppProject\n", encoding="utf-8")
        self.reject()


if __name__ == "__main__":
    unittest.main()

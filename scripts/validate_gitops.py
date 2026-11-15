"""Validate a PREPARED-only Collector catalog; never register, install or sync."""

import argparse
import hashlib
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml
from jsonschema import Draft4Validator

ROOT = Path(__file__).resolve().parents[1]
REPOSITORIES = {
    "config": "AI-SRE-Oberveability/ai-platform-config",
    "chart": "AI-SRE-Oberveability/ai-observability-config",
    "values": "AI-SRE-Oberveability/ai-platform-gitops",
}


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError("Duplicate YAML key")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def file(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or any(
        p in {".git", ".runtime", ".venv"} for p in Path(name).parts
    ):
        raise ValueError("Escaping/private input path")
    if not path.is_file() or Path(name).is_absolute():
        raise ValueError("Missing or absolute source path")
    return path


def load(root, name):
    docs = list(
        yaml.load_all(file(root, name).read_text(encoding="utf-8"), Loader=UniqueLoader)
    )
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise ValueError("One mapping document required")
    return docs[0]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[0-9a-f]{40}", value)
        or value == "0" * 40
    ):
        raise ValueError("Real immutable commit format required")


def validate(root=ROOT, verify_published=False):
    root = root.resolve()
    catalog = json.loads(file(root, "releases/collector.json").read_text())
    if (
        catalog["schema_version"] != 1
        or catalog["status"] != "PREPARED_OFFLINE_REVIEW"
        or catalog["deployable"] is not False
        or catalog["azure_deployment_enabled"] is not False
    ):
        raise ValueError("Only disabled PREPARED source accepted")
    sources = catalog["sources"]
    if set(sources) != set(REPOSITORIES):
        raise ValueError("Unexpected source role")
    for role, row in sources.items():
        if row["repository"] != REPOSITORIES[role]:
            raise ValueError("Unapproved source repository")
        revision(row["commit"])
    if (
        sources["config"]["path"] != "environments/platform"
        or sources["chart"]["path"] != "charts/otel-collector"
    ):
        raise ValueError("Unapproved source path")
    provenance = json.loads(file(root, "vendor/provenance.json").read_text())
    if (
        provenance["license"] != "Apache-2.0"
        or digest(file(root, provenance["license_path"]))
        != provenance["license_sha256"]
    ):
        raise ValueError("Vendor licence integrity mismatch")
    schemas = {}
    for row in provenance["artifacts"]:
        kind = row["kind"]
        filename = {"Application": "application", "AppProject": "appproject"}[kind]
        expected_url = (
            "https://raw.githubusercontent.com/argoproj/argo-cd/94037c4d4e1af4bd0651d37a179fbd9e347e668c/manifests/crds/"
            + filename
            + "-crd.yaml"
        )
        if (
            row["upstream_url"] != expected_url
            or row["version"] != "3.6.1"
            or row["path"] != "vendor/argocd/" + kind + ".json"
            or kind in schemas
        ):
            raise ValueError("Unexpected vendor provenance")
        path = file(root, row["path"])
        if digest(path) != row["sha256"]:
            raise ValueError("Vendor schema integrity mismatch")
        schema = json.loads(path.read_text())
        if '"$ref"' in path.read_text():
            raise ValueError("Schema reference retrieval forbidden")
        Draft4Validator.check_schema(schema)
        schemas[kind] = Draft4Validator(schema)
    if set(schemas) != {"Application", "AppProject"}:
        raise ValueError("Both selected Argo schemas required")
    inputs = json.loads(file(root, "locks/published-inputs.json").read_text())["inputs"]
    expected_inputs = {
        ("config", "vendor/manifest-lock.json"),
        ("chart", "charts/otel-collector/Chart.yaml"),
        ("chart", "charts/otel-collector/values.yaml"),
        ("values", "environments/dev/collector.yaml"),
        ("values", "environments/qa/collector.yaml"),
    }
    if (
        len(inputs) != len(expected_inputs)
        or {(r["role"], r["path"]) for r in inputs} != expected_inputs
    ):
        raise ValueError("Exact published input set required")
    for row in inputs:
        source = sources[row["role"]]
        if (
            row["repository"] != source["repository"]
            or row["commit"] != source["commit"]
            or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
        ):
            raise ValueError("Published input/catalog mismatch")
        if row["role"] == "values" and digest(file(root, row["path"])) != row["sha256"]:
            raise ValueError("Local values differ from immutable published revision")
    allowed_files = {".github/workflows/ci.yaml"}
    if set(catalog["profiles"]) != {"dev", "qa"}:
        raise ValueError("Only two offline alternatives accepted")
    for env, profile in catalog["profiles"].items():
        cluster = "poc-offline-" + env
        name = "collector-" + env
        paths = {
            "project": "projects/" + name + ".yaml",
            "application": "applications/" + name + ".yaml",
            "values": "environments/" + env + "/collector.yaml",
        }
        if (
            any(profile[k] != value for k, value in paths.items())
            or profile["cluster_name"] != cluster
            or profile["namespace"] != "ai-observability"
            or profile["expected_chart_objects"] != 4
        ):
            raise ValueError("Unexpected profile identity/path")
        allowed_files.update(paths.values())
        values = load(root, profile["values"])
        if values != {"enabled": True, "profile": env}:
            raise ValueError("Unreviewed environment values")
        project = load(root, profile["project"])
        app = load(root, profile["application"])
        for obj in [project, app]:
            if (
                obj["apiVersion"] != "argoproj.io/v1alpha1"
                or obj["metadata"]["name"] != name
                or obj["metadata"]["namespace"] != "argocd"
                or obj["metadata"].get("finalizers")
                or obj["metadata"].get("annotations")
                != {"ai-lab.example/execution": "offline-only"}
            ):
                raise ValueError("Unexpected object identity/finalizer")
        if project["kind"] != "AppProject" or app["kind"] != "Application":
            raise ValueError("Unexpected Argo kind")
        for obj in [project, app]:
            if list(schemas[obj["kind"]].iter_errors(obj)):
                raise ValueError("Argo schema keyword validation failed")
        spec = project["spec"]

        def repo_url(role):
            return "https://github.com/" + REPOSITORIES[role] + ".git"

        kinds = [
            {"group": "", "kind": k} for k in ["ServiceAccount", "ConfigMap", "Service"]
        ] + [{"group": "apps", "kind": "Deployment"}]
        if (
            set(spec)
            != {
                "description",
                "sourceRepos",
                "destinations",
                "clusterResourceWhitelist",
                "namespaceResourceWhitelist",
                "roles",
                "orphanedResources",
            }
            or spec["sourceRepos"] != [repo_url("chart"), repo_url("values")]
            or spec["destinations"]
            != [{"name": cluster, "namespace": "ai-observability"}]
            or spec["clusterResourceWhitelist"] != []
            or spec["namespaceResourceWhitelist"] != kinds
            or spec["roles"] != []
        ):
            raise ValueError("Project source/destination/permission escape")
        a = app["spec"]
        if (
            set(a) != {"project", "destination", "sources", "syncPolicy"}
            or a["project"] != name
            or a["destination"] != {"name": cluster, "namespace": "ai-observability"}
            or a["syncPolicy"]
            != {"syncOptions": ["CreateNamespace=false", "FailOnSharedResource=true"]}
        ):
            raise ValueError("Application target/automated sync escape")
        expected = [
            {
                "repoURL": repo_url("chart"),
                "targetRevision": sources["chart"]["commit"],
                "path": "charts/otel-collector",
                "helm": {
                    "releaseName": "otel-collector",
                    "skipCrds": True,
                    "valueFiles": ["$values/" + paths["values"]],
                },
            },
            {
                "repoURL": repo_url("values"),
                "targetRevision": sources["values"]["commit"],
                "ref": "values",
            },
        ]
        if a["sources"] != expected:
            raise ValueError("Immutable source/values contract mismatch")
    found = {
        p.relative_to(root).as_posix()
        for suffix in ["*.yaml", "*.yml"]
        for p in root.rglob(suffix)
        if ".git" not in p.relative_to(root).parts
    }
    if found != allowed_files:
        raise ValueError("Uncatalogued/missing YAML source")
    ledger = json.loads(file(root, "bootstrap/prepared-ownership.json").read_text())
    if (
        ledger["state"] != "PREPARED"
        or ledger["active_writers"] != []
        or ledger["bootstrap_execution_authorized"] is not False
        or ledger["live_adoption_receipt"] is not False
    ):
        raise ValueError("No bootstrap/adoption execution accepted")
    expected = [
        {
            "group": group,
            "kind": kind,
            "namespace": "ai-observability",
            "name": "otel-collector",
            "source_role": "chart",
            "intended_writer": "argo_after_separate_handover",
        }
        for group, kind in [
            ("", "ServiceAccount"),
            ("", "ConfigMap"),
            ("", "Service"),
            ("apps", "Deployment"),
        ]
    ]
    if ledger["objects_per_profile"] != expected:
        raise ValueError("Partial ownership ledger mismatch")
    if verify_published:

        def fetch(row):
            url = (
                "https://raw.githubusercontent.com/"
                + row["repository"]
                + "/"
                + row["commit"]
                + "/"
                + row["path"]
            )
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(1024 * 1024 + 1)
            if (
                len(data) > 1024 * 1024
                or hashlib.sha256(data).hexdigest() != row["sha256"]
            ):
                raise ValueError("Published immutable blob integrity mismatch")

        with ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(fetch, inputs))
    return {
        "status": "passed_prepared_collector_gitops_source",
        "profiles": ["dev", "qa"],
        "argo_objects": 4,
        "published_inputs_verified": len(inputs) if verify_published else 0,
        "schema_version": "Argo 3.6.1 keyword checks only",
        "ownership_state": "PREPARED_partial",
        "deployable": False,
        "azure_deployment_enabled": False,
        "cluster_operations": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-published", action="store_true")
    args = parser.parse_args()
    print(json.dumps(validate(verify_published=args.verify_published), indent=2))


if __name__ == "__main__":
    main()

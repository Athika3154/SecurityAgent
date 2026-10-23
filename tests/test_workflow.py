import re
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scan.yml"


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def steps(workflow):
    return workflow["jobs"]["scan"]["steps"]


def test_runs_on_pull_request_not_pull_request_target(workflow):
    triggers = workflow.get(True, workflow.get("on"))  # YAML parses a bare `on` as True
    assert set(triggers) == {"pull_request"}


def test_permissions_are_least_privilege(workflow):
    assert workflow["permissions"] == {
        "contents": "read", "security-events": "write", "pull-requests": "write",
    }


def test_every_action_is_pinned_to_a_full_commit_sha(steps):
    uses = [step["uses"] for step in steps if "uses" in step]
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), ref


def test_scanner_and_config_come_from_the_base_not_the_pr(workflow, steps):
    tool = next(s for s in steps if s.get("with", {}).get("path") == "tool")
    assert tool["with"]["ref"] == "${{ env.BASE_SHA }}"
    assert workflow["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    config = next(s for s in steps if "scan.yaml" in s.get("run", "") and "git" in s["run"])
    assert 'show "${BASE_SHA}:scan.yaml"' in config["run"]
    scan = next(s for s in steps if s.get("id") == "scan")
    assert '--config "$RUNNER_TEMP/scan.yaml"' in scan["run"]


def test_scan_covers_only_the_pr_commits_with_full_history(steps):
    target = next(s for s in steps if s.get("with", {}).get("path") == "target")
    assert target["with"]["fetch-depth"] == 0 and target["with"]["persist-credentials"] is False
    scan = next(s for s in steps if s.get("id") == "scan")
    assert '--commit-range "${BASE_SHA}..${HEAD_SHA}"' in scan["run"]


def test_gitleaks_is_version_pinned_and_checksum_verified(workflow, steps):
    assert re.fullmatch(r"\d+\.\d+\.\d+", workflow["env"]["GITLEAKS_VERSION"])
    assert re.fullmatch(r"[0-9a-f]{64}", workflow["env"]["GITLEAKS_SHA256"])
    install = next(s for s in steps if "Gitleaks" in s.get("name", ""))
    assert "sha256sum --check" in install["run"]


def test_comment_failure_cannot_change_the_scan_result(steps):
    comment = next(s for s in steps if s.get("name") == "Comment on the PR")
    assert comment["continue-on-error"] is True
    assert "GITHUB_TOKEN" in comment["env"]
    scan = next(s for s in steps if s.get("id") == "scan")
    assert "GITHUB_TOKEN" not in scan.get("env", {})  # scan step never sees the token


def test_sarif_upload_runs_even_when_the_gate_fails(steps):
    upload = next(s for s in steps if s.get("uses", "").startswith("github/codeql-action/upload-sarif"))
    assert upload["if"].startswith("always()")

import re
from pathlib import Path

import pytest
import yaml

GITHUB = Path(__file__).resolve().parent.parent / ".github"
PINNED = re.compile(r"[\w./-]+@[0-9a-f]{40}")


def _load(relative: str) -> dict:
    return yaml.safe_load((GITHUB / relative).read_text(encoding="utf-8"))


def _steps(document: dict) -> list[dict]:
    return document["jobs"]["scan"]["steps"] if "jobs" in document else document["runs"]["steps"]


def _step(steps: list[dict], **match) -> dict:
    for step in steps:
        if all(step.get(key) == value for key, value in match.items()):
            return step
    raise AssertionError(f"no step matching {match}")


def _named(steps: list[dict], text: str) -> dict:
    return next(step for step in steps if text in step.get("name", ""))


def _triggers(document: dict) -> set[str]:
    return set(document.get(True, document.get("on")))  # YAML parses a bare `on` as True


@pytest.fixture(scope="module")
def pr():
    return _load("workflows/scan.yml")


@pytest.fixture(scope="module")
def nightly():
    return _load("workflows/nightly.yml")


@pytest.fixture(scope="module")
def action():
    return _load("actions/install-scanners/action.yml")


@pytest.mark.parametrize("name", ["workflows/scan.yml", "workflows/nightly.yml",
                                  "actions/install-scanners/action.yml"])
def test_third_party_actions_are_pinned_to_a_full_commit_sha(name):
    uses = [step["uses"] for step in _steps(_load(name)) if "uses" in step]
    assert uses
    for ref in uses:
        assert ref.startswith("./") or PINNED.fullmatch(ref), ref


# ---- pull request workflow -------------------------------------------------

def test_pr_workflow_uses_pull_request_not_pull_request_target(pr):
    assert _triggers(pr) == {"pull_request"}


def test_pr_workflow_permissions_are_least_privilege(pr):
    assert pr["permissions"] == {
        "contents": "read", "security-events": "write", "pull-requests": "write",
    }


def test_scanner_config_and_baseline_come_from_the_base_not_the_pr(pr):
    steps = _steps(pr)
    tool = next(s for s in steps if s.get("with", {}).get("path") == "tool")
    assert tool["with"]["ref"] == "${{ env.BASE_SHA }}"
    assert pr["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    read = _named(steps, "Read scan.yaml and baseline")["run"]
    assert 'show "${BASE_SHA}:scan.yaml"' in read
    assert 'show "${BASE_SHA}:.scan-baseline.json"' in read
    install = _named(steps, "Install scanners")
    assert install["uses"].startswith("./tool/")  # the action also comes from the base checkout
    scan = _step(steps, id="scan")["run"]
    assert '--config "$RUNNER_TEMP/scan.yaml"' in scan
    assert '--baseline "$RUNNER_TEMP/baseline.json"' in scan


def test_scan_covers_only_the_pr_commits_with_full_history(pr):
    steps = _steps(pr)
    target = next(s for s in steps if s.get("with", {}).get("path") == "target")
    assert target["with"]["fetch-depth"] == 0 and target["with"]["persist-credentials"] is False
    assert '--commit-range "${BASE_SHA}..${HEAD_SHA}"' in _step(steps, id="scan")["run"]


def test_comment_failure_cannot_change_the_scan_result(pr):
    steps = _steps(pr)
    comment = _step(steps, name="Comment on the PR")
    assert comment["continue-on-error"] is True and "GITHUB_TOKEN" in comment["env"]
    assert "GITHUB_TOKEN" not in _step(steps, id="scan").get("env", {})  # scan never sees it


def test_sarif_upload_runs_even_when_the_gate_fails(pr):
    upload = next(s for s in _steps(pr)
                  if s.get("uses", "").startswith("github/codeql-action/upload-sarif"))
    assert upload["if"].startswith("always()")


# ---- shared install action -------------------------------------------------

def test_install_action_pins_every_tool(action):
    steps = _steps(action)
    for name, tool in (("Gitleaks", "GITLEAKS"), ("Trivy", "TRIVY")):
        step = _named(steps, name)
        assert re.fullmatch(r"\d+\.\d+\.\d+", step["env"][f"{tool}_VERSION"])
        assert re.fullmatch(r"[0-9a-f]{64}", step["env"][f"{tool}_SHA256"])
        assert "sha256sum --check" in step["run"]
    semgrep = _named(steps, "Semgrep")
    assert re.fullmatch(r"\d+\.\d+\.\d+", semgrep["env"]["SEMGREP_VERSION"])
    assert "semgrep==${SEMGREP_VERSION}" in semgrep["run"]
    assert "PyYAML==" in semgrep["run"] and "Jinja2==" in semgrep["run"]


def test_install_action_steps_declare_a_shell(action):
    assert all("shell" in s for s in _steps(action) if "run" in s)


# ---- nightly workflow ------------------------------------------------------

def test_nightly_is_scheduled_and_manually_runnable(nightly):
    assert _triggers(nightly) == {"schedule", "workflow_dispatch"}
    cron = nightly.get(True, nightly.get("on"))["schedule"][0]["cron"]
    assert len(cron.split()) == 5


def test_nightly_permissions_are_least_privilege(nightly):
    assert nightly["permissions"] == {"contents": "read", "security-events": "write"}


def test_nightly_scans_the_full_history_with_the_baseline(nightly):
    steps = _steps(nightly)
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0
    assert _named(steps, "Install scanners")["uses"] == "./.github/actions/install-scanners"
    scan = _step(steps, id="scan")["run"]
    assert "--config scan.yaml" in scan and "--baseline .scan-baseline.json" in scan
    assert "--commit-range" not in scan  # whole history, not a range


def test_nightly_sarif_upload_runs_even_when_the_gate_fails(nightly):
    upload = next(s for s in _steps(nightly)
                  if s.get("uses", "").startswith("github/codeql-action/upload-sarif"))
    assert upload["if"].startswith("always()")

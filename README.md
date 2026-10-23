# Secret and vulnerability scanner

A thin Python layer over three free, open-source scanners. Give it a repo (local path or
GitHub URL) and it reports leaked secrets, vulnerable dependencies, Dockerfile/IaC mistakes and
code flaws, then passes or fails the build by rule.

| Scanner | Finds | Reads |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secrets | every commit in Git history |
| [Trivy](https://github.com/aquasecurity/trivy) | vulnerable packages, IaC misconfiguration, secrets | working tree |
| [Semgrep Community](https://github.com/semgrep/semgrep) | code flaws | working tree |

Results are normalized, secrets are never written anywhere, duplicates across tools are merged,
and the run ends with an exit code. For a plain-English walkthrough see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

## Pinned versions

| Component | Version | Where it is pinned |
|---|---|---|
| Gitleaks | 8.30.1 (SHA-256 verified) | `.github/actions/install-scanners/action.yml` |
| Trivy | 0.76.1 (SHA-256 verified) | same |
| Semgrep | 1.182.1 | same |
| PyYAML / Jinja2 | 6.0.2 / 3.1.6 | same |
| GitHub Actions | full commit SHAs | each workflow |

Python 3.10 or newer is required.

## Quick start

```bash
pip install -e ".[dev]"          # PyYAML, Jinja2, pytest
```

Install the scanners (Windows shown; on Linux/macOS use your package manager or the release tarballs):

```powershell
winget install Gitleaks.Gitleaks
winget install AquaSecurity.Trivy
python -m pip install semgrep
```

If a binary is not on `PATH`, point to it with `SCAN_GITLEAKS_BIN`, `SCAN_TRIVY_BIN` or
`SCAN_SEMGREP_BIN`.

### Web UI (paste a link, get a report)

```bash
python -m scanner.web            # then open http://127.0.0.1:8000
```

It listens on localhost only and rejects requests from other sites.

### Command line

```bash
python -m scanner.cli https://github.com/OWNER/REPO \
    --output report.json --sarif report.sarif --html report.html
python -m scanner.cli path/to/local/repo          # local repos must contain .git
```

| Option | Meaning |
|---|---|
| `--config PATH` | policy file (default `./scan.yaml` if present) |
| `--runners a,b` | run only these scanners (`gitleaks`, `trivy`, `semgrep`) |
| `--commit-range BASE..HEAD` | PR mode: scan only these commits (full 40-char or short SHAs) |
| `--baseline PATH` | ignore findings already recorded in this baseline |
| `--write-baseline PATH` | record all current findings as the baseline, exit 0 |
| `--output / --sarif / --html` | report files (JSON is always written) |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | clean: nothing at or above `fail_on` |
| `2` | findings at or above `fail_on` |
| `1` | tool or scanner error, bad config, bad input. A missing or crashed scanner is **never** a pass |

## Configuration: `scan.yaml`

```yaml
fail_on: high            # low | medium | high | critical
timeout: 600             # seconds, applied to every subprocess
allowed_hosts: [github.com]   # hosts a repo URL may be cloned from
allowlist:               # findings matching ANY entry are hidden
  fingerprints: []       # exact findings, from a report
  rules: []              # e.g. "generic-api-key", "CVE-2018-1000656"
  paths: []              # glob patterns, e.g. "tests/fixtures/*"
```

Unknown keys are rejected, so typos cannot silently disable a rule.

## Reports

- **JSON**: findings plus a summary (counts by severity, suppressed, baselined).
- **SARIF 2.1.0**: for GitHub code scanning.
- **HTML**: self-contained, no scripts, all repo-derived text escaped.

Every finding has: `file`, `line`, `rule`, `category` (secret, vulnerability, misconfiguration,
code), `title`, `severity`, `tool`, `commit` (short), `fingerprint`, `remediation`. For secrets the
remediation says to **rotate** the credential, because deleting it does not remove it from history.

## Baseline: fail only on new findings

Adopt the scanner on a repo that already has issues without failing every build:

```bash
python -m scanner.cli . --write-baseline .scan-baseline.json   # record today's findings
git add .scan-baseline.json && git commit -m "Add scan baseline"
```

From then on, pass `--baseline .scan-baseline.json`; only findings not in the file count. The
baseline holds fingerprints only, never secret values. Notes:

- Fingerprints are salted. **Changing `SCAN_FP_SALT` invalidates the baseline**; write a new one.
- A finding whose line moves (code added above it) gets a new fingerprint and shows up as new.
- Re-run `--write-baseline` after you fix things to shrink the file.
- An invalid or missing baseline file is an error (exit 1), never a silent pass.

## GitHub setup

1. Push this repo to GitHub. Code scanning (SARIF upload) is free on public repos and needs
   GitHub Advanced Security on private ones.
2. Optional: add a repo secret `SCAN_FP_SALT` (any long random string) for private fingerprints.
3. Workflows (already included):
   - **`.github/workflows/scan.yml`**, on every pull request: scans only the PR's commits
     (`base..head`), uploads SARIF, posts or updates one summary comment, keeps the HTML report
     as an artifact, and fails the check by `fail_on`.
   - **`.github/workflows/nightly.yml`**, daily at 02:17 UTC and on demand: scans the full history
     (using `.scan-baseline.json` if present) and fails on new findings. A failed scheduled run
     can notify you through GitHub's workflow notification settings.

To scan other repos, copy the workflow and point the "Check out scanner" step at this repo
(`repository:`), pinned to a commit SHA.

Fork PRs get a read-only token, so for them the SARIF upload and comment steps are skipped; the
scan and the gate still run.

## Security model

- **No secret values anywhere.** Gitleaks runs with `--redact`; the normalizer copies only
  whitelisted fields (never `Secret`, `Match`, `Line`, `Code`, Semgrep `lines`/`message`); scanner
  stderr is discarded, never logged; only exit codes and safe messages are printed.
- **Raw reports are temporary** and deleted in a `finally` step; cloned repos too.
- **Fingerprints** are salted HMACs of the finding's location, so they are stable across runs
  and cannot be reversed to a secret.
- **The scanned repo cannot weaken the scan.** Its `.gitleaks.toml`, `.gitleaksignore`,
  `.semgrepignore`, `.gitignore`, `# nosem` comments and `trivy.yaml` / `.trivyignore` are ignored.
  In CI, `scan.yaml`, the baseline and the scanner code itself come from the **base branch**.
- **Inputs are validated**: https-only URLs on allowed hosts with no credentials, commit ranges
  must be `<sha>..<sha>`, config and baseline files are strictly checked.
- **Every subprocess and network call has a timeout.** The GitHub API client never follows
  redirects (so the token cannot be forwarded) and only updates comments written by the Actions bot.
- **Workflows** use `pull_request` (not `pull_request_target`), least-privilege permissions, and
  pinned, checksum-verified tools.

## Known limitations

- Trivy and Semgrep see the working tree only. In PR mode they report files the PR changed;
  only Gitleaks reads commit by commit.
- Trivy downloads its vulnerability database and Semgrep its rules (`p/default`) from their
  registries on each run, so a network is required. No code or secrets are uploaded and Semgrep
  metrics are off.
- Trivy honours inline `# trivy:ignore` comments in IaC files; Semgrep's `# nosem` is disabled.
- A multi-line private key can be reported at lines one apart by different tools and then appears twice.
- Semgrep pins only its own version; its dependencies float. Use a lockfile if you need more.
- The web UI scans one repo at a time and has no baseline option.

## Development

```bash
python -m pytest -q       # 200+ tests; Gitleaks-backed tests need the gitleaks binary
```

To add a scanner, add one module in `scanner/runners/` that defines a class with `name`,
`history` and `run(repo, timeout, commit_range)` returning findings built with `make_finding`,
and a module-level `RUNNER`. It is discovered automatically.

```
scanner/
  cli.py  web.py  sources.py  config.py  normalizer.py  report.py
  gate.py  baseline.py  pr_comment.py
  runners/  gitleaks.py  trivy.py  semgrep.py
tests/  scan.yaml  .github/
```

# How the scanner works (Level 1 overview)

This explains what happens behind the scenes, step by step, from "paste a link" to "see a report".
No code knowledge needed. Real numbers come from scanning `GanitSecurityAgent`.

---

## The big picture

```
 You paste a repo link
        |
        v
 1. CHECK the link is safe  --->  2. DOWNLOAD the repo (all its history)
                                         |
                    +--------------------+--------------------+
                    v                    v                    v
              3a. GITLEAKS         3b. TRIVY            3c. SEMGREP
              hunts secrets        checks packages,     reads the code
              in every commit      Docker, secrets      for dangerous
              ever made                                 patterns
                    |                    |                    |
                    +--------------------+--------------------+
                                         v
                    4. CLEAN UP each tool's answer (drop secrets, same format)
                                         v
                    5. MERGE duplicates (same issue found by 2-3 tools = 1 row)
                                         v
                    6. APPLY your allowlist (hide things you chose to ignore)
                                         v
                    7. DECIDE pass / fail  (exit code 0, 1 or 2)
                                         v
                    8. WRITE reports  (screen, JSON, SARIF, HTML)
                                         v
                    9. DELETE the downloaded copy and temp files
```

Three separate tools do the finding. Our Python code is the "glue" around them.
It does not find anything itself; it runs the tools, tidies their results, and makes the decisions.

---

## Step by step

### 1. Check the link
The scanner only accepts links that start with `https://`, point at an allowed website
(`github.com` by default, set in `scan.yaml`), and contain no username or password.
This stops someone from tricking the scanner into fetching something dangerous.
*Code: `scanner/sources.py`*

### 2. Download the repo
It makes a full copy with `git clone`, **including the whole history** (every old commit),
into a temporary folder. History matters because a secret deleted last month is still readable
in the old commits. When the scan ends, that folder is deleted, even if something failed.

### 3. Run the three scanners
Each one looks for something different. All three are free, open-source tools.

| Tool | Looks at | Finds | Example from the test repo |
|---|---|---|---|
| **Gitleaks** | every commit in history | passwords and API keys | the `.env` keys, even though that file was deleted once |
| **Trivy** | the current files | vulnerable packages, Docker mistakes, secrets | `flask 0.12.2` has 17 known bugs; Dockerfile runs as root |
| **Semgrep** | the current code | risky code patterns | `eval()` and SQL built from text in `tools.py` |

Safety rules for how we run them:
- Their raw output goes to a temp file, never to the screen, because tool output can
  accidentally contain the secret itself.
- Every run has a time limit, so a stuck tool cannot hang the scan.
- The scanned repo cannot weaken the scan. Its own ignore files and "skip this" comments are switched off.
- If a tool is missing, crashes, or returns garbage, the whole scan **fails** (exit code 1).
  It never quietly reports "all clear".

*Code: `scanner/runners/gitleaks.py`, `trivy.py`, `semgrep.py`*

### 4. Clean up each tool's answer
Each tool speaks its own format. The cleaner (the "normalizer") converts everything into one
shape with these fields: file, line, rule, category, title, severity, tool, commit, fingerprint, remediation.

The important part: it copies **only a short approved list of fields** from the tool's answer.
The fields that contain the actual secret (`Secret`, `Match`, `Line`, `Code`) are never copied.
That is why no key ever appears in a report.

Each finding also gets:
- **A category**: `secret`, `vulnerability`, `misconfiguration` or `code`.
- **A fingerprint**: a scrambled ID, built from the finding's location mixed with a private "salt".
  It stays the same on every run, but you cannot work backwards from it to the secret.
- **A fix suggestion.** For secrets it says *rotate the key*, not just "delete the line", because
  once a key has been in Git it must be treated as stolen.

*Code: `scanner/normalizer.py`*

### 5. Merge duplicates
The same leaked key is often found by two or three tools. Showing it three times would be noise,
so findings on the same file and line are merged into one row that lists every tool that saw it
(for example `gitleaks, semgrep, trivy`), keeping the highest severity.
For the test repo this turned a raw pile of results into **47 findings**.

Merge rules, kept deliberately simple:
- Only secrets are merged across tools (they are named differently by each tool).
- One secret that appears in several commits keeps one row per commit, because that shows its history.
- Two findings from the *same* tool are never merged.

### 6. Apply your allowlist and baseline
`scan.yaml` can list things to ignore (by fingerprint, by rule name, or by file path pattern).
If you pass a baseline file, findings already recorded in it are ignored too, so only new problems
count. The report says how many were hidden each way.

*Code: `scanner/gate.py`, `scanner/config.py`*

### 7. Ignore known findings, then decide pass or fail
The scanner ends with an exit code, which is what a build pipeline reads:

| Code | Meaning |
|---|---|
| `0` | Clean. Nothing at or above your `fail_on` level (default `high`). |
| `2` | Findings at or above `fail_on`. The build should fail. |
| `1` | Something broke (tool missing, crashed, bad config). Never treated as a pass. |

Severity runs low, medium, high, critical.

### 8. Write the reports
- **On screen / web page**: the table you see after clicking Scan.
- **HTML file**: the same table, saved. Anything taken from the scanned repo is escaped so a
  malicious file name cannot run code in your browser.
- **JSON file**: for programs to read.
- **SARIF file**: the standard format GitHub understands, so findings show in its Security tab.

*Code: `scanner/report.py`*

### 9. Clean up
Temp reports and the downloaded repo copy are removed in a `finally` step,
which runs whether the scan succeeded or failed.

---

## The two ways to use it

**The website** (`python -m scanner.web`, then open http://127.0.0.1:8000)
You paste a link and click Scan. It runs steps 1 to 8 and shows the result on the page.
It only listens on your own computer, and it rejects requests from other websites,
so a random web page cannot make it scan things.
*Code: `scanner/web.py`*

**The GitHub Action** (`.github/workflows/scan.yml`)
Runs automatically on every pull request in the repo that holds this workflow. It differs in
three ways:
1. It scans only the commits in that pull request, not the whole history.
2. It reads the rules (`scan.yaml`) and the scanner code from the **base branch**, so a pull
   request cannot weaken its own checks.
3. It uploads results to GitHub's Security tab and posts one summary comment on the pull request.

*Code: `scanner/pr_comment.py`, `scanner/cli.py` (`--commit-range`)*

---

## Where each piece lives

| File | Job |
|---|---|
| `scanner/cli.py` | Command-line entry point; runs the whole pipeline |
| `scanner/web.py` | The website |
| `scanner/sources.py` | Checks the link and downloads the repo |
| `scanner/runners/` | One file per scanner (Gitleaks, Trivy, Semgrep) |
| `scanner/normalizer.py` | Common format, fingerprints, merging |
| `scanner/config.py` | Reads and validates `scan.yaml` |
| `scanner/gate.py` | Allowlist and pass/fail decision |
| `scanner/baseline.py` | Known-findings baseline (fingerprints only) |
| `scanner/report.py` | JSON, SARIF and HTML output |
| `scanner/pr_comment.py` | Pull request comment |
| `scan.yaml` | Your settings: `fail_on`, allowlist, allowed hosts, timeout |
| `tests/` | 206 automated tests |

Adding a new scanner later means adding one new file in `scanner/runners/`. Nothing else changes.

---

## Good to know

- **Rules and databases come from the internet.** Trivy downloads its vulnerability database and
  Semgrep downloads its rule set from its registry (`p/default`) on each run. Your code and secrets
  are not uploaded, and Semgrep's usage reporting is turned off.
- **Pull request scans of Trivy and Semgrep** look at the final state of the files the pull request
  changed. Only Gitleaks reads commit by commit.
- **A private key can appear twice** if two tools disagree by one line about where it starts.
- **Baseline:** you can record today's findings (`--write-baseline`) and then scan with
  `--baseline`, so only *new* findings fail the build. The baseline file stores fingerprints only.
  In GitHub, it is read from the base branch so a pull request cannot add its own findings to it.
- **Nightly scan:** `.github/workflows/nightly.yml` rescans the full history every night and fails the
  run if anything new appears.
- **More detail:** see `README.md` for setup, settings and the security model.

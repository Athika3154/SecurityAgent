"""Report generation: JSON, SARIF 2.1.0 and HTML."""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment

from scanner.normalizer import SEVERITIES, Finding
from scanner.runners import ScannerError

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "secret-scanner"
_SARIF_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
# GitHub code scanning ranks alerts by this CVSS-style score.
_SECURITY_SEVERITY = {"low": "3.0", "medium": "5.5", "high": "8.0", "critical": "9.5"}

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1f2328}
h1{font-size:1.5rem;margin-bottom:.25rem}.meta{color:#59636e;margin-bottom:1.5rem;word-break:break-all}
.cards{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.5rem}
.card{border:1px solid #d1d9e0;border-radius:6px;padding:.6rem 1rem;min-width:90px}
.card b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.5rem;border-bottom:1px solid #d1d9e0;vertical-align:top}
code{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.sev{border-radius:1rem;padding:.1rem .6rem;font-size:12px;font-weight:600;color:#fff}
.sev-critical{background:#82071e}.sev-high{background:#cf222e}.sev-medium{background:#9a6700}.sev-low{background:#57606a}
.empty{padding:1rem;border:1px solid #d1d9e0;border-radius:6px}
form{display:flex;gap:.5rem;margin:1rem 0 1.5rem}input{flex:1;padding:.5rem;font:inherit;border:1px solid #d1d9e0;border-radius:6px}
button{padding:.5rem 1.2rem;font:inherit;font-weight:600;border:0;border-radius:6px;background:#1f6feb;color:#fff;cursor:pointer}
.error{padding:1rem;border:1px solid #cf222e;border-radius:6px;color:#82071e;margin-bottom:1.5rem}
.hint{color:#59636e;margin:-.75rem 0 1.5rem}
</style>
</head>
<body>
<h1>Scan report</h1>
{% if show_form %}
<form method="post" action="/scan">
<input type="url" name="url" required maxlength="300" placeholder="https://github.com/owner/repo" value="{{ url }}">
<button type="submit">Scan</button>
</form>
<div class="hint">Scans the full Git history. This can take up to a minute for large repos.</div>
{% endif %}
{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if report %}
<div class="meta">Source: {{ report.source }} &middot; Generated {{ report.generated_at }}</div>
<div class="cards">
<div class="card"><b>{{ report.summary.total }}</b>findings</div>
{% for level, count in report.summary.by_severity.items() %}
<div class="card"><b>{{ count }}</b>{{ level }}</div>
{% endfor %}
<div class="card"><b>{{ report.summary.suppressed }}</b>suppressed</div>
<div class="card"><b>{{ report.summary.baselined }}</b>in baseline</div>
</div>
{% if report.findings %}
<table>
<thead><tr><th>Severity</th><th>Category</th><th>Location</th><th>Issue</th><th>Tool</th><th>Commit</th><th>Fingerprint</th><th>What to do</th></tr></thead>
<tbody>
{% for f in report.findings %}
<tr>
<td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
<td>{{ f.category }}</td>
<td><code>{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}</code></td>
<td>{{ f.title }}<br><code>{{ f.rule }}</code></td>
<td>{{ f.tool }}</td>
<td><code>{{ f.commit }}</code></td>
<td><code>{{ f.fingerprint }}</code></td>
<td>{{ f.remediation }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<div class="empty">No findings.</div>
{% endif %}
{% endif %}
</body>
</html>
"""
# autoescape=True: file names and rule ids come from the scanned repo and are untrusted.
_HTML = Environment(autoescape=True).from_string(_HTML_TEMPLATE)


def build_report(
    source: str, findings: list[Finding], suppressed: int, baselined: int = 0
) -> dict[str, object]:
    counts = Counter(finding.severity for finding in findings)
    return {
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "total": len(findings),
            "suppressed": suppressed,
            "baselined": baselined,
            "by_severity": {level: counts.get(level, 0) for level in SEVERITIES},
        },
        "findings": [finding.to_dict() for finding in findings],
    }


def build_sarif(findings: list[Finding]) -> dict[str, object]:
    """SARIF 2.1.0 log with one run. Fingerprints are the salted ones, never secret values."""
    rule_ids: list[str] = []
    rules: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    for finding in findings:
        rule_id = f"{finding.category}/{finding.rule}"
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                "properties": {"security-severity": _SECURITY_SEVERITY[finding.severity]},
            })
        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_ids.index(rule_id),
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.title} (commit {finding.commit}). "
                                f"{finding.remediation}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": {"startLine": max(finding.line, 1)},
            }}],
            "partialFingerprints": {"scannerFingerprint/v1": finding.fingerprint},
            "properties": {"tool": finding.tool, "commit": finding.commit,
                           "severity": finding.severity, "category": finding.category},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": TOOL_NAME, "rules": rules}}, "results": results}],
    }


def render_html(
    report: dict[str, object] | None,
    *,
    show_form: bool = False,
    error: str | None = None,
    url: str = "",
) -> str:
    return _HTML.render(report=report, show_form=show_form, error=error, url=url)


def _write(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError:
        raise ScannerError(f"could not write report to {path}") from None


def write_json(data: dict[str, object], path: Path) -> None:
    _write(path, json.dumps(data, indent=2))


def write_html(report: dict[str, object], path: Path) -> None:
    _write(path, render_html(report))

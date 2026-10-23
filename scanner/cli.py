"""Command line entry point: scan a repo, write a report, return the gate's exit code."""
import argparse
import sys
from pathlib import Path
from typing import NoReturn

from scanner.config import Config, ConfigError, load_config
from scanner.gate import EXIT_ERROR, apply_allowlist, exit_code
from scanner.normalizer import Finding
from scanner.report import build_report, build_sarif, write_html, write_json
from scanner.runners import ScannerError, load_runners
from scanner.sources import open_source, validate_commit_range


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        """Usage errors exit 1: argparse's default 2 would read as 'findings' to a CI gate."""
        self.print_usage(sys.stderr)
        print(f"error: {message}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = _Parser(prog="scanner", description="Scan a Git repo for secrets.")
    parser.add_argument("source", help="local Git repo path or https repo URL")
    parser.add_argument("--config", type=Path, help="path to scan.yaml (default: ./scan.yaml)")
    parser.add_argument(
        "--output", type=Path, default=Path("scan-report.json"), help="JSON report path"
    )
    parser.add_argument(
        "--commit-range", help="scan only these commits, as <base-sha>..<head-sha> (PR mode)"
    )
    parser.add_argument("--sarif", type=Path, help="also write a SARIF 2.1.0 report here")
    parser.add_argument("--html", type=Path, help="also write an HTML report here")
    return parser.parse_args(argv)


def run_scan(
    source: str, config: Config, commit_range: str | None = None
) -> tuple[list[Finding], int]:
    """Scan the source with every runner; return (findings after allowlist, suppressed count)."""
    if commit_range is not None:
        validate_commit_range(commit_range)
    findings: list[Finding] = []
    with open_source(source, config) as repo:
        for runner in load_runners():
            findings.extend(runner.run(repo, config.timeout, commit_range))
    return apply_allowlist(findings, config.allowlist)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        config = load_config(args.config)
        kept, suppressed = run_scan(args.source, config, args.commit_range)
        report = build_report(args.source, kept, suppressed)
        write_json(report, args.output)
        if args.sarif:
            write_json(build_sarif(kept), args.sarif)
        if args.html:
            write_html(report, args.html)
    except (ConfigError, ScannerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    for finding in kept:
        print(
            f"[{finding.severity}] {finding.secret_type} "
            f"{finding.file}:{finding.line} (commit {finding.commit}, {finding.tool})"
        )
    code = exit_code(kept, config.fail_on)
    print(
        f"{len(kept)} finding(s), {suppressed} suppressed, fail_on={config.fail_on}, "
        f"exit {code}; report: {args.output}"
    )
    return code


if __name__ == "__main__":
    sys.exit(main())

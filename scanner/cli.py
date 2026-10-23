"""Command line entry point: scan a repo, write a report, return the gate's exit code."""
import argparse
import sys
from pathlib import Path
from typing import NoReturn

from scanner.baseline import apply_baseline, load_baseline, write_baseline
from scanner.config import Config, ConfigError, load_config
from scanner.gate import EXIT_CLEAN, EXIT_ERROR, apply_allowlist, exit_code
from scanner.normalizer import Finding, merge_findings
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
    parser.add_argument(
        "--runners", help="comma-separated scanners to run (default: all), e.g. gitleaks,trivy"
    )
    parser.add_argument(
        "--baseline", type=Path, help="ignore findings whose fingerprints are in this file"
    )
    parser.add_argument(
        "--write-baseline", type=Path,
        help="write all current findings to this baseline file and exit 0 (skips the gate)",
    )
    parser.add_argument("--sarif", type=Path, help="also write a SARIF 2.1.0 report here")
    parser.add_argument("--html", type=Path, help="also write an HTML report here")
    args = parser.parse_args(argv)
    if args.baseline and args.write_baseline:
        parser.error("--baseline and --write-baseline cannot be used together")
    return args


def run_scan(
    source: str,
    config: Config,
    commit_range: str | None = None,
    runner_names: list[str] | None = None,
) -> tuple[list[Finding], int]:
    """Scan with the chosen runners (default all); return (merged findings after allowlist,
    suppressed count). A runner that is missing or fails raises ScannerError."""
    if commit_range is not None:
        validate_commit_range(commit_range)
    history: list[Finding] = []
    current: list[Finding] = []
    runners = load_runners(runner_names)
    if not runners:
        raise ScannerError("no scanners selected")
    with open_source(source, config) as repo:
        for runner in runners:
            target = history if runner.history else current
            target.extend(runner.run(repo, config.timeout, commit_range))
    return apply_allowlist(merge_findings(history, current), config.allowlist)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        config = load_config(args.config)
        known = load_baseline(args.baseline) if args.baseline else frozenset()
        names = [n.strip() for n in args.runners.split(",")] if args.runners else None
        kept, suppressed = run_scan(args.source, config, args.commit_range, names)
        if args.write_baseline:
            write_baseline(kept, args.write_baseline)
            print(f"baseline written: {len(kept)} finding(s) -> {args.write_baseline}")
            return EXIT_CLEAN
        kept, baselined = apply_baseline(kept, known)
        report = build_report(args.source, kept, suppressed, baselined)
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
            f"[{finding.severity}] {finding.category}: {finding.rule} "
            f"{finding.location} (commit {finding.commit}, {finding.tool})"
        )
    code = exit_code(kept, config.fail_on)
    print(
        f"{len(kept)} finding(s), {suppressed} suppressed, {baselined} in baseline, "
        f"fail_on={config.fail_on}, exit {code}; report: {args.output}"
    )
    return code


if __name__ == "__main__":
    sys.exit(main())

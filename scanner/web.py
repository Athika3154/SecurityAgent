"""Local web UI: paste a GitHub repo URL, get the HTML report. Listens on localhost only."""
import argparse
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from scanner.cli import run_scan
from scanner.config import Config, ConfigError, load_config
from scanner.gate import EXIT_ERROR
from scanner.report import build_report, render_html
from scanner.runners import ScannerError

BIND_HOST = "127.0.0.1"
MAX_BODY_BYTES = 4096
MAX_DRAIN_BYTES = 1024 * 1024
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class ScanServer(HTTPServer):
    # On Windows SO_REUSEADDR lets a second process bind a port that is already in use.
    allow_reuse_address = sys.platform != "win32"

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        super().__init__(address, Handler)
        self.config = config


class Handler(BaseHTTPRequestHandler):
    server: ScanServer

    def _trusted_hosts(self) -> set[str]:
        port = self.server.server_port
        return {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _is_trusted_request(self) -> bool:
        """Reject DNS-rebinding (bad Host) and cross-site form posts (bad Origin)."""
        if self.headers.get("Host") not in self._trusted_hosts():
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {f"http://{host}" for host in self._trusted_hosts()}

    def _send_html(self, status: HTTPStatus, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: HTTPStatus) -> None:
        self._send_html(status, f"<!doctype html><title>{status.value}</title>{status.phrase}")

    def _read_body(self) -> bytes | None:
        """Read the body (bounded) so early error replies do not reset the connection."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if not 0 <= length <= MAX_DRAIN_BYTES:
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:
        if not self._is_trusted_request():
            self._send_text(HTTPStatus.FORBIDDEN)
        elif self.path != "/":
            self._send_text(HTTPStatus.NOT_FOUND)
        else:
            self._send_html(HTTPStatus.OK, render_html(None, show_form=True))

    def do_POST(self) -> None:
        body = self._read_body()
        if not self._is_trusted_request():
            self._send_text(HTTPStatus.FORBIDDEN)
            return
        if self.path != "/scan":
            self._send_text(HTTPStatus.NOT_FOUND)
            return
        if body is None or not 0 < len(body) <= MAX_BODY_BYTES:
            self._send_text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        fields = parse_qs(body.decode("utf-8", errors="replace"))
        url = fields.get("url", [""])[0].strip()
        try:
            if not url:
                raise ScannerError("Enter a repository URL.")
            findings, suppressed = run_scan(url, self.server.config)
        except ScannerError as error:
            html = render_html(None, show_form=True, error=str(error), url=url)
            self._send_html(HTTPStatus.BAD_REQUEST, html)
            return
        report = build_report(url, findings, suppressed)
        self._send_html(HTTPStatus.OK, render_html(report, show_form=True, url=url))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner-web", description="Local scanner web UI.")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on")
    parser.add_argument("--config", type=Path, help="path to scan.yaml (default: ./scan.yaml)")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        server = ScanServer((BIND_HOST, args.port), config)
    except (ConfigError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    with server:
        print(f"Open http://{BIND_HOST}:{server.server_port} (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

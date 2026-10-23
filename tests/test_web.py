import http.client
import threading

import pytest

from scanner.config import Config
from scanner.normalizer import make_finding
from scanner.runners import ScannerError
from scanner.web import MAX_BODY_BYTES, ScanServer, main


@pytest.fixture
def server():
    srv = ScanServer(("127.0.0.1", 0), Config())
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def _request(server, method, path, body=None, headers=None):
    port = server.server_port
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        merged = {"Host": f"127.0.0.1:{port}", **(headers or {})}
        if body is not None:
            merged.setdefault("Content-Type", "application/x-www-form-urlencoded")
        conn.request(method, path, body=body, headers=merged)
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8"), dict(response.getheaders())
    finally:
        conn.close()


def test_home_page_has_the_form_and_security_headers(server):
    status, html, headers = _request(server, "GET", "/")
    assert status == 200 and 'name="url"' in html and 'action="/scan"' in html
    assert headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"


def test_unknown_path_is_404(server):
    assert _request(server, "GET", "/etc/passwd")[0] == 404
    assert _request(server, "POST", "/other", body="url=x")[0] == 404


def test_foreign_host_header_is_rejected(server):
    assert _request(server, "GET", "/", headers={"Host": "evil.example.com"})[0] == 403


def test_cross_site_post_is_rejected(server, monkeypatch):
    monkeypatch.setattr("scanner.web.run_scan", lambda *a: pytest.fail("scanned"))
    status, _, _ = _request(server, "POST", "/scan", body="url=https://github.com/o/r",
                            headers={"Origin": "https://evil.example.com"})
    assert status == 403


def test_scan_shows_the_report(server, monkeypatch):
    finding = make_finding(tool="gitleaks", rule="private-key", file="deploy_key.pem", line=1,
                           severity="critical", commit="abcdef123456")
    seen = []
    monkeypatch.setattr("scanner.web.run_scan", lambda url, cfg: (seen.append(url) or ([finding], 1)))
    status, html, _ = _request(server, "POST", "/scan",
                               body="url=https%3A%2F%2Fgithub.com%2Fo%2Fr")
    assert status == 200 and seen == ["https://github.com/o/r"]
    assert "deploy_key.pem:1" in html and "private-key" in html and "suppressed" in html


def test_scanner_error_is_shown_safely_and_input_is_escaped(server, monkeypatch):
    def fail(url, cfg):
        raise ScannerError("could not clone the repository (check the URL and your access)")

    monkeypatch.setattr("scanner.web.run_scan", fail)
    status, html, _ = _request(server, "POST", "/scan",
                               body="url=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert status == 400 and "could not clone" in html
    assert "<script>alert(1)" not in html


def test_invalid_url_is_rejected_without_cloning(server, monkeypatch):
    monkeypatch.setattr("scanner.sources.run_quiet", lambda *a, **k: pytest.fail("cloned"))
    status, html, _ = _request(server, "POST", "/scan", body="url=http%3A%2F%2Fgithub.com%2Fo%2Fr")
    assert status == 400 and "only https" in html


def test_empty_url_is_rejected(server):
    status, html, _ = _request(server, "POST", "/scan", body="url=")
    assert status == 400 and "Enter a repository URL" in html


def test_oversized_or_missing_body_is_rejected(server):
    assert _request(server, "POST", "/scan", body="url=" + "a" * (MAX_BODY_BYTES + 1))[0] == 413
    assert _request(server, "POST", "/scan", body="")[0] == 413


def test_main_reports_port_in_use(server, capsys):
    assert main(["--port", str(server.server_port)]) == 1
    assert "error" in capsys.readouterr().err

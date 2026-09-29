"""Smoke tests for the `reap` command line.

The 1.0.0 CLI failed at import time with a SyntaxError, and no test imported
it. These tests import the module, run --help, and run `reap get` against a
local server so the whole path works offline.
"""
import http.server
import subprocess
import sys
import threading

import pytest

import curl_reap.cli as cli


def test_cli_imports_and_builds_parser():
    parser = cli.build_parser()
    assert parser.prog == "reap"


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for cmd in ("get", "meta", "links", "crawl"):
        assert cmd in out


def test_help_in_subprocess():
    proc = subprocess.run(
        [sys.executable, "-m", "curl_reap.cli", "--help"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "usage: reap" in proc.stdout


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>T</title></head><body><h1>Hello reap</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def local_url():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


def test_get_default_markdown_returns_zero(local_url, capsys):
    # This is the branch that held the SyntaxError in 1.0.0.
    assert cli.main(["get", local_url]) == 0
    assert "Hello reap" in capsys.readouterr().out


def test_get_css(local_url, capsys):
    assert cli.main(["get", local_url, "--css", "h1::text"]) == 0
    assert capsys.readouterr().out.strip() == "Hello reap"

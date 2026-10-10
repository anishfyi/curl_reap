"""Live HTTP/2 fingerprint checks, run only with REAP_LIVE_TESTS=1.

tls.peet.ws echoes the Akamai HTTP/2 fingerprint it observed.  The TLS
layer here is the standard library (OpenSSL) because this package only
owns HTTP/2; the Akamai string depends on the HTTP/2 frames alone.
"""
import json
import os
import socket
import ssl
import time

import pytest

if not os.environ.get("REAP_LIVE_TESTS"):
    pytest.skip("set REAP_LIVE_TESTS=1 to run live HTTP/2 checks", allow_module_level=True)

pytest.importorskip("hpack")

from curl_reap._h2 import H2Connection, spec  # noqa: E402
from curl_reap._h2.templates_data import SPECS  # noqa: E402

HOST = "tls.peet.ws"


def fetch_all(name):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    sock = socket.create_connection((HOST, 443), timeout=15)
    tls = context.wrap_socket(sock, server_hostname=HOST)
    assert tls.selected_alpn_protocol() == "h2"
    deadline = time.monotonic() + 20
    conn = H2Connection(tls, spec(name), deadline=deadline)
    headers = [(n, "identity" if n == "accept-encoding" else v)
               for n, v in SPECS[name]["headers"] if not n.startswith(":")]
    try:
        response = conn.request("GET", "https", HOST, "/api/all", headers, deadline=deadline)
    finally:
        conn.close()
    assert response.status == 200
    return json.loads(response.body.decode("utf-8"))


@pytest.mark.parametrize("name", ["chrome", "firefox", "safari", "safari170"])
def test_peet_reports_the_captured_akamai_fingerprint(name):
    data = fetch_all(name)
    http2 = data["http2"]
    assert http2["akamai_fingerprint"] == SPECS[name]["akamai"]
    sent = [f["frame_type"] for f in http2["sent_frames"]]
    assert sent[:3] == ["SETTINGS", "WINDOW_UPDATE", "HEADERS"]
    headers_frame = next(f for f in http2["sent_frames"] if f["frame_type"] == "HEADERS")
    # peet lists header lines such as ":method: GET"; keep the pseudo names in order.
    letters = {"method": "m", "authority": "a", "scheme": "s", "path": "p"}
    pseudo = [line[1:].split(":", 1)[0] for line in headers_frame["headers"] if line.startswith(":")]
    assert "".join(letters[p] for p in pseudo) == SPECS[name]["pseudo_order"]

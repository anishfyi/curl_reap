"""Live checks behind REAP_LIVE_TESTS=1: tls.peet.ws fingerprints and ML-KEM.

For each family the engine handshakes with https://tls.peet.ws, fetches
/api/all (over HTTP/2 through hyper-h2 when the server selects h2, otherwise
HTTP/1.1) and compares ja4 and peetprint_hash with the values curl_cffi
produced in tools/hello_templates/peet_<family>.json.
"""
import json
import os
import socket
import sys

import pytest

from curl_reap._tls import template, wrap_socket

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIVE = os.environ.get("REAP_LIVE_TESTS") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="set REAP_LIVE_TESTS=1 to run live network tests")


def expected(family):
    with open(os.path.join(ROOT, "tools", "hello_templates", "peet_%s.json" % family)) as fh:
        return json.load(fh)["tls"]


def fetch_http1(tls, host, path):
    tls.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl_reap-tls-live-test\r\nAccept: */*\r\nConnection: close\r\n\r\n" % (path, host)).encode())
    raw = b""
    while True:
        chunk = tls.recv(65536)
        if not chunk:
            break
        raw += chunk
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        headers[k.strip().lower()] = v.strip()
    if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
        out = b""
        rest = body
        while True:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        body = out
    return status, body


def fetch_http2(tls, host, path):
    h2 = pytest.importorskip("h2.connection")
    import h2.config
    import h2.events

    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    conn.send_headers(1, [(":method", "GET"), (":authority", host), (":scheme", "https"), (":path", path),
                          ("user-agent", "curl_reap-tls-live-test"), ("accept", "*/*")], end_stream=True)
    tls.sendall(conn.data_to_send())
    status = None
    body = b""
    done = False
    while not done:
        chunk = tls.recv(65536)
        if not chunk:
            break
        for ev in conn.receive_data(chunk):
            if isinstance(ev, h2.events.ResponseReceived):
                status = int(dict(ev.headers)[":status"])
            elif isinstance(ev, h2.events.DataReceived):
                body += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset, h2.events.ConnectionTerminated)):
                done = True
        out = conn.data_to_send()
        if out:
            tls.sendall(out)
    return status, body


def fetch(host, path, name, alpn=("h2", "http/1.1")):
    sock = socket.create_connection((host, 443), timeout=20)
    tls = wrap_socket(sock, host, template(name), alpn=alpn, timeout=20)
    try:
        if tls.selected_alpn_protocol() == "h2":
            status, body = fetch_http2(tls, host, path)
        else:
            status, body = fetch_http1(tls, host, path)
        return tls, status, body
    finally:
        tls.close()


@pytest.mark.parametrize("family", ["chrome", "firefox", "safari", "edge"])
def test_peet_ws_fingerprints_match_curl_cffi(family, capsys):
    exp = expected(family)
    tls, status, body = fetch("tls.peet.ws", "/api/all", family)
    assert status == 200
    doc = json.loads(body)["tls"]
    with capsys.disabled():
        print("\n%s: ja4=%s peetprint_hash=%s ja3_hash=%s alpn=%s group=%s" % (
            family, doc["ja4"], doc["peetprint_hash"], doc["ja3_hash"], tls.selected_alpn_protocol(), tls.negotiated_group))
    assert doc["ja4"] == exp["ja4"], (doc["ja4"], exp["ja4"])
    assert doc["peetprint_hash"] == exp["peetprint_hash"], (doc["peetprint"], exp["peetprint"])
    if family != "chrome":
        assert doc["ja3_hash"] == exp["ja3_hash"]
    assert doc["tls_version_negotiated"] == "772"


@pytest.mark.parametrize("host", ["www.cloudflare.com", "www.google.com"])
def test_mlkem_negotiated_on_the_live_web(host, capsys):
    tls, status, body = fetch(host, "/", "chrome", alpn=("http/1.1",))
    with capsys.disabled():
        print("\n%s: status=%s group=%s cipher=%s compressed_cert=%s resumed=%s bytes=%d" % (
            host, status, tls.negotiated_group, tls.cipher()[0], tls.handshake_info.cert_compression, tls.resumed, len(body)))
    assert status == 200
    assert tls.negotiated_group == "X25519MLKEM768"
    assert tls.handshake_info.cert_verified is True


@pytest.mark.parametrize("host,name", [("github.com", "firefox"), ("www.wikipedia.org", "safari"), ("example.com", "edge")])
def test_other_families_fetch_200(host, name, capsys):
    tls, status, body = fetch(host, "/", name, alpn=("http/1.1",))
    with capsys.disabled():
        print("\n%s (%s): status=%s group=%s cipher=%s" % (host, name, status, tls.negotiated_group, tls.cipher()[0]))
    assert status == 200


def test_live_resumption_with_session_cache(capsys):
    from curl_reap._tls import SessionCache

    cache = SessionCache()
    host = "www.cloudflare.com"
    for attempt in range(2):
        sock = socket.create_connection((host, 443), timeout=20)
        tls = wrap_socket(sock, host, template("chrome"), alpn=("http/1.1",), timeout=20, session_cache=cache)
        status, _ = fetch_http1(tls, host, "/")
        tls.close()
        with capsys.disabled():
            print("\n%s attempt %d: status=%s resumed=%s tickets_in_cache=%d" % (host, attempt, status, tls.resumed, len(cache)))
        assert status == 200
        if attempt == 1:
            assert tls.client.offering_psk

import zlib

import pytest

import curl_reap
from curl_reap.http import RetryPolicy
from curl_reap.tls import Profile, resolve_profile


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if not self.incoming:
            return b""
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data

    def close(self):
        self.closed = True


def response(body=b"ok", headers=b""):
    return (b"HTTP/1.1 200 OK\r\n" + headers +
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


def test_header_order_and_casing_are_deterministic(monkeypatch):
    sockets = [FakeSocket(response()), FakeSocket(response())]
    monkeypatch.setattr("curl_reap.http.socket.create_connection",
                        lambda address, timeout: sockets.pop(0))

    sent = []
    for unused in range(2):
        session = curl_reap.Session(
            headers=[("uSeR-aGeNt", "ordered-agent"), ("X-First", "1"), ("x-second", "2")],
            retries=0)
        result = session.get("http://example.test/a?b=1",
                             headers=[("X-Request", "3")])
        assert result.text == "ok"
        pooled = next(iter(session._transport._pool.values()))[0]
        sent.append(pooled.sock.sent[0])

    assert sent[0] == sent[1]
    lines = sent[0].split(b"\r\n")
    assert lines[0] == b"GET /a?b=1 HTTP/1.1"
    assert lines[1] == b"Host: example.test"
    assert lines[2] == b"uSeR-aGeNt: ordered-agent"
    assert lines.index(b"X-First: 1") < lines.index(b"x-second: 2") < lines.index(b"X-Request: 3")


def test_retry_backoff_with_mocked_socket(monkeypatch):
    good = FakeSocket(response(b"retried"))
    attempts = []

    def connect(address, timeout):
        attempts.append(address)
        if len(attempts) == 1:
            raise OSError("temporary connect failure")
        return good

    sleeps = []
    monkeypatch.setattr("curl_reap.http.socket.create_connection", connect)
    monkeypatch.setattr("curl_reap.http.random.random", lambda: 0.5)
    monkeypatch.setattr("curl_reap.http.time.sleep", sleeps.append)
    policy = RetryPolicy(retries=1, backoff=2.0, max_backoff=10.0)
    result = curl_reap.Session(retry_policy=policy).get("http://retry.test/")

    assert result.text == "retried"
    assert len(attempts) == 2
    assert sleeps == [2.0]


def test_chunked_gzip_and_connection_reuse(monkeypatch):
    compressed = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    payload = compressed.compress(b"decoded") + compressed.flush()
    chunk = b"%x\r\n" % len(payload) + payload + b"\r\n0\r\n\r\n"
    first = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
             b"Content-Encoding: gzip\r\n\r\n" + chunk)
    sock = FakeSocket(first + response(b"second"))
    calls = []

    def connect(address, timeout):
        calls.append(address)
        return sock

    monkeypatch.setattr("curl_reap.http.socket.create_connection", connect)
    session = curl_reap.Session(retries=0)
    assert session.get("http://reuse.test/one").content == b"decoded"
    assert session.get("http://reuse.test/two").content == b"second"
    assert len(calls) == 1
    assert len(sock.sent) == 2


def test_profile_validation_and_custom_profile():
    assert resolve_profile("chrome") is curl_reap.PROFILES["chrome"]
    with pytest.raises(ValueError, match="unknown TLS profile"):
        curl_reap.Session(profile="netscape")
    with pytest.raises(TypeError, match="Profile"):
        curl_reap.Session(profile=object())

    custom = Profile(name="custom", headers=(("user-agent", "custom"),))
    assert curl_reap.Session(profile=custom).profile is custom

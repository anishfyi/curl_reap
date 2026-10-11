"""H2Connection against a local hyper-h2 server over plain TCP (prior knowledge).

The client preface is the same with or without TLS, so these tests exercise
the real socket driver: flow control in both directions, large bodies, push
refusal, GOAWAY, RST_STREAM, trailers, 1xx, body caps, ping, close and
connection reuse with HPACK dynamic table hits.
"""
import gzip
import socket
import threading
import time

import pytest

h2 = pytest.importorskip("h2")
from h2.config import H2Configuration  # noqa: E402
from h2.connection import H2Connection as ServerConnection  # noqa: E402
from h2.errors import ErrorCodes  # noqa: E402
from h2.events import (  # noqa: E402
    ConnectionTerminated, DataReceived, PingReceived, RequestReceived, StreamEnded,
    StreamReset, WindowUpdated,
)
from h2.settings import SettingCodes, Settings  # noqa: E402

from curl_reap._h2 import (  # noqa: E402
    H2Connection, H2Error, H2Response, spec, spec_from_akamai,
)
from curl_reap._h2 import frames as F  # noqa: E402
from curl_reap._h2.templates_data import SPECS  # noqa: E402
from curl_reap.exceptions import (  # noqa: E402
    ConnectionError as ReapConnectionError, IncompleteRead, InvalidHeader, ReadTimeout,
)

CHROME_HEADERS = [(n, v) for n, v in SPECS["chrome"]["headers"] if not n.startswith(":")]


class Ctx(object):
    """Per connection helpers handed to the test's handler."""

    def __init__(self, conn, sock, server, index):
        self.conn = conn
        self.sock = sock
        self.server = server
        self.index = index
        self.requests = {}
        self.bodies = {}
        self.pending = {}
        self.raw = bytearray()
        self.closing = False

    def respond(self, stream_id, status=200, headers=(), body=b"", trailers=None, informational=()):
        for inf_status, inf_headers in informational:
            self.conn.send_headers(stream_id, [(":status", str(inf_status))] + list(inf_headers))
        end = not body and not trailers
        self.conn.send_headers(stream_id, [(":status", str(status))] + list(headers), end_stream=end)
        if not end:
            self.pending[stream_id] = [bytes(body), list(trailers) if trailers else None]
        self.pump()

    def pump(self):
        for stream_id in list(self.pending):
            body, trailers = self.pending[stream_id]
            while body:
                window = min(self.conn.local_flow_control_window(stream_id),
                             self.conn.max_outbound_frame_size)
                if window <= 0:
                    break
                piece, body = body[:window], body[window:]
                self.conn.send_data(stream_id, piece, end_stream=not body and not trailers)
            if body:
                self.pending[stream_id][0] = body
                continue
            if trailers:
                self.conn.send_headers(stream_id, trailers, end_stream=True)
            del self.pending[stream_id]

    def flush(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)


def echo(ctx, event):
    """Answer every request with 200 and a tiny body once it is complete."""
    if isinstance(event, RequestReceived):
        ctx.requests[event.stream_id] = event.headers
        ctx.bodies.setdefault(event.stream_id, bytearray())
    elif isinstance(event, DataReceived):
        ctx.bodies[event.stream_id] += event.data
        ctx.conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
    elif isinstance(event, StreamEnded):
        ctx.respond(event.stream_id, 200, [("content-type", "text/plain")],
                    body=b"ok:%d" % len(ctx.bodies.get(event.stream_id, b"")))


class H2TestServer(object):
    def __init__(self, handler=echo, local_settings=None, record_raw=False):
        self.handler = handler
        self.local_settings = local_settings
        self.record_raw = record_raw
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.contexts = []
        self.events = []
        self.errors = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def connect(self, name="chrome", h2spec=None, **kw):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return H2Connection(sock, h2spec or spec(name), **kw)

    def wait_events(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                hits = [e for e in self.events if predicate(e)]
            if hits:
                return hits
            time.sleep(0.01)
        return []

    def client_frames(self, index=0):
        """Frames the client sent on connection ``index`` (needs record_raw=True)."""
        parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)
        with self.lock:
            raw = bytes(self.contexts[index].raw)
        assert raw.startswith(F.CONNECTION_PREFACE)
        parser.feed(raw[len(F.CONNECTION_PREFACE):])
        return list(parser.frames())

    def wait_rst(self, stream_id, timeout=5.0):
        """The RST_STREAM error code the client sent for ``stream_id``."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for frame in self.client_frames():
                if frame.type == F.RST_STREAM and frame.stream_id == stream_id:
                    return int.from_bytes(frame.payload, "big")
            time.sleep(0.01)
        return None

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                index = len(self.contexts)
            threading.Thread(target=self._serve, args=(client, index), daemon=True).start()

    def _serve(self, client, index):
        conn = ServerConnection(config=H2Configuration(client_side=False, header_encoding="latin-1"))
        if self.local_settings:
            conn.local_settings = Settings(client=False, initial_values=self.local_settings)
        conn.initiate_connection()
        ctx = Ctx(conn, client, self, index)
        with self.lock:
            self.contexts.append(ctx)
        client.settimeout(0.2)
        try:
            ctx.flush()
            idle = time.monotonic()
            while True:
                try:
                    data = client.recv(65536)
                except socket.timeout:
                    if ctx.closing or time.monotonic() - idle > 10:
                        break
                    continue
                except OSError:
                    break
                if not data:
                    break
                idle = time.monotonic()
                if self.record_raw:
                    ctx.raw += data
                try:
                    events = conn.receive_data(data)
                except Exception as exc:  # protocol error on the server side
                    self.errors.append(exc)
                    ctx.flush()
                    break
                for event in events:
                    with self.lock:
                        self.events.append(event)
                    try:
                        self.handler(ctx, event)
                    except Exception as exc:
                        self.errors.append(exc)
                ctx.pump()
                ctx.flush()
        finally:
            try:
                client.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

def test_get_with_gzip_body_returns_raw_bytes():
    payload = gzip.compress(b"hello " * 100)

    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            ctx.requests[event.stream_id] = event.headers
            ctx.respond(event.stream_id, 200, [("content-encoding", "gzip"),
                                               ("content-length", str(len(payload)))], body=payload)

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        response = conn.request("GET", "https", "127.0.0.1:%d" % server.port, "/some/path?q=1",
                                CHROME_HEADERS + [("Connection", "close"), ("X-Extra", "1")],
                                deadline=time.monotonic() + 5)
        assert isinstance(response, H2Response)
        assert response.status == 200
        assert response.body == payload, "decoding is the transport's job"
        assert ("content-encoding", "gzip") in response.headers
        assert response.trailers == [] and response.stream_id == 1 and response.informational == []
        seen = server.contexts[0].requests[1]
        names = [n for n, _ in seen]
        assert names[:4] == [":method", ":authority", ":scheme", ":path"]
        assert names[4:] == [n for n, _ in CHROME_HEADERS] + ["x-extra"]
        assert ("te", "trailers") not in seen
        assert conn.alive
        conn.close()
        assert not conn.alive
        assert server.wait_events(lambda e: isinstance(e, ConnectionTerminated))
        assert not server.errors


def test_request_body_with_small_peer_window():
    body = bytes(range(256)) * 274  # 70144 bytes
    body = body[:70000]
    with H2TestServer(local_settings={SettingCodes.INITIAL_WINDOW_SIZE: 10000,
                                      SettingCodes.MAX_CONCURRENT_STREAMS: 100}) as server:
        conn = server.connect("chrome")
        conn.ping()  # the server's SETTINGS are applied before the body goes out
        assert conn.core.remote_settings[F.SETTINGS_INITIAL_WINDOW_SIZE] == 10000
        response = conn.request("POST", "https", "h", "/upload", [("content-length", "70000")],
                                body=body, deadline=time.monotonic() + 10)
        assert response.status == 200 and response.body == b"ok:70000"
        ctx = server.contexts[0]
        assert bytes(ctx.bodies[1]) == body
        sizes = [e.flow_controlled_length for e in server.events
                 if isinstance(e, DataReceived) and e.stream_id == 1]
        assert max(sizes) <= 10000 and sum(sizes) == 70000
        assert len(sizes) >= 7
        assert not server.errors


def test_request_body_as_iterable_of_chunks():
    with H2TestServer() as server:
        conn = server.connect("firefox")
        chunks = (b"chunk-%d-" % i for i in range(1000))
        response = conn.request("POST", "https", "h", "/upload", [], body=chunks,
                                deadline=time.monotonic() + 10)
        assert response.status == 200
        assert bytes(server.contexts[0].bodies[1]) == b"".join(b"chunk-%d-" % i for i in range(1000))
        with pytest.raises(TypeError):
            conn.request("POST", "https", "h", "/", [], body="text")


def test_large_response_body_emits_window_updates():
    payload = bytes(range(256)) * 1200  # 307200 bytes

    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, [("content-length", str(len(payload)))], body=payload)

    with H2TestServer(handler) as server:
        conn = server.connect("firefox")  # 131072 stream window forces WINDOW_UPDATEs
        response = conn.request("GET", "https", "h", "/big", [], deadline=time.monotonic() + 10)
        assert response.body == payload
        updates = [e for e in server.events if isinstance(e, WindowUpdated) and e.stream_id == 1]
        assert updates, "the client must open the stream window to receive 300 KB"
        assert all(u.delta > 131072 // 2 for u in updates)
        assert not any(e.stream_id == 0 for e in server.events if isinstance(e, WindowUpdated)
                       and e.delta != 12517377), "no connection update below half of 12 MB"
        assert not server.errors


def test_on_data_streams_without_buffering_or_cap():
    payload = b"z" * 200000

    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=payload)

    with H2TestServer(handler) as server:
        conn = server.connect("chrome", max_body=1000)
        chunks = []
        response = conn.request("GET", "https", "h", "/stream", [], on_data=chunks.append,
                                deadline=time.monotonic() + 10)
        assert response.body is None
        assert b"".join(chunks) == payload
        assert len(chunks) > 1


def test_on_data_exception_cancels_stream_and_keeps_connection():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=b"x" * 50000)

    with H2TestServer(handler, record_raw=True) as server:
        conn = server.connect("chrome")

        def boom(chunk):
            raise RuntimeError("stop")

        with pytest.raises(RuntimeError):
            conn.request("GET", "https", "h", "/a", [], on_data=boom, deadline=time.monotonic() + 5)
        assert conn.alive
        assert server.wait_rst(1) == F.CANCEL
        response = conn.request("GET", "https", "h", "/b", [], deadline=time.monotonic() + 5)
        assert response.status == 200 and response.stream_id == 3


def test_max_body_exceeded():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=b"y" * 5000)

    with H2TestServer(handler, record_raw=True) as server:
        conn = server.connect("chrome", max_body=1000)
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/big", [], deadline=time.monotonic() + 5)
        assert info.value.code == 63 and info.value.stream_id == 1 and not info.value.retryable
        assert server.wait_rst(1) == F.CANCEL
        assert conn.alive
        small = conn.request("GET", "https", "h", "/small", [], on_data=lambda c: None,
                             deadline=time.monotonic() + 5)
        assert small.status == 200


def test_push_promise_is_refused():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            if event.stream_id == 1:  # push once; stream 2 cannot be reused after the RST
                ctx.conn.push_stream(event.stream_id, 2, [
                    (":method", "GET"), (":authority", "h"), (":scheme", "https"), (":path", "/push.css")])
                ctx.conn.send_headers(2, [(":status", "200")])
                ctx.conn.send_data(2, b"pushed", end_stream=True)
            ctx.respond(event.stream_id, 200, body=b"main")

    push_spec = spec_from_akamai("1:65536;2:1;4:6291456;6:262144|15663105|0|m,a,s,p", name="pushy")
    with H2TestServer(handler, record_raw=True) as server:
        conn = server.connect(h2spec=push_spec)
        response = conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert response.body == b"main"
        assert server.wait_rst(2) == F.REFUSED_STREAM
        assert conn.alive
        again = conn.request("GET", "https", "h", "/again", [], deadline=time.monotonic() + 5)
        assert again.status == 200 and again.stream_id == 3
        assert not server.errors


def test_goaway_before_processing_is_retryable():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            ctx.conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=0)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert info.value.retryable
        assert not conn.alive
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert info.value.retryable


def test_graceful_goaway_lets_the_current_stream_finish():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=b"last one")
            ctx.conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=event.stream_id)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("safari")
        response = conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert response.body == b"last one"
        assert not conn.alive
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert info.value.retryable


def test_goaway_with_error_is_not_retryable():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            ctx.conn.close_connection(error_code=ErrorCodes.ENHANCE_YOUR_CALM,
                                      last_stream_id=event.stream_id)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert not info.value.retryable
        assert info.value.error_code == ErrorCodes.ENHANCE_YOUR_CALM


def test_rst_stream_from_server():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            path = dict(event.headers)[":path"]
            if path == "/refused":
                ctx.conn.reset_stream(event.stream_id, ErrorCodes.REFUSED_STREAM)
            elif path == "/internal":
                ctx.conn.send_headers(event.stream_id, [(":status", "200")])
                ctx.conn.reset_stream(event.stream_id, ErrorCodes.INTERNAL_ERROR)
            else:
                ctx.respond(event.stream_id, 200, body=b"fine")

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/refused", [], deadline=time.monotonic() + 5)
        assert info.value.error_code == F.REFUSED_STREAM and info.value.retryable
        assert info.value.stream_id == 1 and info.value.code == 92
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/internal", [], deadline=time.monotonic() + 5)
        assert info.value.error_code == F.INTERNAL_ERROR and not info.value.retryable
        assert conn.alive
        response = conn.request("GET", "https", "h", "/ok", [], deadline=time.monotonic() + 5)
        assert response.body == b"fine" and response.stream_id == 5


def test_trailers():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            ctx.requests[event.stream_id] = event.headers
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, [("content-type", "text/plain")], body=b"body",
                        trailers=[("x-checksum", "abc"), ("x-count", "1")])

    with H2TestServer(handler) as server:
        conn = server.connect("firefox")
        response = conn.request("GET", "https", "h", "/t", [("te", "trailers")],
                                deadline=time.monotonic() + 5)
        assert response.body == b"body"
        assert response.trailers == [("x-checksum", "abc"), ("x-count", "1")]
        assert ("te", "trailers") in server.contexts[0].requests[1]


def test_informational_then_final_response():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, [("x-final", "1")], body=b"done",
                        informational=[(103, [("link", "</style.css>; rel=preload")]), (100, [])])

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        response = conn.request("GET", "https", "h", "/early", [], deadline=time.monotonic() + 5)
        assert response.status == 200 and response.body == b"done"
        assert response.headers == [("x-final", "1")]
        assert response.informational == [(103, [("link", "</style.css>; rel=preload")]), (100, [])]


def test_ping_round_trip():
    with H2TestServer() as server:
        conn = server.connect("chrome")
        rtt = conn.ping()
        assert 0 <= rtt < 5
        assert server.wait_events(lambda e: isinstance(e, PingReceived))
        rtt2 = conn.ping(timeout=5)
        assert 0 <= rtt2 < 5
        assert conn.alive


def test_close_sends_goaway():
    with H2TestServer() as server:
        conn = server.connect("chrome")
        conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        conn.close()
        terminated = server.wait_events(lambda e: isinstance(e, ConnectionTerminated))
        assert terminated and terminated[0].error_code == 0 and terminated[0].last_stream_id == 0
        assert terminated[0].additional_data in (None, b"")
        assert not conn.alive
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/", [])
        assert info.value.retryable
        conn.close()  # idempotent


def test_sequential_requests_reuse_connection_and_dynamic_table():
    with H2TestServer(record_raw=True) as server:
        conn = server.connect("chrome")
        first = conn.request("GET", "https", "h", "/a?x=1", CHROME_HEADERS, deadline=time.monotonic() + 5)
        second = conn.request("GET", "https", "h", "/a?x=2", CHROME_HEADERS, deadline=time.monotonic() + 5)
        assert (first.stream_id, second.stream_id) == (1, 3)
        assert conn.requests_sent == 2
        time.sleep(0.05)
        assert len(server.contexts) == 1
        ctx = server.contexts[0]
        assert [n for n, _ in ctx.requests[1]] == [n for n, _ in ctx.requests[3]]
        parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)
        parser.feed(bytes(ctx.raw)[len(F.CONNECTION_PREFACE):])
        heads = {f.stream_id: f for f in parser.frames() if f.type == F.HEADERS}
        assert len(heads[3].payload) * 4 < len(heads[1].payload)
        assert heads[1].flags == heads[3].flags == 0x25


def test_requests_from_threads_are_serialised():
    results = {}

    def worker(i):
        try:
            results[i] = conn.request("GET", "https", "h", "/t%d" % i, CHROME_HEADERS,
                                      deadline=time.monotonic() + 10).status
        except Exception as exc:  # pragma: no cover - reported by the assertion below
            results[i] = exc

    with H2TestServer() as server:
        conn = server.connect("chrome")
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert results == {0: 200, 1: 200, 2: 200, 3: 200}
        ids = sorted(e.stream_id for e in server.events if isinstance(e, RequestReceived))
        assert ids == [1, 3, 5, 7]
        assert len(server.contexts) == 1


def test_deadline_raises_read_timeout_and_kills_connection():
    def handler(ctx, event):
        pass  # never answers

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        started = time.monotonic()
        with pytest.raises(ReadTimeout):
            conn.request("GET", "https", "h", "/slow", [], deadline=time.monotonic() + 0.3)
        assert time.monotonic() - started < 3
        assert not conn.alive
        with pytest.raises(H2Error):
            conn.request("GET", "https", "h", "/", [])


def test_server_closing_mid_response():
    def handler(ctx, event):
        if isinstance(event, RequestReceived):
            path = dict(event.headers)[":path"]
            if path == "/after-headers":
                ctx.conn.send_headers(event.stream_id, [(":status", "200"), ("content-length", "10")])
                ctx.flush()
            ctx.closing = True
            ctx.sock.shutdown(socket.SHUT_WR)  # FIN after the frames already sent

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/after-headers", [], deadline=time.monotonic() + 5)
        assert not info.value.retryable, "the response head was received, so no blind retry"
        assert not conn.alive
        conn = server.connect("chrome")
        with pytest.raises(H2Error) as info:
            conn.request("GET", "https", "h", "/before", [], deadline=time.monotonic() + 5)
        assert info.value.retryable


def test_incomplete_read_when_body_shorter_than_content_length():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, [("content-length", "10")], body=b"abc")

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(IncompleteRead):
            conn.request("GET", "https", "h", "/short", [], deadline=time.monotonic() + 5)
        head = conn.request("HEAD", "https", "h", "/short", [], deadline=time.monotonic() + 5)
        assert head.body == b"abc", "HEAD responses are never length checked"


def test_poll_sees_idle_goaway():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=b"ok")
            ctx.conn.close_connection(error_code=ErrorCodes.NO_ERROR, last_stream_id=event.stream_id)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        response = conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert response.body == b"ok"
        # generous deadline: the daemon server thread may lag under a loaded CI box
        deadline = time.monotonic() + 10
        while conn.poll() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not conn.alive


def test_completed_response_survives_a_goaway_error_in_the_same_read():
    # The response and an error GOAWAY arrive back to back (one flush). The
    # stream already ended, so the response must be returned, not discarded.
    # This is the race behind the old test_poll_sees_idle_goaway flake: the
    # strict test server answered a late SETTINGS ACK with PROTOCOL_ERROR.
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.respond(event.stream_id, 200, body=b"ok")
            ctx.conn.close_connection(error_code=ErrorCodes.PROTOCOL_ERROR,
                                      last_stream_id=event.stream_id)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        response = conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert response.status == 200 and response.body == b"ok"
        deadline = time.monotonic() + 10
        while conn.poll() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not conn.alive


def test_goaway_error_before_the_response_still_raises():
    def handler(ctx, event):
        if isinstance(event, StreamEnded):
            ctx.conn.close_connection(error_code=ErrorCodes.PROTOCOL_ERROR,
                                      last_stream_id=event.stream_id)
            ctx.closing = True

    with H2TestServer(handler) as server:
        conn = server.connect("chrome")
        with pytest.raises(H2Error, match="PROTOCOL_ERROR") as excinfo:
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        # the server claimed the stream (last_stream_id covers it), so it may
        # have been processed: never advertise it as safe to retry
        assert excinfo.value.retryable is False


def test_invalid_headers_are_rejected_before_sending():
    with H2TestServer() as server:
        conn = server.connect("chrome")
        with pytest.raises(InvalidHeader):
            conn.request("GET", "https", "h", "/", [(":authority", "x")])
        with pytest.raises(InvalidHeader):
            conn.request("GET", "https", "h", "/", [("x", "a\r\nb")])
        assert conn.alive
        assert conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5).status == 200


def test_connection_error_on_dead_socket():
    with H2TestServer() as server:
        conn = server.connect("chrome")
        conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        conn.sock.close()
        with pytest.raises((ReapConnectionError, H2Error, OSError)):
            conn.request("GET", "https", "h", "/", [], deadline=time.monotonic() + 5)
        assert not conn.alive


def test_spec_type_is_checked():
    with pytest.raises(TypeError):
        H2Connection(socket.socket(), "chrome")

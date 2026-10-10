"""Sans-IO core tests: frames are handcrafted and fed to H2Core directly."""
import struct

import pytest

pytest.importorskip("hpack")
from hpack import Decoder, Encoder  # noqa: E402

from curl_reap._h2 import (  # noqa: E402
    ConnectionTerminated, DataReceived, H2Core, H2Error, InformationalResponse,
    PingAckReceived, PingReceived, PushPromiseRefused, RemoteSettingsChanged,
    ResponseReceived, SettingsAcknowledged, StreamEnded, StreamReset, TrailersReceived,
    WindowUpdated, build_request_fields, spec, spec_from_akamai,
)
from curl_reap._h2 import frames as F  # noqa: E402
from curl_reap.exceptions import InvalidHeader  # noqa: E402

HEADERS = [("user-agent", "test/1"), ("accept", "*/*")]


class Peer(object):
    """A fake server side: encodes response blocks and parses what the core sends."""

    def __init__(self):
        self.encoder = Encoder()
        self.decoder = Decoder()
        self.parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)

    def headers(self, stream_id, fields, end_stream=False, end_headers=True, priority=None):
        block = self.encoder.encode([(n.encode(), v.encode()) for n, v in fields])
        flags = (F.FLAG_END_STREAM if end_stream else 0) | (F.FLAG_END_HEADERS if end_headers else 0)
        if priority:
            flags |= F.FLAG_PRIORITY
        return F.pack_headers(stream_id, block, flags, priority)

    def response(self, stream_id, status="200", extra=(), end_stream=False):
        return self.headers(stream_id, [(":status", status)] + list(extra), end_stream=end_stream)

    def sent(self, core):
        data = core.data_to_send()
        if data.startswith(F.CONNECTION_PREFACE):
            data = data[len(F.CONNECTION_PREFACE):]
        self.parser.feed(data)
        return list(self.parser.frames())


def start(name="chrome", path="/", headers=HEADERS, end_stream=True):
    core = H2Core(spec(name))
    core.initiate_connection()
    peer = Peer()
    peer.sent(core)
    sid = core.send_request("GET" if end_stream else "POST", "https", "example.com", path, headers,
                            end_stream=end_stream)
    peer.sent(core)
    return core, peer, sid


def kinds(events):
    return [type(e).__name__ for e in events]


# --------------------------------------------------------------------------
# preface and request building
# --------------------------------------------------------------------------

def test_preface_is_magic_settings_window_update_only():
    core = H2Core(spec("chrome"))
    assert not core.alive
    core.initiate_connection()
    assert core.alive
    data = core.data_to_send()
    assert data.startswith(F.CONNECTION_PREFACE)
    peer = Peer()
    peer.parser.feed(data[len(F.CONNECTION_PREFACE):])
    frames = list(peer.parser.frames())
    assert [f.name for f in frames] == ["SETTINGS", "WINDOW_UPDATE"]
    assert F.parse_settings(frames[0].payload) == [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
    assert frames[1].payload == struct.pack(">I", 15663105)
    assert core.data_to_send() == b""
    with pytest.raises(H2Error):
        core.initiate_connection()


def test_request_fields_follow_spec_pseudo_order_and_drop_connection_headers():
    raw = [("Host", "ignored"), ("Connection", "keep-alive"), ("Keep-Alive", "300"),
           ("Transfer-Encoding", "chunked"), ("Upgrade", "h2c"), ("Proxy-Connection", "x"),
           ("TE", "gzip"), ("User-Agent", " ua "), ("X-Mixed-Case", "Value"), ("te", "Trailers")]
    fields = build_request_fields(spec("firefox"), "get", "HTTPS", "example.com", "", raw)
    assert fields == [(b":method", b"get"), (b":path", b"/"), (b":authority", b"example.com"),
                      (b":scheme", b"https"), (b"user-agent", b"ua"), (b"x-mixed-case", b"Value"),
                      (b"te", b"Trailers")]
    fields = build_request_fields(spec("safari170"), "GET", "https", "h", "/p", [])
    assert [n for n, _ in fields] == [b":method", b":scheme", b":path", b":authority"]


@pytest.mark.parametrize("bad", [
    [(":authority", "x")], [("", "x")], [("x y", "1")], [("x", "a\r\nb")], [("x\x00", "1")],
])
def test_request_fields_reject_invalid_headers(bad):
    with pytest.raises(InvalidHeader):
        build_request_fields(spec("chrome"), "GET", "https", "h", "/", bad)


def test_request_fields_reject_bad_request_line():
    with pytest.raises(InvalidHeader):
        build_request_fields(spec("chrome"), "", "https", "h", "/", [])
    with pytest.raises(InvalidHeader):
        build_request_fields(spec("chrome"), "GET", "https", "", "/", [])
    with pytest.raises(InvalidHeader):
        build_request_fields(spec("chrome"), "GET", "https", "h", "/a b", [])
    with pytest.raises(InvalidHeader):
        build_request_fields(spec("chrome"), "G ET", "https", "h", "/", [])


def test_headers_frame_flags_for_body_and_bodyless_requests():
    core, peer, sid = start("chrome", end_stream=True)
    assert sid == 1
    core.send_request("POST", "https", "example.com", "/", HEADERS, end_stream=False)
    frame, = peer.sent(core)
    assert frame.flags == F.FLAG_END_HEADERS | F.FLAG_PRIORITY
    assert core.streams[3].state == "open"
    assert core.streams[1].state == "half_closed_local"
    core2, peer2, _ = start("safari")
    core2.send_request("POST", "https", "example.com", "/", HEADERS, end_stream=False)
    frame, = peer2.sent(core2)
    assert frame.flags == F.FLAG_END_HEADERS
    assert len(frame.payload) and not frame.flags & F.FLAG_PRIORITY


def test_large_header_block_uses_continuation_frames():
    core, peer, _ = start()
    core.send_request("GET", "https", "example.com", "/", [("x-big-%d" % i, "v" * 3000) for i in range(16)])
    frames = peer.sent(core)
    assert [f.name for f in frames] == ["HEADERS", "CONTINUATION", "CONTINUATION"]
    assert frames[0].flags & F.FLAG_END_HEADERS == 0
    assert frames[-1].flags == F.FLAG_END_HEADERS
    assert all(len(f.payload) <= 16384 for f in frames)


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------

def test_peer_settings_applied_and_acked():
    core, peer, sid = start(end_stream=False)
    events = core.receive_data(F.pack_settings([
        (F.SETTINGS_HEADER_TABLE_SIZE, 1024), (F.SETTINGS_ENABLE_PUSH, 0),
        (F.SETTINGS_MAX_CONCURRENT_STREAMS, 50), (F.SETTINGS_INITIAL_WINDOW_SIZE, 1000),
        (F.SETTINGS_MAX_FRAME_SIZE, 20000), (F.SETTINGS_MAX_HEADER_LIST_SIZE, 9999),
        (0x99, 5),
    ]))
    assert kinds(events) == ["RemoteSettingsChanged"]
    assert events[0].settings == {1: 1024, 2: 0, 3: 50, 4: 1000, 5: 20000, 6: 9999}
    assert core.remote_settings[F.SETTINGS_MAX_FRAME_SIZE] == 20000
    assert core.max_data_frame_size == 20000
    assert core.encoder.max_table_size == 1024
    assert core.streams[sid].send_window == 1000, "open streams follow INITIAL_WINDOW_SIZE"
    ack, = peer.sent(core)
    assert ack.type == F.SETTINGS and ack.flags == F.FLAG_ACK and ack.payload == b""
    events = core.receive_data(F.pack_settings((), ack=True))
    assert kinds(events) == ["SettingsAcknowledged"]
    assert core.settings_acked


@pytest.mark.parametrize("pairs, code", [
    ([(F.SETTINGS_ENABLE_PUSH, 2)], F.PROTOCOL_ERROR),
    ([(F.SETTINGS_INITIAL_WINDOW_SIZE, 1 << 31)], F.FLOW_CONTROL_ERROR),
    ([(F.SETTINGS_MAX_FRAME_SIZE, 100)], F.PROTOCOL_ERROR),
    ([(F.SETTINGS_MAX_FRAME_SIZE, 1 << 24)], F.PROTOCOL_ERROR),
])
def test_invalid_peer_settings_are_connection_errors(pairs, code):
    core, peer, _ = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_settings(pairs))
    assert info.value.error_code == code
    assert not core.alive
    goaway, = peer.sent(core)
    assert goaway.type == F.GOAWAY
    assert struct.unpack(">I", goaway.payload[4:8])[0] == code


def test_settings_frame_errors():
    core, _, _ = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_frame(F.SETTINGS, 0, 0, b"\x00\x01\x00"))
    assert info.value.error_code == F.FRAME_SIZE_ERROR
    core, _, _ = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.SETTINGS, F.FLAG_ACK, 0, b"\x00"))
    core, _, _ = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.SETTINGS, 0, 1, b""))


def test_max_concurrent_streams_zero_refuses_new_requests():
    core, _, _ = start()
    core.receive_data(F.pack_settings([(F.SETTINGS_MAX_CONCURRENT_STREAMS, 1)]))
    with pytest.raises(H2Error) as info:
        core.send_request("GET", "https", "h", "/", [])
    assert info.value.retryable


# --------------------------------------------------------------------------
# responses
# --------------------------------------------------------------------------

def test_response_headers_data_and_end_stream():
    core, peer, sid = start()
    events = core.receive_data(peer.response(sid, extra=[("content-type", "text/plain")]) +
                               F.pack_data(sid, b"hel") + F.pack_data(sid, b"lo", end_stream=True))
    assert kinds(events) == ["ResponseReceived", "DataReceived", "DataReceived", "StreamEnded"]
    assert events[0].status == 200 and events[0].headers == [("content-type", "text/plain")]
    assert events[1].data == b"hel" and events[1].flow_controlled_length == 3
    assert sid not in core.streams, "closed streams are forgotten"
    assert core.alive


def test_informational_responses_are_reported_then_skipped():
    core, peer, sid = start()
    data = peer.response(sid, "103", [("link", "</s.css>; rel=preload")])
    data += peer.response(sid, "100")
    data += peer.response(sid, "200", end_stream=True)
    events = core.receive_data(data)
    assert kinds(events) == ["InformationalResponse", "InformationalResponse", "ResponseReceived", "StreamEnded"]
    assert events[0].status == 103 and events[0].headers == [("link", "</s.css>; rel=preload")]
    assert events[2].status == 200


def test_informational_with_end_stream_or_101_is_a_stream_error():
    core, peer, sid = start()
    events = core.receive_data(peer.response(sid, "100", end_stream=True))
    assert kinds(events) == ["StreamReset"]
    assert events[0].remote is False and events[0].error_code == F.PROTOCOL_ERROR
    rst, = peer.sent(core)
    assert rst.type == F.RST_STREAM and rst.stream_id == sid
    core, peer, sid = start()
    events = core.receive_data(peer.response(sid, "101"))
    assert kinds(events) == ["StreamReset"]


def test_trailers():
    core, peer, sid = start()
    data = peer.response(sid) + F.pack_data(sid, b"body")
    data += peer.headers(sid, [("x-checksum", "abc")], end_stream=True)
    events = core.receive_data(data)
    assert kinds(events) == ["ResponseReceived", "DataReceived", "TrailersReceived", "StreamEnded"]
    assert events[2].headers == [("x-checksum", "abc")]


def test_trailers_without_end_stream_or_with_pseudo_headers_reset_the_stream():
    core, peer, sid = start()
    events = core.receive_data(peer.response(sid) + peer.headers(sid, [("x", "y")], end_stream=False))
    assert kinds(events) == ["ResponseReceived", "StreamReset"]
    assert "END_STREAM" in events[1].reason
    core, peer, sid = start()
    events = core.receive_data(peer.response(sid) + peer.headers(sid, [(":status", "200")], end_stream=True))
    assert kinds(events) == ["ResponseReceived", "StreamReset"]


@pytest.mark.parametrize("fields, reason", [
    ([("content-type", "x")], "without :status"),
    ([("content-type", "x"), (":status", "200")], "after a regular"),
    ([(":status", "200"), (":path", "/")], "unexpected pseudo"),
    ([(":status", "20x")], "malformed :status"),
    ([(":status", "200"), ("Content-Type", "x")], "uppercase"),
])
def test_malformed_response_heads_reset_the_stream(fields, reason):
    core, peer, sid = start()
    events = core.receive_data(peer.headers(sid, fields, end_stream=True))
    assert kinds(events) == ["StreamReset"]
    assert reason in events[0].reason
    rst, = peer.sent(core)
    assert rst.type == F.RST_STREAM and struct.unpack(">I", rst.payload)[0] == F.PROTOCOL_ERROR
    assert core.alive


def test_continuation_assembles_header_block():
    core, peer, sid = start()
    block = peer.encoder.encode([(b":status", b"200"), (b"x-a", b"1"), (b"x-b", b"2")])
    data = F.pack_headers(sid, block[:2], F.FLAG_END_STREAM)
    data += F.pack_frame(F.CONTINUATION, 0, sid, block[2:4])
    data += F.pack_frame(F.CONTINUATION, F.FLAG_END_HEADERS, sid, block[4:])
    events = core.receive_data(data)
    assert kinds(events) == ["ResponseReceived", "StreamEnded"]
    assert events[0].headers == [("x-a", "1"), ("x-b", "2")]


def test_interleaved_frame_during_header_block_is_a_connection_error():
    core, peer, sid = start()
    block = peer.encoder.encode([(b":status", b"200")])
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_headers(sid, block, 0) + F.pack_ping(b"12345678"))
    assert info.value.error_code == F.PROTOCOL_ERROR
    core, peer, sid = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.CONTINUATION, F.FLAG_END_HEADERS, sid, b""))


def test_hpack_decoding_error_is_compression_error():
    core, peer, sid = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_headers(sid, b"\xff\xff\xff\xff\xff", F.FLAG_END_HEADERS))
    assert info.value.error_code == F.COMPRESSION_ERROR
    goaway, = peer.sent(core)
    assert goaway.type == F.GOAWAY


def test_padded_headers_and_data_frames():
    core, peer, sid = start()
    block = peer.encoder.encode([(b":status", b"200")])
    data = F.pack_headers(sid, block, F.FLAG_END_HEADERS, pad_length=7)
    data += F.pack_data(sid, b"abc", end_stream=True, pad_length=200)
    events = core.receive_data(data)
    assert kinds(events) == ["ResponseReceived", "DataReceived", "StreamEnded"]
    assert events[1].data == b"abc" and events[1].flow_controlled_length == 204


def test_data_before_headers_resets_stream_and_keeps_connection():
    core, peer, sid = start()
    events = core.receive_data(F.pack_data(sid, b"x"))
    assert kinds(events) == ["StreamReset"]
    assert core.alive


def test_frames_on_closed_or_unknown_streams_are_ignored_but_decoded():
    core, peer, sid = start()
    core.receive_data(peer.response(sid, end_stream=True))
    # The peer keeps using its dynamic table on a stream we no longer track.
    late = peer.headers(sid, [(":status", "200"), ("x-late", "1")], end_stream=True)
    late += F.pack_data(sid, b"late", end_stream=True)
    late += peer.headers(99, [(":status", "404")], end_stream=True)
    assert core.receive_data(late) == []
    sid2 = core.send_request("GET", "https", "example.com", "/", [])
    peer.sent(core)
    events = core.receive_data(peer.headers(sid2, [(":status", "200"), ("x-late", "1")], end_stream=True))
    assert kinds(events) == ["ResponseReceived", "StreamEnded"]
    assert events[0].headers == [("x-late", "1")]


def test_headers_on_stream_zero_and_data_on_stream_zero_are_connection_errors():
    for frame in (F.pack_headers(0, b"", F.FLAG_END_HEADERS), F.pack_data(0, b"x")):
        core, _, _ = start()
        with pytest.raises(H2Error) as info:
            core.receive_data(frame)
        assert info.value.error_code == F.PROTOCOL_ERROR


# --------------------------------------------------------------------------
# flow control
# --------------------------------------------------------------------------

def test_receive_window_updates_follow_chrome_half_window_rule():
    core, peer, sid = start("firefox")
    stream_half = 131072 // 2
    conn_half = (65535 + 12517377) // 2
    core.receive_data(peer.response(sid))
    peer.sent(core)
    core.acknowledge_received_data(sid, stream_half)
    assert peer.sent(core) == []
    core.acknowledge_received_data(sid, 1)
    frame, = peer.sent(core)
    assert frame.type == F.WINDOW_UPDATE and frame.stream_id == sid
    assert struct.unpack(">I", frame.payload)[0] == stream_half + 1
    core.acknowledge_received_data(sid, 10)
    assert peer.sent(core) == [], "counter restarts after an update"
    core.acknowledge_received_data(sid, conn_half)
    frames = peer.sent(core)
    # Connection update first, then the stream, as nghttp2_session_consume does.
    assert [(f.stream_id, struct.unpack(">I", f.payload)[0]) for f in frames] == [
        (0, stream_half + 1 + 10 + conn_half), (sid, 10 + conn_half)]
    core.acknowledge_received_data(sid, 0)
    assert peer.sent(core) == []


def test_no_stream_window_update_after_end_stream_but_connection_still_accounts():
    core, peer, sid = start("firefox")
    core.receive_data(peer.response(sid) + F.pack_data(sid, b"x" * 100, end_stream=True))
    peer.sent(core)
    core.acknowledge_received_data(sid, 131072)
    frames = peer.sent(core)
    assert frames == []
    core.acknowledge_received_data(sid, (65535 + 12517377) // 2)
    frame, = peer.sent(core)
    assert frame.stream_id == 0


def test_data_on_unknown_stream_counts_against_connection_window():
    core, peer, _ = start("firefox")
    half = (65535 + 12517377) // 2
    assert core.receive_data(F.pack_data(77, b"x" * 16000)) == []
    core.recv_unacked = half
    assert core.receive_data(F.pack_data(77, b"x")) == []
    frame, = peer.sent(core)
    assert frame.type == F.WINDOW_UPDATE and frame.stream_id == 0


def test_send_data_respects_frame_size_stream_and_connection_windows():
    core, peer, sid = start(end_stream=False)
    body = b"x" * 70000
    sent = core.send_data(sid, body, end_stream=True)
    assert sent == 16384
    frame, = peer.sent(core)
    assert frame.type == F.DATA and len(frame.payload) == 16384 and not frame.flags & F.FLAG_END_STREAM
    total = sent
    while True:
        n = core.send_data(sid, body[total:], end_stream=True)
        if not n:
            break
        total += n
    assert total == 65535, "the default windows are exhausted"
    assert core.send_window == 0 and core.streams[sid].send_window == 0
    assert core.send_window_for(sid) == 0
    events = core.receive_data(F.pack_window_update(0, 10000))
    assert kinds(events) == ["WindowUpdated"] and events[0].stream_id == 0
    assert core.send_data(sid, body[total:], end_stream=True) == 0, "stream window still 0"
    events = core.receive_data(F.pack_window_update(sid, 100000))
    assert events[0].stream_id == sid and events[0].delta == 100000
    assert core.send_window_for(sid) == 10000
    n = core.send_data(sid, body[total:], end_stream=True)
    assert n == 4465 and core.streams[sid].state == "half_closed_local"
    frames = peer.sent(core)
    assert frames[-1].flags & F.FLAG_END_STREAM
    assert sum(len(f.payload) for f in frames) == 70000 - 16384


def test_send_data_empty_end_stream_and_errors():
    core, peer, sid = start(end_stream=False)
    assert core.send_data(sid, b"", end_stream=True) == 0
    frame, = peer.sent(core)
    assert frame.type == F.DATA and frame.flags == F.FLAG_END_STREAM and frame.payload == b""
    with pytest.raises(H2Error):
        core.send_data(sid, b"x")
    with pytest.raises(H2Error):
        core.send_data(999, b"x")


def test_window_update_errors():
    core, peer, sid = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_frame(F.WINDOW_UPDATE, 0, 0, b"\x00\x00\x00\x00"))
    assert info.value.error_code == F.PROTOCOL_ERROR
    core, peer, sid = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_window_update(0, (1 << 31) - 1))
    assert info.value.error_code == F.FLOW_CONTROL_ERROR
    core, peer, sid = start()
    events = core.receive_data(F.pack_frame(F.WINDOW_UPDATE, 0, sid, b"\x00\x00\x00\x00"))
    assert kinds(events) == ["StreamReset"] and core.alive
    core, peer, sid = start()
    events = core.receive_data(F.pack_window_update(sid, (1 << 31) - 1))
    assert kinds(events) == ["StreamReset"] and events[0].error_code == F.FLOW_CONTROL_ERROR
    core, peer, sid = start()
    assert core.receive_data(F.pack_window_update(55, 1)) == []
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.WINDOW_UPDATE, 0, 0, b"\x00\x01"))


# --------------------------------------------------------------------------
# push, ping, goaway, rst_stream, priority
# --------------------------------------------------------------------------

def test_push_promise_is_refused_and_its_frames_ignored():
    core, peer, sid = start()
    block = peer.encoder.encode([(b":method", b"GET"), (b":path", b"/push.css"),
                                 (b":scheme", b"https"), (b":authority", b"example.com")])
    data = F.pack_frame(F.PUSH_PROMISE, F.FLAG_END_HEADERS, sid, struct.pack(">I", 2) + block)
    data += peer.response(2, extra=[("x-pushed", "1")]) + F.pack_data(2, b"pushed", end_stream=True)
    data += peer.response(sid, end_stream=True)
    events = core.receive_data(data)
    assert kinds(events) == ["PushPromiseRefused", "ResponseReceived", "StreamEnded"]
    assert events[0].promised_stream_id == 2 and events[0].stream_id == sid
    assert events[0].headers[1] == (":path", "/push.css")
    frames = peer.sent(core)
    assert [f.name for f in frames] == ["RST_STREAM"]
    assert frames[0].stream_id == 2 and struct.unpack(">I", frames[0].payload)[0] == F.REFUSED_STREAM
    assert core.highest_promised_stream == 2
    core.close()
    goaway, = peer.sent(core)
    assert struct.unpack(">I", goaway.payload[:4])[0] == 2, "GOAWAY names the last pushed stream"


def test_push_promise_with_continuation_and_padding():
    core, peer, sid = start()
    block = peer.encoder.encode([(b":method", b"GET"), (b":path", b"/p")])
    payload = b"\x02" + struct.pack(">I", 4) + block[:3] + b"\x00\x00"
    data = F.pack_frame(F.PUSH_PROMISE, F.FLAG_PADDED, sid, payload)
    data += F.pack_frame(F.CONTINUATION, F.FLAG_END_HEADERS, sid, block[3:])
    events = core.receive_data(data)
    assert kinds(events) == ["PushPromiseRefused"]
    assert events[0].promised_stream_id == 4


@pytest.mark.parametrize("promised", [0, 3, 2])
def test_invalid_push_promise_ids_are_connection_errors(promised):
    core, peer, sid = start()
    if promised == 2:
        core.highest_promised_stream = 2
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.PUSH_PROMISE, F.FLAG_END_HEADERS, sid, struct.pack(">I", promised)))


def test_ping_is_acked_and_ping_ack_reported():
    core, peer, _ = start()
    events = core.receive_data(F.pack_ping(b"abcdefgh"))
    assert kinds(events) == ["PingReceived"]
    ack, = peer.sent(core)
    assert ack.type == F.PING and ack.flags == F.FLAG_ACK and ack.payload == b"abcdefgh"
    data = core.ping()
    frame, = peer.sent(core)
    assert frame.payload == data and frame.flags == 0 and len(data) == 8
    events = core.receive_data(F.pack_ping(data, ack=True))
    assert kinds(events) == ["PingAckReceived"] and events[0].data == data
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_frame(F.PING, 0, 0, b"short"))
    assert info.value.error_code == F.FRAME_SIZE_ERROR
    core, _, _ = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.PING, 0, 1, b"12345678"))


def test_goaway_marks_dead_and_flags_streams_above_last_id():
    core, peer, sid = start()
    sid3 = core.send_request("GET", "https", "example.com", "/b", [])
    events = core.receive_data(F.pack_goaway(1, F.NO_ERROR, b"shutting down"))
    assert kinds(events) == ["ConnectionTerminated"]
    assert events[0].last_stream_id == 1 and events[0].debug_data == b"shutting down"
    assert not core.alive
    assert core.last_stream_id == 1
    assert core.streams[sid3].refused_by_goaway and not core.streams[sid].refused_by_goaway
    with pytest.raises(H2Error) as info:
        core.send_request("GET", "https", "example.com", "/c", [])
    assert info.value.retryable
    # stream 1 can still complete
    events = core.receive_data(peer.response(sid, end_stream=True))
    assert kinds(events) == ["ResponseReceived", "StreamEnded"]
    events = core.receive_data(F.pack_goaway(0, F.ENHANCE_YOUR_CALM))
    assert core.last_stream_id == 0 and core.goaway_error_code == F.ENHANCE_YOUR_CALM
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.GOAWAY, 0, 0, b"\x00\x00"))


def test_rst_stream_from_peer():
    core, peer, sid = start()
    events = core.receive_data(F.pack_rst_stream(sid, F.REFUSED_STREAM))
    assert kinds(events) == ["StreamReset"]
    assert events[0].remote and events[0].error_code == F.REFUSED_STREAM
    assert sid not in core.streams and core.alive
    assert core.receive_data(F.pack_rst_stream(sid, F.CANCEL)) == [], "closed stream: ignored"
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_rst_stream(sid + 2, F.CANCEL))
    assert "idle" in str(info.value)
    core, _, _ = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.RST_STREAM, 0, 0, b"\x00\x00\x00\x01"))
    core, _, _ = start()
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_frame(F.RST_STREAM, 0, 1, b"\x00"))
    assert info.value.error_code == F.FRAME_SIZE_ERROR


def test_local_reset_and_close():
    core, peer, sid = start()
    core.reset_stream(sid, F.CANCEL)
    rst, = peer.sent(core)
    assert rst.type == F.RST_STREAM and struct.unpack(">I", rst.payload)[0] == F.CANCEL
    assert sid not in core.streams
    core.reset_stream(sid)
    assert peer.sent(core) == []
    core.close()
    goaway, = peer.sent(core)
    assert goaway.type == F.GOAWAY
    assert goaway.payload == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert not core.alive
    core.close()
    assert peer.sent(core) == []
    with pytest.raises(H2Error) as info:
        core.send_request("GET", "https", "h", "/", [])
    assert info.value.retryable


def test_priority_frames_are_ignored_but_validated():
    core, peer, sid = start()
    assert core.receive_data(F.pack_priority(sid, True, 0, 16)) == []
    assert core.receive_data(F.pack_priority(99, True, 0, 16)) == []
    events = core.receive_data(F.pack_frame(F.PRIORITY, 0, sid, b"\x00\x00"))
    assert kinds(events) == ["StreamReset"] and events[0].error_code == F.FRAME_SIZE_ERROR
    with pytest.raises(H2Error):
        core.receive_data(F.pack_priority(0, True, 0, 16))


def test_unknown_frame_types_and_oversized_frames():
    core, peer, sid = start()
    assert core.receive_data(F.pack_frame(0x0A, 0, 0, b"altsvc")) == []
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_frame(F.DATA, 0, sid, b"x" * 16385))
    assert info.value.error_code == F.FRAME_SIZE_ERROR
    with pytest.raises(H2Error):
        core.receive_data(b"\x00")


def test_response_header_block_too_large_is_connection_error():
    core, peer, sid = start()
    core.decoder.max_header_list_size = 100
    block = peer.encoder.encode([(b":status", b"200"), (b"x-long", b"v" * 200)])
    with pytest.raises(H2Error) as info:
        core.receive_data(F.pack_headers(sid, block, F.FLAG_END_HEADERS))
    assert info.value.error_code == F.COMPRESSION_ERROR


def test_decoder_allows_server_table_up_to_advertised_size():
    core, peer, sid = start("chrome")
    assert core.decoder.max_allowed_table_size == 65536
    peer.encoder.header_table_size = 60000
    events = core.receive_data(peer.response(sid, extra=[("x", "y")], end_stream=True))
    assert kinds(events) == ["ResponseReceived", "StreamEnded"]
    core, peer, sid = start("safari")
    assert core.decoder.max_allowed_table_size == 4096
    peer.encoder.header_table_size = 60000
    with pytest.raises(H2Error):
        core.receive_data(peer.response(sid, extra=[("x", "y")], end_stream=True))


def test_multiple_streams_are_tracked_independently():
    core, peer, a = start()
    b = core.send_request("GET", "https", "example.com", "/b", [])
    peer.sent(core)
    data = peer.response(b, "404") + peer.response(a, "200") + F.pack_data(a, b"A", end_stream=True)
    data += F.pack_data(b, b"B", end_stream=True)
    events = core.receive_data(data)
    assert [(type(e).__name__, e.stream_id) for e in events] == [
        ("ResponseReceived", b), ("ResponseReceived", a), ("DataReceived", a), ("StreamEnded", a),
        ("DataReceived", b), ("StreamEnded", b)]
    assert core.streams == {}


def test_receive_after_failure_raises():
    core, _, _ = start()
    with pytest.raises(H2Error):
        core.receive_data(F.pack_frame(F.PING, 0, 0, b""))
    with pytest.raises(H2Error):
        core.receive_data(F.pack_ping(b"12345678"))
    assert core.receive_data(b"") == []


def test_custom_akamai_spec_drives_preface():
    core = H2Core(spec_from_akamai("3:100;4:1048576|1048576|0|m,s,p,a"))
    core.initiate_connection()
    peer = Peer()
    frames = peer.sent(core)
    assert F.parse_settings(frames[0].payload) == [(3, 100), (4, 1048576)]
    assert core.recv_window_max == 65535 + 1048576
    assert core.stream_recv_window == 1048576
    core.send_request("GET", "https", "h", "/", [])
    head, = peer.sent(core)
    fields = peer.decoder.decode(head.payload[5:], raw=True)
    assert [n for n, _ in fields] == [b":method", b":scheme", b":path", b":authority"]

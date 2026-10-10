"""RFC 9113 frame codec tests for curl_reap._h2.frames."""
import struct

import pytest

from curl_reap._h2 import frames as F
from curl_reap._h2.errors import H2Error


def parse(data, max_frame_size=F.DEFAULT_MAX_FRAME_SIZE):
    parser = F.FrameParser(max_frame_size)
    parser.feed(data)
    return list(parser.frames())


def test_frame_header_layout():
    frame = F.pack_frame(F.PING, F.FLAG_ACK, 0, b"12345678")
    assert frame[:3] == b"\x00\x00\x08"
    assert frame[3] == F.PING
    assert frame[4] == F.FLAG_ACK
    assert frame[5:9] == b"\x00\x00\x00\x00"
    assert frame[9:] == b"12345678"
    big = F.pack_frame(F.DATA, 0, 0x7FFFFFFF | 0x80000000, b"")
    assert big[5:9] == b"\x7f\xff\xff\xff", "the reserved bit is cleared"
    with pytest.raises(ValueError):
        F.pack_frame(F.DATA, 0, 1, b"x" * (F.MAX_FRAME_SIZE_LIMIT + 1))


def test_data_frame_padding_round_trip():
    frame = F.pack_data(5, b"hello", end_stream=True, pad_length=3)
    parsed, = parse(frame)
    assert parsed.type == F.DATA
    assert parsed.flags == F.FLAG_END_STREAM | F.FLAG_PADDED
    assert parsed.stream_id == 5
    assert parsed.payload == b"\x03hello\x00\x00\x00"
    assert F.strip_padding(parsed) == b"hello"
    plain, = parse(F.pack_data(5, b"hello"))
    assert plain.flags == 0 and F.strip_padding(plain) == b"hello"
    with pytest.raises(ValueError):
        F.pack_data(1, b"x", pad_length=256)


def test_padding_errors():
    bad = F.Frame(F.DATA, F.FLAG_PADDED, 1, b"\x05abc")
    with pytest.raises(H2Error) as info:
        F.strip_padding(bad)
    assert info.value.error_code == F.PROTOCOL_ERROR
    empty = F.Frame(F.DATA, F.FLAG_PADDED, 1, b"")
    with pytest.raises(H2Error):
        F.strip_padding(empty)
    exact = F.Frame(F.DATA, F.FLAG_PADDED, 1, b"\x04abc")
    with pytest.raises(H2Error):
        F.strip_padding(exact)
    only_padding = F.Frame(F.DATA, F.FLAG_PADDED, 1, b"\x03abc")
    assert F.strip_padding(only_padding) == b""


def test_headers_frame_with_priority_field_matches_chrome_layout():
    frame = F.pack_headers(1, b"\x82", F.FLAG_END_STREAM | F.FLAG_END_HEADERS | F.FLAG_PRIORITY,
                           priority=(True, 0, 256))
    parsed, = parse(frame)
    assert parsed.flags == 0x25
    assert parsed.payload == b"\x80\x00\x00\x00\xff\x82"
    assert F.parse_priority_field(parsed.payload) == (True, 0, 256)
    firefox = F.pack_headers(1, b"", F.FLAG_END_HEADERS | F.FLAG_PRIORITY, priority=(False, 0, 42))
    assert parse(firefox)[0].payload == b"\x00\x00\x00\x00\x29"
    with pytest.raises(ValueError):
        F.pack_headers(1, b"", F.FLAG_PRIORITY)
    with pytest.raises(ValueError):
        F.pack_headers(1, b"", F.FLAG_END_HEADERS, priority=(False, 0, 1))
    with pytest.raises(ValueError):
        F.pack_priority_field(False, 0, 0)
    with pytest.raises(H2Error):
        F.parse_priority_field(b"\x00\x00")


def test_headers_frame_padding():
    frame = F.pack_headers(3, b"\x82\x87", F.FLAG_END_HEADERS, pad_length=2)
    parsed, = parse(frame)
    assert parsed.flags == F.FLAG_END_HEADERS | F.FLAG_PADDED
    assert F.strip_padding(parsed) == b"\x82\x87"


def test_header_block_split_into_continuation_frames():
    block = bytes(range(256)) * 10  # 2560 bytes
    data = F.pack_header_block(7, block, F.FLAG_END_STREAM | F.FLAG_END_HEADERS | F.FLAG_PRIORITY,
                               (True, 0, 256), max_frame_size=1000)
    frames = parse(data)
    assert [f.type for f in frames] == [F.HEADERS, F.CONTINUATION, F.CONTINUATION]
    assert frames[0].flags == F.FLAG_END_STREAM | F.FLAG_PRIORITY
    assert len(frames[0].payload) == 1000
    assert frames[1].flags == 0
    assert frames[2].flags == F.FLAG_END_HEADERS
    assert all(f.stream_id == 7 for f in frames)
    joined = frames[0].payload[5:] + frames[1].payload + frames[2].payload
    assert joined == block
    single = parse(F.pack_header_block(1, b"\x82", F.FLAG_END_HEADERS, None, 16384))
    assert len(single) == 1 and single[0].flags == F.FLAG_END_HEADERS


def test_settings_frame():
    frame = F.pack_settings([(1, 65536), (2, 0), (4, 6291456), (6, 262144)])
    parsed, = parse(frame)
    assert parsed.type == F.SETTINGS and parsed.stream_id == 0 and parsed.flags == 0
    assert F.parse_settings(parsed.payload) == [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
    ack, = parse(F.pack_settings((), ack=True))
    assert ack.flags == F.FLAG_ACK and ack.payload == b""
    with pytest.raises(ValueError):
        F.pack_settings([(1, 1)], ack=True)
    with pytest.raises(H2Error) as info:
        F.parse_settings(b"\x00\x01\x00")
    assert info.value.error_code == F.FRAME_SIZE_ERROR


def test_other_control_frames():
    rst, = parse(F.pack_rst_stream(9, F.REFUSED_STREAM))
    assert rst.type == F.RST_STREAM and rst.stream_id == 9
    assert struct.unpack(">I", rst.payload)[0] == F.REFUSED_STREAM
    ping, = parse(F.pack_ping(b"abcdefgh"))
    assert ping.flags == 0 and ping.payload == b"abcdefgh"
    with pytest.raises(ValueError):
        F.pack_ping(b"short")
    goaway, = parse(F.pack_goaway(5, F.NO_ERROR, b"bye"))
    assert goaway.payload == b"\x00\x00\x00\x05\x00\x00\x00\x00bye"
    window, = parse(F.pack_window_update(0, 15663105))
    assert window.payload == struct.pack(">I", 15663105)
    with pytest.raises(ValueError):
        F.pack_window_update(0, 0)
    with pytest.raises(ValueError):
        F.pack_window_update(0, 1 << 31)
    prio, = parse(F.pack_priority(3, False, 0, 201))
    assert prio.payload == b"\x00\x00\x00\x00\xc8"


def test_parser_handles_partial_input_and_unknown_types():
    parser = F.FrameParser()
    frame = F.pack_frame(0x42, 0x7, 11, b"payload")  # unknown type passes through
    parser.feed(frame[:4])
    assert list(parser.frames()) == []
    parser.feed(frame[4:12])
    assert list(parser.frames()) == []
    parser.feed(frame[12:] + F.pack_ping(b"12345678")[:5])
    frames = list(parser.frames())
    assert len(frames) == 1
    assert frames[0] == F.Frame(0x42, 0x7, 11, b"payload")
    assert frames[0].name == "UNKNOWN_0x42"
    assert parser.buffered == 5


def test_parser_enforces_max_frame_size():
    parser = F.FrameParser(16384)
    parser.feed(F.pack_frame(F.DATA, 0, 1, b"x" * 16384))
    assert len(list(parser.frames())) == 1
    parser.feed(F.pack_frame(F.DATA, 0, 1, b"x" * 16385))
    with pytest.raises(H2Error) as info:
        list(parser.frames())
    assert info.value.error_code == F.FRAME_SIZE_ERROR

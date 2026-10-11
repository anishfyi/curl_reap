"""HPACK encoder tests: nghttp2's representation rules and dynamic table reuse.

The second half replays multi request sessions captured from curl_cffi
0.16.3 (nghttp2 1.63.0) on 2026-10-11 against a local TLS server and checks
that every HEADERS block curl_reap builds is byte for byte the block nghttp2
sent, including dynamic table hits on later requests, the never indexed
cookie and authorization rules, oversized headers, and the dynamic table
size update nghttp2 emits after the server's SETTINGS_HEADER_TABLE_SIZE.
``NGHTTP2_SEQUENCES`` at the end of this file is that capture (header
values repeated more than 20 times are written ``x*count``).
"""
import re

import pytest

hpack = pytest.importorskip("hpack")
from hpack import Decoder  # noqa: E402

from curl_reap._h2 import H2Core, spec  # noqa: E402
from curl_reap._h2 import frames as F  # noqa: E402
from curl_reap._h2.hpack_encoder import (  # noqa: E402
    DEFAULT_TABLE_SIZE, NEVER_INDEXING, STATIC_TABLE, STATIC_TABLE_LENGTH, WITH_INDEXING,
    WITHOUT_INDEXING, HpackEncoder, encode_integer, encode_string, entry_size, huffman_length,
)
from curl_reap._h2.templates_data import SPECS  # noqa: E402


def walk(block):
    """Classify every field of a block: (kind, index_or_None, name_huffman, value_huffman)."""
    out = []
    pos = 0

    def integer(prefix):
        nonlocal pos
        mask = (1 << prefix) - 1
        value = block[pos] & mask
        pos += 1
        if value < mask:
            return value
        shift = 0
        while True:
            byte = block[pos]
            pos += 1
            value += (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    def string():
        nonlocal pos
        huffman = bool(block[pos] & 0x80)
        length = integer(7)
        pos += length
        return huffman

    while pos < len(block):
        first = block[pos]
        if first & 0x80:
            out.append(("indexed", integer(7), None, None))
            continue
        if first & 0x40:
            kind, prefix = "incremental", 6
        elif first & 0x20:
            out.append(("size-update", integer(5), None, None))
            continue
        elif first & 0x10:
            kind, prefix = "never", 4
        else:
            kind, prefix = "without", 4
        index = integer(prefix)
        name_huffman = None
        if index == 0:
            name_huffman = string()
        value_huffman = string()
        out.append((kind, index or None, name_huffman, value_huffman))
    return out


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def test_integer_encoding_rfc7541_examples():
    assert encode_integer(10, 5) == b"\x0a"
    assert encode_integer(1337, 5) == b"\x1f\x9a\x0a"
    assert encode_integer(42, 8) == b"\x2a"
    assert encode_integer(62, 7, 0x80) == b"\xbe"
    assert encode_integer(4096, 5, 0x20) == b"\x3f\xe1\x1f"
    with pytest.raises(ValueError):
        encode_integer(-1, 5)


def test_huffman_only_when_shorter():
    assert huffman_length(b"te") == 2 and encode_string(b"te") == b"\x02te"
    assert huffman_length(b"?0") == 2 and encode_string(b"?0")[0] == 0x02
    assert huffman_length(b"none") == 3
    assert encode_string(b"none") == b"\x83\xa8\xf5\x17"  # Huffman flag set, 3 octets (as captured)
    assert encode_string(b"") == b"\x00"
    assert encode_string(b"/a") == b"\x02/a"
    assert encode_string(b"www.example.com") == b"\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"


def test_static_table_from_hpack_package():
    assert STATIC_TABLE_LENGTH == 61
    assert STATIC_TABLE[0] == (b":authority", b"")
    assert STATIC_TABLE[1] == (b":method", b"GET")
    assert STATIC_TABLE[57] == (b"user-agent", b"")
    assert STATIC_TABLE[60] == (b"www-authenticate", b"")


# --------------------------------------------------------------------------
# representation rules
# --------------------------------------------------------------------------

def test_indexing_mode_rules():
    enc = HpackEncoder()
    assert enc.indexing_mode(b":path", b"/x") == WITHOUT_INDEXING
    assert enc.indexing_mode(b"content-length", b"1") == WITHOUT_INDEXING
    for name in (b"age", b"etag", b"if-modified-since", b"if-none-match", b"location", b"set-cookie"):
        assert enc.indexing_mode(name, b"v") == WITHOUT_INDEXING
    assert enc.indexing_mode(b"authorization", b"Bearer x") == NEVER_INDEXING
    assert enc.indexing_mode(b"cookie", b"a=b") == NEVER_INDEXING
    assert enc.indexing_mode(b"cookie", b"a" * 19) == NEVER_INDEXING
    assert enc.indexing_mode(b"cookie", b"a" * 20) == WITH_INDEXING
    assert enc.indexing_mode(b"user-agent", b"Mozilla") == WITH_INDEXING
    assert enc.indexing_mode(b":authority", b"example.com") == WITH_INDEXING
    assert enc.indexing_mode(b":method", b"HEAD") == WITH_INDEXING
    # three quarters of the table: 3072 bytes including the 32 byte overhead
    assert enc.indexing_mode(b"x-big", b"q" * 3035) == WITH_INDEXING
    assert entry_size(b"x-big", b"q" * 3035) == 3072
    assert enc.indexing_mode(b"x-big", b"q" * 3036) == WITHOUT_INDEXING
    enc.change_table_size(2048)
    assert enc.indexing_mode(b"x-big", b"q" * 1600) == WITHOUT_INDEXING


def test_static_name_and_value_matches():
    enc = HpackEncoder()
    block = enc.encode([
        (b":method", b"GET"), (b":method", b"POST"), (b":scheme", b"https"),
        (b":scheme", b"http"), (b":path", b"/"), (b":path", b"/index.html"),
        (b"accept-encoding", b"gzip, deflate"),
    ])
    assert block == b"\x82\x83\x87\x86\x84\x85\x90"
    assert enc.dynamic_table == []


def test_literal_with_static_name_and_dynamic_hits():
    enc = HpackEncoder()
    first = enc.encode([(b":authority", b"example.com"), (b"user-agent", b"ua/1"), (b"x-token", b"abc")])
    kinds = walk(first)
    assert kinds[0] == ("incremental", 1, None, True)
    assert kinds[1] == ("incremental", 58, None, True)  # huffman: 3 < 4 bytes
    assert kinds[2] == ("incremental", None, True, True)  # abc: 2 < 3 bytes
    assert enc.dynamic_table == [(b"x-token", b"abc"), (b"user-agent", b"ua/1"), (b":authority", b"example.com")]
    second = enc.encode([(b":authority", b"example.com"), (b"user-agent", b"ua/1"), (b"x-token", b"abc")])
    assert second == b"\xc0\xbf\xbe"  # dynamic indices 64, 63, 62
    assert len(second) < len(first)
    decoder = Decoder()
    assert decoder.decode(first, raw=True) == [(b":authority", b"example.com"), (b"user-agent", b"ua/1"), (b"x-token", b"abc")]
    assert decoder.decode(second, raw=True) == [(b":authority", b"example.com"), (b"user-agent", b"ua/1"), (b"x-token", b"abc")]


def test_name_only_match_uses_newest_dynamic_entry_unless_static_has_the_name():
    enc = HpackEncoder()
    enc.encode([(b"x-custom", b"v1")])
    enc.encode([(b"x-custom", b"v2")])
    third = enc.encode([(b"x-custom", b"v3")])
    assert walk(third) == [("incremental", 62, None, False)]  # newest x-custom is v2 at 62
    assert enc.dynamic_table[:3] == [(b"x-custom", b"v3"), (b"x-custom", b"v2"), (b"x-custom", b"v1")]
    enc.encode([(b"user-agent", b"ua/1")])
    block = enc.encode([(b"user-agent", b"ua/2")])
    assert walk(block) == [("incremental", 58, None, True)], "static name wins over a dynamic name match"


def test_never_indexed_fields_use_static_name_and_skip_dynamic_values():
    enc = HpackEncoder()
    block = enc.encode([(b"cookie", b"a=b"), (b"authorization", b"Bearer abc")])
    assert walk(block) == [("never", 32, None, False), ("never", 23, None, True)]
    assert enc.dynamic_table == []
    again = enc.encode([(b"cookie", b"a=b"), (b"authorization", b"Bearer abc")])
    assert again == block
    long_cookie = enc.encode([(b"cookie", b"session=abcdefghijklmnopqr")])
    assert walk(long_cookie) == [("incremental", 32, None, True)]
    assert enc.encode([(b"cookie", b"session=abcdefghijklmnopqr")]) == b"\xbe"
    assert walk(enc.encode([(b"cookie", b"short=1")])) == [("never", 32, None, True)]


def test_without_indexing_fields_never_enter_the_table():
    enc = HpackEncoder()
    block = enc.encode([(b":path", b"/some/path?q=1"), (b"content-length", b"100"),
                        (b"if-none-match", b"\"etag1\""), (b"x-big", b"q" * 3100)])
    assert walk(block) == [("without", 4, None, True), ("without", 28, None, True),
                           ("without", 41, None, True), ("without", None, True, True)]
    assert enc.dynamic_table == []
    assert enc.encode([(b"x-big", b"q" * 3100)]) == block[-len(encode_string(b"x-big")) - len(encode_string(b"q" * 3100)) - 1:]


def test_eviction_keeps_table_within_limit():
    enc = HpackEncoder()
    value = b"v" * 1000
    for i in range(6):
        enc.encode([(b"x-%d" % i, value)])
    assert enc.table_size <= DEFAULT_TABLE_SIZE
    assert len(enc.dynamic_table) == 3  # 1035 bytes each
    assert [n for n, _ in enc.dynamic_table] == [b"x-5", b"x-4", b"x-3"]
    big = enc.encode([(b"x-huge", b"h" * 3000)])  # 3038 > 3072? no: with indexing
    assert walk(big)[0][0] == "incremental"
    assert enc.dynamic_table[0] == (b"x-huge", b"h" * 3000)
    assert enc.table_size <= DEFAULT_TABLE_SIZE


def test_table_size_update_follows_nghttp2():
    enc = HpackEncoder()
    assert enc.encode([(b":method", b"GET")]) == b"\x82", "no update without a peer setting"
    enc.change_table_size(65536)
    assert enc.max_table_size == 4096, "nghttp2 caps its deflater at 4096"
    assert enc.encode([(b":method", b"GET")]) == b"\x3f\xe1\x1f\x82"
    assert enc.encode([(b":method", b"GET")]) == b"\x82", "emitted once"
    enc.change_table_size(2048)
    assert enc.max_table_size == 2048
    assert enc.encode([(b":method", b"GET")]) == b"\x3f\xe1\x0f\x82"
    enc.change_table_size(1024)
    enc.change_table_size(4096)
    assert enc.encode([(b":method", b"GET")]) == b"\x3f\xe1\x07\x3f\xe1\x1f\x82", \
        "the lowest intermediate size is signalled first"
    decoder = Decoder()
    decoder.decode(b"\x3f\xe1\x07\x3f\xe1\x1f\x82", raw=True)
    assert decoder.header_table_size == 4096


def test_shrinking_evicts_entries():
    enc = HpackEncoder()
    enc.encode([(b"x-a", b"a" * 500), (b"x-b", b"b" * 500)])
    assert len(enc.dynamic_table) == 2
    enc.change_table_size(600)
    assert enc.dynamic_table == [(b"x-b", b"b" * 500)]
    enc.change_table_size(0)
    assert enc.dynamic_table == [] and enc.table_size == 0
    block = enc.encode([(b"x-c", b"c")])
    assert walk(block) == [("size-update", 0, None, None), ("without", None, False, False)]  # nothing fits a zero table; x-c does not shrink
    assert enc.dynamic_table == [], "nothing fits in a zero sized table"


def test_small_deflater_cap_signals_at_start():
    enc = HpackEncoder(max_table_size=1024)
    assert enc.encode([(b":method", b"GET")]) == b"\x3f\xe1\x07\x82"


def test_str_headers_are_latin1_with_utf8_fallback():
    enc = HpackEncoder()
    assert enc.encode([("x-a", "caf\xe9")]) == enc.__class__().encode([(b"x-a", b"caf\xe9")])
    assert enc.__class__().encode([("x-b", "☃")]) == enc.__class__().encode([(b"x-b", "☃".encode("utf-8"))])


# --------------------------------------------------------------------------
# replay of curl_cffi sessions
# --------------------------------------------------------------------------

def expand(value):
    match = re.match(r"^(.*?)([^*])\*(\d+)$", value)
    if match:
        return match.group(1) + match.group(2) * int(match.group(3))
    return value


def request_headers(target, request):
    template = [tuple(h) for h in SPECS[target]["headers"] if not h[0].startswith(":")]
    headers = [(name, expand(request["override"].get(name, value))) for name, value in template]
    headers += [(name, expand(value)) for name, value in request["extra"]]
    return headers


def headers_block(core):
    data = core.data_to_send()
    parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)
    if data.startswith(F.CONNECTION_PREFACE):
        data = data[len(F.CONNECTION_PREFACE):]
    parser.feed(data)
    frames = [f for f in parser.frames() if f.type == F.HEADERS]
    assert len(frames) == 1
    payload = frames[0].payload
    if frames[0].flags & F.FLAG_PRIORITY:
        payload = payload[5:]
    return frames[0].flags, payload


SEQUENCE_NAMES = [
    "chrome_path_root_and_reuse", "chrome_server_table_4096", "chrome_server_table_2048",
    "chrome_server_table_65536", "firefox_reuse", "safari_reuse", "chrome_header_rules",
    "chrome_name_only_order",
]


def test_sequence_fixture_is_complete():
    assert [s["name"] for s in NGHTTP2_SEQUENCES] == SEQUENCE_NAMES
    assert sum(len(c) for s in NGHTTP2_SEQUENCES for c in s["connections"]) == 27


@pytest.mark.parametrize("name", SEQUENCE_NAMES)
def test_nghttp2_session_replay(name):
    scenario = next(s for s in NGHTTP2_SEQUENCES if s["name"] == name)
    target = scenario["target"]
    server_settings = F.pack_settings(scenario["server_settings"])
    for requests in scenario["connections"]:
        core = H2Core(spec(target))
        core.initiate_connection()
        for index, request in enumerate(requests):
            body = request["flags"] & F.FLAG_END_STREAM == 0
            core.send_request(request["method"], "https", request["authority"], request["path"],
                              request_headers(target, request), end_stream=not body)
            flags, block = headers_block(core)
            assert flags == request["flags"]
            assert block.hex() == request["block"], "%s request %d" % (scenario["name"], index)
            updates = [v for kind, v, _, _ in walk(block) if kind == "size-update"]
            assert updates == request["updates"]
            if index == 0:
                # The server's SETTINGS arrive after the first request went out.
                core.receive_data(server_settings)
                core.data_to_send()
        if len(requests) > 1 and requests[0]["path"] == requests[1]["path"]:
            assert len(requests[1]["block"]) < len(requests[0]["block"]) // 4


def test_second_request_block_is_smaller_through_dynamic_table():
    core = H2Core(spec("chrome"))
    core.initiate_connection()
    headers = [(n, v) for n, v in SPECS["chrome"]["headers"] if not n.startswith(":")]
    core.send_request("GET", "https", "example.com", "/some/path?q=1", headers)
    _, first = headers_block(core)
    core.send_request("GET", "https", "example.com", "/some/path?q=2", headers)
    _, second = headers_block(core)
    assert len(first) > 400
    assert len(second) < 40
    kinds = walk(second)
    assert kinds[0] == ("indexed", 2, None, None)
    assert kinds[1] == ("indexed", 75, None, None)       # :authority from the dynamic table
    assert kinds[2] == ("indexed", 7, None, None)
    assert kinds[3][0] == "without" and kinds[3][1] == 4  # :path literal every time
    assert all(kind == "indexed" and 62 <= index <= 74 for kind, index, _, _ in kinds[4:])
    decoder = Decoder()
    decoder.max_allowed_table_size = 65536
    assert [n for n, _ in decoder.decode(first, raw=True)][:4] == [b":method", b":authority", b":scheme", b":path"]
    assert decoder.decode(second, raw=True)[3] == (b":path", b"/some/path?q=2")


def test_peer_header_table_size_setting_reaches_the_encoder():
    core = H2Core(spec("chrome"))
    core.initiate_connection()
    core.data_to_send()
    core.receive_data(F.pack_settings([(F.SETTINGS_HEADER_TABLE_SIZE, 512)]))
    assert core.encoder.max_table_size == 512
    core.send_request("GET", "https", "example.com", "/", [("user-agent", "x" * 400)])
    _, block = headers_block(core)
    assert walk(block)[0] == ("size-update", 512, None, None)
    assert walk(block)[-1] == ("without", 58, None, True), "400 + 32 bytes exceed 3/4 of 512"


# Captured from curl_cffi 0.16.3 (libcurl 8.21.0-IMPERSONATE, nghttp2 1.63.0)
# on 2026-10-11 with a scratch variant of tools/capture_h2.py: one TLS
# server answering every request with 200, several requests per Session so
# connections are reused, and the listed server SETTINGS sent right after
# the handshake (the client's first HEADERS always precedes them).
NGHTTP2_SEQUENCES = \
[{'name': 'chrome_path_root_and_reuse',
  'target': 'chrome',
  'server_settings': [[3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56841',
                    'path': '/',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79a0f878440874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56841',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82cb87048b6107a4ac5634cffe76803fcac9c8c7c6c5c4c3c2c1c0bfbe'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56841',
                    'path': '/other?x=2',
                    'override': {},
                    'extra': [['referer', 'https://example.com/']],
                    'flags': 37,
                    'updates': [],
                    'block': '82cb87048860e99cb67f9e6017cac9c8c7c6c5c4c3c2c1c0bfbe738f9d29ad171860be474d7415721e963f'},
                   {'method': 'POST',
                    'authority': '127.0.0.1:56841',
                    'path': '/post',
                    'override': {},
                    'extra': [['cookie', 'a=b'],
                              ['content-type', 'application/x-www-form-urlencoded'],
                              ['content-length', '100']],
                    'flags': 36,
                    'updates': [],
                    'block': '83cc87048462b3a13fcbcac9c8c7c6c5c4c3c2c1c0bf1f1103613d625f981d75d0620d263d4c795bc78f0b4a7b295adb282d443c85930f0d820801'},
                   {'method': 'HEAD',
                    'authority': '127.0.0.1:56841',
                    'path': '/head',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '420448454144ce87048462728e4fcdcccbcac9c8c7c6c5c4c3c2c1'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56841',
                    'path': '/bigcookie',
                    'override': {},
                    'extra': [['cookie', 'c=z*4000']],
                    'flags': 37,
                    'updates': [],
                    'block': '82ce87048762334c439fa98bcdcccbcac9c8c7c6c5c4c3c2c10f11ffaf1a241efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7efdfbf7f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56841',
                    'path': '/index.html',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82ce8785cdcccbcac9c8c7c6c5c4c3c2c1'},
                   {'method': 'PUT',
                    'authority': '127.0.0.1:56841',
                    'path': '/put',
                    'override': {},
                    'extra': [['content-type', 'application/octet-stream'],
                              ['content-length', '70000']],
                    'flags': 36,
                    'updates': [],
                    'block': '4203505554cf87048362bb53cecdcccbcac9c8c7c6c5c4c3c25f901d75d0620d263d4c1c892a56426c28e90f0d847400003f'}],
                  [{'method': 'PUT',
                    'authority': '127.0.0.1:56841',
                    'path': '/put',
                    'override': {},
                    'extra': [['content-type', 'application/octet-stream'],
                              ['content-length', '70000']],
                    'flags': 36,
                    'updates': [],
                    'block': '4203505554418b089d5c0b8170dc6dc79a0f87048362bb5340874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f5f901d75d0620d263d4c1c892a56426c28e90f0d847400003f'}]]},
 {'name': 'chrome_server_table_4096',
  'target': 'chrome',
  'server_settings': [[1, 4096], [3, 100], [4, 65535], [5, 16384]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56845',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79a6f87048b6107a4ac5634cffe76803f40874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56845',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [4096],
                    'block': '3fe11f82cb87048b6107a4ac5634cffe76803fcac9c8c7c6c5c4c3c2c1c0bfbe'}]]},
 {'name': 'chrome_server_table_2048',
  'target': 'chrome',
  'server_settings': [[1, 2048], [3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56847',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79a7787048b6107a4ac5634cffe76803f40874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56847',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [2048],
                    'block': '3fe10f82cb87048b6107a4ac5634cffe76803fcac9c8c7c6c5c4c3c2c1c0bfbe'}]]},
 {'name': 'chrome_server_table_65536',
  'target': 'chrome',
  'server_settings': [[1, 65536], [3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56849',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79a7f87048b6107a4ac5634cffe76803f40874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56849',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [4096],
                    'block': '3fe11f82cb87048b6107a4ac5634cffe76803fcac9c8c7c6c5c4c3c2c1c0bfbe'}]]},
 {'name': 'firefox_reuse',
  'target': 'firefox',
  'server_settings': [[3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56851',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82048b6107a4ac5634cffe76803f418b089d5c0b8170dc6dc79b0f877abed07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28102e16fed4b3bdc0b4eae0fed4c452753b02004000802a61358594fe580b4eae053b0497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9fbed00177b518b2d4b70ddf45abefb4005df50929bd9abfa5242cb40d25fa523b3e94f684c9f4092b6b9ac1c8558d520a4b6c2ad617b5a54251f0131408a4148b4a549275a42a13f8690e4b692d49f408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275906497f83a8f517408a4148b4a549275ad416cf023f314086aec31ec327d785b6007d286f40027465864d833505b11f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56851',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 37,
                    'updates': [],
                    'block': '82048b6107a4ac5634cffe76803fc987c8c7c6c5c4c3c2c1c0bfbe'}]]},
 {'name': 'safari_reuse',
  'target': 'safari',
  'server_settings': [[3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56853',
                    'path': '/some/path?q=1',
                    'override': {},
                    'extra': [],
                    'flags': 5,
                    'updates': [],
                    'block': '8287418b089d5c0b8170dc6dc79b67048b6107a4ac5634cffe76803f408a4148b4a549275a42a13f8690e4b692d49f7adad07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e63258700dae15c2da9fd66c7bf467fa5283752a988a4ea7fed4e25b1063d4c09c5c0b854dc39476198700dae15c2dff53b0497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177febe58f9fbed00177b408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f508d9bd9abfa5242cb40d25fa523b3'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56853',
                    'path': '/',
                    'override': {},
                    'extra': [],
                    'flags': 5,
                    'updates': [],
                    'block': '8287c684c5c4c3c2c1c0bfbe'}]]},
 {'name': 'chrome_header_rules',
  'target': 'chrome',
  'server_settings': [[3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56855',
                    'path': '/a',
                    'override': {'accept-encoding': 'gzip, deflate'},
                    'extra': [['cookie', 'session=abcdefghijklmnopqr'],
                              ['authorization', 'Bearer abc'],
                              ['x-custom', 'v1'],
                              ['te', 'trailers']],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79b6f8704022f6140874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f90518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f60934150831ea80719242cb34e6e9d68a6a3d7dacf1f0887ba51d85b141c644086f2b12d424f4f02763140027465864d833505b11f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56855',
                    'path': '/b',
                    'override': {'accept-encoding': 'gzip, deflate'},
                    'extra': [['cookie', 'session=abcdefghijklmnopqr'],
                              ['authorization', 'Bearer abc'],
                              ['x-custom', 'v2']],
                    'flags': 37,
                    'updates': [],
                    'block': '82cd8704022f62cccbcac9c8c7c6c5c4c390c2c1c01f0887ba51d85b141c647f00027632'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56855',
                    'path': '/c',
                    'override': {},
                    'extra': [['cookie', 'short=1'],
                              ['x-custom', 'v2'],
                              ['if-none-match', '"etag1"'],
                              ['x-big', 'q*3100']],
                    'flags': 37,
                    'updates': [],
                    'block': '82ce8704022f63cdcccbcac9c8c7c6c5c450929bd9abfa5242cb40d25fa523b3e94f684c9fc4c31f118544e7b13007bf0f1a86fe4a91cc1fe70084f2b4669bff9a14eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56855',
                    'path': '/d',
                    'override': {},
                    'extra': [['x-big', 'q*3100'], ['x-custom', 'v1']],
                    'flags': 37,
                    'updates': [],
                    'block': '82cf8704022f64cecdcccbcac9c8c7c6c5bec4c30084f2b4669bff9a14eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76fc1'}]]},
 {'name': 'chrome_name_only_order',
  'target': 'chrome',
  'server_settings': [[3, 100]],
  'connections': [[{'method': 'GET',
                    'authority': '127.0.0.1:56857',
                    'path': '/a',
                    'override': {},
                    'extra': [['x-custom', 'v1'], ['x-edge', 'q*3035']],
                    'flags': 37,
                    'updates': [],
                    'block': '82418b089d5c0b8170dc6dc79b778704022f6140874148b1275ad1ffb7fe749d3f70c176c1d527f3f7de0fe5efe7e94fe6f4f61e935b4ff3f7de0fe42d83f9fa53f9c473cd4154bd3d87a4bfcfdf783f90b60fe7408b4148b1275ad1ad49e33505023f30408d4148b1275ad1ad5d034ca7b29f07226d61634f53224092b6b9ac1c8558d520a4b6c2ad617b5a54251f01317ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b605c0b817029b8728ec330db2eaecb9f53e5497ca589d34d1f43aeba0c41a4c7a98f33a69a3fdf9a68fa1d75d0620d263d4c79a68fbed00177fe8d48e62b03ee697e8d48e62b1e0b1d7f46a4731581d754df5f2c7cfdf6800bbdf43aeba0c41a4c7a9841a6a8b22c5f249c754c5fbef046cfdf6800bbbf408a4148b4a549275906497f83a8f517408a4148b4a549275a93c85f86a87dcd30d25f408a4148b4a549275ad416cf023f31408a4148b4a549275a42a13f8690e4b692d49f50929bd9abfa5242cb40d25fa523b3e94f684c9f518b2d4b70ddf45abefb4005df4086aec31ec327d785b6007d286f4086f2b12d424f4f0276310085f2b16498bfffe113eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb7'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56857',
                    'path': '/b',
                    'override': {},
                    'extra': [['x-custom', 'v2'], ['x-edge', 'q*3036']],
                    'flags': 37,
                    'updates': [],
                    'block': '82cc8704022f62cbcac9c8c7c6c5c4c3c2c1c0bf7e0276320085f2b16498bfffe213eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76f'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56857',
                    'path': '/c',
                    'override': {},
                    'extra': [['x-custom', 'v3'], ['x-edge', 'q*3035']],
                    'flags': 37,
                    'updates': [],
                    'block': '82cd8704022f63cccbcac9c8c7c6c5c4c3c2c1c07e0276330085f2b16498bfffe113eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb76eddbb7'},
                   {'method': 'GET',
                    'authority': '127.0.0.1:56857',
                    'path': '/d',
                    'override': {},
                    'extra': [['x-custom', 'v4']],
                    'flags': 37,
                    'updates': [],
                    'block': '82ce8704022f64cdcccbcac9c8c7c6c5c4c3c2c17e027634'}]]}]

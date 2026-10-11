"""Offline fingerprint parity: the calculators against the captured browser bytes.

Every template is rendered for server_name tls.peet.ws with ALPN h2,http/1.1
(dummy key shares, as in test_tls_hello.py) and pushed through
curl_reap.fingerprint's own calculators; the results must equal the values
recorded in the capture JSON files and baked into EXPECTED.  The HTTP/2 side
replays the captured client byte streams and the frames packed from the
_h2 specs through akamai_from_frames.  check() is exercised with a stub
session (the real fetch is live-only).
"""
import ast
import hashlib
import importlib.util
import json
import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import fingerprint_calc as fc  # noqa: E402  (the capture-time oracle)

from curl_reap import fingerprint as fp  # noqa: E402
from curl_reap._h2 import spec as h2spec, spec_names  # noqa: E402
from curl_reap._h2.frames import (  # noqa: E402
    CONNECTION_PREFACE,
    FrameParser,
    pack_frame,
    pack_headers,
    pack_priority,
    pack_settings,
    pack_window_update,
)
from curl_reap._tls import build_client_hello, template, template_names  # noqa: E402
from curl_reap._tls.consts import EXT_PADDING  # noqa: E402

# The dummy key shares test_tls_hello.py renders templates with: zero bytes
# in the right lengths, good enough for every fingerprint (no fingerprint
# covers key material).
DUMMY_SHARES = {0x11EC: bytes(1216), 0x6399: bytes(1216), 29: bytes(32),
                23: b"\x04" + bytes(64), 24: b"\x04" + bytes(96)}
SNI = "tls.peet.ws"
ALPN = ("h2", "http/1.1")


def hello_json(name):
    with open(os.path.join(ROOT, "tools", "hello_templates", name + ".json")) as fh:
        return json.load(fh)


def h2_json(name):
    with open(os.path.join(ROOT, "tools", "h2_templates", name + ".json")) as fh:
        return json.load(fh)


def render(name, **kw):
    return build_client_hello(template(name), SNI, alpn=ALPN, key_shares=DUMMY_SHARES, **kw)


def padded_variant(ja4_r):
    """JA4 and ja4_r of the same hello with a padding extension added.

    BoringSSL pads a 256..511 byte hello to 512 bytes. Any target whose
    captured hello length straddles the line may or may not send the padding
    extension on a given connection, so the check accepts either form (same
    helper pattern as tests/test_tls_hello.py, on this module's calculator).
    """
    a, ciphers, rest = ja4_r.split("_", 2)
    exts, _, sigs = rest.partition("_")
    ext_list = sorted(exts.split(",") + ["0015"])
    count = int(a[6:8]) + 1
    a2 = a[:6] + "%02d" % count + a[8:]
    c_raw = ",".join(ext_list) + ("_" + sigs if sigs else "")
    ja4 = "%s_%s_%s" % (a2, fp._sha12(ciphers), fp._sha12(c_raw))
    return ja4, "%s_%s_%s" % (a2, ciphers, c_raw)


def padded_peetprint(peet):
    """The peetprint without the dynamic padding extension (its one '21')."""
    parts = peet.split("|")
    exts = parts[7].split("-")
    exts.remove("21")
    parts[7] = "-".join(exts)
    return "|".join(parts)


def render_unpadded(name):
    """Render until the dynamic padding extension is absent (or it is fixed)."""
    doc = hello_json(name)
    for _ in range(64):
        hello = render(name)
        parsed = fp.parse_client_hello(hello)
        if doc.get("padding_length") is not None or \
                not any(e["type"] == EXT_PADDING for e in parsed["extensions"]):
            return hello, parsed
    raise AssertionError(name + " never rendered unpadded")


# --------------------------------------------------------------------------
# the expected table
# --------------------------------------------------------------------------

def test_expected_table_is_the_capture_data():
    assert sorted(fp.EXPECTED) == sorted(template_names()) == sorted(spec_names())
    assert len(fp.EXPECTED) == 53
    for name, entry in fp.EXPECTED.items():
        doc = hello_json(name)
        exp = doc["fingerprints"]
        assert set(entry) == {"ja4", "ja4_r", "akamai", "ja3_fixed", "ja3"}, name
        assert entry["ja4"] == exp["ja4"]
        assert entry["ja4_r"] == exp["ja4_r"]
        assert entry["akamai"] == doc.get("peet_live", {}).get(
            "akamai", h2_json(name)["akamai_fingerprint"])
        assert entry["ja3_fixed"] == exp["ja3_stable"]
        assert entry["ja3"] == (exp["ja3"] if exp["ja3_stable"] else None)


@pytest.mark.parametrize("name", template_names())
def test_expected_ja4_and_ja4_r_match_the_built_hello(name):
    exp = fp.EXPECTED[name]
    padded_ja4, padded_ja4_r = padded_variant(exp["ja4_r"])
    for _ in range(8):
        parsed = fp.parse_client_hello(render(name))
        padded = (hello_json(name).get("padding_length") is None
                  and any(e["type"] == EXT_PADDING for e in parsed["extensions"]))
        if padded:
            assert fp.ja4(parsed) == padded_ja4, name
            assert fp.ja4_r(parsed) == padded_ja4_r, name
        else:
            assert fp.ja4(parsed) == exp["ja4"], name
            assert fp.ja4_r(parsed) == exp["ja4_r"], name


@pytest.mark.parametrize("name", template_names())
def test_expected_ja3_matches_the_built_hello_when_stable(name):
    exp = fp.EXPECTED[name]
    text, digest = fp.ja3(render_unpadded(name)[1])
    if exp["ja3_fixed"]:
        assert text == exp["ja3"], name
        assert digest == hashlib.md5(exp["ja3"].encode()).hexdigest(), name
        assert exp["ja3"] == hello_json(name)["fingerprints"]["ja3"]
    else:
        assert exp["ja3"] is None, name


@pytest.mark.parametrize("name", [n for n in template_names()
                                  if (hello_json(n).get("peet_live") or {}).get("peetprint_hash")])
def test_peetprint_hash_matches_the_live_capture(name):
    want = hello_json(name)["peet_live"]["peetprint_hash"]
    for _ in range(4):
        parsed = fp.parse_client_hello(render(name))
        peet = fp.peetprint(parsed)
        padded = (hello_json(name).get("padding_length") is None
                  and any(e["type"] == EXT_PADDING for e in parsed["extensions"]))
        got = hashlib.md5((padded_peetprint(peet) if padded else peet).encode()).hexdigest()
        assert got == want, name


def test_peetprint_reproduces_the_live_chrome_string():
    live = json.load(open(os.path.join(ROOT, "tools", "hello_templates", "peet_chrome.json")))
    for _ in range(4):
        parsed = fp.parse_client_hello(render("chrome"))
        assert fp.peetprint(parsed) == live["tls"]["peetprint"]


def test_peetprint_segments():
    parsed = fp.parse_client_hello(render("firefox"))
    parts = fp.peetprint(parsed).split("|")
    assert parts[0] == "772-771"           # supported_versions, decimal, GREASE kept
    assert parts[1] == "2-1.1"             # h2 -> 2, http/1.1 -> 1.1
    assert parts[2].startswith("4588-29-23-24-25-256-257")
    assert parts[3] == "1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513"
    assert parts[4] == "1"                 # psk_key_exchange_modes
    assert parts[5] == "1-2-3"             # compress_certificate: zlib, brotli, zstd
    assert parts[6].startswith("4865-4867-4866-")
    assert parts[7] == "-".join(sorted(parts[7].split("-")))  # extensions sorted as strings
    tor = fp.parse_client_hello(render("tor145"))
    tor_parts = fp.peetprint(tor).split("|")
    assert tor_parts[4] == "0"             # no psk_key_exchange_modes extension
    assert tor_parts[5] == ""              # no compress_certificate extension


@pytest.mark.parametrize("name", template_names())
def test_parser_and_calculators_agree_with_the_capture_tool(name):
    """The copied parser must not drift from the oracle in tools/."""
    hello = render(name)
    mine = fp.parse_client_hello(hello)
    theirs = fc.parse_client_hello(hello)
    assert mine == theirs, name
    assert fp.ja3(mine) == (fc.ja3(theirs)["ja3"], fc.ja3(theirs)["ja3_hash"])
    assert fp.ja4(mine, alpn=None) == fc.ja4(theirs)["ja4"]
    assert fp.ja4_r(mine) == fc.ja4(theirs)["ja4_r"]


def test_ja4_alpn_parameter():
    parsed = fp.parse_client_hello(build_client_hello(
        template("chrome"), SNI, alpn=("http/1.1",), key_shares=DUMMY_SHARES))
    assert fp.ja4(parsed, alpn=None).split("_")[0].endswith("h1")
    assert fp.ja4(parsed).split("_")[0].endswith("h2")  # default override
    assert fp.ja4(parsed, alpn="http/1.1") == fp.ja4(parsed, alpn=None)


# --------------------------------------------------------------------------
# akamai_from_frames
# --------------------------------------------------------------------------

def captured_frames(name):
    """The client's (type, payload) frames from the captured raw byte stream."""
    raw = bytes.fromhex(h2_json(name)["raw"]["client_raw_hex"])
    if raw.startswith(CONNECTION_PREFACE):
        raw = raw[len(CONNECTION_PREFACE):]
    parser = FrameParser(max_frame_size=1 << 24)
    parser.feed(raw)
    return [(f.type, f.payload) for f in parser.frames()]


@pytest.mark.parametrize("name", spec_names())
def test_akamai_from_frames_matches_the_capture(name):
    assert fp.akamai_from_frames(captured_frames(name)) == fp.EXPECTED[name]["akamai"]


@pytest.mark.parametrize("name", ["chrome", "firefox", "safari"])
def test_akamai_from_frames_from_the_h2_spec(name):
    spec = h2spec(name)
    block = bytes.fromhex(h2_json(name)["headers_frame"]["header_block_hex"])
    wire = pack_settings(spec.settings)
    if spec.window_update:
        wire += pack_window_update(0, spec.window_update)
    for stream_id, exclusive, dependency, weight in spec.priority_frames:
        wire += pack_priority(stream_id, exclusive, dependency, weight)
    wire += pack_headers(1, block, spec.headers_flags, priority=spec.headers_priority)
    parser = FrameParser(max_frame_size=1 << 24)
    parser.feed(wire)
    frames = list(parser.frames())
    assert fp.akamai_from_frames(frames) == spec.akamai == fp.EXPECTED[name]["akamai"]
    # the (type, payload) contract shape (no flags, no stream ids)
    assert fp.akamai_from_frames([(f.type, f.payload) for f in frames]) == spec.akamai


def test_akamai_from_frames_rules():
    block = bytes.fromhex(h2_json("chrome")["headers_frame"]["header_block_hex"])
    wire = (pack_settings([(1, 65536), (2, 0)]) +      # the preface SETTINGS
            pack_settings([], ack=True) +               # a later ACK is ignored
            pack_window_update(3, 999) +                # stream window: not the connection one
            pack_window_update(0, 15663105) +
            pack_priority(3, True, 0, 42) +             # before the first HEADERS
            pack_headers(1, block, 0x25, priority=(True, 0, 256)))
    parser = FrameParser(max_frame_size=1 << 24)
    parser.feed(wire)
    frames = list(parser.frames())
    assert fp.akamai_from_frames(frames) == "1:65536;2:0|15663105|3:1:0:42|m,a,s,p"
    # frames after the first HEADERS never change the fingerprint
    trailing = frames + [(0x4, b""), (0x8, struct.pack("!I", 7))]
    assert fp.akamai_from_frames(trailing) == "1:65536;2:0|15663105|3:1:0:42|m,a,s,p"
    # without stream ids the first WINDOW_UPDATE wins and PRIORITY is refused
    pairs = [(f.type, f.payload) for f in frames if f.type != 0x2]
    assert fp.akamai_from_frames(pairs) == "1:65536;2:0|999|0|m,a,s,p"
    with pytest.raises(ValueError):
        fp.akamai_from_frames([(f.type, f.payload) for f in frames])


def test_akamai_from_frames_continuation_and_padding():
    block = bytes.fromhex(h2_json("chrome")["headers_frame"]["header_block_hex"])
    wire = pack_settings([(1, 65536)]) + pack_frame(0x9, 0, 1, block[:100])
    with pytest.raises(ValueError):                     # CONTINUATION before HEADERS
        fp.akamai_from_frames([(f.type, f.payload) for f in _parse(wire)])
    wire = (pack_settings([(1, 65536)]) +
            pack_frame(0x1, 0x4, 1, block[:100]) +     # HEADERS without END_HEADERS
            pack_frame(0x9, 0x4, 1, block[100:]))      # completed by CONTINUATION
    assert fp.akamai_from_frames([(f.type, f.payload) for f in _parse(wire)]) == \
        "1:65536|0|0|m,a,s,p"
    padded_payload = bytes((20,)) + b"\x00\x00\x00\x00\x19" + block + b"\x00" * 20
    wire = pack_settings([(1, 65536)]) + pack_frame(0x1, 0x4 | 0x8 | 0x20, 1, padded_payload)
    frames = _parse(wire)
    assert fp.akamai_from_frames(frames) == "1:65536|0|0|m,a,s,p"
    with pytest.raises(ValueError):                     # padding cannot be stripped without flags
        fp.akamai_from_frames([(f.type, f.payload) for f in frames])


def _parse(wire):
    parser = FrameParser(max_frame_size=1 << 24)
    parser.feed(wire)
    return list(parser.frames())


def test_akamai_from_frames_input_errors():
    with pytest.raises(ValueError):                     # no HEADERS frame at all
        fp.akamai_from_frames([])
    with pytest.raises(TypeError):                      # raw bytes, not frames
        fp.akamai_from_frames([b"\x00\x00"])
    with pytest.raises(TypeError):                      # wrong arity
        fp.akamai_from_frames([(0x4, 0, b"")])
    with pytest.raises(ValueError):                     # SETTINGS payload not a multiple of 6
        fp.akamai_from_frames([(0x4, b"\x00\x01"), (0x1, b"\x82")])
    with pytest.raises(ValueError):                     # WINDOW_UPDATE must be 4 bytes
        fp.akamai_from_frames([(0x8, b"\x01"), (0x1, b"\x82")])


# --------------------------------------------------------------------------
# parse_client_hello on truncated or malformed buffers
# --------------------------------------------------------------------------

def test_parse_client_hello_truncated_prefixes_raise():
    hello = render("edge")
    for cut in range(len(hello)):                       # bare handshake form
        with pytest.raises(ValueError):
            fp.parse_client_hello(hello[:cut])
    record = b"\x16\x03\x01" + struct.pack("!H", len(hello)) + hello
    for cut in range(len(record)):                      # record layer form
        with pytest.raises(ValueError):
            fp.parse_client_hello(record[:cut])
    assert fp.parse_client_hello(hello)["handshake_length"] == len(hello) - 4
    assert fp.parse_client_hello(record)["handshake_length"] == len(hello) - 4


def _extensions_length_offset(hello):
    """Offset of the extensions block length field inside a bare handshake."""
    body = hello[4:]
    i = 2 + 32                                          # legacy_version + random
    i += 1 + body[i]                                    # session id
    i += 2 + int.from_bytes(body[i:i + 2], "big")       # cipher suites
    i += 1 + body[i]                                    # compression methods
    return 4 + i


def test_parse_client_hello_malformed_framing_raises():
    hello = render("chrome")
    # extensions block longer than the body
    at = _extensions_length_offset(hello)
    over = hello[:at] + struct.pack("!H", 0xFFFF)
    with pytest.raises(ValueError):
        fp.parse_client_hello(over)
    # one extension longer than the extensions block
    ext_total = int.from_bytes(hello[at:at + 2], "big")
    last_len_at = at + 2 + ext_total - 4                # length field of the last extension
    forged = bytearray(hello)
    forged[last_len_at:last_len_at + 2] = struct.pack("!H", 0x0FFF)
    with pytest.raises(ValueError):
        fp.parse_client_hello(bytes(forged))
    with pytest.raises(ValueError):
        fp.parse_client_hello(b"")                      # empty
    with pytest.raises(ValueError):
        fp.parse_client_hello(b"\x17\x03\x03\x00\x01\x00")  # not a handshake record
    with pytest.raises(ValueError):
        fp.parse_client_hello(b"\x02\x00\x00\x00")      # not a ClientHello
    with pytest.raises(ValueError):
        fp.parse_client_hello(b"\x16\x03\x01\x00\x05\x15\x03\x03\x00\x01\x00")  # no handshake data


# --------------------------------------------------------------------------
# check()
# --------------------------------------------------------------------------

class _StubResponse:
    def __init__(self, payload, http_version="h2"):
        self._payload = payload
        self.http_version = http_version

    def json(self):
        return self._payload


class _StubSession:
    def __init__(self, payload):
        self.payload = payload
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return _StubResponse(self.payload)


def _peet_payload(target):
    exp = fp.EXPECTED[target]
    return {
        "http_version": "h2",
        "tls": {"ja3": exp["ja3"] or "771,4865-4866",
                "ja3_hash": "0" * 32,
                "ja4": exp["ja4"],
                "ja4_r": exp["ja4_r"],
                "peetprint": "772-771|2-1.1|29-23|1027|1|1|4865-4866|0-10"},
        "http2": {"akamai_fingerprint": exp["akamai"],
                  "sent_frames": [
                      {"frame_type": "SETTINGS", "settings": ["HEADER_TABLE_SIZE = 65536"]},
                      {"frame_type": "WINDOW_UPDATE", "increment": 15663105},
                      {"frame_type": "HEADERS", "headers": [
                          ":method: GET", ":authority: tls.peet.ws", ":scheme: https",
                          ":path: /api/all", "user-agent: probe",
                          "sec-ch-ua: \"Not;A=Brand\";v=\"8\"", "accept-encoding: gzip, br"]}]},
    }


def test_check_against_a_matching_echo():
    session = _StubSession(_peet_payload("firefox"))
    report = fp.check(target="firefox", url="https://tls.peet.ws/api/all", session=session)
    assert session.urls == ["https://tls.peet.ws/api/all"]
    assert report["target"] == "firefox"
    assert report["ja4"] == fp.EXPECTED["firefox"]["ja4"]
    assert report["akamai"] == fp.EXPECTED["firefox"]["akamai"]
    assert report["peetprint"].startswith("772-771|2-1.1|")
    assert report["expected"] == fp.EXPECTED["firefox"]
    assert report["matches"] == {"ja4": True, "ja4_r": True, "akamai": True, "ja3": True}
    assert report["headers"] == [":method", ":authority", ":scheme", ":path",
                                 "user-agent", "sec-ch-ua", "accept-encoding"]
    assert report["http_version"] == "h2"


def test_check_reports_mismatches():
    payload = _peet_payload("firefox")
    payload["tls"]["ja4"] = "t13d1516h2_000000000000_000000000000"
    payload["tls"]["ja3"] = "771,4865"
    report = fp.check(target="firefox", session=_StubSession(payload))
    assert report["matches"]["ja4"] is False
    assert report["matches"]["ja4_r"] is True
    assert report["matches"]["akamai"] is True
    assert report["matches"]["ja3"] is False


def test_check_ja3_is_not_compared_for_permuting_targets():
    report = fp.check(target="chrome", session=_StubSession(_peet_payload("chrome")))
    assert fp.EXPECTED["chrome"]["ja3_fixed"] is False
    assert report["matches"]["ja3"] is None
    assert report["matches"]["ja4"] is True


def test_check_falls_back_to_the_response_http_version_and_header_order():
    payload = _peet_payload("firefox")
    payload.pop("http_version")
    payload["http2"].pop("sent_frames")
    payload["header_order"] = ["Host", "User-Agent", "Accept"]
    report = fp.check(target="firefox", session=_StubSession(payload))
    assert report["http_version"] == "h2"
    assert report["headers"] == ["Host", "User-Agent", "Accept"]
    assert report["akamai"] == fp.EXPECTED["firefox"]["akamai"]  # from the payload


def test_check_rejects_unknown_targets():
    with pytest.raises(KeyError):
        fp.check(target="netscape", session=_StubSession(_peet_payload("chrome")))


# --------------------------------------------------------------------------
# import purity: the calculators must work without the transport
# --------------------------------------------------------------------------

def test_fingerprint_module_needs_no_package_imports():
    """Only the standard library at import time; hpack and http are lazy."""
    source_path = fp.__file__
    tree = ast.parse(open(source_path).read())
    for node in tree.body:                              # top level only
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            assert not name.startswith(("curl_reap", "hpack", "h2")), name
    spec = importlib.util.spec_from_file_location("_fingerprint_standalone", source_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)                     # no package import happens
    assert module.EXPECTED["chrome"]["ja4"] == fp.EXPECTED["chrome"]["ja4"]
    assert module._sha12("0") == fp._sha12("0")

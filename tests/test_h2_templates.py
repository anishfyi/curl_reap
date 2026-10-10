"""Byte equality against the curl_cffi captures in tools/h2_templates.

For every template the connection preface (SETTINGS, WINDOW_UPDATE and
PRIORITY frames) and the first HEADERS frame (flags, priority field and the
HPACK block) produced by curl_reap's HTTP/2 core must equal the bytes
nghttp2 sent, and the Akamai string must round trip.
"""
import glob
import json
import os

import pytest

pytest.importorskip("hpack")

from curl_reap._h2 import (  # noqa: E402
    H2Core, H2Spec, akamai_string, spec, spec_from_akamai, spec_names,
)
from curl_reap._h2 import frames as F  # noqa: E402
from curl_reap._h2.templates_data import CAPTURE_INFO, SPECS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(os.path.dirname(HERE), "tools", "h2_templates")
TEMPLATE_FILES = sorted(glob.glob(os.path.join(TEMPLATE_DIR, "*.json")))
TEMPLATE_NAMES = [os.path.splitext(os.path.basename(p))[0] for p in TEMPLATE_FILES]


def load(name):
    with open(os.path.join(TEMPLATE_DIR, name + ".json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def captured_frames(template):
    """Client frames nghttp2 sent before the response, parsed from the raw hex."""
    raw = bytes.fromhex(template["raw"]["client_raw_hex"])
    assert raw.startswith(F.CONNECTION_PREFACE)
    parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)
    parser.feed(raw[len(F.CONNECTION_PREFACE):])
    frames = list(parser.frames())
    before = []
    for frame in frames:
        if frame.type == F.HEADERS:
            before.append(frame)
            break
        before.append(frame)
    return before


def build_first_request(template):
    """Replay the capture: same spec, authority, path and header list."""
    core = H2Core(spec(template["target"]))
    core.initiate_connection()
    headers = template["headers"]
    authority = next(h["value"] for h in headers if h["name"] == ":authority")
    path = next(h["value"] for h in headers if h["name"] == ":path")
    method = next(h["value"] for h in headers if h["name"] == ":method")
    scheme = next(h["value"] for h in headers if h["name"] == ":scheme")
    regular = [(h["name"], h["value"]) for h in headers if not h["name"].startswith(":")]
    stream_id = core.send_request(method, scheme, authority, path, regular)
    assert stream_id == template["headers_frame"]["stream_id"]
    out = core.data_to_send()
    assert out.startswith(F.CONNECTION_PREFACE)
    parser = F.FrameParser(F.MAX_FRAME_SIZE_LIMIT)
    parser.feed(out[len(F.CONNECTION_PREFACE):])
    return list(parser.frames())


def test_every_template_file_has_a_spec():
    assert TEMPLATE_NAMES, "no templates found"
    assert set(TEMPLATE_NAMES) == set(SPECS)
    assert spec_names() == sorted(SPECS)
    assert CAPTURE_INFO["targets"] == sorted(SPECS)


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_headers_block_bytes_equal_capture(name):
    template = load(name)
    frames = build_first_request(template)
    headers_frame = frames[-1]
    assert headers_frame.type == F.HEADERS
    expected = template["headers_frame"]
    assert headers_frame.flags == expected["flags"]
    payload = headers_frame.payload
    if expected["priority"]:
        exclusive, dependency, weight = F.parse_priority_field(payload)
        assert (exclusive, dependency, weight) == (
            expected["priority"]["exclusive"], expected["priority"]["dependency"],
            expected["priority"]["weight"])
        payload = payload[5:]
    assert payload.hex() == expected["header_block_hex"]


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_preface_frames_equal_capture(name):
    template = load(name)
    mine = build_first_request(template)
    theirs = captured_frames(template)
    assert [f.name for f in mine] == [f.name for f in theirs] == \
        template["client_frames_before_response"]
    for ours, captured in zip(mine, theirs):
        assert ours == captured, "%s frame differs" % ours.name
    settings = [f for f in mine if f.type == F.SETTINGS]
    assert len(settings) == 1
    assert F.parse_settings(settings[0].payload) == [
        (s["id"], s["value"]) for s in template["settings"]]
    window = [f for f in mine if f.type == F.WINDOW_UPDATE]
    assert len(window) == 1 and window[0].stream_id == 0
    assert int.from_bytes(window[0].payload, "big") == template["window_update"]["increment"]
    assert template["hpack_dynamic_table_size_updates"] == []
    assert not any(f.type == F.PRIORITY for f in mine) or template["priority_frames"]


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_akamai_string_matches_capture(name):
    template = load(name)
    s = spec(name)
    assert akamai_string(s) == template["akamai_fingerprint"]
    assert s.akamai == template["akamai_fingerprint"]
    peet = template.get("peet_ws", {}) or {}
    if peet.get("akamai_fingerprint"):
        assert akamai_string(s) == peet["akamai_fingerprint"]
    assert s.pseudo_order == "".join(template["pseudo_header_order"])


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_spec_from_akamai_round_trips(name):
    template = load(name)
    parsed = spec_from_akamai(template["akamai_fingerprint"])
    assert akamai_string(parsed) == template["akamai_fingerprint"]
    assert parsed.settings == spec(name).settings
    assert parsed.window_update == spec(name).window_update
    assert parsed.priority_frames == spec(name).priority_frames
    assert parsed.pseudo_order == spec(name).pseudo_order
    # The string does not encode the HEADERS frame shape, so the parsed spec
    # takes it from the first captured template with the same string.
    twins = [n for n in sorted(SPECS) if SPECS[n]["akamai"] == template["akamai_fingerprint"]]
    assert parsed.name == twins[0]
    assert parsed.headers_flags == spec(twins[0]).headers_flags
    assert parsed.headers_priority == spec(twins[0]).headers_priority
    named = spec_from_akamai(template["akamai_fingerprint"], name="custom")
    assert named.name == "custom"
    assert akamai_string(named) == template["akamai_fingerprint"]


def test_spec_from_akamai_custom_string():
    s = spec_from_akamai("1:65536;3:1000;4:6291456;6:262144|15663105|3:0:0:201,5:0:0:101|m,p,a,s")
    assert s.name == "akamai"
    assert s.settings == ((1, 65536), (3, 1000), (4, 6291456), (6, 262144))
    assert s.window_update == 15663105
    assert s.priority_frames == ((3, False, 0, 201), (5, False, 0, 101))
    assert s.pseudo_order == "mpas"
    assert akamai_string(s) == "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:0:201,5:0:0:101|m,p,a,s"
    core = H2Core(s)
    core.initiate_connection()
    parser = F.FrameParser()
    parser.feed(core.data_to_send()[len(F.CONNECTION_PREFACE):])
    frames = list(parser.frames())
    assert [f.name for f in frames] == ["SETTINGS", "WINDOW_UPDATE", "PRIORITY", "PRIORITY"]
    assert F.parse_priority_field(frames[2].payload) == (False, 0, 201)
    assert frames[3].stream_id == 5


@pytest.mark.parametrize("text", [
    "1:65536|0|0|m,a,s",            # pseudo order too short
    "1:65536|0|0",                  # missing part
    "1:x|0|0|m,a,s,p",              # bad setting
    "1:1|0|3:0:0|m,a,s,p",          # bad priority entry
    "1:1|y|0|m,a,s,p",              # bad window update
])
def test_spec_from_akamai_rejects_garbage(text):
    with pytest.raises(ValueError):
        spec_from_akamai(text)


def test_spec_lookup():
    assert spec("Chrome").name == "chrome"
    with pytest.raises(KeyError):
        spec("netscape4")
    chrome = spec("chrome")
    assert chrome.header_table_size == 65536
    assert chrome.initial_window_size == 6291456
    assert chrome.connection_window_size == 65535 + 15663105
    assert chrome.max_frame_size == 16384
    assert chrome.max_header_list_size == 262144
    assert chrome.pseudo_header_names == (":method", ":authority", ":scheme", ":path")
    safari = spec("safari")
    assert safari.header_table_size == 4096
    assert safari.headers_priority is None
    assert safari.headers_flags == F.FLAG_END_STREAM | F.FLAG_END_HEADERS
    firefox = spec("firefox")
    assert firefox.headers_priority == (False, 0, 42)
    assert spec("firefox135").headers_priority == (False, 0, 256)
    assert spec("safari170").pseudo_order == "mspa"
    assert spec("safari170").headers_priority == (False, 0, 255)


def test_spec_validation():
    with pytest.raises(ValueError):
        H2Spec("x", ((1, 1),), 0, (), F.FLAG_END_STREAM | F.FLAG_END_HEADERS, (True, 0, 256), "masp")
    with pytest.raises(ValueError):
        H2Spec("x", ((1, 1),), 0, (), F.FLAG_END_HEADERS, None, "mmmm")
    with pytest.raises(ValueError):
        H2Spec("x", ((1, 1),), 0, (), F.FLAG_END_HEADERS | F.FLAG_PRIORITY, (True, 0, 300), "masp")
    s = H2Spec("x", [[1, 1]], 5, [[3, 0, 0, 10]], F.FLAG_END_HEADERS, None, "m,a,s,p")
    assert s.settings == ((1, 1),)
    assert s.priority_frames == ((3, False, 0, 10),)
    assert s.pseudo_order == "masp"


def test_generator_output_is_current(tmp_path):
    """tools/gen_h2_templates.py must reproduce the committed templates_data.py."""
    import importlib.util
    gen_path = os.path.join(os.path.dirname(HERE), "tools", "gen_h2_templates.py")
    module_spec = importlib.util.spec_from_file_location("gen_h2_templates", gen_path)
    gen = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(gen)
    text = gen.render(gen.load_templates(TEMPLATE_DIR), TEMPLATE_DIR)
    committed = os.path.join(os.path.dirname(HERE), "curl_reap", "_h2", "templates_data.py")
    with open(committed, "r", encoding="utf-8") as fh:
        assert fh.read() == text
    assert text == gen.render(gen.load_templates(TEMPLATE_DIR), TEMPLATE_DIR)
    assert "Generated by tools/gen_h2_templates.py" in text

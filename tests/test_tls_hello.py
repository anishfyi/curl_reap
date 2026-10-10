"""Offline ClientHello fidelity: templates, GREASE, permutation, padding, PSK.

Every template is rendered for server_name tls.peet.ws with ALPN h2,http/1.1
and compared with the fingerprints recorded in tools/hello_templates/*.json
through tools/fingerprint_calc.py, the same calculator that verified those
captures against https://tls.peet.ws.
"""
import json
import os
import random
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import fingerprint_calc as fc  # noqa: E402

from curl_reap._tls import (  # noqa: E402
    GREASE,
    ClientHelloBuilder,
    HelloTemplate,
    build_client_hello,
    parse_client_hello,
    template,
    template_from_ja3,
    template_names,
)
from curl_reap._tls.consts import (  # noqa: E402
    EXT_COOKIE,
    EXT_ECH,
    EXT_KEY_SHARE,
    EXT_PADDING,
    EXT_PRE_SHARED_KEY,
    EXT_SUPPORTED_VERSIONS,
    is_grease,
)
from curl_reap._tls.hello import grease_from_seed_byte  # noqa: E402
from curl_reap._tls.keyschedule import SUITES, psk_binder  # noqa: E402
from curl_reap._tls.session import Ticket  # noqa: E402

DUMMY_SHARES = {0x11EC: bytes(1216), 0x6399: bytes(1216), 29: bytes(32), 23: b"\x04" + bytes(64), 24: b"\x04" + bytes(96)}
SNI = "tls.peet.ws"
ALPN = ("h2", "http/1.1")


def source_json(name):
    with open(os.path.join(ROOT, "tools", "hello_templates", name + ".json")) as fh:
        return json.load(fh)


def render(name, **kw):
    return build_client_hello(template(name), SNI, alpn=ALPN, key_shares=DUMMY_SHARES, **kw)


@pytest.fixture(scope="module")
def all_names():
    names = template_names()
    assert len(names) == 24
    return names


def test_every_capture_has_a_template(all_names):
    captured = sorted(
        f[:-5] for f in os.listdir(os.path.join(ROOT, "tools", "hello_templates"))
        if f.endswith(".json") and not f.startswith("peet_")
    )
    assert captured == all_names


def test_unknown_template_raises():
    with pytest.raises(KeyError):
        template("netscape4")


def padded_variant(ja4_r):
    """JA4 and ja4_r of the same hello with a padding extension added.

    BoringSSL pads a 256..511 byte hello to 512 bytes. chrome_android is the
    one captured target whose hello crosses that line: with the smallest ECH
    payload (144 bytes) curl_cffi itself sends padding and reports
    t13d1517h2_8daaf6152771_b1ff8ab2d16f (verified with 16 local captures of
    curl_cffi 0.16.3, 7 of which padded), so the engine must do the same.
    """
    a, ciphers, rest = ja4_r.split("_", 2)
    exts, _, sigs = rest.partition("_")
    ext_list = sorted(exts.split(",") + ["0015"])
    count = int(a[6:8]) + 1
    a2 = a[:6] + "%02d" % count + a[8:]
    c_raw = ",".join(ext_list) + ("_" + sigs if sigs else "")
    ja4 = "%s_%s_%s" % (a2, fc._sha12(ciphers), fc._sha12(c_raw))
    return ja4, "%s_%s_%s" % (a2, ciphers, c_raw)


@pytest.mark.parametrize("name", template_names())
def test_fingerprints_match_capture(name):
    doc = source_json(name)
    exp = doc["fingerprints"]
    hl = doc["handshake_length"]
    seen_lengths = set()
    padded_ja4, padded_ja4_r = padded_variant(exp["ja4_r"])
    for _ in range(8):
        hello = render(name)
        parsed = fc.parse_client_hello(hello)
        fp = fc.fingerprints(parsed)
        padded = any(e["type"] == EXT_PADDING for e in parsed["extensions"]) and doc.get("padding_length") is None
        if padded:
            assert name == "chrome_android", "only chrome_android crosses the 512 byte line"
            assert len(hello) == 512
            assert fp["ja4"] == padded_ja4 and fp["ja4_r"] == padded_ja4_r
            continue
        assert fp["ja4"] == exp["ja4"], name
        assert fp["ja4_r"] == exp["ja4_r"], name
        if exp["ja3_stable"]:
            assert fp["ja3_hash"] == exp["ja3_hash"], name
            assert fp["ja3"] == exp["ja3"], name
        seen_lengths.add(len(hello) - 4)
    tpl = template(name)
    if tpl.ech is None:
        # No ECH: every byte of the hello is fixed apart from random fields.
        assert seen_lengths == {hl["min"]}, (name, seen_lengths, hl)
        assert hl["fixed"] or hl["min"] == hl["max"]
    else:
        # The ECH payload is 144, 176, 208 or 240 bytes; three captures saw
        # only some of those sizes, so the lengths must sit on that lattice.
        for length in seen_lengths:
            assert (length - hl["min"]) % 32 == 0, (name, length, hl)
            assert hl["min"] - 96 <= length <= hl["max"] + 96, (name, length, hl)


@pytest.mark.parametrize("name", template_names())
def test_fixed_extension_bodies_are_byte_identical(name):
    doc = source_json(name)
    hello = render(name)
    parsed = fc.parse_client_hello(hello)
    got = {e["type_hex"]: e["body_hex"] for e in parsed["extensions"] if not e["grease"]}
    checked = 0
    for ext in doc["extensions"]:
        if ext["type"] == "GREASE" or not ext.get("body_fixed") or ext.get("body_hex") is None:
            continue
        assert got[ext["type"]] == ext["body_hex"], (name, ext["type"])
        checked += 1
    assert checked >= 8
    # Variable fields have the captured shape too.
    for ext in doc["extensions"]:
        if ext["name"] == "padding":
            assert len(got["0015"]) // 2 == ext["params"]["length"]
        if ext["name"] == "key_share":
            shares = [s for s in fc.parse_client_hello(hello)["extensions"] if s["type"] == 51][0]["decoded"]["shares"]
            assert [(s["id"] if not s.get("grease") else "GREASE", s["key_length"]) for s in shares] == [
                (s["group"], s["key_length"]) for s in ext["params"]["shares"]
            ]
    assert parsed["session_id_len"] == doc["session_id_len"]
    assert parsed["legacy_version"] == doc["legacy_version"]
    assert parsed["compression_methods"] == doc["compression_methods"]


@pytest.mark.parametrize("name", template_names())
def test_extension_order_rules(name):
    doc = source_json(name)
    tpl = template(name)
    orders = set()
    for _ in range(6):
        parsed = parse_client_hello(render(name))
        types = tuple("GREASE" if is_grease(t) else "%04x" % t for t, _ in parsed["extensions"])
        if doc.get("padding_length") is None and types[-1] == "0015":
            types = types[:-1]  # the BoringSSL padding on a small chrome_android hello
        orders.add(types)
        prefix = tuple(doc["extension_fixed_prefix"])
        suffix = tuple(doc["extension_fixed_suffix"])
        assert types[:len(prefix)] == prefix
        assert types[-len(suffix):] == suffix
        assert sorted(types) == sorted(doc["extensions"][i]["type"] for i in range(len(doc["extensions"])))
    if tpl.permute_extensions:
        assert len(orders) > 1, "Chrome must permute the middle extensions per connection"
    else:
        assert len(orders) == 1


def test_chrome_grease_values_vary_but_ja4_is_constant():
    ja4s = set()
    greases = set()
    for _ in range(12):
        hello = render("chrome")
        parsed = fc.parse_client_hello(hello)
        ja4s.add(fc.ja4(parsed)["ja4"])
        cipher_grease = [c["decimal"] for c in parsed["cipher_suites"] if c.get("grease")]
        ext_grease = [e["type"] for e in parsed["extensions"] if e["grease"]]
        greases.add((tuple(cipher_grease), tuple(ext_grease)))
        assert len(ext_grease) == 2 and ext_grease[0] != ext_grease[1]
        assert parsed["extensions"][0]["grease"] and parsed["extensions"][0]["length"] == 0
        assert parsed["extensions"][-1]["grease"] and parsed["extensions"][-1]["body_hex"] == "00"
    assert len(ja4s) == 1
    assert len(greases) > 1


def test_grease_values_follow_boringssl_seed_rule():
    seed = bytes([0x7A, 0x3A, 0x8A, 0x8A, 0xAA, 0x1A, 0x95])
    b = ClientHelloBuilder(template("chrome"), SNI, grease_seed=seed)
    assert b.grease["cipher"] == 0x7A7A
    assert b.grease["group"] == 0x3A3A
    assert b.grease["ext1"] == 0x8A8A
    assert b.grease["ext2"] == 0x9A9A, "second extension GREASE is XORed with 0x1010 when it collides"
    assert b.grease["version"] == 0xAAAA
    assert b.ech_config_id == 0x95
    assert grease_from_seed_byte(0x00) == 0x0A0A and grease_from_seed_byte(0xFF) == 0xFAFA
    hello = parse_client_hello(b.build(DUMMY_SHARES))
    assert hello["ciphers"][0] == 0x7A7A
    assert hello["groups"][0] == 0x3A3A
    assert hello["key_share_order"][0] == 0x3A3A, "the GREASE key share uses the supported_groups GREASE value"
    assert hello["versions"][0] == 0xAAAA


def test_firefox_sends_no_grease_and_three_key_shares():
    parsed = parse_client_hello(render("firefox"))
    assert parsed["grease_count"] == 0
    assert not any(is_grease(c) for c in parsed["ciphers"])
    assert not any(is_grease(g) for g in parsed["groups"])
    assert parsed["key_share_order"] == [0x11EC, 29, 23]
    assert len(parsed["key_shares"][0x11EC]) == 1216
    assert len(parsed["key_shares"][23]) == 65
    assert parsed["record_size_limit"] == 16385
    assert parsed["compress_certificate"] == [1, 2, 3]
    assert parsed["extensions"][0][0] == 0 and parsed["extensions"][-1][0] == EXT_ECH


def test_chrome124_kyber_draft_share_size_and_android_no_pq():
    parsed = parse_client_hello(render("chrome124"))
    assert len(parsed["key_shares"][0x6399]) == 1216
    assert 0x6399 in parsed["groups"]
    android = parse_client_hello(render("chrome_android"))
    assert [g for g in android["key_share_order"] if not is_grease(g)] == [29]


def test_safari_duplicate_sigalg_and_cbc_suites():
    parsed = parse_client_hello(render("safari"))
    assert parsed["sigalgs"].count(0x0805) == 2
    assert 0x000A in parsed["ciphers"] and 0xC008 in parsed["ciphers"]
    assert [c for c in parsed["ciphers"] if not is_grease(c)][:3] == [0x1302, 0x1303, 0x1301]


def test_padding_rule_pads_to_512_for_every_sni_length():
    tpl = template("edge")
    long_host = ".".join(["x" * 85, "y" * 85, "z" * 85, "example"])
    for host in ("a.io", "tls.peet.ws", "a-much-longer-host-name.example.org", long_host):
        hello = build_client_hello(tpl, host, alpn=ALPN, key_shares=DUMMY_SHARES)
        parsed = parse_client_hello(hello)
        pad = dict(parsed["extensions"]).get(EXT_PADDING)
        if host != long_host:
            assert len(hello) == 512, host
            assert pad is not None and set(pad) == {0}
        else:
            assert len(hello) > 512 and pad is None, "no padding once the hello passes 511 bytes"


def test_padding_rule_edge_cases_from_boringssl():
    # A hello of exactly 508 bytes without padding gets a 1-byte padding
    # (512 - 508 = 4, too small to subtract the 4-byte header).
    tpl = template("edge")
    found = {}
    for n in range(1, 60):
        host = "h" * n + ".test"
        hello = build_client_hello(tpl, host, alpn=ALPN, key_shares=DUMMY_SHARES)
        pad = dict(parse_client_hello(hello)["extensions"]).get(EXT_PADDING)
        found[len(hello)] = len(pad) if pad is not None else None
    assert all(v is None or v >= 1 for v in found.values())
    assert 512 in found


def test_hello_is_deterministic_with_random_bytes():
    seed = bytes(range(32))
    a = render("chrome", random_bytes=seed)
    b = render("chrome", random_bytes=seed)
    assert a == b
    assert parse_client_hello(a)["random"] == seed
    assert render("chrome", random_bytes=bytes(32)) != a


def test_hrr_second_hello_keeps_everything_but_key_share_and_cookie():
    b = ClientHelloBuilder(template("chrome"), SNI)
    h1 = parse_client_hello(b.build(DUMMY_SHARES))
    h2 = parse_client_hello(b.build(DUMMY_SHARES, key_share_groups=[23], cookie=b"\x01\x02\x03"))
    assert h1["random"] == h2["random"] and h1["session_id"] == h2["session_id"]
    same1 = [(t, body) for t, body in h1["extensions"] if t != EXT_KEY_SHARE]
    same2 = [(t, body) for t, body in h2["extensions"] if t not in (EXT_KEY_SHARE, EXT_COOKIE)]
    assert same1 == same2
    assert h2["key_share_order"] == [23], "after HRR only the requested group, no GREASE share"
    types2 = [t for t, _ in h2["extensions"]]
    assert types2.index(EXT_COOKIE) == types2.index(EXT_SUPPORTED_VERSIONS) + 1
    assert h2["cookie"] == b"\x01\x02\x03"


def test_psk_extension_is_last_with_a_valid_binder():
    suite = SUITES[0x1301]
    ticket = Ticket(ticket=b"T" * 40, psk=b"\x11" * 32, cipher=0x1301, lifetime=7200, age_add=1000, received=0.0)
    b = ClientHelloBuilder(template("chrome"), SNI)
    hello = b.build(DUMMY_SHARES, psk=ticket, now=5.0)
    parsed = parse_client_hello(hello)
    assert parsed["extensions"][-1][0] == EXT_PRE_SHARED_KEY
    assert parsed["psk_identities"] == [(b"T" * 40, (5000 + 1000) & 0xFFFFFFFF)]
    binder = parsed["psk_binders"][0]
    truncated = hello[:-(2 + 1 + len(binder))]
    assert binder == psk_binder(suite, ticket.psk, suite.hash(truncated))
    # JA4 counts the extra extension, as a resuming browser's hello does.
    assert fc.ja4(fc.parse_client_hello(hello))["ja4"].startswith("t13d1517h2_")
    # Padding accounts for the PSK extension (edge stays at 512 bytes).
    edge = ClientHelloBuilder(template("edge"), SNI).build(DUMMY_SHARES, psk=ticket, now=5.0)
    assert len(edge) == 512
    assert parse_client_hello(edge)["extensions"][-1][0] == EXT_PRE_SHARED_KEY


def test_alpn_override_changes_only_alpn():
    tpl = template("chrome")
    hello = build_client_hello(tpl, SNI, alpn=("http/1.1",), key_shares=DUMMY_SHARES)
    parsed = parse_client_hello(hello)
    assert parsed["alpn"] == ["http/1.1"]
    assert fc.ja4(fc.parse_client_hello(hello))["ja4"].startswith("t13d1516h1_")


def test_idna_server_name():
    hello = build_client_hello(template("chrome"), "bücher.example", alpn=ALPN, key_shares=DUMMY_SHARES)
    assert parse_client_hello(hello)["sni"] == "xn--bcher-kva.example"


def test_missing_key_share_is_an_error():
    with pytest.raises(KeyError):
        build_client_hello(template("chrome"), SNI, alpn=ALPN, key_shares={29: bytes(32)})


def test_build_without_key_shares_generates_real_ones():
    hello = build_client_hello(template("chrome_android"), SNI, alpn=ALPN)
    parsed = parse_client_hello(hello)
    assert len(parsed["key_shares"][29]) == 32 and parsed["key_shares"][29] != bytes(32)


def test_template_from_ja3_reproduces_the_hash():
    doc = source_json("edge")
    ja3 = doc["fingerprints"]["ja3"]
    tpl = template_from_ja3(ja3, alpn=ALPN)
    assert isinstance(tpl, HelloTemplate)
    hello = build_client_hello(tpl, SNI, alpn=ALPN, key_shares=DUMMY_SHARES)
    parsed = fc.parse_client_hello(hello)
    assert fc.ja3(parsed)["ja3"] == ja3
    assert fc.ja3(parsed)["ja3_hash"] == doc["fingerprints"]["ja3_hash"]
    grease = template_from_ja3(ja3, alpn=ALPN, grease=True)
    hello2 = build_client_hello(grease, SNI, alpn=ALPN, key_shares=DUMMY_SHARES)
    assert fc.ja3(fc.parse_client_hello(hello2))["ja3_hash"] == doc["fingerprints"]["ja3_hash"]
    assert parse_client_hello(hello2)["grease_count"] == 2
    firefox = source_json("firefox")["fingerprints"]["ja3"]
    tpl_ff = template_from_ja3(firefox)
    hello3 = build_client_hello(tpl_ff, SNI, alpn=ALPN, key_shares=DUMMY_SHARES)
    assert fc.ja3(fc.parse_client_hello(hello3))["ja3"] == firefox
    with pytest.raises(ValueError):
        template_from_ja3("771,4865")


def test_template_loader_fields():
    tpl = template("chrome")
    assert tpl.alias_of == "chrome150" and tpl.family == "chrome"
    assert tpl.ciphers[0] == GREASE and tpl.grease and tpl.permute_extensions and tpl.session_ticket
    assert tpl.alps_codepoint == 0x44CD and tpl.alps_value == bytes.fromhex("0003026832") and tpl.alps_protocols == ("h2",)
    assert tpl.key_share_groups == [GREASE, 0x11EC, 29]
    assert tpl.psk_modes == [1] and tpl.compress_certificate == [2]
    assert tpl.ech["payload_lengths"] == [144, 176, 208, 240]
    ff = template("firefox")
    assert not ff.grease and not ff.permute_extensions
    assert ff.record_size_limit == 16385 and ff.delegated_credentials == [0x0403, 0x0503, 0x0603, 0x0203]
    assert ff.compress_certificate == [1, 2, 3]
    assert template("tor145").psk_modes == [] and template("tor145").compress_certificate == []
    assert template("chrome").expected["fingerprints"]["ja4"] == "t13d1516h2_8daaf6152771_806a8c22fdea"


def test_generated_data_matches_the_generator():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "gen_tls_templates.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_ech_grease_shape():
    seen = set()
    for _ in range(16):
        parsed = fc.parse_client_hello(render("firefox"))
        ech = [e for e in parsed["extensions"] if e["type"] == EXT_ECH][0]["decoded"]
        assert ech["type"] == 0 and ech["kdf_id"] == "0001" and ech["aead_id"] == "0001" and ech["enc_len"] == 32
        seen.add(ech["payload_len"])
    assert seen <= {144, 176, 208, 240} and len(seen) >= 2


def test_seeded_rng_gives_reproducible_permutation():
    tpl = template("chrome")
    a = ClientHelloBuilder(tpl, SNI, rng=random.Random(7))
    b = ClientHelloBuilder(tpl, SNI, rng=random.Random(7))
    assert a.order == b.order and a.grease == b.grease and a.random == b.random
    assert a.build(DUMMY_SHARES) == b.build(DUMMY_SHARES)

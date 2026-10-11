"""Tests for the impersonate target registry (curl_reap.tls, WP-registry).

Everything here runs offline.  The captured ground truth under
``tools/hello_templates`` and ``tools/h2_templates`` is read when the
checkout has it; curl_cffi is imported for cross-checks when installed and
those tests skip otherwise.
"""
from __future__ import annotations

import importlib
import json
import os
import ssl
import sys

import pytest

import curl_reap
from curl_reap import _profiles_data as data
from curl_reap import tls
from curl_reap.exceptions import ImpersonateError
from curl_reap.tls import (
    ALIASES, FINGERPRINTS, LEGACY, PROFILES, TARGETS, Profile, UnknownProfileError,
    canonical_target, create_ssl_context, families, profile_for_h2, resolve_profile,
    targets,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
HELLO_DIR = os.path.join(TOOLS, "hello_templates")
H2_DIR = os.path.join(TOOLS, "h2_templates")
HAVE_CAPTURES = os.path.isdir(HELLO_DIR) and os.path.isdir(H2_DIR)

# The 56 names curl_cffi 0.16.3 lists in BrowserTypeLiteral, plus 'tor'
# which its REAL_TARGET_MAP resolves.
CURL_CFFI_NAMES = (
    "edge99 edge101 chrome99 chrome100 chrome101 chrome104 chrome107 chrome110 "
    "chrome116 chrome119 chrome120 chrome123 chrome124 chrome131 chrome133a "
    "chrome136 chrome142 chrome145 chrome146 chrome150 chrome99_android "
    "chrome131_android safari153 safari155 safari170 safari172_ios safari180 "
    "safari180_ios safari184 safari184_ios safari260 safari2601 safari260_ios "
    "firefox133 firefox135 firefox144 firefox147 tor145 chrome edge safari "
    "safari_ios safari_beta safari_ios_beta chrome_android firefox safari15_3 "
    "safari15_5 safari17_0 safari17_2_ios safari18_0 safari18_0_ios safari18_4 "
    "safari18_4_ios edge_99 edge_101"
).split()
EXPECTED_ALIASES = {
    "chrome": "chrome150", "edge": "edge101", "firefox": "firefox147",
    "safari": "safari2601", "safari_ios": "safari260_ios",
    "safari_beta": "safari2601", "safari_ios_beta": "safari260_ios",
    "chrome_android": "chrome131_android", "tor": "tor145",
    "edge_99": "edge99", "edge_101": "edge101",
    "safari15_3": "safari153", "safari15_5": "safari155",
    "safari17_0": "safari170", "safari17_2_ios": "safari172_ios",
    "safari18_0": "safari180", "safari18_0_ios": "safari180_ios",
    "safari18_4": "safari184", "safari18_4_ios": "safari184_ios",
}
LEGACY_NAMES = (
    "chrome98 chrome126 chrome128 chrome129 chrome130 chrome133 edge126 edge128 "
    "edge129 edge130 edge131 edge133 firefox95 firefox102 firefox109 firefox117 "
    "firefox127 firefox128 firefox132 safari16_0 safari16_4 safari17_2"
).split()
LIBCURL_ONLY = {"host", "upgrade", "http2-settings", "connection"}


def _load(directory, name):
    with open(os.path.join(directory, "%s.json" % name)) as fh:
        return json.load(fh)


def _names(headers):
    return [name for name, _ in headers]


def _values(headers):
    return {name.lower(): value for name, value in headers}


# ----------------------------------------------------------------- names


def test_registry_size_is_reported():
    print("FINGERPRINTS has %d entries: %d concrete, %d aliases, %d legacy"
          % (len(FINGERPRINTS), len(TARGETS), len(ALIASES), len(LEGACY)))
    assert len(TARGETS) == 38
    assert len(ALIASES) == 19
    assert len(LEGACY) == 22
    assert len(FINGERPRINTS) == len(TARGETS) + len(ALIASES) + len(LEGACY)
    assert set(FINGERPRINTS) == set(TARGETS) | set(ALIASES) | set(LEGACY)


def test_every_curl_cffi_name_resolves():
    assert len(CURL_CFFI_NAMES) == 56
    for name in CURL_CFFI_NAMES + ["tor"]:
        profile = resolve_profile(name)
        assert profile.name == name
        assert profile.tls_template is not None
        assert profile.h2_spec is not None
        assert profile.family in tls.FAMILIES
        assert profile is FINGERPRINTS[name]


def test_alias_map_matches_curl_cffi_resolution():
    assert ALIASES == EXPECTED_ALIASES
    for alias, concrete in ALIASES.items():
        profile = resolve_profile(alias)
        target = FINGERPRINTS[concrete]
        # The alias keeps its own name (as 1.x did for 'chrome') and is
        # otherwise the concrete target.
        assert profile.name == alias
        assert profile.headers == target.headers
        assert profile.h2_headers == target.h2_headers
        assert profile.tls_template == target.tls_template == concrete
        assert profile.h2_spec == target.h2_spec == concrete
        assert profile.version == target.version
        assert canonical_target(alias) == concrete
        assert tls.is_alias(alias) and not tls.is_alias(concrete)


def test_alias_map_matches_installed_curl_cffi():
    imp = pytest.importorskip("curl_cffi.requests.impersonate")
    for alias, concrete in imp.REAL_TARGET_MAP.items():
        assert ALIASES[alias] == concrete, alias
        assert imp.resolve_latest_browser_type(alias) == canonical_target(alias)
    assert ALIASES["chrome"] == imp.DEFAULT_CHROME
    assert ALIASES["edge"] == imp.DEFAULT_EDGE
    assert ALIASES["firefox"] == imp.DEFAULT_FIREFOX
    assert ALIASES["safari"] == imp.DEFAULT_SAFARI
    assert ALIASES["safari_ios"] == imp.DEFAULT_SAFARI_IOS
    assert ALIASES["safari_beta"] == imp.DEFAULT_SAFARI_BETA
    assert ALIASES["safari_ios_beta"] == imp.DEFAULT_SAFARI_IOS_BETA
    assert ALIASES["chrome_android"] == imp.DEFAULT_CHROME_ANDROID
    assert ALIASES["tor"] == imp.DEFAULT_TOR
    # every native and deprecated name curl_cffi's enum lists is a key here
    for member in imp.BrowserType:
        assert member.value in FINGERPRINTS, member.value


def test_concrete_targets_match_curl_cffi_native_table():
    fp = pytest.importorskip("curl_cffi.fingerprints")
    native = {item["target_name"]: item for item in fp.NATIVE_IMPERSONATE_TARGETS}
    assert set(native) == set(TARGETS)
    os_map = {"macOS": "macos", "Windows": "windows", "Android": "android", "iOS": "ios"}
    for name, item in native.items():
        profile = FINGERPRINTS[name]
        assert profile.family == item["browser"].lower()
        assert profile.version == item["version"]
        assert data.CONCRETE[name]["platform"] == os_map[item["os"]]


def test_concrete_targets_resolve_to_themselves():
    for name in TARGETS:
        profile = resolve_profile(name)
        assert profile.name == name
        assert profile.tls_template == name
        assert profile.h2_spec == name
        assert canonical_target(name) == name
        assert not tls.is_alias(name) and not tls.is_legacy(name)


# -------------------------------------------------------- captured ground truth


@pytest.mark.skipif(not HAVE_CAPTURES, reason="tools/ captures not in this checkout")
@pytest.mark.parametrize("name", TARGETS)
def test_header_sets_equal_the_captured_json(name):
    captured = _load(H2_DIR, name)
    profile = FINGERPRINTS[name]
    expected_h1 = [tuple(pair) for pair in captured["http11"]["headers"]
                   if pair[0].lower() not in LIBCURL_ONLY]
    expected_h2 = [(h["name"], h["value"]) for h in captured["headers"]
                   if not h["name"].startswith(":")]
    assert list(profile.headers) == expected_h1
    assert list(profile.h2_headers) == expected_h2
    assert profile.accept_encoding == _values(profile.headers)["accept-encoding"]
    assert data.CONCRETE[name]["akamai"] == captured["akamai_fingerprint"]
    assert captured["peet_ws"]["akamai_matches_local"] is True


@pytest.mark.skipif(not HAVE_CAPTURES, reason="tools/ captures not in this checkout")
def test_every_template_name_has_a_capture():
    hello = {f[:-5] for f in os.listdir(HELLO_DIR) if f.endswith(".json")}
    h2 = {f[:-5] for f in os.listdir(H2_DIR) if f.endswith(".json")}
    for name, profile in FINGERPRINTS.items():
        assert profile.tls_template in hello, (name, profile.tls_template)
        assert profile.h2_spec in h2, (name, profile.h2_spec)
        tpl = _load(HELLO_DIR, profile.tls_template)
        assert tpl["target"] == profile.tls_template
        assert tpl["peet_live"]["ja4_match"] is True
        assert tpl["peet_live"]["ja4_r_match"] is True


@pytest.mark.skipif(not HAVE_CAPTURES, reason="tools/ captures not in this checkout")
def test_alias_captures_point_at_their_target():
    for alias, concrete in ALIASES.items():
        hello_path = os.path.join(HELLO_DIR, "%s.json" % alias)
        if os.path.exists(hello_path):
            # capture_clienthello.py records alias_of for every alias it captures
            assert _load(HELLO_DIR, alias)["alias_of"] == concrete, alias
        h2_path = os.path.join(H2_DIR, "%s.json" % alias)
        if os.path.exists(h2_path):
            # capture_h2.py has no alias notion; the key is added after
            # verification against the concrete capture, so when present it
            # must agree, and the two captures must be the same header sets.
            captured = _load(H2_DIR, alias)
            assert captured.get("alias_of") in (None, concrete), alias
            target = _load(H2_DIR, concrete)
            assert captured["http11"]["headers"][1:] == target["http11"]["headers"][1:], alias
            assert [(h["name"], h["value"]) for h in captured["headers"] if h["name"] != ":authority"] == \
                [(h["name"], h["value"]) for h in target["headers"] if h["name"] != ":authority"], alias
            assert captured["akamai_fingerprint"] == target["akamai_fingerprint"], alias


@pytest.mark.skipif(not HAVE_CAPTURES, reason="tools/ captures not in this checkout")
def test_generated_module_is_current():
    sys.path.insert(0, TOOLS)
    try:
        gen = importlib.import_module("gen_profiles")
    finally:
        sys.path.remove(TOOLS)
    text, report = gen.generate(HELLO_DIR, H2_DIR, generated_at=data.GENERATED_AT)
    with open(os.path.join(ROOT, "curl_reap", "_profiles_data.py")) as fh:
        assert fh.read() == text
    assert report["aliases"] == ALIASES
    assert report["legacy"] == LEGACY
    assert set(report["aliases_verified_by_capture"]) >= {
        "chrome", "edge", "firefox", "safari", "safari_ios", "chrome_android", "tor",
        "safari_beta", "safari_ios_beta", "safari15_3", "safari15_5", "safari17_0",
        "safari17_2_ios", "safari18_0", "safari18_0_ios"}


@pytest.mark.skipif(not HAVE_CAPTURES, reason="tools/ captures not in this checkout")
def test_generator_emits_template_modules(tmp_path):
    sys.path.insert(0, TOOLS)
    try:
        gen = importlib.import_module("gen_profiles")
    finally:
        sys.path.remove(TOOLS)
    rc = gen.main(["--out", str(tmp_path / "_profiles_data.py"), "--templates-data",
                   "--templates-dir", str(tmp_path)])
    assert rc == 0
    namespace = {}
    exec(compile((tmp_path / "_tls" / "templates_data.py").read_text(), "tls", "exec"), namespace)
    assert namespace["template"]("chrome")["fingerprints"]["ja4"] == \
        namespace["TEMPLATES"]["chrome150"]["fingerprints"]["ja4"]
    assert "captures" not in namespace["TEMPLATES"]["chrome150"]
    namespace = {}
    exec(compile((tmp_path / "_h2" / "templates_data.py").read_text(), "h2", "exec"), namespace)
    assert namespace["template"]("firefox")["akamai_fingerprint"] == \
        "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
    assert "raw" not in namespace["TEMPLATES"]["firefox147"]
    assert gen.main(["--out", str(tmp_path / "_profiles_data.py"), "--check"]) == 0


# ------------------------------------------------------------ header shapes


def test_no_profile_carries_libcurl_tells():
    for name, profile in FINGERPRINTS.items():
        assert not LIBCURL_ONLY & {n.lower() for n in _names(profile.headers)}, name
        assert not LIBCURL_ONLY & set(_names(profile.h2_headers)), name
        assert all(n == n.lower() for n in _names(profile.h2_headers)), name


def test_h2_header_sets_follow_the_browser():
    chrome = profile_for_h2("chrome150")
    assert _names(chrome)[-1] == "priority"
    assert _values(chrome)["priority"] == "u=0, i"
    assert _names(chrome)[:3] == ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"]
    firefox = profile_for_h2("firefox147")
    assert _names(firefox)[-2:] == ["priority", "te"]
    assert _values(firefox)["te"] == "trailers"
    assert _names(firefox)[0] == "user-agent"
    safari = profile_for_h2("safari2601")
    assert _names(safari) == ["sec-fetch-dest", "user-agent", "accept", "sec-fetch-site",
                              "sec-fetch-mode", "accept-language", "priority", "accept-encoding"]
    # Safari sends priority over HTTP/2 only; the HTTP/1.1 set has none.
    assert "priority" not in {n.lower() for n in _names(FINGERPRINTS["safari2601"].headers)}
    edge = profile_for_h2("edge101")
    assert "priority" not in _names(edge)
    tor = profile_for_h2("tor145")
    assert _values(tor)["sec-gpc"] == "1"


def test_accept_encoding_is_the_captured_value():
    assert FINGERPRINTS["chrome150"].accept_encoding == "gzip, deflate, br, zstd"
    assert FINGERPRINTS["chrome99"].accept_encoding == "gzip, deflate, br"
    assert FINGERPRINTS["safari2601"].accept_encoding == "gzip, deflate, br"
    assert FINGERPRINTS["firefox147"].accept_encoding == "gzip, deflate, br, zstd"


def test_family_fields():
    assert families() == ("chrome", "edge", "firefox", "tor", "safari")
    assert set(targets("safari")) == {n for n in TARGETS if n.startswith("safari")}
    assert "safari_ios" not in targets("safari")
    assert "safari2601" in targets("safari") and "safari260_ios" in targets("safari")
    assert targets() == TARGETS
    assert targets("edge") == ("edge99", "edge101")
    assert targets("tor") == ("tor145",)
    for name in TARGETS:
        profile = FINGERPRINTS[name]
        assert profile.form_boundary == {"tor": "firefox"}.get(profile.family, profile.family)
        assert profile.ciphers
        assert profile.alpn_protocols == ("h2", "http/1.1")
    assert FINGERPRINTS["edge101"].ciphers == FINGERPRINTS["chrome101"].ciphers
    assert FINGERPRINTS["tor145"].ciphers == FINGERPRINTS["firefox147"].ciphers


# ---------------------------------------------------------------- legacy


@pytest.mark.parametrize("name", LEGACY_NAMES)
def test_legacy_names_resolve_with_their_own_version(name):
    profile = resolve_profile(name)
    assert profile.name == name
    assert tls.is_legacy(name)
    nearest = LEGACY[name]
    assert nearest in TARGETS
    donor = FINGERPRINTS[nearest]
    assert profile.tls_template == donor.tls_template
    assert profile.h2_spec == donor.h2_spec
    assert _names(profile.headers) == _names(donor.headers)
    assert _names(profile.h2_headers) == _names(donor.h2_headers)
    values = _values(profile.headers)
    ua = values["user-agent"]
    if profile.family in ("chrome", "edge"):
        major = profile.version
        assert "Chrome/%s.0.0.0" % major in ua
        assert '"Chromium";v="%s"' % major in values["sec-ch-ua"]
        if profile.family == "edge":
            assert ua.endswith("Edg/%s.0.0.0" % major)
            assert '"Microsoft Edge";v="%s"' % major in values["sec-ch-ua"]
            assert "Google Chrome" not in values["sec-ch-ua"]
        else:
            assert '"Google Chrome";v="%s"' % major in values["sec-ch-ua"]
            assert "Edg/" not in ua
    elif profile.family == "firefox":
        assert ua.endswith("Firefox/%s" % profile.version)
        assert "rv:%s)" % profile.version in ua
    elif profile.family == "safari":
        assert "Version/%s Safari" % profile.version in ua
    # the HTTP/2 set carries the same substituted values
    assert _values(profile.h2_headers)["user-agent"] == ua


def test_legacy_nearest_targets():
    assert LEGACY["chrome98"] == "chrome99"
    assert LEGACY["chrome126"] == "chrome124"
    assert LEGACY["chrome128"] == "chrome131"
    assert LEGACY["chrome133"] == "chrome133a"
    # Edge 126+ is Chromium of the same version, so it borrows Chrome
    assert LEGACY["edge131"] == "chrome131"
    assert LEGACY["edge126"] == "chrome124"
    assert all(LEGACY[n] == "firefox133" for n in LEGACY if n.startswith("firefox"))
    assert LEGACY["safari16_0"] == "safari155"
    assert LEGACY["safari16_4"] == "safari170"
    assert LEGACY["safari17_2"] == "safari170"
    # chrome98 keeps the GREASE brand of its donor but its own Chromium version
    assert _values(FINGERPRINTS["chrome98"].headers)["sec-ch-ua"] == \
        '" Not A;Brand";v="99", "Chromium";v="98", "Google Chrome";v="98"'


def test_legacy_names_are_documented_as_approximations():
    assert "APPROXIMATIONS" in data.__doc__
    assert "approximations" in tls.__doc__


# ------------------------------------------------------ 1.x compatibility


def test_one_x_normalisation_rules_still_work():
    assert resolve_profile("Chrome124") is FINGERPRINTS["chrome124"]
    assert resolve_profile("CHROME124") is FINGERPRINTS["chrome124"]
    assert resolve_profile(" chrome124 ") is FINGERPRINTS["chrome124"]
    a, b = resolve_profile("safari170"), resolve_profile("safari17_0")
    assert a.name == "safari170" and b.name == "safari17_0"
    assert a.headers == b.headers and a.tls_template == b.tls_template == "safari170"
    assert canonical_target("safari17_0") == canonical_target("safari170") == "safari170"
    assert resolve_profile("safari17.0").name == "safari17_0"
    assert resolve_profile("safari26_0").name == "safari260"
    assert resolve_profile("Safari_iOS").name == "safari_ios"
    assert resolve_profile("edge_99").tls_template == "edge99"
    assert resolve_profile("safari18_4").tls_template == "safari184"
    assert resolve_profile("safari18_4_ios").h2_spec == "safari184_ios"


def test_short_names_keep_their_own_name():
    assert resolve_profile("chrome") is PROFILES["chrome"] is FINGERPRINTS["chrome"]
    assert PROFILES["chrome"].name == "chrome"
    assert PROFILES["chrome"].tls_template == "chrome150"
    assert PROFILES["firefox"].tls_template == "firefox147"
    assert PROFILES["safari"].tls_template == "safari2601"
    assert set(PROFILES) == {"chrome", "firefox", "safari"}
    assert curl_reap.PROFILES is PROFILES
    assert curl_reap.FINGERPRINTS is FINGERPRINTS


def test_unknown_names_raise_both_hierarchies():
    with pytest.raises(UnknownProfileError, match="unknown TLS profile") as info:
        resolve_profile("netscape")
    assert isinstance(info.value, ValueError)
    assert isinstance(info.value, ImpersonateError)
    assert "chrome124" in str(info.value)
    with pytest.raises(ValueError, match="chrome124"):
        canonical_target("netscape")
    with pytest.raises(TypeError, match="Profile"):
        resolve_profile(object())
    with pytest.raises(TypeError):
        resolve_profile(42)


def test_custom_profile_construction():
    custom = Profile(name="custom", headers=(("user-agent", "custom"),))
    assert resolve_profile(custom) is custom
    assert custom.family == "custom"
    assert custom.version == ""
    assert custom.h2_headers is None
    assert custom.tls_template is None and custom.h2_spec is None
    assert custom.accept_encoding == ""
    assert custom.form_boundary == "other"
    assert custom.ciphers == ()
    assert custom.alpn_protocols == ("h2", "http/1.1")
    assert custom.curve == "X25519" and custom.minimum_version == "TLSv1_2"
    assert not custom.native
    assert custom.user_agent == "custom"
    assert profile_for_h2(custom) == (("user-agent", "custom"),)
    assert canonical_target(custom) == "custom"
    # headers passed as lists are coerced to tuples
    listy = Profile(name="listy", headers=[["Accept", "*/*"], ("Accept-Encoding", "gzip")])
    assert listy.headers == (("Accept", "*/*"), ("Accept-Encoding", "gzip"))
    assert listy.accept_encoding == "gzip"
    assert profile_for_h2(listy) == (("accept", "*/*"), ("accept-encoding", "gzip"))
    # a family picks the boundary rule and keeps explicit fields
    chromish = Profile(name="mine", family="chrome", headers=(), h2_headers=(("x", "1"),),
                       accept_encoding="gzip", ciphers=["AES128-GCM-SHA256"])
    assert chromish.form_boundary == "chrome"
    assert chromish.h2_headers == (("x", "1"),)
    assert chromish.accept_encoding == "gzip"
    assert chromish.ciphers == ("AES128-GCM-SHA256",)
    with pytest.raises(ValueError, match="non-empty"):
        Profile(name="")
    with pytest.raises(ValueError, match="pairs"):
        Profile(name="bad", headers=(("only-name",),))
    with pytest.raises(ValueError, match="ALPN"):
        Profile(name="bad", alpn_protocols=())
    # frozen
    with pytest.raises(Exception):
        custom.name = "other"  # type: ignore[misc]


def test_profiles_are_frozen_and_hashable():
    assert hash(FINGERPRINTS["chrome150"]) == hash(FINGERPRINTS["chrome150"])
    assert FINGERPRINTS["chrome"] != FINGERPRINTS["chrome150"]  # names differ
    assert FINGERPRINTS["chrome"].headers == FINGERPRINTS["chrome150"].headers


# ----------------------------------------------------- curl_cffi fingerprints


def test_fingerprint_dict_maps_to_nearest_target():
    assert resolve_profile({"client": "chrome", "client_version": "131", "os": "macos"}).name == "chrome131"
    assert resolve_profile({"client": "chrome", "client_version": "130", "os": "macOS"}).name == "chrome131"
    # equidistant versions prefer the newer capture
    assert resolve_profile({"client": "chrome", "client_version": "132", "os": "macOS"}).name == "chrome133a"
    assert resolve_profile({"client": "chrome", "client_version": "105", "os": "windows"}).name == "chrome104"
    assert resolve_profile({"client": "chrome", "client_version": "99", "os": "android"}).name == "chrome99_android"
    assert resolve_profile({"client": "chrome", "os": "android"}).name == "chrome131_android"
    assert resolve_profile({"client": "safari", "client_version": "18.0", "os": "ios"}).name == "safari180_ios"
    assert resolve_profile({"client": "safari", "client_version": "17.1", "os": "macos"}).name == "safari170"
    assert resolve_profile({"client": "safari", "client_version": "26.0.1"}).name == "safari2601"
    assert resolve_profile({"client": "firefox", "client_version": "140"}).name == "firefox144"
    assert resolve_profile({"client": "firefox"}).name == "firefox147"
    assert resolve_profile({"client": "edge", "client_version": "100"}).name == "edge101"
    assert resolve_profile({"client": "Chrome", "client_version": "", "os": ""}).name == "chrome150"
    assert resolve_profile({"client": "tor", "client_version": "14"}).name == "tor145"
    # an unknown platform is a preference, not a filter
    assert resolve_profile({"client": "firefox", "os": "windows", "client_version": "135"}).name == "firefox135"
    # a version far beyond the newest capture maps to the newest
    assert resolve_profile({"client": "chrome", "client_version": "999"}).name == "chrome150"


def test_fingerprint_object_maps_like_a_dict():
    class Spec:
        client = "safari"
        client_version = "18.4"
        os = "iOS"

    assert resolve_profile(Spec()).name == "safari184_ios"
    fp = pytest.importorskip("curl_cffi.fingerprints")
    native = fp.FingerprintManager.load_fingerprints()
    for name, fingerprint in native.items():
        if name in TARGETS:
            assert resolve_profile(fingerprint).name == name, name


def test_fingerprint_without_a_target_raises_with_choices():
    with pytest.raises(ImpersonateError, match="brave"):
        resolve_profile({"client": "brave", "client_version": "120"})
    with pytest.raises(ImpersonateError, match="chrome"):
        resolve_profile({"client": ""})
    with pytest.raises(ImpersonateError, match="no ios target for firefox"):
        resolve_profile({"client": "firefox", "os": "ios"})
    # dicts that are not fingerprints are a type error
    with pytest.raises(TypeError):
        resolve_profile({"name": "chrome"})


# ------------------------------------------------------- OpenSSL fallback


@pytest.mark.parametrize("name", ["chrome", "firefox", "safari", "edge99", "tor145", "chrome98"])
def test_create_ssl_context_for_each_family(name):
    context = create_ssl_context(name, verify=False, alpn=("h2", "http/1.1"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.options & ssl.OP_NO_COMPRESSION


def test_create_ssl_context_default_verifies_and_accepts_custom_profile():
    context = create_ssl_context("chrome")
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    custom = Profile(name="plain", headers=(), ciphers=(), minimum_version="TLSv1.3")
    context = create_ssl_context(custom, verify=False)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    with pytest.raises(UnknownProfileError):
        create_ssl_context("netscape")


def test_module_docstring_states_native_engine_and_fallback():
    doc = tls.__doc__
    assert "curl_reap._tls" in doc
    assert "fallback" in doc
    assert "Honesty" in doc

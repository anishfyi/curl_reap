"""RFC 6265bis Set-Cookie parsing and CookieJar scope semantics: (domain,
path, name) keys, host-only vs domain cookies, default-path, path
boundaries, scoped expiry, persistence, and the request-API facade."""
import json
import time

import pytest

from curl_reap.cookies import (
    CookieConflict,
    CookieJar,
    Cookies,
    _default_cookie_path,
    parse_set_cookie,
)


def spec_of(header):
    return parse_set_cookie(header)


# -- parser ------------------------------------------------------------

def test_set_cookie_parser_preserves_missing_path_and_host_only():
    spec = spec_of("a=1; Path=/; Domain=Example.COM; Secure")
    assert spec["name"] == "a" and spec["value"] == "1"
    assert spec["domain"] == "example.com" and spec["path"] == "/"
    assert spec["secure"] is True
    spec = spec_of("b=2")
    assert spec["domain"] is None and spec["path"] is None
    assert spec["secure"] is False and spec["httponly"] is False


def test_partitioned_attribute_keeps_the_whole_cookie():
    # F02: the 1.x parser dropped any Set-Cookie carrying Partitioned.
    spec = spec_of("sid=abc; Path=/; Secure; SameSite=None; Partitioned")
    assert spec["name"] == "sid" and spec["value"] == "abc"
    assert spec["partitioned"] is True
    assert spec["secure"] is True and spec["samesite"] == "None"
    jar = CookieJar()
    jar.absorb("https://tube.example/", [spec])
    assert jar.header_for("https://tube.example/") == "sid=abc"
    assert jar.get_dict() == {"sid": "abc"}
    assert list(jar)[0]["partitioned"] is True


def test_unknown_valued_attribute_is_ignored_not_stored():
    # F02: an unknown key=value attribute must not become a phantom cookie.
    spec = spec_of("sid=abc; Path=/; Priority=High")
    assert spec["name"] == "sid" and spec["value"] == "abc"
    assert set(spec) == {
        "name", "value", "domain", "path", "secure", "httponly", "samesite",
        "partitioned", "max_age", "expires"}
    jar = CookieJar()
    jar.absorb("https://ex.com/", [spec])
    assert jar.header_for("https://ex.com/") == "sid=abc"
    assert "Priority" not in jar.header_for("https://ex.com/")
    assert jar.get_dict() == {"sid": "abc"}
    assert len(jar) == 1


def test_unknown_flag_attribute_is_ignored():
    spec = spec_of("sid=abc; SameParty; Whatever=1")
    assert spec["name"] == "sid" and spec["value"] == "abc"
    jar = CookieJar()
    jar.absorb("https://ex.com/", [spec])
    assert jar.header_for("https://ex.com/") == "sid=abc"


def test_value_may_contain_spaces_commas_and_equals():
    # F02: "name=John Doe" was dropped whole by the 1.x parser.
    assert spec_of("name=John Doe")["value"] == "John Doe"
    assert spec_of("token=a,b c; Path=/")["value"] == "a,b c"
    assert spec_of("v=a=b=c")["value"] == "a=b=c"
    jar = CookieJar()
    jar.absorb("https://ex.com/", [spec_of("name=John Doe")])
    assert jar.header_for("https://ex.com/") == "name=John Doe"


def test_malformed_headers_return_none():
    assert parse_set_cookie("novalue") is None      # no '=' at all
    assert parse_set_cookie("=value") is None       # empty name
    assert parse_set_cookie("") is None
    assert parse_set_cookie(None) is None


def test_attribute_values_are_parsed_or_ignored():
    spec = spec_of("a=1; Max-Age=1_0; Expires=bogus; Path=/")
    assert spec["max_age"] is None and spec["expires"] is None
    assert spec_of("a=1; Max-Age=3600")["max_age"] == 3600
    assert spec_of("a=1; Max-Age=-5")["max_age"] == -5
    spec = spec_of("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
    assert spec["expires"] is not None and spec["expires"] > 1.6e9
    assert spec_of("a=1; SameSite=lax")["samesite"] == "Lax"
    assert spec_of("a=1; SameSite=Weird")["samesite"] is None
    assert spec_of("a=1; HttpOnly")["httponly"] is True
    assert spec_of("a=1; domain=.EXAMPLE.com")["domain"] == "example.com"


def test_duplicate_attributes_last_wins():
    assert spec_of("a=1; Path=/x; Path=/y")["path"] == "/y"
    assert spec_of("a=1; Max-Age=1; Max-Age=99")["max_age"] == 99


# -- default-path and path boundaries ----------------------------------

def test_default_cookie_path_is_request_directory():
    assert _default_cookie_path("/app/login") == "/app"
    assert _default_cookie_path("/app/") == "/app"
    assert _default_cookie_path("/") == "/"
    assert _default_cookie_path("") == "/"
    assert _default_cookie_path("/a/b/c") == "/a/b"
    assert _default_cookie_path("/a") == "/"
    assert _default_cookie_path("relative") == "/"


def test_host_only_cookie_does_not_reach_subdomains():
    jar = CookieJar()
    jar.absorb("https://app.example.com/login", [
        {"name": "s", "value": "1"},
    ])
    assert "s=1" in jar.header_for("https://app.example.com/x")
    assert "s=1" not in jar.header_for("https://sub.app.example.com/x")
    assert "s=1" not in jar.header_for("https://example.com/x")


def test_domain_cookie_matches_subdomains_without_leading_dot():
    jar = CookieJar()
    jar.absorb("https://app.example.com/login", [
        {"name": "d", "value": "1", "domain": "example.com"},
        {"name": "e", "value": "2", "domain": ".example.com"},
    ])
    for cookie in ("d=1", "e=2"):
        assert cookie in jar.header_for("https://deep.app.example.com/")
        assert cookie in jar.header_for("https://example.com/")


def test_foreign_and_ip_domain_attributes_rejected():
    jar = CookieJar()
    jar.absorb("https://app.example.com/", [
        {"name": "foreign", "value": "x", "domain": "evil.com"},
        {"name": "sibling", "value": "x", "domain": "other.example.com"},
        {"name": "child", "value": "x", "domain": "sub.app.example.com"},
        {"name": "ok", "value": "x", "domain": "example.com"},
    ])
    jar.absorb("https://10.0.0.5/", [
        {"name": "ipc", "value": "x", "domain": "10.0.0.5"},
    ])
    jar.absorb("https://app.example.com/", [
        {"name": "ipliteral", "value": "x", "domain": "10.0.0.5"},
    ])
    header = jar.header_for("https://app.example.com/")
    assert "ok=x" in header
    assert "foreign" not in header and "sibling" not in header
    assert "child" not in header and "ipliteral" not in header
    assert jar.header_for("https://10.0.0.5/") == ""


def test_path_boundary_app_is_not_apple():
    jar = CookieJar()
    jar.absorb("https://ex.com/app/login", [
        {"name": "scoped", "value": "v"},
        {"name": "slash", "value": "w", "path": "/app/"},
        {"name": "root", "value": "r", "path": "/"},
    ])
    assert "scoped=v" in jar.header_for("https://ex.com/app/child")
    assert "scoped=v" not in jar.header_for("https://ex.com/apple")
    assert "slash=w" not in jar.header_for("https://ex.com/apple")
    assert "slash=w" in jar.header_for("https://ex.com/app/x")
    jar.absorb("https://ex.com/dir/page", [{"name": "odd", "value": "o",
                                            "path": "relative"}])
    assert "odd=o" in jar.header_for("https://ex.com/dir/sub")
    assert "odd=o" not in jar.header_for("https://ex.com/relative")


def test_longer_paths_first_then_stable_order():
    jar = CookieJar()
    jar.absorb("https://ex.com/", [
        {"name": "a", "value": "1", "path": "/"},
        {"name": "b", "value": "2", "path": "/deep/path"},
        {"name": "c", "value": "3", "path": "/deep"},
    ])
    header = jar.header_for("https://ex.com/deep/path/x")
    assert header.index("b=2") < header.index("c=3") < header.index("a=1")


# -- secure, expiry and IDNA --------------------------------------------

def test_secure_cookie_rejected_from_http_origin():
    jar = CookieJar()
    jar.absorb("http://ex.com/", [
        {"name": "s", "value": "1", "secure": True},
        {"name": "plain", "value": "2", "secure": False},
    ])
    assert len(jar) == 1
    assert jar.header_for("https://ex.com/") == "plain=2"
    jar.absorb("https://ex.com/", [{"name": "s", "value": "1", "secure": True}])
    assert jar.header_for("https://ex.com/") == "plain=2; s=1"
    assert jar.header_for("http://ex.com/") == "plain=2"


def test_max_age_zero_deletes_exact_key_only():
    jar = CookieJar()
    jar.absorb("https://ex.com/a/b", [
        {"name": "n", "value": "shallow", "path": "/a"},
        {"name": "n", "value": "deep", "path": "/a/b"},
        {"name": "other", "value": "x", "path": "/a/b"},
    ])
    header = jar.header_for("https://ex.com/a/b/c")
    assert "n=deep" in header and "n=shallow" in header
    jar.absorb("https://ex.com/a/b", [{"name": "n", "value": "",
                                       "path": "/a/b", "max_age": 0}])
    header = jar.header_for("https://ex.com/a/b/c")
    assert "n=deep" not in header
    assert "n=shallow" in header
    assert "other=x" in header


def test_past_expiry_and_negative_max_age_delete():
    jar = CookieJar()
    jar.absorb("https://ex.com/", [
        {"name": "gone", "value": "1", "expires": 0},
        {"name": "neg", "value": "2", "max_age": -1},
        {"name": "kept", "value": "3", "expires": time.time() + 3600},
    ])
    assert jar.get_dict() == {"kept": "3"}


def test_hosts_and_domains_are_idna_normalized():
    jar = CookieJar()
    jar.absorb("https://münchen.example/", [
        {"name": "u", "value": "1"},
        {"name": "d", "value": "2", "domain": "MÜNCHEN.EXAMPLE"},
    ])
    punycode = "https://xn--mnchen-3ya.example/"
    assert "u=1" in jar.header_for(punycode) and "d=2" in jar.header_for(punycode)
    assert "u=1" in jar.header_for("https://münchen.example/")
    assert "u=1" not in jar.header_for("https://sub.xn--mnchen-3ya.example/")
    assert "d=2" in jar.header_for("https://sub.xn--mnchen-3ya.example/")


# -- jar API: set/get/delete, iteration, dict view ----------------------

def test_set_get_delete_with_scope_selectors():
    jar = CookieJar()
    jar.set("a", "1")
    assert jar.get("a") == "1"
    jar.set("a", "2", domain="EX.com", path="/x")
    with pytest.raises(CookieConflict):
        jar.get("a")
    assert jar.get("a", domain="ex.com") == "2"
    assert jar.get("a", path="/") == "1"
    assert jar.get("missing") is None and jar.get("missing", "d") == "d"
    assert len(jar) == 2
    jar.delete("a", domain="ex.com")
    assert jar.get("a") == "1"
    jar.delete("a")
    assert len(jar) == 0
    with pytest.raises(KeyError):
        jar.delete("a")


def test_iter_yields_cookie_dicts_and_items_pairs():
    jar = CookieJar()
    jar.set("a", "1")
    jar.absorb("https://ex.com/", [spec_of("b=2; Secure")])
    records = list(jar)
    assert [r["name"] for r in records] == ["a", "b"]
    assert records[1]["secure"] is True and records[1]["domain"] == "ex.com"
    assert jar.items() == [("a", "1"), ("b", "2")]


def test_get_dict_is_documented_lossy_flattened_view():
    jar = CookieJar()
    jar.absorb("https://ex.com/a/b", [
        {"name": "n", "value": "first", "path": "/a"},
        {"name": "n", "value": "second", "path": "/a/b"},
    ])
    assert jar.get_dict() == {"n": "second"}


def test_unscoped_set_cookies_replay_to_every_host():
    jar = CookieJar()
    jar.set("a", "1")
    assert jar.header_for("https://any.example/") == "a=1"
    assert jar.header_for("http://other.test/x") == "a=1"
    jar.set("s", "9", secure=True)
    assert "s=9" not in jar.header_for("http://other.test/")
    assert "s=9" in jar.header_for("https://other.test/")


def test_header_for_extra_overrides_and_appends():
    jar = CookieJar()
    jar.absorb("https://ex.com/", [{"name": "a", "value": "1"}])
    assert jar.header_for("https://ex.com/", {"b": "2"}) == "a=1; b=2"
    assert jar.header_for("https://ex.com/", {"a": "9"}) == "a=9"
    assert jar.header_for("https://ex.com/") == "a=1"  # extra not stored
    assert jar.header_for("https://ex.com/", [("c", "3"), ("a", "8")]) == "a=8; c=3"


def test_update_merges_jars_facades_and_mappings():
    jar = CookieJar()
    jar.update({"a": "1"})
    scoped = CookieJar()
    scoped.absorb("https://ex.com/", [spec_of("b=2; Secure; HttpOnly")])
    jar.update(scoped)
    jar.update(Cookies({"c": "3"}))
    assert jar.get_dict() == {"a": "1", "b": "2", "c": "3"}
    # Scoped cookies keep their scope; only the mapping cookies are global.
    assert "b=2" not in jar.header_for("https://other.test/")
    assert jar.header_for("https://ex.com/") == "a=1; b=2; c=3"


def test_to_cookiejar_exports_stdlib_cookies():
    jar = CookieJar()
    jar.absorb("https://app.example.com/", [
        spec_of("host=1"),
        spec_of("dom=2; Domain=example.com; Secure"),
    ])
    jar.set("flat", "3")
    exported = jar.to_cookiejar()
    by_name = {c.name: c for c in exported}
    assert set(by_name) == {"host", "dom", "flat"}
    assert by_name["host"].value == "1" and by_name["host"].path == "/"
    assert by_name["dom"].domain == ".example.com" and by_name["dom"].secure
    assert by_name["dom"].domain_specified is True
    assert by_name["flat"].domain == ""
    assert len(list(exported)) == 3


def test_save_load_round_trip(tmp_path):
    path = tmp_path / "cookies.json"
    jar = CookieJar()
    jar.absorb("https://ex.com/", [
        spec_of("a=1; Secure; HttpOnly; SameSite=Lax"),
        spec_of("b=2; Domain=ex.com; Partitioned"),
        {"name": "c", "value": "3", "expires": time.time() + 3600},
    ])
    jar.set("d", "4")
    jar.save(path)
    loaded = CookieJar()
    loaded.load(path)
    assert loaded.get_dict() == jar.get_dict()
    assert len(loaded) == len(jar) == 4
    assert loaded.header_for("https://ex.com/") == jar.header_for("https://ex.com/")
    records = {r["name"]: r for r in loaded}
    assert records["a"]["secure"] and records["a"]["httponly"]
    assert records["a"]["samesite"] == "Lax" and records["a"]["host_only"]
    assert records["b"]["partitioned"] and not records["b"]["host_only"]
    assert records["d"]["domain"] is None
    assert records["c"]["expires"] == pytest.approx(
        {r["name"]: r for r in jar}["c"]["expires"])
    # Expired entries are dropped instead of resurrected.
    stale = {"version": 1, "cookies": [
        {"name": "old", "value": "1", "domain": "ex.com", "path": "/",
         "secure": False, "httponly": False, "samesite": None,
         "partitioned": False, "expires": time.time() - 10, "host_only": True},
    ]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(stale, fh)
    loaded.load(path)
    assert len(loaded) == 0


def test_clear_removes_everything():
    jar = CookieJar()
    jar.update({"a": "1"})
    jar.clear()
    assert len(jar) == 0 and jar.get_dict() == {}


# -- Cookies facade ------------------------------------------------------

def test_facade_get_set_del_through_the_jar():
    cookies = Cookies()
    assert len(cookies) == 0 and not cookies
    cookies["a"] = "1"
    assert cookies.jar.get("a") == "1"        # set goes through the jar
    assert cookies["a"] == "1"                # get reads through the jar
    assert "a" in cookies
    cookies["a"] = "2"
    assert cookies.jar.get("a") == "2"
    assert len(cookies) == 1 and list(cookies) == ["a"]
    assert list(cookies.items()) == [("a", "2")]
    del cookies["a"]
    with pytest.raises(KeyError):
        cookies["a"]
    assert len(cookies) == 0


def test_facade_scoped_set_get_delete():
    cookies = Cookies()
    cookies.set("b", "2", domain="ex.com")
    assert cookies.jar.get("b", domain="ex.com") == "2"
    assert cookies.get("b", domain="ex.com") == "2"
    assert cookies.get("b") == "2"          # one scope: not ambiguous
    cookies.delete("b", domain="ex.com")
    with pytest.raises(KeyError):
        cookies["b"]
    assert cookies.get("b", "x") == "x"


def test_facade_conflict_on_ambiguous_name():
    jar = CookieJar()
    jar.set("n", "1")
    jar.set("n", "2", domain="ex.com")
    cookies = Cookies(jar)                    # wraps the jar, no copy
    assert cookies.jar is jar
    with pytest.raises(CookieConflict):
        cookies["n"]
    assert "n" in cookies                     # conflict still means present
    assert cookies.get("n", domain="ex.com") == "2"


def test_facade_construction_from_mappings_and_other_facades():
    assert dict(Cookies({"x": "1"}).jar.get_dict()) == {"x": "1"}
    assert dict(Cookies([("y", "2")]).jar.get_dict()) == {"y": "2"}
    original = Cookies({"z": "3"})
    copy = Cookies(original)
    assert copy["z"] == "3" and copy.jar is not original.jar
    merged = Cookies({"a": "1"})
    merged.update({"b": "2"}, c="3")
    assert dict(merged.jar.get_dict()) == {"a": "1", "b": "2", "c": "3"}
    assert "Cookies[" in repr(merged)


def test_facade_update_from_jar_preserves_scopes():
    jar = CookieJar()
    jar.absorb("https://ex.com/", [spec_of("k=1")])
    cookies = Cookies({"f": "2"})
    cookies.update(jar)
    assert cookies.jar.header_for("https://ex.com/") == "f=2; k=1"
    assert cookies.jar.header_for("https://other.test/") == "f=2"

"""CookieJar scope semantics: (domain, path, name) keys, host-only vs
domain cookies, default-path, path boundaries, and scoped expiry."""
import curl_reap
from curl_reap.http import _default_cookie_path, _parse_set_cookie

def test_set_cookie_parser_preserves_missing_path_and_host_only():
    triples = _parse_set_cookie("a=1; Path=/; Domain=Example.COM; Secure")
    name, value, spec = triples[0]
    assert spec["domain"] == "example.com" and spec["path"] == "/"
    triples = _parse_set_cookie("b=2")
    _, _, spec = triples[0]
    assert spec["domain"] is None and spec["path"] is None

def test_default_cookie_path_is_request_directory():
    assert _default_cookie_path("/app/login") == "/app"
    assert _default_cookie_path("/app/") == "/app"
    assert _default_cookie_path("/") == "/"
    assert _default_cookie_path("") == "/"

def test_host_only_cookie_does_not_reach_subdomains():
    jar = curl_reap.CookieJar()
    jar.absorb("https://app.example.com/login", [
        {"name": "s", "value": "1"},
    ])
    assert "s=1" in jar.header_for("https://app.example.com/x")
    assert "s=1" not in jar.header_for("https://sub.app.example.com/x")
    assert "s=1" not in jar.header_for("https://example.com/x")

def test_domain_cookie_matches_subdomains_without_leading_dot():
    jar = curl_reap.CookieJar()
    jar.absorb("https://app.example.com/login", [
        {"name": "d", "value": "1", "domain": "example.com"},
        {"name": "e", "value": "2", "domain": ".example.com"},
    ])
    for cookie in ("d=1", "e=2"):
        assert cookie in jar.header_for("https://deep.app.example.com/")
        assert cookie in jar.header_for("https://example.com/")

def test_foreign_and_ip_domain_attributes_rejected():
    jar = curl_reap.CookieJar()
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
    jar = curl_reap.CookieJar()
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
    jar = curl_reap.CookieJar()
    jar.absorb("https://ex.com/", [
        {"name": "a", "value": "1", "path": "/"},
        {"name": "b", "value": "2", "path": "/deep/path"},
        {"name": "c", "value": "3", "path": "/deep"},
    ])
    header = jar.header_for("https://ex.com/deep/path/x")
    assert header.index("b=2") < header.index("c=3") < header.index("a=1")

def test_max_age_zero_deletes_exact_key_only():
    jar = curl_reap.CookieJar()
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

def test_get_dict_is_documented_lossy_flattened_view():
    jar = curl_reap.CookieJar()
    jar.absorb("https://ex.com/a/b", [
        {"name": "n", "value": "first", "path": "/a"},
        {"name": "n", "value": "second", "path": "/a/b"},
    ])
    assert jar.get_dict() == {"n": "second"}

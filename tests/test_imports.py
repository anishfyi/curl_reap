"""The native engines load with the package, not lazily per request.

Regression test for the Python 3.14 import deadlock: transport.py imports
``curl_reap._h2`` inside ``_connect``, and ``_h2`` imports ``hpack``. When
another thread (an embedded server, another library) imports ``hpack`` at the
same moment a first HTTP/2 request triggers the lazy import, the per-module
import locks deadlock (``_DeadlockError``). The fix loads both engines during
``import curl_reap``, which the import system serializes.
"""
import sys

import pytest

from curl_reap._h2 import spec as _load_spec
from curl_reap._h2.core import build_request_fields
from curl_reap.exceptions import InvalidHeader


def test_native_engines_load_with_package():
    import curl_reap

    assert "curl_reap._h2" in sys.modules
    assert "curl_reap._tls" in sys.modules


def _fields(method="GET", path="/", headers=()):
    return build_request_fields(_load_spec("chrome131"), method, "https",
                                "example.com", path, headers)


def test_valid_request_builds():
    fields = _fields(headers=[("User-Agent", "reap"), ("Accept", "*/*")])
    assert fields[0] == (b":method", b"GET")
    names = [n for n, _ in fields]
    assert b"user-agent" in names and b"accept" in names


@pytest.mark.parametrize("method", [b"", b"GE T", b"GE\tT", "gét"])
def test_bad_method_rejected(method):
    with pytest.raises(InvalidHeader):
        _fields(method=method)


@pytest.mark.parametrize("path", ["/a b", "/a\nb", "/a\rb", "/a\x00b"])
def test_forbidden_path_characters_rejected(path):
    with pytest.raises(InvalidHeader):
        _fields(path=path)


@pytest.mark.parametrize("name", [b"bad name", b"bad\nname", b"na*me"[:2] + b"@", "()"])
def test_bad_header_name_rejected(name):
    with pytest.raises(InvalidHeader):
        _fields(headers=[(name, "v")])


@pytest.mark.parametrize("value", [b"v\x00", b"v\n", b"v\r"])
def test_control_characters_in_value_rejected(value):
    with pytest.raises(InvalidHeader):
        _fields(headers=[("X-Test", value)])

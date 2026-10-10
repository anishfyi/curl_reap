import json

import pytest

from curl_reap.headers import CaseInsensitiveHeaders, Headers, header_pairs


def test_constructor_forms():
    via_list = Headers([("Accept", "text/html"), ("accept", "application/json")])
    via_mapping = Headers({"Accept": "text/html"})
    via_lines = Headers("Accept: text/html\r\nX-A: 1\r\n\r\n")
    via_pairs = Headers((("a", "1"), ("A", "2")))
    assert via_list.get_list("accept") == ["text/html", "application/json"]
    assert via_mapping["ACCEPT"] == "text/html"
    assert via_lines.get_list("x-a") == ["1"]
    assert via_pairs.get_list("A") == ["1", "2"]
    assert Headers(Headers({"a": "1"}))["a"] == "1"


def test_getitem_joins_and_is_case_insensitive():
    h = Headers()
    h.add("Set-Cookie", "a=1")
    h.add("set-cookie", "b=2")
    assert h["set-cookie"] == "a=1, b=2"
    assert h["SET-COOKIE"] == "a=1, b=2"


def test_setitem_replaces_all_and_keeps_first_casing():
    h = Headers([("X-A", "1"), ("x-a", "2"), ("X-B", "3")])
    h["x-a"] = "9"
    assert h.get_list("X-A") == ["9"]
    assert h.multi_items() == [("X-A", "9"), ("X-B", "3")]


def test_get_list_split_commas():
    h = Headers({"Accept-Encoding": "gzip, br, zstd"})
    assert h.get_list("accept-encoding") == ["gzip, br, zstd"]
    assert h.get_list("accept-encoding", split_commas=True) == ["gzip", "br", "zstd"]
    assert h.get_list("missing", split_commas=True) == []


def test_multi_items_raw_and_none():
    h = Headers([("A", "1"), ("B", None), ("A", "2")])
    assert h.multi_items() == [("A", "1"), ("A", "2")]
    assert h.multi_items(include_none=True) == [("A", "1"), ("B", None), ("A", "2")]
    assert h.raw() == [(b"A", b"1"), (b"A", b"2")]  # first-seen casing, None dropped


def test_none_values_never_sent():
    h = Headers([("User-Agent", "reap"), ("X-Drop", None)])
    pairs = [p for p in header_pairs(h) if p[1] is not None]
    assert ("User-Agent", "reap") in pairs
    assert all(name.lower() != "x-drop" for name, _ in pairs)


def test_add_updates_del_pop_contains_len():
    h = Headers()
    h["A"] = "1"
    h.add("a", "2")
    assert len(h) == 1 and "a" in h
    assert h.pop("A") == "1, 2"
    assert "a" not in h and len(h) == 0
    h.add("B", "1")
    del h["b"]
    assert len(h) == 0


def test_dict_compatibility():
    h = Headers([("A", "1"), ("A", "2"), ("B", "3")])
    assert isinstance(h, dict)
    assert json.loads(json.dumps(h)) == {"A": "1, 2", "B": "3"}
    assert dict(h) == {"A": "1, 2", "B": "3"}
    assert list(h.keys()) == ["A", "B"]
    h2 = h.copy()
    h2.add("a", "9")
    assert h.get_list("a") == ["1", "2"]
    assert h2.get_list("a") == ["1", "2", "9"]


def test_equality_and_alias():
    a = Headers({"X": "1"})
    b = Headers()
    b.add("x", "1")
    assert a == b and a != {"X": "2"}
    assert CaseInsensitiveHeaders is Headers


def test_update_is_case_insensitive():
    h = Headers({"X-Old": "1"})
    h.update({"x-old": "2", "New": "3"})
    assert h.get_list("x-old") == ["2"]
    assert h["new"] == "3"

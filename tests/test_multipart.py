"""Tests for curl_reap.multipart: boundaries, byte-exact bodies, escaping, API parity."""
import io
import os
import re
import socket
import threading

import pytest

from curl_reap import multipart
from curl_reap.multipart import (
    CurlMime, Multipart, MultipartPart, boundary_for, encode_multipart,
    escape_filename, escape_name, guess_content_type,
)

B = "----WebKitFormBoundaryTESTtest0123456"
BB = B.encode("ascii")
CT = "multipart/form-data; boundary=" + B

WEBKIT_RE = re.compile(r"^----WebKitFormBoundary[A-Za-z0-9]{16}$")
GECKO_RE = re.compile(r"^----geckoformboundary[0-9a-f]{32}$")


def part(name, value, extra=b""):
    return (b"--" + BB + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
            + extra + b"\r\n\r\n" + value + b"\r\n")


def file_part(name, filename, ctype, value, extra_headers=b""):
    return (b"--" + BB + b'\r\nContent-Disposition: form-data; name="' + name
            + b'"; filename="' + filename + b'"\r\nContent-Type: ' + ctype + b"\r\n"
            + extra_headers + b"\r\n" + value + b"\r\n")


CLOSE = b"--" + BB + b"--\r\n"


# ---------------------------------------------------------------- boundaries

@pytest.mark.parametrize("family", ["chrome", "edge", "safari", "Chrome", "CHROMIUM",
                                    "webkit", "safari_ios", "chrome_android", "brave"])
def test_boundary_webkit_family_shape(family):
    assert WEBKIT_RE.match(boundary_for(family))


@pytest.mark.parametrize("family", ["firefox", "Firefox", "gecko", "tor"])
def test_boundary_gecko_shape(family):
    assert GECKO_RE.match(boundary_for(family))


def test_boundary_firefox_legacy_shape():
    assert re.match(r"^-{27}[0-9]{20}$", boundary_for("firefox_legacy"))


def test_boundary_curl_shape():
    assert re.match(r"^-{24}[A-Za-z0-9]{22}$", boundary_for("curl"))


@pytest.mark.parametrize("family", ["other", "custom", "", None, "unknown-family"])
def test_boundary_other_is_32_hex(family):
    assert re.match(r"^[0-9a-f]{32}$", boundary_for(family))


def test_boundaries_are_random_and_rfc2046_valid():
    seen = {boundary_for(f) for f in ["chrome"] * 10 + ["firefox"] * 10 + ["other"] * 10}
    assert len(seen) == 30
    for value in seen:
        assert multipart._validate_boundary(value) == value.encode("ascii")
        assert len(value) <= 70


def test_boundary_default_family_is_chrome():
    assert WEBKIT_RE.match(boundary_for())


# ---------------------------------------------------------------- encode_multipart

def test_empty_form_is_just_the_closing_delimiter():
    assert encode_multipart(boundary=B) == (CLOSE, CT)


def test_data_only_layout_is_byte_exact():
    body, ctype = encode_multipart({"a": "1", "b": "two"}, boundary=B)
    assert ctype == CT
    assert body == part(b"a", b"1") + part(b"b", b"two") + CLOSE
    assert len(body) == len(part(b"a", b"1")) + len(part(b"b", b"two")) + len(CLOSE)


def test_data_fields_come_before_files_in_their_own_orders():
    body, _ = encode_multipart(data=[("z", "1"), ("a", "2")],
                               files=[("y", ("y.txt", b"Y")), ("b", ("b.txt", b"B"))],
                               boundary=B)
    assert body == (part(b"z", b"1") + part(b"a", b"2")
                    + file_part(b"y", b"y.txt", b"text/plain", b"Y")
                    + file_part(b"b", b"b.txt", b"text/plain", b"B") + CLOSE)


def test_repeated_names_from_list_values_and_pair_sequences():
    body, _ = encode_multipart({"tag": ["x", "y"]}, boundary=B)
    assert body == part(b"tag", b"x") + part(b"tag", b"y") + CLOSE
    body, _ = encode_multipart([("tag", "x"), ("tag", "y")], boundary=B)
    assert body == part(b"tag", b"x") + part(b"tag", b"y") + CLOSE


def test_none_values_are_skipped_and_scalars_go_through_str():
    body, _ = encode_multipart({"skip": None, "n": 5, "f": 1.5, "t": True,
                                "l": [None, "v"]}, boundary=B)
    assert body == (part(b"n", b"5") + part(b"f", b"1.5") + part(b"t", b"True")
                    + part(b"l", b"v") + CLOSE)


def test_bytes_values_are_sent_verbatim():
    body, _ = encode_multipart({"raw": b"\x00\xff\r\n--" + BB}, boundary=B)
    assert body == part(b"raw", b"\x00\xff\r\n--" + BB) + CLOSE


@pytest.mark.parametrize("filename, ctype", [
    ("a.txt", b"text/plain"), ("pic.png", b"image/png"), ("data.json", b"application/json"),
    ("x.tar.gz", b"application/gzip"), ("archive", b"application/octet-stream"),
    ("", b"application/octet-stream"),
])
def test_two_tuple_file_guesses_content_type_from_filename(filename, ctype):
    body, _ = encode_multipart(files={"f": (filename, b"x")}, boundary=B)
    assert body == file_part(b"f", filename.encode(), ctype, b"x") + CLOSE


def test_three_tuple_explicit_type_and_none_means_guess():
    body, _ = encode_multipart(files={"f": ("a.txt", b"x", "text/x-custom")}, boundary=B)
    assert body == file_part(b"f", b"a.txt", b"text/x-custom", b"x") + CLOSE
    body, _ = encode_multipart(files={"f": ("a.txt", b"x", None)}, boundary=B)
    assert body == file_part(b"f", b"a.txt", b"text/plain", b"x") + CLOSE


def test_four_tuple_headers_follow_content_type_and_override_in_place():
    body, _ = encode_multipart(files={"f": ("a.txt", b"x", "text/plain",
                                            {"X-Extra": "1", "Content-Location": "/a"})},
                               boundary=B)
    assert body == file_part(b"f", b"a.txt", b"text/plain", b"x",
                             b"X-Extra: 1\r\nContent-Location: /a\r\n") + CLOSE
    body, _ = encode_multipart(files={"f": ("a.txt", b"x", "text/plain",
                                            [("content-type", "text/html"), ("X", "y")])},
                               boundary=B)
    assert body == file_part(b"f", b"a.txt", b"text/html", b"x", b"X: y\r\n") + CLOSE
    body, _ = encode_multipart(files={"f": ("a.txt", b"x", "text/plain",
                                            {"Content-Disposition": "attachment"})},
                               boundary=B)
    assert body == (b"--" + BB + b"\r\nContent-Disposition: attachment\r\n"
                    b"Content-Type: text/plain\r\n\r\nx\r\n" + CLOSE)


@pytest.mark.parametrize("spec", [("only",), ("a", b"b", "c", {}, "extra")])
def test_file_tuple_with_wrong_length_is_rejected(spec):
    with pytest.raises(ValueError):
        encode_multipart(files={"f": spec}, boundary=B)


def test_file_object_takes_filename_from_its_name(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b'{"a": 1}')
    with open(str(path), "rb") as fh:
        body, _ = encode_multipart(files={"doc": fh}, boundary=B)
    assert body == file_part(b"doc", b"report.json", b"application/json", b'{"a": 1}') + CLOSE


def test_file_object_without_a_path_name_uses_the_field_name():
    body, _ = encode_multipart(files={"blob": io.BytesIO(b"zz")}, boundary=B)
    assert body == file_part(b"blob", b"blob", b"application/octet-stream", b"zz") + CLOSE
    body, _ = encode_multipart(files={"text": io.StringIO("h\u00e9")}, boundary=B)
    assert body == file_part(b"text", b"text", b"application/octet-stream",
                             "h\u00e9".encode("utf-8")) + CLOSE


def test_file_object_inside_a_tuple_is_read(tmp_path):
    path = tmp_path / "a.txt"
    path.write_bytes(b"disk")
    with open(str(path), "rb") as fh:
        body, _ = encode_multipart(files={"f": ("renamed.txt", fh)}, boundary=B)
    assert body == file_part(b"f", b"renamed.txt", b"text/plain", b"disk") + CLOSE


def test_plain_bytes_or_str_file_value_uses_the_field_name_as_filename():
    body, _ = encode_multipart(files={"up.txt": b"raw"}, boundary=B)
    assert body == file_part(b"up.txt", b"up.txt", b"text/plain", b"raw") + CLOSE
    body, _ = encode_multipart(files={"note": "caf\u00e9"}, boundary=B)
    assert body == file_part(b"note", b"note", b"application/octet-stream",
                             "caf\u00e9".encode("utf-8")) + CLOSE


def test_file_content_none_skips_the_part():
    body, _ = encode_multipart(files={"f": ("a.txt", None), "g": ("b.txt", b"B")}, boundary=B)
    assert body == file_part(b"g", b"b.txt", b"text/plain", b"B") + CLOSE


def test_tuple_with_filename_none_is_a_plain_field():
    body, _ = encode_multipart(files={"f": (None, b"v")}, boundary=B)
    assert body == part(b"f", b"v") + CLOSE
    body, _ = encode_multipart(files={"f": (None, b"v", "text/plain")}, boundary=B)
    assert body == part(b"f", b"v", b"\r\nContent-Type: text/plain") + CLOSE


@pytest.mark.parametrize("name, escaped", [
    ('a"b', b"a%22b"), ("x\ny", b"x%0D%0Ay"), ("x\ry", b"x%0D%0Ay"), ("x\r\ny", b"x%0D%0Ay"),
    ("x\n\ny", b"x%0D%0A%0D%0Ay"), ("back\\slash", b"back\\slash"), ("semi;colon", b"semi;colon"),
    ("n\u00e4me", "n\u00e4me".encode("utf-8")),
])
def test_field_name_escaping_follows_the_html_standard(name, escaped):
    body, _ = encode_multipart({name: "v"}, boundary=B)
    assert body == part(escaped, b"v") + CLOSE


@pytest.mark.parametrize("filename, escaped", [
    ('a"b.txt', b"a%22b.txt"), ("a\nb.txt", b"a%0Ab.txt"), ("a\rb.txt", b"a%0Db.txt"),
    ("a\r\nb.txt", b"a%0D%0Ab.txt"), ("C:\\dir\\f.txt", b"C:\\dir\\f.txt"),
    ("f\u00efle.txt", "f\u00efle.txt".encode("utf-8")),
])
def test_filename_escaping_has_no_newline_normalisation(filename, escaped):
    body, _ = encode_multipart(files={"f": (filename, b"x")}, boundary=B)
    assert body == file_part(b"f", escaped, b"text/plain", b"x") + CLOSE


def test_escape_helpers_accept_str_and_bytes():
    assert escape_name('q"\r\n\\') == b"q%22%0D%0A\\"
    assert escape_name(b"a\nb") == b"a%0D%0Ab"
    assert escape_filename("a\n\"") == b"a%0A%22"
    assert escape_filename(b"x\ry") == b"x%0Dy"


def test_bytes_names_and_filenames_pass_through():
    body, _ = encode_multipart([(b"n\xc3\xa4", b"v")], files=[(b"f", (b"\xff.bin", b"x"))],
                               boundary=B)
    assert body == (part(b"n\xc3\xa4", b"v")
                    + file_part(b"f", b"\xff.bin", b"application/octet-stream", b"x") + CLOSE)


def test_content_type_header_has_unquoted_boundary():
    _, ctype = encode_multipart({"a": "b"}, boundary=B)
    assert ctype == "multipart/form-data; boundary=" + B
    _, ctype = encode_multipart({"a": "b"}, boundary=BB)
    assert ctype == "multipart/form-data; boundary=" + B


def test_default_boundary_is_chrome_shaped_and_used_in_the_body():
    body, ctype = encode_multipart({"a": "b"})
    boundary = ctype.split("boundary=", 1)[1]
    assert WEBKIT_RE.match(boundary)
    assert body.startswith(b"--" + boundary.encode() + b"\r\n")
    assert body.endswith(b"--" + boundary.encode() + b"--\r\n")


@pytest.mark.parametrize("bad", ["", "trailing space ", "x" * 71, 'has"quote', "nl\n", "a;b"])
def test_invalid_boundaries_are_rejected(bad):
    with pytest.raises(ValueError):
        encode_multipart({"a": "b"}, boundary=bad)


def test_boundary_may_use_every_rfc2046_character():
    boundary = "ab09'()+_,-./:=? end"
    body, ctype = encode_multipart({"a": "b"}, boundary=boundary)
    assert ctype.endswith("boundary=" + boundary)
    assert body.endswith(b"--" + boundary.encode() + b"--\r\n")


@pytest.mark.parametrize("data", ["a=1", b"a=1"])
def test_string_data_is_rejected(data):
    with pytest.raises(ValueError):
        encode_multipart(data, files={"f": ("a.txt", b"x")}, boundary=B)


def test_malformed_pairs_are_rejected():
    with pytest.raises(ValueError):
        encode_multipart([("a",)], boundary=B)
    with pytest.raises(ValueError):
        encode_multipart(files=[("f", "a.txt", b"x")], boundary=B)


@pytest.mark.parametrize("files", [
    {"f": ("a.txt", b"x", "text/plain\r\nX-Injected: 1")},
    {"f": ("a.txt", b"x", "text/plain", {"X": "a\nb"})},
    {"f": ("a.txt", b"x", "text/plain", {"X\r\nY": "a"})},
])
def test_header_injection_is_rejected(files):
    with pytest.raises(ValueError):
        encode_multipart(files=files, boundary=B)


def test_requests_documentation_example(tmp_path):
    path = tmp_path / "report.xls"
    path.write_bytes(b"XLS")
    with open(str(path), "rb") as fh:
        body, ctype = encode_multipart(
            files={"file": ("report.xls", fh, "application/vnd.ms-excel", {"Expires": "0"})},
            boundary=B)
    assert body == file_part(b"file", b"report.xls", b"application/vnd.ms-excel", b"XLS",
                             b"Expires: 0\r\n") + CLOSE
    assert ctype == CT


# ---------------------------------------------------------------- guess_content_type

@pytest.mark.parametrize("filename, expected", [
    ("a.txt", "text/plain"), ("A.TXT", "text/plain"), ("a.json", "application/json"),
    ("a.png", "image/png"), ("a.jpg", "image/jpeg"), ("a.js", "text/javascript"),
    ("a.tar.gz", "application/gzip"), ("a.webp", "image/webp"), ("a.pdf", "application/pdf"),
    ("a.csv", "text/csv"), ("a.svg", "image/svg+xml"), (b"a.xml", "text/xml"),
    ("noext", "application/octet-stream"), ("", "application/octet-stream"),
    (None, "application/octet-stream"), ("odd.zzzqqq", "application/octet-stream"),
])
def test_guess_content_type(filename, expected):
    assert guess_content_type(filename) == expected


# ---------------------------------------------------------------- Multipart class

def test_addpart_data_bytes_and_str_render_in_order():
    form = Multipart()
    first = form.addpart("a", data=b"one")
    form.addpart("b", data="tw\u00f6")
    assert isinstance(first, MultipartPart)
    assert len(form) == 2 and [p.name for p in form] == ["a", "b"]
    body, ctype = form.to_body(B)
    assert body == part(b"a", b"one") + part(b"b", "tw\u00f6".encode("utf-8")) + CLOSE
    assert ctype == CT


def test_addpart_filename_makes_a_file_part_with_guessed_or_given_type():
    form = Multipart()
    form.addpart("f", filename="a.txt", data=b"x")
    form.addpart("img", filename="pic.png", data=b"\x89PNG", content_type="image/png")
    form.addpart("empty", filename="", data=b"")
    body, _ = form.to_body(B)
    assert body == (file_part(b"f", b"a.txt", b"text/plain", b"x")
                    + file_part(b"img", b"pic.png", b"image/png", b"\x89PNG")
                    + file_part(b"empty", b"", b"application/octet-stream", b"") + CLOSE)


def test_addpart_content_type_on_a_plain_part_is_emitted_like_libcurl():
    form = Multipart()
    form.addpart("typed", data=b"typed data", content_type="text/plain")
    body, _ = form.to_body(B)
    assert body == part(b"typed", b"typed data", b"\r\nContent-Type: text/plain") + CLOSE


def test_addpart_local_path_defaults_filename_and_reads_at_render(tmp_path):
    path = tmp_path / "local file.txt"
    path.write_bytes(b"from disk")
    form = Multipart()
    added = form.addpart("disk", local_path=str(path))
    assert added.data is None and added.local_path == str(path)
    body, _ = form.to_body(B)
    assert body == file_part(b"disk", b"local file.txt", b"text/plain", b"from disk") + CLOSE
    path.write_bytes(b"changed")
    body, _ = form.to_body(B)
    assert body == file_part(b"disk", b"local file.txt", b"text/plain", b"changed") + CLOSE


def test_addpart_local_path_accepts_pathlib_and_bytes_and_filename_override(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00\x01")
    form = Multipart()
    form.addpart("a", local_path=path, filename="renamed.json")
    form.addpart("b", local_path=os.fsencode(str(path)), content_type="application/x-thing")
    body, _ = form.to_body(B)
    assert body == (file_part(b"a", b"renamed.json", b"application/json", b"\x00\x01")
                    + file_part(b"b", b"data.bin", b"application/x-thing", b"\x00\x01") + CLOSE)


def test_addpart_rejects_both_sources_and_missing_files(tmp_path):
    form = Multipart()
    with pytest.raises(ValueError):
        form.addpart("x", local_path=str(tmp_path / "a"), data=b"y")
    with pytest.raises(FileNotFoundError):
        form.addpart("x", local_path=str(tmp_path / "missing.txt"))
    assert len(form) == 0


def test_addpart_without_data_is_an_empty_part_and_scalars_convert():
    form = Multipart()
    form.addpart("empty")
    form.addpart("num", data=123)
    body, _ = form.to_body(B)
    assert body == part(b"empty", b"") + part(b"num", b"123") + CLOSE


def test_addpart_headers_and_part_repr():
    form = Multipart()
    added = form.addpart("f", filename="a.txt", data=b"x", headers={"X-Extra": "1"})
    assert "a.txt" in repr(added) and "text/plain" in repr(added)
    body, _ = form.to_body(B)
    assert body == file_part(b"f", b"a.txt", b"text/plain", b"x", b"X-Extra: 1\r\n") + CLOSE


def test_parts_property_returns_a_copy():
    form = Multipart()
    form.addpart("a", data=b"1")
    parts = form.parts
    parts.clear()
    assert len(form) == 1


def test_from_list_takes_addpart_keyword_dicts(tmp_path):
    path = tmp_path / "pic.png"
    path.write_bytes(b"PNG")
    form = Multipart.from_list([
        {"name": "plain", "data": b"value"},
        {"name": "f", "filename": "a.txt", "data": b"file content"},
        {"name": "disk", "local_path": str(path), "content_type": "image/png"},
    ])
    body, _ = form.to_body(B)
    assert body == (part(b"plain", b"value")
                    + file_part(b"f", b"a.txt", b"text/plain", b"file content")
                    + file_part(b"disk", b"pic.png", b"image/png", b"PNG") + CLOSE)


def test_to_body_default_boundary_follows_the_family():
    body, ctype = Multipart(family="firefox").to_body()
    boundary = ctype.split("boundary=", 1)[1]
    assert GECKO_RE.match(boundary) and body == b"--" + boundary.encode() + b"--\r\n"
    _, ctype = Multipart().to_body()
    assert WEBKIT_RE.match(ctype.split("boundary=", 1)[1])
    form = Multipart()
    first = form.to_body()[1]
    assert first != form.to_body()[1]


def test_constructor_accepts_parts_and_add_checks_type():
    form = Multipart([MultipartPart("a", data=b"1")])
    form.add(MultipartPart("b", data=b"2", filename="b.txt"))
    with pytest.raises(TypeError):
        form.add("not a part")
    assert form.to_body(B)[0] == (part(b"a", b"1")
                                  + file_part(b"b", b"b.txt", b"text/plain", b"2") + CLOSE)
    with pytest.raises(ValueError):
        MultipartPart(None)
    assert "2 parts" in repr(form)


def test_curlmime_alias_close_and_attach():
    assert CurlMime is Multipart
    form = CurlMime()
    form.addpart("a", data=b"1")
    assert form.close() is None
    assert form.to_body(B)[0] == part(b"a", b"1") + CLOSE
    with pytest.raises(NotImplementedError):
        form.attach()


# ---------------------------------------------------------------- curl_cffi parity

def _capture_server(results):
    """A raw TCP server that records one HTTP request body per connection."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            head, _, body = buf.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            while len(body) < length:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                body += chunk
            results.append((head, body))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            conn.close()

    threading.Thread(target=run, daemon=True).start()
    return srv


def _curl_cffi_body(specs, impersonate):
    cffi = pytest.importorskip("curl_cffi")
    results = []
    srv = _capture_server(results)
    try:
        mime = cffi.CurlMime.from_list([dict(spec) for spec in specs])
        try:
            cffi.requests.post("http://127.0.0.1:%d/up" % srv.getsockname()[1], multipart=mime,
                               impersonate=impersonate, timeout=10)
        finally:
            mime.close()
    finally:
        srv.close()
    head, body = results[-1]
    ctype = [line for line in head.split(b"\r\n") if line.lower().startswith(b"content-type:")][0]
    boundary = ctype.split(b"boundary=", 1)[1].strip()
    return boundary, body


PARITY_SPECS = [
    {"name": "plain", "data": b"value"},
    {"name": "f", "filename": "a.txt", "data": b"file content"},
    {"name": "img", "filename": "pic.png", "data": b"\x89PNG", "content_type": "image/png"},
    {"name": "typed", "data": b"typed data", "content_type": "text/plain"},
    {"name": 'we"ird\\name\r\nx', "filename": 'na"me\\q\nz.txt', "data": b"esc"},
    {"name": "utf8 n\u00e4me", "filename": "f\u00efle.html", "data": b"<p>"},
]


def test_part_layout_matches_curl_cffi_curlmime(tmp_path):
    """Same parts through curl_cffi's CurlMime and ours give the same bytes."""
    path = tmp_path / "local file.txt"
    path.write_bytes(b"from disk")
    specs = PARITY_SPECS + [{"name": "disk", "local_path": str(path)}]
    for target in ("chrome", "firefox"):
        boundary, theirs = _curl_cffi_body(specs, target)
        ours, ctype = Multipart.from_list(specs).to_body(boundary)
        assert ours == theirs
        assert ctype == "multipart/form-data; boundary=" + boundary.decode("ascii")


def test_curl_cffi_boundary_shapes_differ_from_browsers_only_by_two_dashes():
    """curl-impersonate prefixes six dashes where the browsers use four."""
    boundary, _ = _curl_cffi_body([{"name": "a", "data": b"1"}], "chrome")
    assert re.match(rb"^------WebKitFormBoundary[A-Za-z0-9]{16}$", boundary)
    assert WEBKIT_RE.match(boundary[2:].decode("ascii"))
    boundary, _ = _curl_cffi_body([{"name": "a", "data": b"1"}], "firefox")
    assert re.match(rb"^------geckoformboundary[0-9a-f]{32}$", boundary)
    assert GECKO_RE.match(boundary[2:].decode("ascii"))


def test_unguessable_file_type_is_the_one_documented_difference_from_libcurl():
    """libcurl omits Content-Type when it cannot guess; browsers send octet-stream."""
    specs = [{"name": "noext", "filename": "archive", "data": b"zz"}]
    boundary, theirs = _curl_cffi_body(specs, "chrome")
    ours, _ = Multipart.from_list(specs).to_body(boundary)
    assert ours != theirs
    assert ours.replace(b"Content-Type: application/octet-stream\r\n", b"") == theirs

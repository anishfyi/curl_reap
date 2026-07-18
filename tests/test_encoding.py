"""Response encoding detection: a page should decode cleanly even when the
server omits or lies about the charset."""
import curl_reap


def test_meta_charset_repairs_garbled_text():
    # "Bröderbund" where ö is the windows-1252 byte 0xF6, declared via <meta>.
    body = (b'<html><head><meta charset="windows-1252"></head>'
            b'<body><h1>Br\xf6derbund Software</h1></body></html>')
    r = curl_reap.Response(content=body, status=200, url="http://x/", headers={})
    assert "Bröderbund" in r.text
    assert r.encoding.lower() in ("windows-1252", "cp1252")
    assert "�" not in r.text


def test_content_type_header_wins():
    body = b"caf\xe9"  # "café", é = 0xE9 in latin-1
    r = curl_reap.Response(content=body, status=200, url="http://x/",
                           headers={"Content-Type": "text/html; charset=iso-8859-1"})
    assert r.text == "café"


def test_bom_is_detected():
    body = "﻿hola".encode("utf-8")  # utf-8 BOM + text
    assert curl_reap.detect_encoding(body) == "utf-8-sig"


def test_clean_utf8_is_untouched():
    body = "clean café ☕".encode("utf-8")
    r = curl_reap.Response(content=body, status=200, url="http://x/", headers={})
    assert r.text == "clean café ☕"

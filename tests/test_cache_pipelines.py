import json
import sqlite3

from curl_reap import DiskCache, SqlitePipeline
from curl_reap.http import Response


def test_disk_cache_roundtrip_and_ttl(tmp_path):
    cache = DiskCache(directory=str(tmp_path / "c"), ttl=100)
    assert cache.get("GET", "https://x.test/") is None
    resp = Response(status=200, url="https://x.test/", headers={"X": "1"},
                    text="hello world")
    cache.set("GET", "https://x.test/", None, resp)
    hit = cache.get("GET", "https://x.test/", None)
    assert hit is not None
    served = Response(from_cache=True, **hit)
    assert served.text == "hello world"
    assert served.status == 200
    assert served.from_cache is True

    expired = DiskCache(directory=str(tmp_path / "c"), ttl=-1)
    assert expired.get("GET", "https://x.test/", None) is None


def test_sqlite_pipeline_creates_columns(tmp_path):
    db = str(tmp_path / "out.db")
    p = SqlitePipeline(db, table="items")
    p.open()
    p.process({"name": "a", "price": 1})
    p.process({"name": "b", "price": 2, "extra": "z"})
    p.close()

    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT name, price FROM items ORDER BY name").fetchall()
    assert rows == [("a", 1), ("b", 2)]
    cols = [r[1] for r in conn.execute("PRAGMA table_info(items)")]
    assert "extra" in cols
    conn.close()


def test_sqlite_pipeline_upsert_on_key(tmp_path):
    db = str(tmp_path / "u.db")
    p = SqlitePipeline(db, table="products", key="url")
    p.open()
    p.process({"url": "u1", "price": 1})
    p.process({"url": "u1", "price": 2})   # same key -> replace
    p.close()
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT price FROM products").fetchall()
    assert rows == [(2,)]
    conn.close()


def test_response_status_code_alias_and_follow():
    r = Response(status=200, url="https://x.test/dir/page", headers={}, text="")
    assert r.status_code == r.status == 200
    req = r.follow("../other")
    assert req.url == "https://x.test/other"

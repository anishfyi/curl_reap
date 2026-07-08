"""Item pipelines (the Scrapy idea): each scraped item flows through a chain that
can validate, transform, dedup, or export it. A pipeline returning None drops the
item.
"""
from __future__ import annotations

import csv
import json
import sqlite3
import threading


class Pipeline:
    def open(self):
        pass

    def process(self, item):
        return item

    def close(self):
        pass


class DedupPipeline(Pipeline):
    """Drop items already seen. key=None dedups on the whole item."""

    def __init__(self, key=None):
        self.key = key
        self.seen = set()

    def process(self, item):
        try:
            k = item.get(self.key) if self.key else json.dumps(item, sort_keys=True, default=str)
        except Exception:  # noqa: BLE001
            k = str(item)
        if k in self.seen:
            return None
        self.seen.add(k)
        return item


class JsonLinesPipeline(Pipeline):
    """Stream items to a .jsonl file as they are scraped (thread-safe)."""

    def __init__(self, path):
        self.path = path
        self._fh = None
        self._lock = threading.Lock()

    def open(self):
        self._fh = open(self.path, "w", encoding="utf-8")

    def process(self, item):
        line = json.dumps(item, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()
        return item

    def close(self):
        if self._fh:
            self._fh.close()


class CsvPipeline(Pipeline):
    """Collect items and write a CSV on close (header from the first item)."""

    def __init__(self, path):
        self.path = path
        self._rows = []

    def process(self, item):
        if isinstance(item, dict):
            self._rows.append(item)
        return item

    def close(self):
        if not self._rows:
            return
        cols = list({k: None for row in self._rows for k in row})
        with open(self.path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for row in self._rows:
                w.writerow(row)


class SqlitePipeline(Pipeline):
    """Insert each dict item into a SQLite table, creating columns on the fly.

    SqlitePipeline("out.db", table="items")           # autoincrement rowid
    SqlitePipeline("out.db", table="products", key="url")  # upsert on url
    """

    def __init__(self, path, table="items", key=None):
        self.path = path
        self.table = table
        self.key = key
        self._conn = None
        self._cols = []
        self._lock = threading.Lock()

    def open(self):
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        keydef = "PRIMARY KEY" if self.key else ""
        if self.key:
            self._cols = [self.key]
            self._conn.execute(
                f'CREATE TABLE IF NOT EXISTS "{self.table}" ("{self.key}" TEXT {keydef})')
        else:
            self._conn.execute(
                f'CREATE TABLE IF NOT EXISTS "{self.table}" (_rowid INTEGER PRIMARY KEY AUTOINCREMENT)')
        self._conn.commit()

    def _ensure_columns(self, item):
        for col in item:
            if col not in self._cols:
                try:
                    self._conn.execute(f'ALTER TABLE "{self.table}" ADD COLUMN "{col}"')
                except sqlite3.OperationalError:
                    pass
                self._cols.append(col)

    def process(self, item):
        if not isinstance(item, dict):
            return item
        with self._lock:
            self._ensure_columns(item)
            cols = list(item.keys())
            placeholders = ",".join("?" for _ in cols)
            colnames = ",".join(f'"{c}"' for c in cols)
            verb = "INSERT OR REPLACE" if self.key else "INSERT"
            vals = [json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
                    for v in item.values()]
            self._conn.execute(
                f'{verb} INTO "{self.table}" ({colnames}) VALUES ({placeholders})', vals)
            self._conn.commit()
        return item

    def close(self):
        if self._conn:
            self._conn.close()

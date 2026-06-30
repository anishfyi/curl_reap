"""Item pipelines (the Scrapy idea): each scraped item flows through a chain that
can validate, transform, dedup, or export it. A pipeline returning None drops the
item.
"""
from __future__ import annotations

import csv
import json


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
    """Stream items to a .jsonl file as they are scraped."""

    def __init__(self, path):
        self.path = path
        self._fh = None

    def open(self):
        self._fh = open(self.path, "w", encoding="utf-8")

    def process(self, item):
        self._fh.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
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
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            for row in self._rows:
                w.writerow(row)

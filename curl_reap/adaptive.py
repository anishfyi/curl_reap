"""Self-healing selectors (the Scrapling-inspired pillar).

Save a structural signature of an element once. Later, even if the site renames
classes or reshuffles its DOM, relocate() finds the element again by scoring every
node against that signature. This keeps scrapers alive across markup changes, which
is the single biggest maintenance cost of plain CSS/XPath scrapers.
"""
from __future__ import annotations

import json
import os

DEFAULT_STORE = ".reap_selectors.json"

_WEIGHTS = {"tag": 2.0, "classes": 3.0, "id": 2.0, "attrs": 1.0, "text": 1.5, "path": 1.5}


def signature(el):
    """A compact, comparable description of one element and where it sits."""
    parent = el.getparent()
    sibs = list(parent) if parent is not None else [el]
    idx = sibs.index(el) if el in sibs else 0
    return {
        "tag": str(el.tag),
        "classes": sorted((el.get("class") or "").split()),
        "id": el.get("id") or "",
        "attrs": sorted(k for k in el.keys() if k not in ("class", "id")),
        "text": (el.text or "").strip()[:48],
        "depth": _depth(el),
        "index": idx,
        "path": _path(el),
    }


def _depth(el):
    d = 0
    p = el.getparent()
    while p is not None:
        d += 1
        p = p.getparent()
    return d


def _path(el):
    parts = []
    cur = el
    while cur is not None and isinstance(cur.tag, str):
        parts.append(cur.tag)
        cur = cur.getparent()
    return "/".join(reversed(parts))


def _jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def similarity(a, b):
    """0..1 similarity between two signatures."""
    score = total = 0.0
    score += _WEIGHTS["tag"] * (1.0 if a["tag"] == b["tag"] else 0.0)
    score += _WEIGHTS["classes"] * _jaccard(a["classes"], b["classes"])
    score += _WEIGHTS["id"] * (1.0 if a["id"] and a["id"] == b["id"] else 0.0)
    score += _WEIGHTS["attrs"] * _jaccard(a["attrs"], b["attrs"])
    score += _WEIGHTS["text"] * (1.0 if a["text"] and a["text"] == b["text"] else 0.0)
    tail_a, tail_b = a["path"].split("/")[-3:], b["path"].split("/")[-3:]
    path_sc = 1.0 if a["path"] == b["path"] else (0.5 if tail_a == tail_b else 0.0)
    score += _WEIGHTS["path"] * path_sc
    total = sum(_WEIGHTS.values())
    return score / total


def save(identifier, el, storage=None):
    path = storage or DEFAULT_STORE
    data = _load(path)
    data[identifier] = signature(el)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)


def relocate(identifier, tree, storage=None, threshold=0.6):
    """Return the best-matching element for a saved identifier, or None."""
    sig = _load(storage or DEFAULT_STORE).get(identifier)
    if not sig:
        return None
    best, best_score = None, threshold
    for e in tree.iter():
        if not isinstance(e.tag, str):
            continue
        sc = similarity(sig, signature(e))
        if sc > best_score:
            best, best_score = e, sc
    return best


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}

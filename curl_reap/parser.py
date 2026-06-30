"""Parsing layer: a fast lxml selector with parsel-style ergonomics plus the
Scrapling-style extras (find by text, find similar, and self-healing selectors).

Supports CSS with ::text and ::attr(name) pseudo elements, XPath, regex, and an
auto_match mode that re-locates an element from a saved signature when the site
changes its markup (see adaptive.py).
"""
from __future__ import annotations

import re

import lxml.html

_ATTR_RE = re.compile(r"::attr\(\s*([\w:-]+)\s*\)\s*$")
_TEXT_RE = re.compile(r"::text\s*$")


def _parse_pseudo(query):
    m = _ATTR_RE.search(query)
    if m:
        return ("attr", m.group(1), _ATTR_RE.sub("", query).strip())
    if _TEXT_RE.search(query):
        return ("text", None, _TEXT_RE.sub("", query).strip())
    return (None, None, query)


def _text_of(el):
    try:
        return el.text_content().strip()
    except Exception:  # noqa: BLE001
        return (getattr(el, "text", "") or "").strip()


class SelectorList(list):
    """A list of Selectors or strings with parsel-style get / getall helpers."""

    def get(self, default=None):
        return self[0] if self else default

    def getall(self):
        return list(self)

    def text(self):
        out = SelectorList()
        for s in self:
            out.append(s.text if isinstance(s, Selector) else s)
        return out

    def attr(self, name, default=None):
        out = SelectorList()
        for s in self:
            if isinstance(s, Selector):
                out.append(s.attr(name, default))
        return out

    def css(self, query, **kw):
        out = SelectorList()
        for s in self:
            if isinstance(s, Selector):
                out.extend(s.css(query, **kw))
        return out


class Selector:
    """Wraps one lxml element (or a parsed document)."""

    def __init__(self, content=None, element=None, url=None, status=None, headers=None):
        if element is not None:
            self._el = element
        elif content is not None:
            self._el = lxml.html.fromstring(content)
        else:
            self._el = lxml.html.fromstring("<html></html>")
        self.url = url
        self.status = status
        self.headers = dict(headers or {})

    # --- selection ---------------------------------------------------------
    def css(self, query, auto_match=False, identifier=None, storage=None):
        kind, attr, q = _parse_pseudo(query)
        try:
            els = self._el.cssselect(q) if q else [self._el]
        except Exception:  # noqa: BLE001
            els = []
        if not els and auto_match:
            from .adaptive import relocate
            found = relocate(identifier or query, self._root(), storage=storage)
            els = [found] if found is not None else []
        if kind == "attr":
            return SelectorList(e.get(attr) for e in els)
        if kind == "text":
            return SelectorList(_text_of(e) for e in els)
        return SelectorList(Selector(element=e, url=self.url) for e in els)

    def css_first(self, query, default=None, **kw):
        res = self.css(query, **kw)
        return res[0] if res else default

    def xpath(self, query):
        try:
            res = self._el.xpath(query)
        except Exception:  # noqa: BLE001
            return SelectorList()
        out = SelectorList()
        for r in res:
            out.append(r if isinstance(r, str) else Selector(element=r, url=self.url))
        return out

    # --- Scrapling-style finders ------------------------------------------
    def find_by_text(self, text, partial=True, first=False):
        out = SelectorList()
        for e in self._el.iter():
            if not isinstance(e.tag, str):
                continue
            t = (e.text or "").strip()
            hit = (text in t) if partial else (text == t)
            if hit:
                out.append(Selector(element=e, url=self.url))
                if first:
                    break
        return out

    def find_similar(self, sample, threshold=0.6, limit=None):
        """Return elements structurally similar to a sample Selector."""
        from .adaptive import signature, similarity
        target = signature(sample._el if isinstance(sample, Selector) else sample)
        scored = []
        for e in self._el.iter():
            if not isinstance(e.tag, str) or e is getattr(sample, "_el", None):
                continue
            sc = similarity(target, signature(e))
            if sc >= threshold:
                scored.append((sc, e))
        scored.sort(key=lambda x: -x[0])
        if limit:
            scored = scored[:limit]
        return SelectorList(Selector(element=e, url=self.url) for _, e in scored)

    def save(self, identifier, storage=None):
        """Persist this element's signature so css(auto_match=True) can re-find it."""
        from .adaptive import save as _save
        _save(identifier, self._el, storage=storage)
        return self

    # --- value access ------------------------------------------------------
    @property
    def text(self):
        return _text_of(self._el)

    @property
    def attrib(self):
        return dict(self._el.attrib)

    def attr(self, name, default=None):
        return self._el.get(name, default)

    @property
    def html(self):
        return lxml.html.tostring(self._el, encoding="unicode")

    def re(self, pattern, flags=0):
        return SelectorList(re.findall(pattern, self.html, flags))

    def _root(self):
        root = self._el
        while root.getparent() is not None:
            root = root.getparent()
        return root

    def __repr__(self):
        t = getattr(self._el, "tag", "?")
        return f"<Selector {t}>"

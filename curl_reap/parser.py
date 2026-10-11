"""Parsing layer: a fast lxml selector with parsel-style ergonomics plus the
Scrapling-style extras (find by text, find similar, and self-healing selectors).

Supports CSS with ::text and ::attr(name) pseudo elements, XPath, regex, and an
auto_match mode that re-locates an element from a saved signature when the site
changes its markup (see adaptive.py).

Structured extraction (v0.2): jsonld(), meta_tags(), links(), images(),
tables(), markdown() - the answers most scrapes actually want, one call away.
"""
from __future__ import annotations

import copy
import json as _json
import re
from collections.abc import Mapping
from urllib.parse import urldefrag, urljoin, urlparse

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


def _page_origin(parts):
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return (parts.scheme.lower(), (parts.hostname or "").lower(), port)


def _is_ancestor(el, candidate):
    """True if `candidate` is an ancestor of `el`."""
    p = el.getparent()
    while p is not None:
        if p is candidate:
            return True
        p = p.getparent()
    return False


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
        elif content is not None and getattr(content, "strip", lambda: content)():
            self._el = lxml.html.fromstring(content)
        else:
            self._el = lxml.html.fromstring("<html></html>")
        self.url = url
        self.status = status
        self.headers = dict(headers or {})

    @property
    def base_url(self):
        """The page's effective base URL.

        The first ``<base href>`` (in document order) resolved against the
        page URL; the page URL itself when no base element is present.
        """
        bases = self._el.xpath("//base")
        if not bases:
            return self.url
        href = (bases[0].get("href") or "").strip()
        return urljoin(self.url or "", href) or self.url

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
    def find_by_text(self, text, partial=True, first=False, deepest=True):
        """Find elements whose text matches. Checks full text content (not just
        the direct .text node), preferring the deepest matching element so you
        get the <a>, not every ancestor up to <html>."""
        out = SelectorList()
        matched = []
        for e in self._el.iter():
            if not isinstance(e.tag, str):
                continue
            t = _text_of(e)
            hit = (text in t) if partial else (text == t)
            if hit:
                matched.append(e)
        if deepest:
            # drop any element that is an ancestor of another match
            matched = [e for e in matched
                       if not any(other is not e and _is_ancestor(other, e) for other in matched)]
        for e in matched:
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

    def re_first(self, pattern, default=None, flags=0):
        res = self.re(pattern, flags)
        return res[0] if res else default

    # --- structured extraction (v0.2) ---------------------------------------
    def jsonld(self):
        """All JSON-LD blocks on the page as parsed dicts (flattens @graph).
        This is where sites keep their product/article/event data, pre-structured."""
        out = []
        for node in self._el.xpath('//script[@type="application/ld+json"]/text()'):
            try:
                data = _json.loads(node)
            except ValueError:
                continue
            if isinstance(data, list):
                out.extend(d for d in data if isinstance(d, dict))
            elif isinstance(data, dict):
                if isinstance(data.get("@graph"), list):
                    out.extend(d for d in data["@graph"] if isinstance(d, dict))
                else:
                    out.append(data)
        return out

    def meta_tags(self):
        """One dict of the page's metadata: <title>, name= and property= metas
        (og:*, twitter:*, description...), plus rel=canonical."""
        out = {}
        title = self._el.xpath("//title/text()")
        if title:
            out["title"] = title[0].strip()
        for m in self._el.xpath("//meta"):
            key = m.get("name") or m.get("property") or m.get("itemprop")
            val = m.get("content")
            if key and val is not None and key not in out:
                out[key] = val
        canon = self._el.xpath('//link[@rel="canonical"]/@href')
        if canon:
            out["canonical"] = canon[0]
        return out

    def links(self, absolute=True, unique=True, internal_only=False):
        """All hyperlinks as {url, text} dicts.

        Only http/https links are returned - ``javascript:``, ``mailto:``,
        ``data:`` and other schemes are dropped regardless of letter case.
        absolute resolves against ``base_url`` (so a ``<base href>`` is
        honored); unique dedups on the fragment-stripped URL; internal_only
        compares against the real page origin, not a possibly off-origin
        ``<base>``.
        """
        base = self.base_url or ""
        page_origin = _page_origin(urlparse(self.url or ""))
        seen = set()
        out = []
        for a in self._el.xpath("//a[@href]"):
            href = (a.get("href") or "").strip()
            if not href or href.startswith("#"):
                continue
            url = urljoin(base, href) if absolute else href
            scheme = urlparse(url).scheme.lower()
            if absolute:
                if scheme not in ("http", "https"):
                    continue
            elif scheme and scheme not in ("http", "https"):
                continue
            if internal_only:
                probe = url if absolute else urljoin(base, href)
                if _page_origin(urlparse(probe)) != page_origin:
                    continue
            if unique:
                url = urldefrag(url)[0]
                if url in seen:
                    continue
                seen.add(url)
            out.append({"url": url, "text": _text_of(a)})
        return out

    def images(self, absolute=True):
        """All images as {url, alt} dicts (handles src and data-src lazy loading)."""
        base = self.base_url or ""
        out = []
        for img in self._el.xpath("//img"):
            src = img.get("src") or img.get("data-src") or img.get("data-lazy-src")
            if not src:
                continue
            if urlparse(src).scheme.lower() not in ("", "http", "https"):
                continue
            url = urljoin(base, src) if absolute else src
            if absolute and urlparse(url).scheme.lower() not in ("http", "https"):
                continue
            out.append({"url": url, "alt": img.get("alt", "")})
        return out

    def extract(self, fields, *, many=False):
        """Pull named scalar fields out of the page with CSS queries.

        ``fields`` maps a name to a CSS query string. With ``many=False``
        (default) each name gets the first match's scalar - element text
        for element matches, or the attr/text pseudo value for
        ``::attr()``/``::text`` queries - or None when nothing matches.
        With ``many=True`` each name gets the list of all matching scalars.
        """
        if not isinstance(fields, Mapping):
            raise TypeError("fields must be a mapping of name -> CSS query")
        out = {}
        for name, query in fields.items():
            if not isinstance(name, str) or not isinstance(query, str):
                raise TypeError("extract fields must map str names to str CSS queries")
            results = self.css(query)
            if many:
                out[name] = [v.text if isinstance(v, Selector) else v
                             for v in results]
            else:
                first = results.get()
                out[name] = first.text if isinstance(first, Selector) else first
        return out

    def tables(self):
        """Every <table> as a list of rows; first row of each table is its header
        if it has <th> cells. Returns list[table] where table = list[list[str]]."""
        out = []
        for tbl in self._el.xpath("//table"):
            rows = []
            for tr in tbl.xpath(".//tr"):
                cells = tr.xpath("./th|./td")
                if cells:
                    rows.append([_text_of(c) for c in cells])
            if rows:
                out.append(rows)
        return out

    _MD_TAGS = frozenset(
        {"h1", "h2", "h3", "h4", "p", "li", "blockquote", "pre", "figcaption"})

    def markdown(self, max_len=None, main_only=False):
        """The page's readable content as markdown-ish text: headings, paragraphs,
        list items, blockquotes, code. The 'just let me read it' method.

        ``main_only=True`` restricts output to the first ``<main>`` or
        ``<article>`` element, with nav/footer/aside/script/style stripped
        from a *cloned* subtree (the source document is never mutated) and
        nested content elements emitted once at their outermost level.
        """
        emit = self._MD_TAGS
        if main_only:
            main = self._el.xpath("//main|//article")
            if not main:
                return ""
            root = copy.deepcopy(main[0])
            for bad in root.xpath(".//nav|.//footer|.//aside|.//script|.//style"):
                parent = bad.getparent()
                if parent is not None:
                    parent.remove(bad)
            query = ".//*[self::h1 or self::h2 or self::h3 or self::h4 or " \
                    "self::p or self::li or self::blockquote or self::pre or " \
                    "self::figcaption]"
        else:
            root = self._el
            query = ("//h1|//h2|//h3|//h4|//p|//li|//blockquote|//pre"
                     "|//figcaption")
        parts = []
        for e in root.xpath(query):
            if main_only:
                nested = False
                ancestor = e.getparent()
                while ancestor is not None and ancestor is not root:
                    if ancestor.tag in emit:
                        nested = True
                        break
                    ancestor = ancestor.getparent()
                if nested:
                    continue
            t = " ".join(_text_of(e).split())
            if not t:
                continue
            tag = e.tag
            if tag in ("h1", "h2", "h3", "h4"):
                parts.append("#" * int(tag[1]) + " " + t)
            elif tag == "li":
                parts.append("- " + t)
            elif tag == "blockquote":
                parts.append("> " + t)
            elif tag == "pre":
                parts.append("```\n" + _text_of(e) + "\n```")
            else:
                parts.append(t)
        text = "\n\n".join(parts)
        if max_len and len(text) > max_len:
            text = text[:max_len] + "\n\n[truncated]"
        return text

    def _root(self):
        root = self._el
        while root.getparent() is not None:
            root = root.getparent()
        return root

    def __repr__(self):
        t = getattr(self._el, "tag", "?")
        return f"<Selector {t}>"

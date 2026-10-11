"""base_url resolution, link scheme whitelist, extract(), markdown
main_only, and empty-body safety."""
import pytest

import curl_reap
from curl_reap import Selector, SelectorList


def test_base_href_resolves_links_against_base():
    sel = Selector(
        content='<base href="https://cdn.example.com/assets/">'
                '<a href="img/1.png">x</a>',
        url="https://site.example.com/page")
    assert sel.base_url == "https://cdn.example.com/assets/"
    assert sel.links()[0]["url"] == \
        "https://cdn.example.com/assets/img/1.png"
    assert sel.images() == []


def test_first_base_wins_even_when_empty():
    sel = Selector(
        content='<base href=""><base href="https://cdn.example.com/">'
                '<a href="/in">x</a>',
        url="https://site.example.com/page")
    assert sel.base_url == "https://site.example.com/page"
    assert sel.links()[0]["url"] == "https://site.example.com/in"


def test_response_urljoin_and_follow_use_base_url():
    r = curl_reap.Response(
        status=200, url="https://site.example.com/page",
        content=b'<base href="https://cdn.example.com/a/">')
    assert r.urljoin("b") == "https://cdn.example.com/a/b"
    req = r.follow("b")
    assert req.url == "https://cdn.example.com/a/b"


def test_internal_only_uses_page_origin_not_offsite_base():
    sel = Selector(
        content='<base href="https://cdn.example.com/">'
                '<a href="/in">in</a><a href="https://cdn.example.com/x">c</a>',
        url="https://site.example.com/")
    urls = [l["url"] for l in sel.links(internal_only=True)]
    assert urls == []


def test_internal_only_resolves_relative_candidates_and_effective_ports():
    sel = Selector(
        content='<a href="/in">in</a>'
                '<a href="https://e.com/x">default-port</a>'
                '<a href="http://e.com/y">other-scheme</a>'
                '<a href="https://e.com:8443/z">other-port</a>',
        url="https://e.com/page")
    urls = [l["url"] for l in sel.links(internal_only=True)]
    assert urls == ["https://e.com/in", "https://e.com/x"]
    urls = [l["url"] for l in
            sel.links(internal_only=True, absolute=False)]
    assert urls == ["/in", "https://e.com/x"]


def test_link_scheme_whitelist_case_insensitive():
    sel = Selector(
        content='<a href="JaVaScRiPt:alert(1)">j</a>'
                '<a href="MAILTO:x@y.z">m</a>'
                '<a href="DATA:text/html,x">d</a>'
                '<a href="TEL:123">t</a>'
                '<a href="ftp://f/x">f</a>'
                '<a href="/ok">ok</a>',
        url="https://e.com/")
    urls = [l["url"] for l in sel.links()]
    assert urls == ["https://e.com/ok"]


def test_fragment_links_skipped_and_unique_strips_fragments():
    sel = Selector(
        content='<a href="#top">top</a>'
                '<a href="/p#one">1</a><a href="/p#two">2</a>'
                '<a href="/p">3</a>',
        url="https://e.com/")
    assert [l["url"] for l in sel.links()] == ["https://e.com/p"]
    assert len(sel.links(unique=False)) == 3
    assert sel.links(unique=False)[0]["url"] == "https://e.com/p#one"


def test_images_whitelist_schemes_case_insensitively():
    sel = Selector(
        content='<img src="DATA:image/png;base64,xx">'
                '<img src="JaVaScRiPt:x">'
                '<img src="data:skip">'
                '<img src="/pic.png" alt="p">'
                '<img src="https://e.com/abs.png">',
        url="https://e.com/")
    urls = [i["url"] for i in sel.images()]
    assert urls == ["https://e.com/pic.png", "https://e.com/abs.png"]
    urls = [i["url"] for i in sel.images(absolute=False)]
    assert urls == ["/pic.png", "https://e.com/abs.png"]


def test_empty_body_selector_yields_empty_collections():
    for content in (b"", "", None, "   "):
        sel = Selector(content=content, url="https://e.com/")
        assert sel.links() == [] and sel.images() == []
        assert sel.css("p") == SelectorList()
        assert sel.markdown() == ""
        assert sel.jsonld() == []
        assert sel.extract({"t": "h1::text"}) == {"t": None}


def test_extract_scalars_and_lists():
    sel = Selector(
        content='<h1>Title</h1><a href="/a">A</a><a href="/b">B</a>'
                '<span class="v">one</span><span class="v">two</span>',
        url="https://e.com/")
    out = sel.extract({"title": "h1::text", "href": "a::attr(href)",
                       "el": "span.v"})
    assert out == {"title": "Title", "href": "/a", "el": "one"}
    out = sel.extract({"vals": "span.v::text", "links": "a::attr(href)"},
                      many=True)
    assert out == {"vals": ["one", "two"], "links": ["/a", "/b"]}
    out = sel.extract({"x": ".missing", "y": "h1"}, many=True)
    assert out == {"x": [], "y": ["Title"]}


def test_extract_rejects_non_string_fields():
    sel = Selector(content="<p>x</p>", url="https://e.com/")
    with pytest.raises(TypeError):
        sel.extract("h1")
    with pytest.raises(TypeError):
        sel.extract({"x": 123})
    with pytest.raises(TypeError):
        sel.extract({1: "h1"})


def test_response_extract_delegates():
    r = curl_reap.Response(status=200, url="https://e.com/",
                           content=b"<h1>T</h1>")
    assert r.extract({"t": "h1::text"}) == {"t": "T"}


def test_markdown_main_only_strips_chrome_without_mutating_source():
    html = ('<html><body><nav>menu links</nav>'
            '<main><h1>Real</h1><p>Body text.</p>'
            '<aside>sidenote</aside><script>x()</script>'
            '<ul><li><p>nested para</p></li></ul></main>'
            '<footer>foot</footer></body></html>')
    sel = Selector(content=html, url="https://e.com/")
    md = sel.markdown(main_only=True)
    assert "# Real" in md and "Body text." in md
    assert "menu links" not in md and "foot" not in md
    assert "sidenote" not in md and "x()" not in md
    assert md.count("nested para") == 1
    assert sel.css_first("nav::text") == "menu links"
    assert sel.css_first("footer::text") == "foot"
    assert sel.css_first("aside::text") == "sidenote"


def test_markdown_main_only_empty_without_main():
    sel = Selector(content="<p>no main</p>", url="https://e.com/")
    assert sel.markdown(main_only=True) == ""

from curl_reap import Selector

HTML = """
<html><head>
  <title>  Widget Store  </title>
  <meta name="description" content="best widgets">
  <meta property="og:title" content="Widgets OG">
  <link rel="canonical" href="https://shop.example.com/widgets">
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"Product","name":"Widget","offers":{"price":"9.99"}}
  </script>
  <script type="application/ld+json">
  {"@graph":[{"@type":"Organization","name":"ACME"},{"@type":"WebSite","name":"Shop"}]}
  </script>
</head>
<body>
  <a href="/p/1">Product 1</a>
  <a href="https://other.com/x">External</a>
  <a href="mailto:hi@x.com">Mail</a>
  <img src="/img/a.png" alt="A">
  <img data-src="/img/b.png" alt="B">
  <table>
    <tr><th>Name</th><th>Price</th></tr>
    <tr><td>Widget</td><td>9.99</td></tr>
  </table>
  <h1>Heading</h1>
  <p>Some paragraph text.</p>
</body></html>
"""


def _sel():
    return Selector(content=HTML, url="https://shop.example.com/widgets")


def test_jsonld_flattens_graph():
    data = _sel().jsonld()
    types = {d.get("@type") for d in data}
    assert "Product" in types
    assert "Organization" in types and "WebSite" in types
    product = next(d for d in data if d.get("@type") == "Product")
    assert product["offers"]["price"] == "9.99"


def test_meta_tags():
    meta = _sel().meta_tags()
    assert meta["title"] == "Widget Store"
    assert meta["description"] == "best widgets"
    assert meta["og:title"] == "Widgets OG"
    assert meta["canonical"] == "https://shop.example.com/widgets"


def test_links_absolute_and_internal():
    sel = _sel()
    all_links = sel.links()
    urls = [l["url"] for l in all_links]
    assert "https://shop.example.com/p/1" in urls  # relative resolved
    assert "https://other.com/x" in urls
    assert not any("mailto" in u for u in urls)     # mailto skipped
    internal = sel.links(internal_only=True)
    assert all("shop.example.com" in l["url"] for l in internal)


def test_images_handles_lazy():
    imgs = _sel().images()
    urls = [i["url"] for i in imgs]
    assert "https://shop.example.com/img/a.png" in urls
    assert "https://shop.example.com/img/b.png" in urls  # data-src


def test_tables():
    tables = _sel().tables()
    assert tables == [[["Name", "Price"], ["Widget", "9.99"]]]


def test_markdown():
    md = _sel().markdown()
    assert "# Heading" in md
    assert "Some paragraph text." in md


def test_re_first():
    sel = _sel()
    assert sel.re_first(r"Product (\d)") == "1"
    assert sel.re_first(r"nope(\d)", default="x") == "x"

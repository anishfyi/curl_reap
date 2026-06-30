from curl_reap import Selector

HTML = """
<html><body>
  <div class="quote" data-id="1">
    <span class="text">First quote</span>
    <a class="author" href="/a/1">Alice</a>
  </div>
  <div class="quote" data-id="2">
    <span class="text">Second quote</span>
    <a class="author" href="/a/2">Bob</a>
  </div>
</body></html>
"""


def test_css_text_and_attr():
    sel = Selector(content=HTML)
    assert sel.css("span.text::text").getall() == ["First quote", "Second quote"]
    assert sel.css("a.author::attr(href)").getall() == ["/a/1", "/a/2"]
    assert sel.css_first("span.text::text") == "First quote"


def test_nested_and_attrib():
    sel = Selector(content=HTML)
    quotes = sel.css("div.quote")
    assert len(quotes) == 2
    assert quotes[0].css_first("a.author::text") == "Alice"
    assert quotes[0].attr("data-id") == "1"


def test_xpath_and_re():
    sel = Selector(content=HTML)
    assert sel.xpath("//span[@class='text']/text()").getall() == ["First quote", "Second quote"]
    assert "Alice" in sel.re(r">(\w+)</a>").getall()


def test_find_by_text():
    sel = Selector(content=HTML)
    hit = sel.find_by_text("Second quote")
    assert len(hit) == 1
    assert hit[0].text == "Second quote"


def test_find_similar():
    sel = Selector(content=HTML)
    first = sel.css_first("div.quote")
    similar = sel.find_similar(first)
    assert len(similar) >= 1  # the second .quote is similar to the first

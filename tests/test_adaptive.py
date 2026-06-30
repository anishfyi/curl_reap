import os

from curl_reap import Selector

# same element, but the site later renamed the class and moved it
V1 = """<html><body><div class="sidebar">
  <a class="buy-btn primary" id="cta" data-track="x" href="/buy">Buy now</a>
</div></body></html>"""

V2 = """<html><body><div class="sidebar">
  <span>noise</span>
  <a class="purchase-button primary" id="cta" data-track="x" href="/buy">Buy now</a>
</div></body></html>"""


def test_self_healing_relocates_after_class_change(tmp_path):
    store = str(tmp_path / "sel.json")
    # 1. save the element's signature from the original markup
    v1 = Selector(content=V1)
    btn = v1.css_first("a.buy-btn")
    assert btn is not None
    btn.save("cta", storage=store)
    assert os.path.exists(store)

    # 2. on new markup the old selector misses, but auto_match relocates it
    v2 = Selector(content=V2)
    assert v2.css_first("a.buy-btn") is None
    healed = v2.css_first("a.buy-btn", auto_match=True, identifier="cta", storage=store)
    assert healed is not None
    assert healed.attr("href") == "/buy"
    assert healed.text == "Buy now"


def test_similarity_self_is_one():
    from curl_reap import signature, similarity
    el = Selector(content=V1).css_first("a.buy-btn")._el
    assert similarity(signature(el), signature(el)) == 1.0

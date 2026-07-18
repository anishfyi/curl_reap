"""SitemapSpider handles gzipped sitemaps and sitemap indexes."""
import gzip

import curl_reap


def _page(content, url):
    return curl_reap.Response(content=content, status=200, url=url, headers={})


def test_gzipped_sitemap_is_decompressed():
    xml = (b'<?xml version="1.0"?><urlset>'
           b'<url><loc>https://ex.com/product/1</loc></url>'
           b'<url><loc>https://ex.com/about</loc></url>'
           b'</urlset>')

    class Sp(curl_reap.SitemapSpider):
        sitemap_urls = ["https://ex.com/sitemap.xml.gz"]
        url_pattern = r"/product/"

    reqs = list(Sp().parse_sitemap(_page(gzip.compress(xml), "https://ex.com/sitemap.xml.gz")))
    urls = [r.url for r in reqs]
    assert "https://ex.com/product/1" in urls
    assert "https://ex.com/about" not in urls  # filtered by url_pattern


def test_sitemap_index_recurses():
    idx = (b'<sitemapindex><sitemap><loc>https://ex.com/s1.xml.gz</loc></sitemap>'
           b'</sitemapindex>')

    class Sp(curl_reap.SitemapSpider):
        sitemap_urls = ["https://ex.com/sitemap.xml"]

    reqs = list(Sp().parse_sitemap(_page(idx, "https://ex.com/sitemap.xml")))
    assert reqs and reqs[0].url == "https://ex.com/s1.xml.gz"
    assert reqs[0].callback.__name__ == "parse_sitemap"

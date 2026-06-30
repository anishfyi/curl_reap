"""End to end example: crawl quotes.toscrape.com with the full stack.

Run:  python examples/quotes.py
"""
import curl_reap as reap
from curl_reap import JsonLinesPipeline


class Quotes(reap.Spider):
    name = "quotes"
    start_urls = ["https://quotes.toscrape.com"]

    def parse(self, page):
        for q in page.css("div.quote"):
            yield {
                "text": q.css_first("span.text::text"),
                "author": q.css_first("small.author::text"),
                "tags": q.css("a.tag::text").getall(),
            }
        nxt = page.css_first("li.next a::attr(href)")
        if nxt:
            yield reap.Request("https://quotes.toscrape.com" + nxt, self.parse)


if __name__ == "__main__":
    reaper = reap.Reaper(
        Quotes(),
        concurrency=8,
        throttle=True,
        pipelines=[JsonLinesPipeline("quotes.jsonl")],
    )
    items = reaper.run()
    print(f"reaped {len(items)} quotes -> quotes.jsonl")
    print("stats:", reaper.stats)

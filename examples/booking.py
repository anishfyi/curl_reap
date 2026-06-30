"""Reap Booking.com's openly-served apartment pages with curl_reap.

Honest note on scope: Booking gates its searchable inventory behind an anti-bot
wall. Its searchresults.html and hotel detail pages return HTTP 202 with an empty
stub and no data. curl_reap does NOT defeat anti-bot walls (it impersonates a real
browser's TLS, it does not solve challenges), so this example reaps only what
Booking serves openly: the featured apartment cards on the city landing page
(name, area, "price from", and the listing link).

Run:  python examples/booking.py
"""
import re

import curl_reap as reap
from curl_reap import JsonLinesPipeline

CITIES = [
    ("gb", "london"), ("fr", "paris"), ("ae", "dubai"),
    ("sg", "singapore"), ("es", "barcelona"), ("it", "rome"),
]


class Booking(reap.Spider):
    name = "booking"
    start_urls = [f"https://www.booking.com/apartments/city/{cc}/{city}.html" for cc, city in CITIES]

    def start(self):
        for cc, city in CITIES:
            url = f"https://www.booking.com/apartments/city/{cc}/{city}.html"
            yield reap.Request(url, self.parse, meta={"city": city}, headers={"Accept-Language": "en"})

    def parse(self, page):
        if page.status != 200:           # 202 wall or anything non-open: skip honestly
            return
        city = page.meta.get("city", "?")
        titles = page.css('[data-testid="title"]::text').getall()
        links = page.css('a[data-testid="title-link"]::attr(href)').getall()
        if not links:
            links = page.css('a[href*="/hotel/"]::attr(href)').getall()
        prices = page.re(r"Price from.{0,160}?(?:₹|US\$|£|€)\s?([\d,]{3,})")
        for i, title in enumerate(titles):
            href = links[i].split("?")[0] if i < len(links) else None
            if href and not href.startswith("http"):
                href = "https://www.booking.com" + href
            yield {
                "city": city,
                "name": title.strip()[:90],
                "price_from": prices[i] if i < len(prices) else None,
                "url": href,
                "source": "Booking.com",
            }


if __name__ == "__main__":
    items = reap.run(
        Booking,
        concurrency=5,
        throttle=True,
        pipelines=[JsonLinesPipeline("booking.jsonl")],
    )
    print(f"reaped {len(items)} apartment cards across {len(CITIES)} cities -> booking.jsonl\n")
    for it in items[:8]:
        print(f"  {it['city']:10} {it['name'][:42]:42} from {it['price_from']}")

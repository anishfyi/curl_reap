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
        # tight per-card alignment: climb from each title to the card that holds the
        # listing link, so name and url always belong to the same card.
        cards = page.css('[data-testid="title"]')
        prices = page.re(r"Price from.{0,160}?(?:₹|US\$|£|€)\s?([\d,]{3,})")
        for i, t in enumerate(cards):
            card = t.xpath("ancestor::div[.//a[contains(@href,'/hotel/')]][1]").get()
            href = card.css('a[href*="/hotel/"]::attr(href)').get() if card else None
            if href:
                href = href.split("?")[0]
                if not href.startswith("http"):
                    href = "https://www.booking.com" + href
            yield {
                "city": city,
                "name": t.text[:90],
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

"""Reap Booking.com with curl_reap, then geo-tag the results.

Booking serves a public apartment landing page per city (name, area, "price from",
listing link) but does not expose per-listing coordinates there. curl_reap's
Geocoder fixes that: it resolves each property to coordinates with a cascade
(name, then district, then city) and reports the precision, so we keep only the
building and district level hits and drop coarse city centroids.

It still does NOT touch Booking's anti-bot wall: searchresults.html returns 202
with no data and curl_reap leaves it at that.

Run:  python examples/booking.py
"""
import json

import curl_reap as reap
from curl_reap import Geocoder, JsonLinesPipeline

CITIES = [
    ("gb", "london", "United Kingdom"),
    ("fr", "paris", "France"),
    ("ae", "dubai", "United Arab Emirates"),
]

GEO = Geocoder()


def _lxacc(html):
    """Pull Booking's embedded LxAccProperty objects (clean name + district)."""
    out, i, marker = [], 0, '{"__typename":"LxAccProperty"'
    while True:
        i = html.find(marker, i)
        if i < 0:
            break
        depth = 0
        for j in range(i, min(i + 8000, len(html))):
            if html[j] == "{":
                depth += 1
            elif html[j] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        out.append(json.loads(html[i:j + 1]))
                    except Exception:
                        pass
                    i = j + 1
                    break
        else:
            i += len(marker)
    return out


class Booking(reap.Spider):
    name = "booking"

    def start(self):
        for cc, city, country in CITIES:
            yield reap.Request(f"https://www.booking.com/apartments/city/{cc}/{city}.html",
                               self.parse, meta={"city": city, "country": country},
                               headers={"Accept-Language": "en"})

    def parse(self, page):
        if page.status != 200:
            return
        city, country = page.meta["city"], page.meta["country"]

        # DOM cards: mashed title -> price + listing url (tight per-card alignment)
        prices = page.re(r"Price from.{0,160}?(?:₹|US\$|£|€)\s?([\d,]{3,})")
        dom = []
        for i, t in enumerate(page.css('[data-testid="title"]')):
            card = t.xpath("ancestor::div[.//a[contains(@href,'/hotel/')]][1]").get()
            url = card.css('a[href*="/hotel/"]::attr(href)').get() if card else None
            dom.append((t.text, prices[i] if i < len(prices) else None, url))

        seen = set()
        for o in _lxacc(page.text):
            name = (o.get("basic") or {}).get("name")
            area = ((o.get("location") or {}).get("district") or {}).get("name")
            if not name or name in seen:
                continue
            seen.add(name)
            price = url = None
            for title, pr, u in dom:                 # the JSON name is a prefix of the DOM title
                if title and title.startswith(name):
                    price, url = pr, u
                    break
            hit = GEO.geocode(name=name, area=area, city=city.title(), country=country)
            if not hit or hit["precision"] == "city":   # keep building/district, drop centroids
                continue
            if url:
                url = url.split("?")[0]
                if not url.startswith("http"):
                    url = "https://www.booking.com" + url
            yield {"city": city, "name": name, "area": area, "price_from": price,
                   "lat": round(hit["lat"], 6), "lon": round(hit["lon"], 6),
                   "precision": hit["precision"], "url": url, "source": "Booking.com"}


if __name__ == "__main__":
    items = reap.run(Booking, concurrency=3, throttle=True,
                     pipelines=[JsonLinesPipeline("booking.jsonl")])
    geotag = sum(1 for it in items if it.get("lat"))
    print(f"reaped {len(items)} geo-tagged Booking apartments ({geotag} with coordinates)\n")
    for it in items[:8]:
        print(f"  {it['city']:8} {it['name'][:34]:34} {it['lat']},{it['lon']} [{it['precision']}]")

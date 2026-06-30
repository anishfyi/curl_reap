"""Geocoding: turn a name or address into coordinates, robustly.

Scraped listings often carry a name and an area but no lat/lon (the coordinates
live behind a wall, or simply are not in the markup). A naive single query fails
a lot: the full marketing name ("Chelsea Cloisters Serviced Apartments") is not in
the gazetteer, and a bare district query collapses every listing onto one centroid.

Geocoder fixes that with a cascade: it tries the raw name, then the name with
generic suffixes stripped, then the district, then the city, and stops at the first
hit. It tells you the precision of that hit ("name", "district", or "city") so you
can keep the exact ones and flag or drop the coarse ones. Results are cached and
requests are rate limited to respect the provider.

    from curl_reap import Geocoder
    g = Geocoder()
    hit = g.geocode(name="Chelsea Cloisters", area="Kensington", city="London", country="United Kingdom")
    # -> {"lat": 51.49.., "lon": -0.17.., "precision": "name", ...}
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

from curl_cffi import requests as _cffi

# trailing generic words that keep a named building out of the gazetteer
_GENERIC = re.compile(
    r"\s*(?:[-,]\s*)?\b("
    r"serviced\s+apartments?|apart[\s-]?hotels?|aparthotels?|holiday\s+homes?|"
    r"vacation\s+rentals?|guest\s*house|bed\s*&?\s*breakfast|b&b|"
    r"apartments?|suites?|hotel|hostel|by\s+[\w&'.\- ]+)\s*$",
    re.I,
)

DEFAULT_CACHE = ".reap_geocode.json"
DEFAULT_UA = "curl_reap/0.1 (+https://github.com/anishfyi/curl_reap)"


class Geocoder:
    def __init__(self, endpoint="https://nominatim.openstreetmap.org/search",
                 user_agent=DEFAULT_UA, cache=DEFAULT_CACHE, min_interval=1.1,
                 impersonate="chrome124", min_importance=0.0):
        self.endpoint = endpoint
        self.user_agent = user_agent
        self.cache_path = cache
        self.min_interval = min_interval
        self.impersonate = impersonate
        self.min_importance = min_importance
        self._cache = _load(cache)
        self._lock = threading.Lock()
        self._last = 0.0

    def clean_name(self, name):
        """Strip one trailing generic descriptor so the core place name remains."""
        prev = None
        out = (name or "").strip()
        while out and out != prev:
            prev = out
            out = _GENERIC.sub("", out).strip(" ,-")
        return out

    def _candidates(self, name, area, city, country):
        def join(*xs):
            return ", ".join([x for x in xs if x])
        cand = []
        if name and (city or area):
            cand.append(("name", join(name, area, city, country)))
            cand.append(("name", join(name, city, country)))
            cn = self.clean_name(name)
            if cn and cn.lower() != name.lower():
                cand.append(("name", join(cn, area, city, country)))
                cand.append(("name", join(cn, city, country)))
        if area and city:
            cand.append(("district", join(area, city, country)))
        if city:
            cand.append(("city", join(city, country)))
        seen, out = set(), []
        for prec, q in cand:
            if q and q not in seen:
                seen.add(q)
                out.append((prec, q))
        return out

    def geocode(self, name=None, area=None, city=None, country=None):
        """Return {lat, lon, precision, importance, display_name, query} or None."""
        ck = "|".join(str(x or "") for x in (name, area, city, country))
        if ck in self._cache:
            return self._cache[ck]
        result = None
        for precision, q in self._candidates(name, area, city, country):
            hit = self._query(q)
            if hit and float(hit.get("importance") or 0) >= self.min_importance:
                result = {
                    "lat": float(hit["lat"]), "lon": float(hit["lon"]),
                    "precision": precision, "importance": hit.get("importance"),
                    "display_name": hit.get("display_name"), "query": q,
                }
                break
        self._cache[ck] = result
        self._save()
        return result

    def _query(self, q):
        with self._lock:                                  # serialize + rate limit
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
        try:
            r = _cffi.get(self.endpoint,
                          params={"q": q, "format": "json", "limit": 1, "addressdetails": 0},
                          headers={"User-Agent": self.user_agent, "Accept-Language": "en"},
                          impersonate=self.impersonate, timeout=30)
            data = r.json() if r.status_code == 200 else []
            return data[0] if data else None
        except Exception:  # noqa: BLE001
            return None

    def _save(self):
        try:
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
        except Exception:  # noqa: BLE001
            pass


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {}


_default = None


def geocode(name=None, area=None, city=None, country=None):
    """Geocode with a shared default Geocoder (cached, rate limited)."""
    global _default
    if _default is None:
        _default = Geocoder()
    return _default.geocode(name=name, area=area, city=city, country=country)

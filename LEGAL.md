# Legal notice and acceptable use

This document is not legal advice. It explains what `curl_reap` is, what
it isn't, and what you're agreeing to by using it.

## What this library does

`curl_reap` is an HTTP client and HTML parsing library. It sends requests
with browser-accurate TLS/JA3 fingerprints, parses responses with
CSS/XPath selectors that can re-locate elements after markup changes, and
provides a concurrent crawl engine with throttling and retry logic.

Every one of those is something a real browser, or a well-behaved crawler,
already does. The library does not exploit a vulnerability, does not
decrypt anything, and does not access systems you aren't otherwise
permitted to reach.

## What this library does not do

- It does not solve CAPTCHAs.
- It does not bypass authentication, paywalls, or rate-limit bans.
- It is not designed or maintained to defeat dedicated anti-bot services
  (Cloudflare, DataDome, PerimeterX, Akamai Bot Manager, etc.). If a
  target site has deployed one of these and is actively blocking you,
  that block is the line the maintainers expect you to respect.

## Your responsibilities as a user

Web scraping legality depends on jurisdiction, what you scrape, and how.
Using `curl_reap` does not change those facts. Before you scrape anything:

1. **Check `robots.txt`.** It's not legally binding everywhere, but
   ignoring it is the first thing courts and opposing counsel point to.
2. **Read the target site's Terms of Service.** Scraping public,
   unauthenticated pages sits on firmer legal ground (see *hiQ Labs v.
   LinkedIn*, 9th Cir.) than scraping behind a login or after you've been
   told to stop.
3. **Don't circumvent technical access controls.** TLS impersonation that
   merely looks like a normal browser is different from actively defeating
   a bot-detection challenge a site has deployed specifically to block you.
   The former is generally low-risk; the latter raises CFAA/DMCA exposure
   in the US and analogous statutes elsewhere.
4. **Handle personal data lawfully.** If what you scrape includes names,
   emails, or other personal data, GDPR, CCPA, or your local equivalent
   may apply to you as the data controller, independent of how you
   collected it.
5. **Respect copyright.** Scraping is not a license to republish. Extract
   facts and data; don't mirror copyrighted text or media wholesale.
6. **Throttle and identify yourself.** Set reasonable concurrency, use
   `throttle=True`, and consider a descriptive `User-Agent` or contact
   header so site operators can reach you if there's a problem.

## No warranty, no liability

`curl_reap` is provided under the MIT License, "as is," without warranty
of any kind. The maintainers are not responsible for how you use it,
including any legal consequences arising from your use. See [LICENSE](LICENSE)
for the full text.

## Reporting misuse

If you believe `curl_reap` is being used to violate a site's terms, scrape
data unlawfully, or evade an access control in a way that concerns you,
open an issue at https://github.com/anishfyi/curl_reap/issues.

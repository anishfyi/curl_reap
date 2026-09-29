"""`reap` command-line: fetch, extract, and crawl without writing a script.

    reap get https://example.com                 # print readable markdown
    reap get https://example.com --html          # raw HTML
    reap get https://example.com --css "h1::text"
    reap get https://api.site.com/x --json        # pretty JSON
    reap meta https://example.com                 # title + og/twitter/jsonld
    reap links https://example.com --internal
    reap crawl https://quotes.toscrape.com --css "span.text::text" --max-pages 20 -o out.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys


def _fetch(url, profile, rotate, impersonate=None, http2=False):
    from .http import Session
    s = Session(profile=profile, rotate=rotate, impersonate=impersonate,
                http2=http2)
    return s.get(url)


def _cmd_get(args):
    r = _fetch(args.url, args.profile, args.rotate, args.impersonate, args.http2)
    if not r.ok:
        print(f"[reap] HTTP {r.status} for {r.url}", file=sys.stderr)
    if args.css:
        for v in r.css(args.css).getall():
            print(v if isinstance(v, str) else v.text)
    elif args.xpath:
        for v in r.xpath(args.xpath).getall():
            print(v if isinstance(v, str) else v.text)
    elif args.json:
        print(json.dumps(r.json(), indent=2, ensure_ascii=False))
    elif args.html:
        print(r.text)
    else:
        print(r.markdown(max_len=args.max_len))
    return 0 if r.ok else 1


def _cmd_meta(args):
    r = _fetch(args.url, args.profile, args.rotate, args.impersonate, args.http2)
    out = {"meta": r.meta_tags(), "jsonld": r.jsonld()}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if r.ok else 1


def _cmd_links(args):
    r = _fetch(args.url, args.profile, args.rotate, args.impersonate, args.http2)
    for link in r.links(internal_only=args.internal):
        print(f"{link['url']}\t{link['text']}")
    return 0 if r.ok else 1


def _cmd_crawl(args):
    from .engine import run
    from .pipelines import CsvPipeline, JsonLinesPipeline, SqlitePipeline
    from .spider import Spider

    css = args.css

    class CliSpider(Spider):
        start_urls = [args.url]
        allowed_domains = args.allowed or None

        def parse(self, page):
            if css:
                for v in page.css(css).getall():
                    yield {"url": page.url, "value": v if isinstance(v, str) else v.text}
            else:
                yield {"url": page.url, "title": page.meta_tags().get("title")}
            if args.follow:
                for link in page.links(internal_only=True):
                    yield page.follow(link["url"])

    pipelines = []
    if args.out:
        if args.out.endswith(".jsonl"):
            pipelines.append(JsonLinesPipeline(args.out))
        elif args.out.endswith(".csv"):
            pipelines.append(CsvPipeline(args.out))
        elif args.out.endswith(".db"):
            pipelines.append(SqlitePipeline(args.out))

    items = run(CliSpider, concurrency=args.concurrency, max_pages=args.max_pages,
                max_depth=args.max_depth, respect_robots=args.robots,
                profile=args.profile, rotate=args.rotate, pipelines=pipelines)
    if not args.out:
        for it in items:
            print(json.dumps(it, ensure_ascii=False, default=str))
    else:
        print(f"[reap] {len(items)} items -> {args.out}", file=sys.stderr)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="reap", description="reap the web from the shell")
    p.add_argument("--http2", action="store_true",
                   help="negotiate HTTP/2 when the server offers it (needs "
                        "the h2 extra)")
    p.add_argument("--impersonate", default=None,
                   help="versioned browser target, e.g. chrome124, firefox133, "
                        "safari17_0 (overrides --profile; best-effort)")
    p.add_argument("--profile", default="chrome", choices=["chrome", "firefox", "safari"],
                   help="TLS/header profile (default chrome)")
    p.add_argument("--rotate", choices=["random", "sequence"], help="rotate profiles")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("get", help="fetch one page")
    g.add_argument("url")
    g.add_argument("--css", help="CSS selector to extract")
    g.add_argument("--xpath", help="XPath to extract")
    g.add_argument("--json", action="store_true", help="parse and pretty-print JSON")
    g.add_argument("--html", action="store_true", help="print raw HTML")
    g.add_argument("--markdown", action="store_true",
                   help="print readable markdown (the default)")
    g.add_argument("--max-len", type=int, default=None, help="truncate markdown output")
    g.set_defaults(func=_cmd_get)

    m = sub.add_parser("meta", help="print title, meta tags, and JSON-LD")
    m.add_argument("url")
    m.set_defaults(func=_cmd_meta)

    ln = sub.add_parser("links", help="list hyperlinks")
    ln.add_argument("url")
    ln.add_argument("--internal", action="store_true", help="only same-domain links")
    ln.set_defaults(func=_cmd_links)

    c = sub.add_parser("crawl", help="crawl a site")
    c.add_argument("url")
    c.add_argument("--css", help="CSS selector for each page")
    c.add_argument("--follow", action="store_true", help="follow internal links")
    c.add_argument("--allowed", nargs="*", help="allowed domains")
    c.add_argument("--concurrency", type=int, default=8)
    c.add_argument("--max-pages", type=int, default=50)
    c.add_argument("--max-depth", type=int, default=3)
    c.add_argument("--robots", action="store_true", help="respect robots.txt")
    c.add_argument("-o", "--out", help="output file (.jsonl/.csv/.db)")
    c.set_defaults(func=_cmd_crawl)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

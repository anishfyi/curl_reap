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
    # HTTP/2 is negotiated by default now; the legacy --http2 flag is a no-op
    s = Session(profile=profile, rotate=rotate, impersonate=impersonate)
    return s.get(url)


def _cmd_doctor(args):
    """Fetch a fingerprint echo service and compare against the captures."""
    from .fingerprint import EXPECTED, check
    if args.list:
        for name in sorted(EXPECTED):
            print(name)
        return 0
    try:
        report = check(target=args.target, url=args.url)
    except Exception as exc:
        print("[reap] doctor could not reach %s: %s" % (args.url, exc),
              file=sys.stderr)
        return 2
    print("target      %s" % report["target"])
    print("url         %s" % args.url)
    print("http        %s" % report.get("http_version"))
    print("ja3         %s" % (report.get("ja3") or "-"))
    print("ja4         %s" % report.get("ja4"))
    print("peetprint   %s" % (report.get("peetprint") or "-"))
    print("akamai h2   %s" % (report.get("akamai") or "-"))
    print("")
    ok = True
    for name, matched in sorted((report.get("matches") or {}).items()):
        if name == "headers":
            continue
        print("  %-12s %s" % (name, "MATCH" if matched else "DIFFERS"))
        ok = ok and matched
    headers = (report.get("matches") or {}).get("headers")
    if headers is not None:
        print("  %-12s %s" % ("headers", "MATCH" if headers else "DIFFERS"))
        ok = ok and headers
    if not ok:
        print("\n[reap] fingerprint differs from the captured bytes; "
              "expected values:", file=sys.stderr)
        for key, value in sorted((report.get("expected") or {}).items()):
            print("  %-12s %s" % (key, value), file=sys.stderr)
    return 0 if ok else 1


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


def _service_env():
    """Shared env config for serve/worker. Secrets stay in the environment."""
    import os
    api_key = os.environ.get("REAP_API_KEY")
    redis_url = os.environ.get("REAP_REDIS_URL", "redis://127.0.0.1:6379/0")
    raw = os.environ.get("REAP_ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    proxy_url = os.environ.get("REAP_PROXY_URL")
    if not api_key:
        print("[reap] REAP_API_KEY is not set", file=sys.stderr)
        return None
    if not origins:
        print("[reap] REAP_ALLOWED_ORIGINS is empty "
              "(comma-separated scheme://host:port list)", file=sys.stderr)
        return None
    return api_key, redis_url, origins, proxy_url


def _redis_queue(redis_url):
    """Connect the job queue without ever echoing the URL - it may carry
    a password."""
    try:
        import redis as _redis
        from .jobs import RedisJobQueue
    except ImportError:
        print("[reap] the job service needs the server extra: "
              "pip install 'curl-reap[server]'", file=sys.stderr)
        return None
    try:
        client = _redis.Redis.from_url(redis_url)
        queue = RedisJobQueue(client)
    except Exception:
        print("[reap] could not connect to Redis via REAP_REDIS_URL",
              file=sys.stderr)
        return None
    return queue


def _cmd_serve(args):
    env = _service_env()
    if env is None:
        return 2
    api_key, redis_url, origins, proxy_url = env
    try:
        import uvicorn
        from .service import create_app
    except ImportError:
        print("[reap] serve needs the server extra: "
              "pip install 'curl-reap[server]'", file=sys.stderr)
        return 2
    queue = _redis_queue(redis_url)
    if queue is None:
        return 2
    try:
        app = create_app(queue=queue, api_key=api_key,
                         allowed_origins=origins)
    except ValueError as exc:
        print("[reap] %s" % exc, file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _cmd_worker(args):
    env = _service_env()
    if env is None:
        return 2
    api_key, redis_url, origins, proxy_url = env
    try:
        from .jobs import Worker
    except ImportError:
        print("[reap] worker needs the server extra: "
              "pip install 'curl-reap[server]'", file=sys.stderr)
        return 2
    queue = _redis_queue(redis_url)
    if queue is None:
        return 2
    try:
        worker = Worker(queue, origins, proxy=proxy_url)
    except ValueError as exc:
        print("[reap] %s" % exc, file=sys.stderr)
        return 2
    print("[reap] worker %s draining jobs" % worker.worker_id,
          file=sys.stderr)
    worker.serve_forever()
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

    s = sub.add_parser("serve", help="run the private job API (server extra; "
                                   "reads REAP_API_KEY/REAP_REDIS_URL/"
                                   "REAP_ALLOWED_ORIGINS)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=_cmd_serve)

    w = sub.add_parser("worker", help="run one distributed job worker "
                                      "(server extra; same env as serve)")
    w.set_defaults(func=_cmd_worker)

    d = sub.add_parser("doctor",
                       help="verify this machine's wire fingerprint against "
                            "the captured browser values")
    d.add_argument("target", nargs="?", default="chrome",
                   help="impersonate target to verify (default chrome)")
    d.add_argument("--url", default="https://tls.peet.ws/api/all",
                   help="fingerprint echo service")
    d.add_argument("--list", action="store_true",
                   help="list every known target and exit")
    d.set_defaults(func=_cmd_doctor)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
"""Reproducible local benchmark: curl_reap versus curl_cffi versus http.client.

Every server runs inside this process in a thread, bound to 127.0.0.1 on an
ephemeral port. Nothing touches the external network. Scenarios:

  A  HTTP/1.1 keep-alive, one connection, N sequential GETs of a 20 KB HTML
     body served gzip-encoded with Content-Length. Requests/s, p50, p99.
  B  Same server, 16 threads x 300 GETs each, one Session object shared per
     library. Aggregate requests/s.
  C  HTTPS fresh connections: TLS server that answers with Connection: close,
     300 connections each doing one GET. Handshakes/s and p50 per request.
  D  HTTPS keep-alive: same TLS server type, N GETs over one connection.
  E  HTTP/2 keep-alive: hyper-h2 TLS server with ALPN h2, N GETs over one
     connection. curl_reap uses Session(http2=True); curl_cffi negotiates h2
     through ALPN by default. http.client cannot speak h2 and is skipped.
  F  Large body: 50 GETs of a 5 MB identity-encoded body over HTTP/1.1
     keep-alive. MB/s.

Usage:
  python bench/bench.py --out bench/baseline.json --md bench/BASELINE.md
  python bench/bench.py --quick --scenarios A,D
  python bench/bench.py --profile-dir /tmp/prof   (cProfile curl_reap A and D)

Each (scenario, client) pair runs in a worker thread with a hard timeout and
reports ERROR instead of hanging the run. Warm-up requests precede timing;
each scenario runs --runs times and the median of every metric is reported.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import cProfile
import datetime
import gzip
import http.client
import io
import ipaddress
import json
import math
import os
import platform
import pstats
import random
import socket
import socketserver
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zlib
from urllib.parse import urlsplit

HTML_SIZE = 20 * 1024
LARGE_SIZE = 5 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

_WORDS = ("the quick brown fox jumps over a lazy dog while seventeen crawlers "
          "index structured data from ordered headers cookies redirects and "
          "gzip bodies measured against a loopback server with deterministic "
          "content so every run compares the same bytes").split()


def build_html(size=HTML_SIZE, seed=1234):
    rng = random.Random(seed)
    parts = ["<!doctype html><html><head><meta charset=\"utf-8\">"
             "<title>curl_reap benchmark page</title></head><body>"]
    i = 0
    while sum(len(p) for p in parts) < size - 64:
        words = " ".join(rng.choice(_WORDS) for _ in range(rng.randint(8, 24)))
        parts.append("<p id=\"p%d\" class=\"c%d\">%s <a href=\"/item/%d\">link %d</a></p>"
                     % (i, i % 7, words, rng.randint(1, 99999), i))
        i += 1
    html = "".join(parts)
    pad = size - len(html) - len("</body></html>")
    if pad > 0:
        html += "<!--" + ("x" * max(0, pad - 7)) + "-->"
    html += "</body></html>"
    data = html.encode("utf-8")
    return data[:size] if len(data) > size else data + b" " * (size - len(data))


HTML = build_html()
HTML_GZ = gzip.compress(HTML, compresslevel=6, mtime=0)
LARGE = random.Random(7).randbytes(LARGE_SIZE)


def _h1_response(body, content_type, content_encoding, close):
    head = [b"HTTP/1.1 200 OK", b"Server: bench", b"Content-Type: " + content_type]
    if content_encoding:
        head.append(b"Content-Encoding: " + content_encoding)
    head.append(b"Content-Length: %d" % len(body))
    head.append(b"Connection: close" if close else b"Connection: keep-alive")
    return b"\r\n".join(head) + b"\r\n\r\n" + body


ROUTES = {
    b"/": (HTML_GZ, b"text/html; charset=utf-8", b"gzip", HTML_SIZE),
    b"/page": (HTML_GZ, b"text/html; charset=utf-8", b"gzip", HTML_SIZE),
    b"/large": (LARGE, b"application/octet-stream", b"", LARGE_SIZE),
}


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def make_cert(directory):
    """Self-signed ECDSA P-256 CA cert for localhost / 127.0.0.1."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, key_cert_sign=True,
            content_commitment=False, data_encipherment=False, key_agreement=False,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


def server_tls_context(cert_path, key_path, alpn, tickets=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.options |= ssl.OP_NO_COMPRESSION
    if not tickets:
        ctx.options |= ssl.OP_NO_TICKET
    ctx.set_alpn_protocols(list(alpn))
    return ctx


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        sock = self.request
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        sock.settimeout(30)
        try:
            if server.tls_context is not None:
                try:
                    sock = server.tls_context.wrap_socket(sock, server_side=True)
                except (OSError, ssl.SSLError):
                    return
                if sock.selected_alpn_protocol() == "h2":
                    server.stats["h2_connections"] += 1
                    self._serve_h2(sock, server)
                    return
            server.stats["h1_connections"] += 1
            self._serve_h1(sock, server)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _serve_h1(sock, server):
        buf = b""
        responses = server.responses
        notfound = server.notfound
        close_mode = server.close_mode
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            parts = lines[0].split(b" ")
            path = parts[1].split(b"?", 1)[0] if len(parts) >= 2 else b"/"
            client_close = False
            body_len = 0
            for line in lines[1:]:
                lower = line.lower()
                if lower.startswith(b"connection:") and b"close" in lower:
                    client_close = True
                elif lower.startswith(b"content-length:"):
                    try:
                        body_len = int(lower.split(b":", 1)[1].strip())
                    except ValueError:
                        body_len = 0
            while len(buf) < body_len:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                buf += chunk
            buf = buf[body_len:]
            sock.sendall(responses.get(path, notfound))
            server.stats["requests"] += 1
            if close_mode or client_close:
                return

    @staticmethod
    def _serve_h2(sock, server):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import ConnectionTerminated, RequestReceived

        conn = H2Connection(config=H2Configuration(client_side=False,
                                                   header_encoding="latin-1"))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        pending = {}

        def pump():
            for sid in list(pending):
                data = pending[sid]
                try:
                    while data:
                        window = min(conn.local_flow_control_window(sid),
                                     conn.max_outbound_frame_size)
                        if window <= 0:
                            break
                        chunk, data = data[:window], data[window:]
                        conn.send_data(sid, chunk, end_stream=not data)
                except Exception:
                    data = b""
                if data:
                    pending[sid] = data
                else:
                    del pending[sid]
            out = conn.data_to_send()
            if out:
                sock.sendall(out)

        while True:
            wire = sock.recv(65536)
            if not wire:
                return
            try:
                events = conn.receive_data(wire)
            except Exception:
                return
            for event in events:
                if isinstance(event, RequestReceived):
                    headers = dict(event.headers)
                    path = headers.get(":path", "/").split("?", 1)[0].encode("latin-1")
                    body, ctype, cenc, _ = ROUTES.get(path, (b"not found", b"text/plain", b"", 0))
                    status = b"200" if path in ROUTES else b"404"
                    hdrs = [(b":status", status), (b"server", b"bench"),
                            (b"content-type", ctype),
                            (b"content-length", str(len(body)).encode())]
                    if cenc:
                        hdrs.append((b"content-encoding", cenc))
                    conn.send_headers(event.stream_id, hdrs)
                    pending[event.stream_id] = body
                    server.stats["requests"] += 1
                elif isinstance(event, ConnectionTerminated):
                    pump()
                    return
            pump()


class BenchServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512

    def __init__(self, tls_context=None, close_mode=False):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.tls_context = tls_context
        self.close_mode = close_mode
        self.responses = {path: _h1_response(body, ctype, cenc, close_mode)
                          for path, (body, ctype, cenc, _) in ROUTES.items()}
        self.notfound = _h1_response(b"not found", b"text/plain", b"", close_mode
                                     ).replace(b"200 OK", b"404 Not Found", 1)
        self.stats = {"requests": 0, "h1_connections": 0, "h2_connections": 0}
        self.thread = threading.Thread(target=self.serve_forever, daemon=True,
                                       name="bench-server-%d" % self.server_address[1])
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    @property
    def scheme(self):
        return "https" if self.tls_context is not None else "http"

    def url(self, path="/"):
        return "%s://127.0.0.1:%d%s" % (self.scheme, self.port, path)

    def stop(self):
        try:
            self.shutdown()
            self.server_close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

class ReapClient:
    name = "curl_reap"

    def __init__(self, verify, http2=False, timeout=DEFAULT_TIMEOUT):
        import curl_reap
        self.session = curl_reap.Session(retries=0, verify=verify, timeout=timeout,
                                         http2=http2)

    def one(self, url):
        r = self.session.get(url)
        return r.status, len(r.content), getattr(r.raw, "http_version", "?")

    def close(self):
        self.session.close()


_CURL_HTTP_VERSION = {1: "HTTP/1.0", 2: "HTTP/1.1", 3: "HTTP/2", 30: "HTTP/3",
                      10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}


class CffiClient:
    name = "curl_cffi"

    def __init__(self, verify, http2=False, timeout=DEFAULT_TIMEOUT):
        from curl_cffi import requests as cffi_requests
        self.session = cffi_requests.Session(verify=verify, timeout=timeout)

    def one(self, url):
        r = self.session.get(url)
        version = getattr(r, "http_version", None)
        return r.status_code, len(r.content), _CURL_HTTP_VERSION.get(version, str(version))

    def close(self):
        self.session.close()


class StdlibClient:
    name = "http.client"

    def __init__(self, verify, http2=False, timeout=DEFAULT_TIMEOUT):
        if http2:
            raise RuntimeError("http.client cannot speak HTTP/2")
        self.timeout = timeout
        self.local = threading.local()
        self.conns = []
        self.lock = threading.Lock()
        if verify is False:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif isinstance(verify, str):
            ctx = ssl.create_default_context(cafile=verify)
        else:
            ctx = ssl.create_default_context()
        self.ctx = ctx

    def _conn(self, parts):
        conn = getattr(self.local, "conn", None)
        if conn is None:
            if parts.scheme == "https":
                conn = http.client.HTTPSConnection(parts.hostname, parts.port,
                                                   timeout=self.timeout, context=self.ctx)
            else:
                conn = http.client.HTTPConnection(parts.hostname, parts.port,
                                                  timeout=self.timeout)
            self.local.conn = conn
            with self.lock:
                self.conns.append(conn)
        return conn

    def one(self, url):
        parts = urlsplit(url)
        conn = self._conn(parts)
        conn.request("GET", parts.path or "/", headers={"Accept-Encoding": "gzip"})
        resp = conn.getresponse()
        body = resp.read()
        if (resp.getheader("Content-Encoding") or "").lower() == "gzip":
            body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
        version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(resp.version, str(resp.version))
        return resp.status, len(body), version

    def close(self):
        with self.lock:
            conns, self.conns = self.conns, []
        for conn in conns:
            try:
                conn.close()
            except Exception:
                pass


CLIENTS = {"curl_reap": ReapClient, "curl_cffi": CffiClient, "http.client": StdlibClient}


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def percentile(values, p):
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


def run_sequential(client, url, n, expected_len, expected_bytes=None):
    latencies = []
    bad = 0
    protocol = None
    append = latencies.append
    one = client.one
    clock = time.perf_counter
    t0 = clock()
    for _ in range(n):
        s = clock()
        status, length, proto = one(url)
        append(clock() - s)
        if status != 200 or length != expected_len:
            bad += 1
        if protocol is None:
            protocol = proto
    total = clock() - t0
    result = {
        "requests": n,
        "seconds": total,
        "rps": n / total if total else float("inf"),
        "p50_ms": percentile(latencies, 50) * 1000.0,
        "p99_ms": percentile(latencies, 99) * 1000.0,
        "bad": bad,
        "protocol": protocol,
    }
    if expected_bytes:
        result["mb_per_s"] = (expected_bytes * n / (1024.0 * 1024.0)) / total if total else float("inf")
    return result


def run_threaded(client, pool, url, threads, per_thread, expected_len):
    barrier = threading.Barrier(threads)
    clock = time.perf_counter

    def worker():
        lat = []
        bad = 0
        proto = None
        barrier.wait()
        start = clock()
        for _ in range(per_thread):
            s = clock()
            status, length, p = client.one(url)
            lat.append(clock() - s)
            if status != 200 or length != expected_len:
                bad += 1
            if proto is None:
                proto = p
        return start, clock(), lat, bad, proto

    futures = [pool.submit(worker) for _ in range(threads)]
    results = [f.result() for f in futures]
    start = min(r[0] for r in results)
    end = max(r[1] for r in results)
    latencies = [x for r in results for x in r[2]]
    total = end - start
    n = threads * per_thread
    return {
        "requests": n,
        "threads": threads,
        "seconds": total,
        "rps": n / total if total else float("inf"),
        "p50_ms": percentile(latencies, 50) * 1000.0,
        "p99_ms": percentile(latencies, 99) * 1000.0,
        "bad": sum(r[3] for r in results),
        "protocol": results[0][4],
    }


def median_of_runs(runs):
    if not runs:
        return {}
    keys = [k for k, v in runs[0].items() if isinstance(v, (int, float)) and k != "threads"]
    out = {k: statistics.median([r[k] for r in runs if k in r]) for k in keys}
    out["protocol"] = runs[0].get("protocol")
    if "threads" in runs[0]:
        out["threads"] = runs[0]["threads"]
    return out


SCENARIOS = {
    "A": {"title": "HTTP/1.1 keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML",
          "server": "h1", "mode": "seq", "n": 2000, "path": "/", "metric": "rps"},
    "B": {"title": "HTTP/1.1 keep-alive, 16 threads x 300 GET, shared Session",
          "server": "h1", "mode": "thr", "threads": 16, "per_thread": 300, "path": "/",
          "metric": "rps"},
    "C": {"title": "HTTPS fresh connections, 300 x 1 GET (server sends Connection: close)",
          "server": "tls_close", "mode": "seq", "n": 300, "path": "/", "metric": "handshakes"},
    "D": {"title": "HTTPS keep-alive, 1 connection, 2000 GET x 20 KB gzip HTML",
          "server": "tls", "mode": "seq", "n": 2000, "path": "/", "metric": "rps"},
    "E": {"title": "HTTP/2 keep-alive (ALPN h2), 1 connection, 1000 GET x 20 KB gzip HTML",
          "server": "h2", "mode": "seq", "n": 1000, "path": "/", "metric": "rps",
          "http2": True, "clients": ("curl_reap", "curl_cffi")},
    "F": {"title": "HTTP/1.1 keep-alive, 50 GET x 5 MB identity body",
          "server": "h1", "mode": "seq", "n": 50, "path": "/large", "metric": "mb_per_s"},
}


def run_pair(scenario, spec, client_name, server, verify, runs, warmup, timeout_s, log):
    """Run one (scenario, client) pair inside a guarded thread."""
    path = spec["path"]
    url = server.url(path)
    expected_len = ROUTES[path.encode()][3]
    expected_bytes = expected_len if spec["metric"] == "mb_per_s" else None
    state = {"runs": [], "error": None}

    def work():
        client = CLIENTS[client_name](verify, http2=spec.get("http2", False))
        pool = None
        try:
            if spec["mode"] == "thr":
                threads = spec["threads"]
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
                warm_each = max(1, math.ceil(warmup / threads))
                run_threaded(client, pool, url, threads, warm_each, expected_len)
                for _ in range(runs):
                    state["runs"].append(run_threaded(client, pool, url, threads,
                                                      spec["per_thread"], expected_len))
            else:
                run_sequential(client, url, warmup, expected_len)
                for _ in range(runs):
                    state["runs"].append(run_sequential(client, url, spec["n"],
                                                        expected_len, expected_bytes))
        finally:
            if pool is not None:
                pool.shutdown(wait=False)
            try:
                client.close()
            except Exception:
                pass

    def target():
        try:
            work()
        except BaseException as exc:  # noqa: BLE001 - report everything
            state["error"] = "%s: %s" % (type(exc).__name__, str(exc).strip() or "no message")
            state["traceback"] = traceback.format_exc()

    thread = threading.Thread(target=target, daemon=True,
                              name="bench-%s-%s" % (scenario, client_name))
    started = time.perf_counter()
    thread.start()
    thread.join(timeout_s)
    elapsed = time.perf_counter() - started
    if thread.is_alive():
        state["error"] = "timeout after %.0fs (%d/%d runs finished)" % (
            timeout_s, len(state["runs"]), runs)
    out = {"runs": state["runs"], "median": median_of_runs(state["runs"]),
           "wall_seconds": elapsed}
    if state["error"]:
        out["error"] = state["error"]
        if state.get("traceback"):
            out["traceback"] = state["traceback"]
        log("    %-12s ERROR %s" % (client_name, state["error"]))
    else:
        med = out["median"]
        log("    %-12s %s" % (client_name, format_cell(spec["metric"], med)))
    return out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def fmt_num(value, digits=0):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/a"
    if digits == 0:
        return "{:,.0f}".format(value)
    return "{:,.{d}f}".format(value, d=digits)


def format_cell(metric, med):
    if not med:
        return "n/a"
    flag = " (bad=%d)" % med["bad"] if med.get("bad") else ""
    if metric == "mb_per_s":
        return "%s MB/s, p50 %s ms%s" % (fmt_num(med["mb_per_s"], 1), fmt_num(med["p50_ms"], 2), flag)
    if metric == "handshakes":
        return "%s conn/s, p50 %s ms, p99 %s ms%s" % (
            fmt_num(med["rps"]), fmt_num(med["p50_ms"], 3), fmt_num(med["p99_ms"], 3), flag)
    return "%s req/s, p50 %s ms, p99 %s ms%s" % (
        fmt_num(med["rps"]), fmt_num(med["p50_ms"], 3), fmt_num(med["p99_ms"], 3), flag)


def primary_metric(metric, med):
    if not med:
        return None
    if metric == "mb_per_s":
        return med.get("mb_per_s")
    return med.get("rps")


def markdown_table(results, client_names):
    unit = {"rps": "req/s", "handshakes": "conn/s", "mb_per_s": "MB/s"}
    header = ["Scenario", "Metric"] + client_names + ["reap / cffi"]
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join("---" for _ in header) + "|"]
    for key, spec in SCENARIOS.items():
        block = results.get(key)
        if not block:
            continue
        clients = block["clients"]
        metric = spec["metric"]
        row_main = [key + ". " + spec["title"], unit[metric]]
        row_lat = ["", "p50 / p99 ms"]
        for name in client_names:
            entry = clients.get(name)
            if entry is None:
                row_main.append("n/a")
                row_lat.append("n/a")
                continue
            if entry.get("error"):
                row_main.append("ERROR")
                row_lat.append(entry["error"][:60])
                continue
            med = entry["median"]
            value = primary_metric(metric, med)
            flag = " (bad=%d)" % med["bad"] if med.get("bad") else ""
            row_main.append(fmt_num(value, 1 if metric == "mb_per_s" else 0) + flag)
            row_lat.append("%s / %s" % (fmt_num(med["p50_ms"], 3), fmt_num(med["p99_ms"], 3)))
        reap = clients.get("curl_reap", {}).get("median")
        cffi = clients.get("curl_cffi", {}).get("median")
        pr = primary_metric(metric, reap) if reap else None
        pc = primary_metric(metric, cffi) if cffi else None
        ratio = "n/a" if not pr or not pc else "%.2fx" % (pr / pc)
        row_main.append(ratio)
        row_lat.append("")
        lines.append("| " + " | ".join(row_main) + " |")
        lines.append("| " + " | ".join(row_lat) + " |")
    return "\n".join(lines)


def cpu_name():
    if sys.platform == "darwin":
        try:
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"],
                                           text=True, timeout=5).strip()
        except Exception:
            pass
    if os.path.exists("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or platform.machine()


def library_versions():
    out = {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION}
    for mod in ("curl_reap", "curl_cffi", "h2", "hpack", "cryptography", "lxml"):
        try:
            module = __import__(mod)
            out[mod] = getattr(module, "__version__", "?")
        except Exception as exc:
            out[mod] = "unavailable (%s)" % type(exc).__name__
    try:
        import curl_cffi
        out["libcurl"] = getattr(curl_cffi, "__curl_version__", "?")
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Profiling
# ---------------------------------------------------------------------------

def profile_reap(server, verify, n, warmup, path_out, label, top=25):
    """cProfile curl_reap alone (the calling thread only; server threads are not sampled)."""
    client = ReapClient(verify)
    url = server.url("/")
    expected = HTML_SIZE
    try:
        run_sequential(client, url, warmup, expected)
        prof = cProfile.Profile()
        prof.enable()
        result = run_sequential(client, url, n, expected)
        prof.disable()
    finally:
        client.close()
    buf = io.StringIO()
    buf.write("curl_reap scenario %s under cProfile: %d requests, %s\n"
              "(profiler overhead inflates absolute times; compare shares)\n\n"
              % (label, n, format_cell("rps", result)))
    full = pstats.Stats(prof, stream=buf)
    buf.write("=== curl_reap package functions only, by tottime ===\n")
    full.sort_stats("tottime").print_stats(r"curl_reap[/\\]curl_reap[/\\]", 30)
    stats = pstats.Stats(prof, stream=buf)
    stats.strip_dirs()
    buf.write("\n=== sorted by cumulative time (top %d) ===\n" % top)
    stats.sort_stats("cumulative").print_stats(top)
    buf.write("\n=== sorted by internal (tottime) (top %d) ===\n" % top)
    stats.sort_stats("tottime").print_stats(top)
    with open(path_out, "w") as fh:
        fh.write(buf.getvalue())
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write JSON results here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=180.0,
                        help="seconds allowed per (scenario, client) pair including warm-up and all runs")
    parser.add_argument("--scenarios", default="A,B,C,D,E,F")
    parser.add_argument("--clients", default="curl_reap,curl_cffi,http.client")
    parser.add_argument("--insecure", action="store_true",
                        help="verify=False for every client instead of verify=<cert path>")
    parser.add_argument("--no-tls-tickets", action="store_true",
                        help="server sets OP_NO_TICKET so no client can resume TLS sessions")
    parser.add_argument("--quick", action="store_true", help="divide request counts by 10")
    parser.add_argument("--profile-dir", help="also cProfile curl_reap scenarios A, D and C into this dir")
    parser.add_argument("--profile-only", action="store_true", help="skip the benchmark, only profile")
    parser.add_argument("--date", default=None, help="date label for the report (default: today)")
    args = parser.parse_args(argv)

    def log(message):
        print(message, flush=True)

    wanted = [s.strip().upper() for s in args.scenarios.split(",") if s.strip()]
    client_names = [c.strip() for c in args.clients.split(",") if c.strip()]
    for name in client_names:
        if name not in CLIENTS:
            parser.error("unknown client %r" % name)
    for key in wanted:
        if key not in SCENARIOS:
            parser.error("unknown scenario %r" % key)
    if args.quick:
        for spec in SCENARIOS.values():
            if "n" in spec:
                spec["n"] = max(5, spec["n"] // 10)
            if "per_thread" in spec:
                spec["per_thread"] = max(5, spec["per_thread"] // 10)

    tmpdir = tempfile.mkdtemp(prefix="curl_reap_bench_")
    cert_path, key_path = make_cert(tmpdir)
    verify = False if args.insecure else cert_path
    tickets = not args.no_tls_tickets

    servers = {
        "h1": BenchServer(),
        "tls_close": BenchServer(server_tls_context(cert_path, key_path, ["http/1.1"], tickets),
                                 close_mode=True),
        "tls": BenchServer(server_tls_context(cert_path, key_path, ["http/1.1"], tickets)),
        "h2": BenchServer(server_tls_context(cert_path, key_path, ["h2", "http/1.1"], tickets)),
    }
    report = {
        "date": args.date or datetime.date.today().isoformat(),
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "machine": {
            "cpu": cpu_name(),
            "cores": os.cpu_count(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "python": sys.version,
        "versions": library_versions(),
        "config": {
            "runs": args.runs,
            "warmup": args.warmup,
            "verify": "insecure" if args.insecure else "self-signed ECDSA P-256 CA cert path",
            "tls_session_tickets": tickets,
            "timeout_per_pair_s": args.timeout,
            "quick": args.quick,
            "html_bytes": HTML_SIZE,
            "html_gzip_bytes": len(HTML_GZ),
            "large_bytes": LARGE_SIZE,
            "client_timeout_s": DEFAULT_TIMEOUT,
        },
        "scenarios": {},
    }
    log("curl_reap bench on %s, Python %s" % (report["machine"]["cpu"], report["versions"]["python"]))
    log("versions: " + ", ".join("%s %s" % kv for kv in report["versions"].items()
                                  if kv[0] not in ("python",)))
    log("verify=%s tickets=%s runs=%d warmup=%d" % (report["config"]["verify"], tickets,
                                                    args.runs, args.warmup))

    try:
        if not args.profile_only:
            for key in wanted:
                spec = SCENARIOS[key]
                server = servers[spec["server"]]
                log("\n[%s] %s  (%s)" % (key, spec["title"], server.url(spec["path"])))
                block = {"title": spec["title"], "spec": {k: v for k, v in spec.items()
                                                          if k not in ("title", "clients")},
                         "clients": {}}
                stats_before = dict(server.stats)
                allowed = spec.get("clients")
                for name in client_names:
                    if allowed is not None and name not in allowed:
                        block["clients"][name] = None
                        log("    %-12s skipped (not applicable)" % name)
                        continue
                    block["clients"][name] = run_pair(key, spec, name, server, verify,
                                                      args.runs, args.warmup, args.timeout, log)
                block["server_stats"] = {k: server.stats[k] - stats_before[k]
                                         for k in server.stats}
                report["scenarios"][key] = block

            table = markdown_table(report["scenarios"], client_names)
            log("\n" + table)
            if args.out:
                os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
                with open(args.out, "w") as fh:
                    json.dump(report, fh, indent=2, sort_keys=False)
                log("\nwrote %s" % args.out)
            if args.md:
                os.makedirs(os.path.dirname(os.path.abspath(args.md)), exist_ok=True)
                with open(args.md, "w") as fh:
                    fh.write(render_markdown(report, table))
                log("wrote %s" % args.md)

        if args.profile_dir:
            os.makedirs(args.profile_dir, exist_ok=True)
            for label, server_key in (("A", "h1"), ("D", "tls"), ("C", "tls_close")):
                n = SCENARIOS[label]["n"]
                path_out = os.path.join(args.profile_dir, "profile_%s.txt" % label)
                result = profile_reap(servers[server_key], verify, n, args.warmup, path_out, label)
                log("profiled curl_reap %s: %s -> %s" % (label, format_cell("rps", result), path_out))
    finally:
        for server in servers.values():
            server.stop()
        for name in ("cert.pem", "key.pem"):
            try:
                os.remove(os.path.join(tmpdir, name))
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
    return 0


def render_markdown(report, table):
    m = report["machine"]
    v = report["versions"]
    c = report["config"]
    lines = [
        "# curl_reap baseline benchmark",
        "",
        "Date: %s. Machine: %s (%s cores, %s). Python %s, %s." % (
            report["date"], m["cpu"], m["cores"], m["platform"], v.get("python"), v.get("openssl")),
        "",
        "Libraries: curl_reap %s, curl_cffi %s (libcurl %s), h2 %s, hpack %s, cryptography %s." % (
            v.get("curl_reap"), v.get("curl_cffi"), v.get("libcurl"), v.get("h2"), v.get("hpack"),
            v.get("cryptography")),
        "",
        "Method: every server runs in a thread of the benchmark process on 127.0.0.1; no external "
        "network. %d warm-up requests, then %d timed runs per scenario; the table shows the median "
        "of each metric across runs. TLS verification: %s. TLS session tickets on the server: %s. "
        "HTML body %d bytes (%d bytes gzip). Large body %d bytes identity. curl_reap uses "
        "Session(retries=0, verify=...); curl_cffi uses requests.Session(verify=...) with its "
        "default thread-local curl handles; http.client uses one connection per thread with manual "
        "gzip decoding and is the floor reference. bad=N marks responses whose status or decoded "
        "length did not match." % (
            c["warmup"], c["runs"], c["verify"], c["tls_session_tickets"], c["html_bytes"],
            c["html_gzip_bytes"], c["large_bytes"]),
        "",
        "Reproduce: `.venv/bin/python bench/bench.py --out bench/baseline.json --md bench/BASELINE.md`",
        "",
        table,
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())

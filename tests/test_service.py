"""Private job API: auth, allowlist, validation, body caps, queue-full,
status surfaces - plus a live HTTP fixture proving the worker refuses an
off-origin redirect before the bad host is ever contacted."""
import http.server
import json
import socketserver
import threading

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient

import curl_reap                            
from curl_reap.service import create_app    
from curl_reap.jobs import Worker, origin_of

KEY = "test-key"


class FakeQueue:
    def __init__(self):
        self.jobs = {}
        self.capacity = None
        self.enqueued = []
        self.healthy = True

    def enqueue(self, url, css=None, max_chars=20000):
        if self.capacity is not None and len(self.enqueued) >= self.capacity:
            return None
        job_id = "job-%d" % len(self.enqueued)
        self.enqueued.append((url, css, max_chars))
        self.jobs[job_id] = {"id": job_id, "status": "queued"}
        return job_id

    def get(self, job_id):
        return self.jobs.get(job_id)

    def health(self):
        return self.healthy


@pytest.fixture
def client():
    queue = FakeQueue()
    app = create_app(queue=queue, api_key=KEY,
                     allowed_origins=["http://127.0.0.1:8080"])
    return TestClient(app), queue


def _post(c, body, key=KEY, headers=None, **kw):
    h = dict(headers or {})
    if key is not None:
        h["x-reap-key"] = key
    return c.post("/jobs", content=body, headers=h, **kw)


def test_auth_required_everywhere_except_healthz(client):
    c, queue = client
    assert c.get("/healthz").status_code == 200
    assert c.post("/jobs", json={}).status_code == 401
    assert c.get("/jobs/x").status_code == 401
    assert c.post("/jobs", json={}, headers={"x-reap-key": "wrong"}
                  ).status_code == 401
    queue.healthy = False
    assert c.get("/healthz").status_code == 503


def test_create_app_requires_key_and_valid_origins():
    with pytest.raises(ValueError):
        create_app(queue=FakeQueue(), api_key="", allowed_origins=["x"])
    with pytest.raises(ValueError):
        create_app(queue=FakeQueue(), api_key=KEY, allowed_origins=[])
    for bad in ("http://u:p@x", "http://x/path", "http://x?q=1",
                "ftp://x", "http://x:bad", "nonsense"):
        with pytest.raises(ValueError):
            create_app(queue=FakeQueue(), api_key=KEY,
                       allowed_origins=[bad])


def test_job_submit_get_flow(client):
    c, queue = client
    r = _post(c, b'{"url": "http://127.0.0.1:8080/a", "css": {"t": "h1::text"}}')
    assert r.status_code == 202, r.text
    job_id = r.json()["id"]
    assert r.json()["status"] == "queued"
    url, css, max_chars = queue.enqueued[0]
    assert url == "http://127.0.0.1:8080/a"
    assert css == {"t": "h1::text"} and max_chars == 20000
    got = c.get("/jobs/" + job_id, headers={"x-reap-key": KEY})
    assert got.json()["status"] == "queued"
    queue.jobs[job_id]["status"] = "succeeded"
    queue.jobs[job_id]["result"] = {"status": 200}
    got = c.get("/jobs/" + job_id, headers={"x-reap-key": KEY})
    assert got.json()["result"] == {"status": 200}
    queue.jobs[job_id]["status"] = "failed"
    queue.jobs[job_id]["error"] = {"reason": "blocked"}
    got = c.get("/jobs/" + job_id, headers={"x-reap-key": KEY})
    assert got.json()["error"]["reason"] == "blocked"
    assert "result" not in got.json()


def test_unknown_fields_and_bad_bodies_rejected(client):
    c, _ = client
    assert _post(c, b'{"url": "http://127.0.0.1:8080/", "hack": 1}'
                 ).status_code == 422
    assert _post(c, b'not json').status_code == 422
    assert _post(c, b'[1,2]').status_code == 422
    assert _post(c, b'{}').status_code == 422


def test_url_validation_credentials_scheme_and_allowlist(client):
    c, queue = client
    assert _post(c, b'{"url": "http://u:p@127.0.0.1:8080/a"}'
                 ).status_code == 422
    assert _post(c, b'{"url": "http://127.0.0.1:8080/a#frag"}'
                 ).status_code == 202
    assert queue.enqueued[0][0] == "http://127.0.0.1:8080/a"
    for body in (b'{"url": "file:///etc/passwd"}',
                 b'{"url": "ftp://127.0.0.1:8080/x"}',
                 b'{"url": "http://127.0.0.1:9999/x"}',
                 b'{"url": "https://127.0.0.1:8080/x"}',
                 b'{"url": "http://example.com/"}',
                 b'{"url": "http://127.0.0.1:bad/x"}',
                 b'{"url": "http://127.0.0.1:8080/b\\\\evil"}',
                 b'{"url": "http://127.0.0.1:8080/x\\x01"}'):
        assert _post(c, body).status_code == 422, body


def test_ipv6_canonical_allowlist_match():
    queue = FakeQueue()
    app = create_app(queue=queue, api_key=KEY,
                     allowed_origins=["http://[::1]:8080"])
    c = TestClient(app)
    assert _post(c, b'{"url": "http://[::1]:8080/v6"}').status_code == 202
    assert queue.enqueued[0][0] == "http://[::1]:8080/v6"
    assert _post(c, b'{"url": "http://[::1]:9999/v6"}').status_code == 422


def test_max_chars_and_css_bounds(client):
    c, _ = client
    for bad in (0, -1, 100001, 3.5, "20000", True):
        body = ('{"url": "http://127.0.0.1:8080/", "max_chars": %s}'
                % repr(bad).replace("'", '"').lower()
                if not isinstance(bad, str) else
                '{"url": "http://127.0.0.1:8080/", "max_chars": "%s"}' % bad)
        assert _post(c, body.encode()).status_code == 422, bad
    too_many = {"f%d" % i: "p" for i in range(65)}
    body = json.dumps({"url": "http://127.0.0.1:8080/", "css": too_many})
    assert _post(c, body.encode()).status_code == 422
    body = json.dumps({"url": "http://127.0.0.1:8080/",
                       "css": {"x" * 200: "p"}})
    assert _post(c, body.encode()).status_code == 422


def test_body_size_cap(client):
    c, _ = client
    big = b'{"url": "http://127.0.0.1:8080/", "pad": "' + b"x" * 70000 + b'"}'
    assert _post(c, big).status_code == 413


def test_body_cap_streamed_and_lying_length(client):
    c, _ = client
    chunks = iter([b'{"url": "http://127.0.0.1:8080/", "pad": "',
                   b"x" * 40000, b"x" * 40000, b'"}'])
    r = _post(c, chunks)
    assert r.status_code == 413
    lying = b'{"url": "http://127.0.0.1:8080/", "pad": "' + b"y" * 70000 + b'"}'
    r = _post(c, lying, headers={"content-length": "5"})
    assert r.status_code == 413
    r = _post(c, b'{"url": "x"}', headers={"content-length": "-1"})
    assert r.status_code == 400
    r = _post(c, b'{"url": "x"}', headers={"content-length": "banana"})
    assert r.status_code == 400


def test_queue_full_returns_429(client):
    c, queue = client
    queue.capacity = 1
    assert _post(c, b'{"url": "http://127.0.0.1:8080/a"}').status_code == 202
    r = _post(c, b'{"url": "http://127.0.0.1:8080/b"}')
    assert r.status_code == 429


def test_missing_job_is_404(client):
    c, _ = client
    assert c.get("/jobs/nope", headers={"x-reap-key": KEY}
                 ).status_code == 404


def test_redis_errors_become_sanitized_503():
    class DeadQueue:
        def enqueue(self, *a):
            raise ConnectionError("redis://:sekret@internal:6379")

        def get(self, job_id):
            raise ConnectionError("redis://:sekret@internal:6379")

        def health(self):
            raise ConnectionError("redis://:sekret@internal:6379")

    app = create_app(queue=DeadQueue(), api_key=KEY,
                     allowed_origins=["http://127.0.0.1:8080"])
    c = TestClient(app, raise_server_exceptions=False)
    r = _post(c, b'{"url": "http://127.0.0.1:8080/a"}')
    assert r.status_code == 503 and "sekret" not in r.text
    r = c.get("/jobs/x", headers={"x-reap-key": KEY})
    assert r.status_code == 503 and "sekret" not in r.text
    assert c.get("/healthz").status_code == 503


                                                                         

class _Egress(http.server.BaseHTTPRequestHandler):
    hits = {"allowed": [], "forbidden": []}
    which = "allowed"

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).hits[type(self).which].append(self.path)
        if self.path == "/robots.txt":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/go":
            self.send_response(302)
            self.send_header("Location", FORBIDDEN + "/never")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/forbidden":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/limited":
            self.send_response(429)
            self.send_header("Retry-After", "45")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/wall":
            body = (b'<html><form><input name="solution">'
                    b'<script>f.requestSubmit()</script></form></html>')
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


FORBIDDEN = ""


def _serve(which):
    class H(_Egress):
        pass
    H.which = which
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_worker_url_policy_blocks_off_origin_redirect_before_contact():
    global FORBIDDEN
    _Egress.hits = {"allowed": [], "forbidden": []}
    good = _serve("allowed")
    bad = _serve("forbidden")
    FORBIDDEN = "http://127.0.0.1:%d" % bad.server_address[1]
    allowed = "http://127.0.0.1:%d" % good.server_address[1]

    class ClaimOnce:
        lease_seconds = 60

        def __init__(self):
            self.finished = []
            self.cooled = []
            self._jobs = iter([
                ("j1", "tok1", {"url": allowed + "/go", "css": {},
                                "max_chars": 1000}),
                ("j2", "tok2", {"url": allowed + "/forbidden", "css": {},
                                "max_chars": 1000}),
                ("j3", "tok3", {"url": allowed + "/limited", "css": {},
                                "max_chars": 1000}),
                ("j4", "tok4", {"url": allowed + "/wall", "css": {},
                                "max_chars": 1000}),
            ])

        def claim(self, worker_id):
            return next(self._jobs, None)

        def heartbeat(self, job_id, token):
            return True

        def finish(self, job_id, token, result=None, error=None):
            self.finished.append((job_id, result, error))
            return True

        def reserve_pace(self, origin, spacing):
            return 0

        def remaining_cooldown(self, origin):
            return 0

        def cooldown(self, origin, seconds):
            self.cooled.append((origin, seconds))

    queue = ClaimOnce()
    session = curl_reap.Session(
        retries=0, url_policy=lambda u: origin_of(u) == allowed)
    worker = Worker(queue, [allowed], session=session,
                    worker_id="egress", respect_robots=False)
    try:
        for _ in range(4):
            worker.run_once()
    finally:
        good.shutdown()
        bad.shutdown()
    errors = {job: err for job, result, err in queue.finished}
    assert all(result is None for _, result, _ in queue.finished)
    assert errors["j1"]["reason"] == "disallowed_origin"
    assert _Egress.hits["forbidden"] == []
    assert "/go" in _Egress.hits["allowed"]
    assert errors["j2"]["status"] == 403
    assert errors["j2"]["block_reason"] == "forbidden"
    assert errors["j3"]["status"] == 429
    assert errors["j3"]["block_reason"] == "rate_limited"
    assert queue.cooled and queue.cooled[0][1] == 45.0
    assert errors["j4"]["block_reason"] == "challenge"

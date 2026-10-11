"""Capture curl_cffi's raw TLS ClientHello per impersonate target.

How it works
------------
1. Open a raw TCP listener on 127.0.0.1 (random port).  The listener never
   sends a byte back; it only reads the first flight.
2. Launch curl_cffi in-process with ``impersonate=<target>``,
   ``verify=False`` and a short timeout against ``https://<sni>:<port>/``.
   The hostname is pinned to 127.0.0.1 with ``CURLOPT_RESOLVE`` so the
   ClientHello carries a real ``server_name`` extension (BoringSSL omits SNI
   for IP literals, which would change the extension count, the JA4 ``d``
   marker and padding).  The default SNI is ``tls.peet.ws`` so captures line
   up with live measurements from https://tls.peet.ws/api/all.
3. Read the TLS record(s) carrying the ClientHello, close the socket (which
   makes curl_cffi fail fast instead of waiting out its timeout), parse the
   hello with :mod:`fingerprint_calc`, and compute JA3 / JA4.
4. With ``--runs N`` the capture is repeated and the runs are diffed to
   classify every field as fixed or variable.  ``--templates`` writes one JSON
   template per target into ``tools/hello_templates/``.

Examples::

    python tools/capture_clienthello.py chrome --runs 3
    python tools/capture_clienthello.py chrome firefox safari --runs 3 --templates
    python tools/capture_clienthello.py --all --runs 3 --templates --raw-dir /tmp/raw
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import fingerprint_calc as fc  # noqa: E402

DEFAULT_SNI = "tls.peet.ws"
DEFAULT_TEMPLATE_DIR = os.path.join(HERE, "hello_templates")

# The set the project tracks; aliases first so they map onto their real target.
DEFAULT_TARGETS = [
    "chrome", "chrome150", "chrome146", "chrome142", "chrome136", "chrome131",
    "chrome124", "chrome133a", "edge", "edge101", "firefox", "firefox147",
    "firefox144", "firefox135", "firefox133", "safari", "safari2601",
    "safari260", "safari184", "safari180", "safari170", "safari_ios",
    "chrome_android", "tor145",
]


class CaptureError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Listener
# --------------------------------------------------------------------------

class _Listener:
    """One-shot TCP listener that reads a complete ClientHello and closes."""

    def __init__(self, host: str = "127.0.0.1", read_timeout: float = 5.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(4)
        self.sock.settimeout(read_timeout + 2.0)
        self.host, self.port = self.sock.getsockname()
        self.read_timeout = read_timeout
        self.data = b""
        self.error: Optional[str] = None
        self.peer: Optional[Tuple[str, int]] = None
        self.started = time.monotonic()
        self.first_byte_at: Optional[float] = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    @staticmethod
    def _complete(buf: bytes) -> bool:
        """True once ``buf`` holds whole record(s) covering a full handshake message."""
        off = 0
        hs = b""
        while off + 5 <= len(buf):
            length = struct.unpack_from("!H", buf, off + 3)[0]
            if off + 5 + length > len(buf):
                return False
            if buf[off] == 22:
                hs += buf[off + 5:off + 5 + length]
            off += 5 + length
            if len(hs) >= 4:
                hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
                if len(hs) >= 4 + hs_len:
                    return True
        return False

    def _serve(self) -> None:
        conn = None
        try:
            conn, self.peer = self.sock.accept()
            conn.settimeout(self.read_timeout)
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                if self.first_byte_at is None:
                    self.first_byte_at = time.monotonic()
                buf += chunk
                if self._complete(buf):
                    # Give a straggling second record a moment to land.
                    conn.settimeout(0.15)
                    try:
                        extra = conn.recv(65536)
                        if extra:
                            buf += extra
                    except (socket.timeout, OSError):
                        pass
                    break
            self.data = buf
        except Exception as exc:  # noqa: BLE001
            self.error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
            try:
                self.sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# Client launch
# --------------------------------------------------------------------------

def _launch_curl_cffi(url: str, target: str, resolve: str, timeout: float,
                      extra_fp: Optional[Dict[str, Any]] = None,
                      http_version: Optional[str] = None) -> Dict[str, Any]:
    from curl_cffi import CurlOpt
    from curl_cffi import requests as cr

    kwargs: Dict[str, Any] = {
        "impersonate": target,
        "verify": False,
        "timeout": timeout,
        "allow_redirects": False,
    }
    if extra_fp:
        from curl_cffi.requests.impersonate import ExtraFingerprints
        kwargs["extra_fp"] = ExtraFingerprints(**extra_fp)
    if http_version:
        kwargs["http_version"] = http_version
    info: Dict[str, Any] = {"ok": False, "error": None}
    # RESOLVE is an slist option and curl_options is a Session-level argument.
    session = cr.Session(curl_options={CurlOpt.RESOLVE: [resolve]})
    try:
        resp = session.get(url, **kwargs)
        info["ok"] = True
        info["status"] = resp.status_code
    except Exception as exc:  # noqa: BLE001
        info["error"] = "%s: %s" % (type(exc).__name__, str(exc).split(". See ")[0])
    finally:
        session.close()
    return info


def capture(target: str, timeout: float = 5.0, sni: str = DEFAULT_SNI,
            extra_fp: Optional[Dict[str, Any]] = None,
            http_version: Optional[str] = None) -> Dict[str, Any]:
    """Capture one ClientHello for ``target`` and return the parsed result."""
    listener = _Listener(read_timeout=timeout)
    listener.start()
    url = "https://%s:%d/" % (sni, listener.port)
    resolve = "%s:%d:127.0.0.1" % (sni, listener.port)
    t0 = time.monotonic()
    client = _launch_curl_cffi(url, target, resolve, timeout, extra_fp, http_version)
    listener.thread.join(timeout + 3.0)
    elapsed = time.monotonic() - t0
    if listener.error and not listener.data:
        raise CaptureError("listener failed for %s: %s" % (target, listener.error))
    if not listener.data:
        raise CaptureError("no bytes received for %s (client: %s)" % (target, client.get("error")))
    hello = fc.parse_client_hello(listener.data)
    result = {
        "target": target,
        "sni": sni,
        "captured_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "elapsed_s": round(elapsed, 3),
        "client": client,
        "raw_hex": listener.data.hex(),
        "hello": hello,
        "fingerprints": fc.fingerprints(hello),
    }
    return result


# --------------------------------------------------------------------------
# Diffing several captures of one target
# --------------------------------------------------------------------------

def _norm_id(entry: Dict[str, Any]) -> str:
    return "GREASE" if entry.get("grease") else entry["id"]


def _ext_label(ext: Dict[str, Any]) -> str:
    return "GREASE" if ext["grease"] else ext["type_hex"]


def _ext_params(ext: Dict[str, Any]) -> Dict[str, Any]:
    """Decoded parameters with GREASE normalised and per-connection bytes dropped."""
    d = ext.get("decoded")
    if d is None:
        return {"length": ext["length"]}
    t = ext["type"]
    if t == 0:
        return {"host_names": [n["host_name"] for n in d["server_name_list"]]}
    if t == 5:
        return {k: v for k, v in d.items() if k != "status_type_name"} | {"status_type_name": d.get("status_type_name")}
    if t == 10:
        return {"groups": [_norm_id(g) for g in d["groups"]], "group_names": [g.get("name", "?") for g in d["groups"]]}
    if t == 11:
        return {"formats": [f["id"] for f in d["formats"]]}
    if t in (13, 34, 50):
        return {"algorithms": [_norm_id(a) for a in d["algorithms"]], "algorithm_names": [a.get("name", "?") for a in d["algorithms"]]}
    if t in (16, 17513, 17613):
        return {"protocols": d["protocols"]}
    if t == 21:
        return {"length": d["length"], "all_zero": d["all_zero"]}
    if t == 27:
        return {"algorithms": [a["id"] for a in d["algorithms"]], "algorithm_names": [a.get("name") for a in d["algorithms"]]}
    if t == 28:
        return {"limit": d["limit"]}
    if t == 35:
        return {"ticket_len": d["ticket_len"]}
    if t == 41:
        return {"identities": len(d["identities"]), "binders": len(d["binders"])}
    if t == 43:
        return {"versions": [_norm_id(v) for v in d["versions"]], "version_names": [v.get("name", "?") for v in d["versions"]]}
    if t == 45:
        return {"modes": [m["id"] for m in d["modes"]], "mode_names": [m.get("name") for m in d["modes"]]}
    if t == 51:
        return {"shares": [{"group": _norm_id(s), "name": s.get("name", "?"), "key_length": s["key_length"]} for s in d["shares"]]}
    if t == 0xFE0D:
        # config_id and payload_len are per-connection; the template records
        # the observed payload lengths separately under "ech".
        return {k: v for k, v in d.items() if k not in ("config_id", "payload_len")}
    if t == 0xFF01:
        return {"renegotiated_connection_len": d["renegotiated_connection_len"]}
    return dict(d)


def _grease_values(hello: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"ciphers": [], "extensions": [], "groups": [], "versions": [], "key_share": []}
    out["ciphers"] = [c["id"] for c in hello["cipher_suites"] if c.get("grease")]
    for ext in hello["extensions"]:
        if ext["grease"]:
            out["extensions"].append(ext["type_hex"])
        d = ext.get("decoded") or {}
        if ext["type"] == 10:
            out["groups"] += [g["id"] for g in d.get("groups", []) if g.get("grease")]
        elif ext["type"] == 43:
            out["versions"] += [v["id"] for v in d.get("versions", []) if v.get("grease")]
        elif ext["type"] == 51:
            out["key_share"] += [s["id"] for s in d.get("shares", []) if s.get("grease")]
    return out


def _common_prefix(seqs: List[List[str]]) -> List[str]:
    if not seqs:
        return []
    out = []
    for items in zip(*seqs):
        if all(i == items[0] for i in items):
            out.append(items[0])
        else:
            break
    return out


def _common_suffix(seqs: List[List[str]]) -> List[str]:
    rev = [list(reversed(s)) for s in seqs]
    return list(reversed(_common_prefix(rev)))


def diff_captures(captures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify fields across several captures of the same target."""
    hellos = [c["hello"] for c in captures]
    n = len(hellos)
    fixed: List[str] = []
    variable: List[str] = []

    def classify(name: str, values: List[Any]) -> None:
        (fixed if all(v == values[0] for v in values) else variable).append(name)

    classify("record_version", [h["record_version"] for h in hellos])
    classify("legacy_version", [h["legacy_version"] for h in hellos])
    classify("random", [h["random"] for h in hellos])
    classify("session_id", [h["session_id"] for h in hellos])
    classify("session_id_len", [h["session_id_len"] for h in hellos])
    classify("compression_methods", [h["compression_methods"] for h in hellos])
    classify("handshake_length", [h["handshake_length"] for h in hellos])
    classify("cipher_suites", [[_norm_id(c) for c in h["cipher_suites"]] for h in hellos])
    orders = [[_ext_label(e) for e in h["extensions"]] for h in hellos]
    classify("extension_order", orders)
    classify("extension_set", [sorted(o) for o in orders])
    grease = [_grease_values(h) for h in hellos]
    for key in ("ciphers", "extensions", "groups", "versions", "key_share"):
        if any(g[key] for g in grease):
            classify("grease_values.%s" % key, [g[key] for g in grease])

    # Per-extension-type comparison.
    per_ext: Dict[str, Dict[str, Any]] = {}
    types = []
    for h in hellos:
        for e in h["extensions"]:
            lbl = _ext_label(e)
            if lbl not in types:
                types.append(lbl)
    for lbl in types:
        bodies = []
        params = []
        positions = []
        for h in hellos:
            matches = [(i, e) for i, e in enumerate(h["extensions"]) if _ext_label(e) == lbl]
            bodies.append([e["body_hex"] for _, e in matches])
            params.append([_ext_params(e) for _, e in matches])
            positions.append([i for i, _ in matches])
        body_fixed = all(b == bodies[0] for b in bodies)
        params_fixed = all(p == params[0] for p in params)
        pos_fixed = all(p == positions[0] for p in positions)
        per_ext[lbl] = {
            "body_fixed": body_fixed,
            "params_fixed": params_fixed,
            "position_fixed": pos_fixed,
            "positions": positions,
        }
        if lbl == "GREASE":
            continue
        if not body_fixed and params_fixed:
            variable.append("ext.%s.bytes" % lbl)
        elif not params_fixed:
            variable.append("ext.%s.params" % lbl)

    # Key share: keys always differ, groups and sizes should not.
    ks = [fc._ext_by_type(h, 51) for h in hellos]
    if all(k is not None and "decoded" in k for k in ks):
        groups = [[(_norm_id(s), s["key_length"]) for s in k["decoded"]["shares"]] for k in ks]
        classify("key_share.groups_and_sizes", groups)
        classify("key_share.key_bytes", [k["body_hex"] for k in ks])
    pad = [fc._ext_by_type(h, 21) for h in hellos]
    if all(p is not None for p in pad):
        classify("padding.length", [p["length"] for p in pad])
    ech = [fc._ext_by_type(h, 0xFE0D) for h in hellos]
    if all(e is not None and "decoded" in e for e in ech):
        classify("ech.config_id", [e["decoded"].get("config_id") for e in ech])
        classify("ech.enc_len", [e["decoded"].get("enc_len") for e in ech])
        classify("ech.payload_len", [e["decoded"].get("payload_len") for e in ech])
        classify("ech.bytes", [e["body_hex"] for e in ech])

    fps = [c["fingerprints"] for c in captures]
    for key in ("ja3_hash", "ja4", "ja4_r", "ja4_o"):
        classify("fingerprint.%s" % key, [f[key] for f in fps])

    return {
        "runs": n,
        "fixed": fixed,
        "variable": variable,
        "extension_orders": orders,
        "extension_order_fixed": all(o == orders[0] for o in orders),
        "fixed_prefix": _common_prefix(orders),
        "fixed_suffix": _common_suffix(orders),
        "per_extension": per_ext,
    }


# --------------------------------------------------------------------------
# Template construction
# --------------------------------------------------------------------------

def _resolve_alias(target: str) -> Optional[str]:
    try:
        from curl_cffi.requests.impersonate import REAL_TARGET_MAP
    except Exception:  # noqa: BLE001
        return None
    real = REAL_TARGET_MAP.get(target)
    return real if real and real != target else None


def build_template(target: str, captures: List[Dict[str, Any]], diff: Dict[str, Any]) -> Dict[str, Any]:
    import curl_cffi

    rep = captures[0]
    hello = rep["hello"]
    ciphers = [_norm_id(c) for c in hello["cipher_suites"]]
    extensions = []
    for ext in hello["extensions"]:
        lbl = _ext_label(ext)
        info = diff["per_extension"].get(lbl, {})
        if diff["extension_order_fixed"]:
            position = "fixed"
        elif info.get("position_fixed"):
            position = "fixed"
        else:
            position = "permuted"
        entry: Dict[str, Any] = {
            "type": lbl,
            "name": ext["name"],
            "length": ext["length"],
            "position": position,
            "body_fixed": bool(info.get("body_fixed")),
            "params": _ext_params(ext),
        }
        if lbl != "GREASE" and ext["type"] not in (51, 0xFE0D, 21, 0) and info.get("body_fixed"):
            entry["body_hex"] = ext["body_hex"]
        extensions.append(entry)

    def ext_param(etype: int, key: str, default: Any = None) -> Any:
        e = fc._ext_by_type(hello, etype)
        if e is None:
            return default
        return _ext_params(e).get(key, default)

    hs_lens = [c["hello"]["handshake_length"] for c in captures]
    tot = [c["hello"]["total_bytes"] for c in captures]
    fps = [c["fingerprints"] for c in captures]
    ja3_hashes = sorted({f["ja3_hash"] for f in fps})
    template = {
        "target": target,
        "alias_of": _resolve_alias(target),
        "source": "curl_cffi %s" % curl_cffi.__version__,
        "captured_at": rep["captured_at"],
        "runs": len(captures),
        "sni": rep["sni"],
        "record_version": hello["record_version"],
        "legacy_version": hello["legacy_version"],
        "session_id_len": hello["session_id_len"],
        "compression_methods": hello["compression_methods"],
        "handshake_length": {"min": min(hs_lens), "max": max(hs_lens), "fixed": min(hs_lens) == max(hs_lens)},
        "total_bytes": {"min": min(tot), "max": max(tot), "fixed": min(tot) == max(tot)},
        "cipher_suites": ciphers,
        "cipher_names": [c.get("name", "?") for c in hello["cipher_suites"]],
        "cipher_count": sum(1 for c in ciphers if c != "GREASE"),
        "extension_count": sum(1 for e in hello["extensions"] if not e["grease"]),
        "extension_count_with_grease": len(hello["extensions"]),
        "extension_order_fixed": diff["extension_order_fixed"],
        "extension_fixed_prefix": diff["fixed_prefix"],
        "extension_fixed_suffix": diff["fixed_suffix"],
        "extension_orders_seen": diff["extension_orders"],
        "extensions": extensions,
        "supported_groups": ext_param(10, "groups", []),
        "supported_group_names": ext_param(10, "group_names", []),
        "signature_algorithms": ext_param(13, "algorithms", []),
        "signature_algorithm_names": ext_param(13, "algorithm_names", []),
        "key_share": ext_param(51, "shares", []),
        "alpn": ext_param(16, "protocols", []),
        "alps": ext_param(17613, "protocols", None) if fc._ext_by_type(hello, 17613) else ext_param(17513, "protocols", None),
        "alps_codepoint": "44cd" if fc._ext_by_type(hello, 17613) else ("4469" if fc._ext_by_type(hello, 17513) else None),
        "supported_versions": ext_param(43, "versions", []),
        "psk_key_exchange_modes": ext_param(45, "modes", []),
        "compress_certificate": ext_param(27, "algorithm_names", []),
        "ec_point_formats": ext_param(11, "formats", []),
        "record_size_limit": ext_param(28, "limit", None),
        "delegated_credentials": ext_param(34, "algorithms", None),
        "padding_length": None,
        "ech": None,
        "variable_fields": diff["variable"],
        "fixed_fields": diff["fixed"],
        "fingerprints": {
            "ja3": fps[0]["ja3"],
            "ja3_hash": fps[0]["ja3_hash"],
            "ja3_hashes_seen": ja3_hashes,
            "ja3_stable": len(ja3_hashes) == 1,
            "ja4": fps[0]["ja4"],
            "ja4_r": fps[0]["ja4_r"],
            "ja4_o": fps[0]["ja4_o"],
            "ja4_ro": fps[0]["ja4_ro"],
            "ja4_o_values_seen": sorted({f["ja4_o"] for f in fps}),
        },
        "captures": [
            {
                "captured_at": c["captured_at"],
                "handshake_length": c["hello"]["handshake_length"],
                "ja3_hash": c["fingerprints"]["ja3_hash"],
                "ja4": c["fingerprints"]["ja4"],
                "ja4_o": c["fingerprints"]["ja4_o"],
                "extension_order": [_ext_label(e) for e in c["hello"]["extensions"]],
                "grease_values": _grease_values(c["hello"]),
                "random": c["hello"]["random"],
                "session_id": c["hello"]["session_id"],
            }
            for c in captures
        ],
    }
    pad = fc._ext_by_type(hello, 21)
    if pad is not None:
        lens = [fc._ext_by_type(c["hello"], 21)["length"] for c in captures]
        template["padding_length"] = {"min": min(lens), "max": max(lens), "fixed": min(lens) == max(lens)}
    ech = fc._ext_by_type(hello, 0xFE0D)
    if ech is not None and "decoded" in ech:
        ech_runs = [fc._ext_by_type(c["hello"], 0xFE0D)["decoded"] for c in captures]
        template["ech"] = {
            "type": ech["decoded"].get("type_name"),
            "kdf": ech["decoded"].get("kdf_name"),
            "kdf_id": ech["decoded"].get("kdf_id"),
            "aead": ech["decoded"].get("aead_name"),
            "aead_id": ech["decoded"].get("aead_id"),
            "enc_len": ech["decoded"].get("enc_len"),
            "payload_len_seen": sorted({r.get("payload_len") for r in ech_runs}),
            "config_id_seen": sorted({r.get("config_id") for r in ech_runs}),
            "total_len": ech["length"],
        }
    return template


# --------------------------------------------------------------------------
# Live cross-check against https://tls.peet.ws/api/all
# --------------------------------------------------------------------------

def fetch_peet(target: str, timeout: float = 25.0, attempts: int = 3) -> Dict[str, Any]:
    """Fetch tls.peet.ws/api/all with curl_cffi impersonating ``target``."""
    from curl_cffi import requests as cr
    last: Optional[Exception] = None
    for _ in range(attempts):
        try:
            return cr.get("https://tls.peet.ws/api/all", impersonate=target, timeout=timeout).json()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(2)
    raise CaptureError("peet.ws fetch failed for %s: %s" % (target, last))


def live_summary(peet: Dict[str, Any]) -> Dict[str, Any]:
    tls = peet["tls"]
    return {
        "ja3_hash": tls.get("ja3_hash"),
        "ja3": tls.get("ja3"),
        "ja4": tls.get("ja4"),
        "ja4_r": tls.get("ja4_r"),
        "peetprint_hash": tls.get("peetprint_hash"),
        "akamai": (peet.get("http2") or {}).get("akamai_fingerprint"),
        "http_version": peet.get("http_version"),
        "ext_order": [e["name"].split(" ")[0] for e in tls.get("extensions", [])],
    }


def annotate_live(template: Dict[str, Any], live: Dict[str, Any]) -> None:
    """Attach a peet.ws measurement and match flags to a template in place."""
    fp = template["fingerprints"]
    template["peet_live"] = dict(live)
    template["peet_live"]["ja4_match"] = live.get("ja4") == fp["ja4"]
    template["peet_live"]["ja4_r_match"] = live.get("ja4_r") == fp["ja4_r"]
    # With permuted extensions JA3 is one sample from a distribution, so the
    # match is only meaningful when the order is fixed.
    if template["extension_order_fixed"]:
        template["peet_live"]["ja3_match"] = live.get("ja3_hash") == fp["ja3_hash"]
    else:
        template["peet_live"]["ja3_match"] = None
        template["peet_live"]["ja3_note"] = "extension order is permuted per connection; JA3 is a sample"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load_raw(raw_dir: str, target: str) -> List[Dict[str, Any]]:
    """Reload per-run capture JSON written by ``--raw-dir``."""
    caps = []
    i = 1
    while True:
        path = os.path.join(raw_dir, "%s.%d.json" % (target, i))
        if not os.path.exists(path):
            break
        with open(path) as fh:
            cap = json.load(fh)
        # Re-parse so parser improvements apply to old captures.
        cap["hello"] = fc.parse_client_hello(bytes.fromhex(cap["raw_hex"]))
        cap["fingerprints"] = fc.fingerprints(cap["hello"])
        caps.append(cap)
        i += 1
    if not caps:
        raise CaptureError("no raw captures for %s in %s" % (target, raw_dir))
    return caps


def _run_target(target: str, runs: int, timeout: float, sni: str, raw_dir: Optional[str],
                from_raw: Optional[str] = None) -> Dict[str, Any]:
    if from_raw:
        caps = _load_raw(from_raw, target)
        return {"target": target, "captures": caps, "diff": diff_captures(caps)}
    caps = []
    for i in range(runs):
        cap = capture(target, timeout=timeout, sni=sni)
        caps.append(cap)
        if raw_dir:
            os.makedirs(raw_dir, exist_ok=True)
            with open(os.path.join(raw_dir, "%s.%d.hex" % (target, i + 1)), "w") as fh:
                fh.write(cap["raw_hex"] + "\n")
            with open(os.path.join(raw_dir, "%s.%d.json" % (target, i + 1)), "w") as fh:
                json.dump(cap, fh, indent=1)
    diff = diff_captures(caps)
    return {"target": target, "captures": caps, "diff": diff}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="curl_cffi impersonate targets (default: the project's tracked set)")
    ap.add_argument("--all", action="store_true", help="capture the full tracked target set")
    ap.add_argument("--runs", type=int, default=1, help="captures per target (default 1)")
    ap.add_argument("--timeout", type=float, default=5.0, help="client timeout in seconds (default 5)")
    ap.add_argument("--sni", default=DEFAULT_SNI, help="hostname to put in server_name (pinned to 127.0.0.1)")
    ap.add_argument("--workers", type=int, default=1, help="parallel targets (default 1)")
    ap.add_argument("--templates", action="store_true", help="write hello_templates/<target>.json")
    ap.add_argument("--template-dir", default=DEFAULT_TEMPLATE_DIR)
    ap.add_argument("--raw-dir", default=None, help="directory for raw per-run captures (hex + json)")
    ap.add_argument("--from-raw", default=None, help="rebuild templates from a --raw-dir instead of capturing")
    ap.add_argument("--verify-live", action="store_true", help="fetch tls.peet.ws per target and record the match in the template")
    ap.add_argument("--live-data", default=None, help="JSON file {target: live_summary} to annotate from instead of fetching")
    ap.add_argument("--json", action="store_true", help="print the full result JSON instead of a summary")
    args = ap.parse_args(argv)

    targets = list(args.targets)
    if args.all or not targets:
        targets = list(DEFAULT_TARGETS)

    results: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, str] = {}

    def work(t: str) -> None:
        try:
            results[t] = _run_target(t, args.runs, args.timeout, args.sni, args.raw_dir, args.from_raw)
        except Exception as exc:  # noqa: BLE001
            errors[t] = "%s: %s" % (type(exc).__name__, exc)

    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(work, targets))
    else:
        for t in targets:
            work(t)

    live_data: Dict[str, Any] = {}
    if args.live_data:
        with open(args.live_data) as fh:
            live_data = json.load(fh)

    summary = {}
    for t in targets:
        if t in errors:
            summary[t] = {"error": errors[t]}
            continue
        r = results[t]
        diff = r["diff"]
        tpl = build_template(t, r["captures"], diff)
        if args.live_data and t in live_data:
            annotate_live(tpl, live_data[t])
        elif args.verify_live:
            try:
                annotate_live(tpl, live_summary(fetch_peet(t)))
            except CaptureError as exc:
                tpl["peet_live"] = {"error": str(exc)}
        if args.templates:
            os.makedirs(args.template_dir, exist_ok=True)
            with open(os.path.join(args.template_dir, "%s.json" % t), "w") as fh:
                json.dump(tpl, fh, indent=2)
                fh.write("\n")
        summary[t] = {
            "ja3_hash": tpl["fingerprints"]["ja3_hash"],
            "ja3_stable": tpl["fingerprints"]["ja3_stable"],
            "ja4": tpl["fingerprints"]["ja4"],
            "ja4_r": tpl["fingerprints"]["ja4_r"],
            "cipher_count": tpl["cipher_count"],
            "ext_count": tpl["extension_count"],
            "hello_len": tpl["handshake_length"],
            "record_version": tpl["record_version"],
            "extension_order_fixed": tpl["extension_order_fixed"],
            "variable_fields": tpl["variable_fields"],
            "key_share_groups": [s["name"] for s in tpl["key_share"]],
            "peet_live": {k: tpl["peet_live"].get(k) for k in ("ja4_match", "ja4_r_match", "ja3_match")} if "peet_live" in tpl else None,
        }

    if args.json:
        print(json.dumps({"summary": summary, "results": {t: {"captures": r["captures"], "diff": r["diff"]} for t, r in results.items()}}, indent=1))
    else:
        for t, s in summary.items():
            if "error" in s:
                print("%-16s ERROR %s" % (t, s["error"]))
                continue
            print("%-16s ja3=%s%s ja4=%s ciphers=%d exts=%d len=%s order=%s" % (
                t, s["ja3_hash"], "" if s["ja3_stable"] else "*", s["ja4"], s["cipher_count"],
                s["ext_count"], s["hello_len"]["min"] if s["hello_len"]["fixed"] else "%d..%d" % (s["hello_len"]["min"], s["hello_len"]["max"]),
                "fixed" if s["extension_order_fixed"] else "permuted"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

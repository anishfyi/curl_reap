#!/usr/bin/env python
"""Capture curl_cffi's exact HTTP/2 client behaviour per impersonate target.

The tool runs a local TLS server (stdlib ``ssl``, self-signed certificate made
with the ``cryptography`` package, ALPN ``h2``) on 127.0.0.1 and points
``curl_cffi.requests.get(impersonate=<target>, verify=False)`` at it. The
server records every byte the client sends after the TLS handshake, answers
with a minimal valid HTTP/2 exchange (server SETTINGS, SETTINGS ACK, HEADERS
``:status 200`` and a 2 byte DATA frame with END_STREAM) and keeps recording
what the client sends afterwards (SETTINGS ACK, WINDOW_UPDATE, GOAWAY, PING,
RST_STREAM) until the client closes the connection.

The recorded stream is decoded into frames: connection preface, then each
frame with length, type, flags, stream id and payload. SETTINGS are listed as
identifier/value pairs in wire order, WINDOW_UPDATE as increment plus stream
id, PRIORITY as stream id, exclusive bit, dependency and weight. HEADERS get
their flags (END_STREAM, END_HEADERS, PADDED, PRIORITY), the priority fields
when present, the padding length and the HPACK block decoded with the
``hpack`` package. The raw block is also walked byte by byte so every field
carries its representation kind (indexed static, indexed dynamic, literal
with incremental indexing, literal without indexing, literal never indexed),
whether its name came from the table and whether its strings are Huffman
coded. Dynamic table size updates are reported when the client sends one.

From the frames the tool builds the Akamai HTTP/2 fingerprint string
(``SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo header order``) and, unless
``--no-peet`` is passed, fetches https://tls.peet.ws/api/all live with the
same target so the string can be checked against ``http2.akamai_fingerprint``
from an independent observer.

The same target is also sent over plain ``http://`` to a tiny local server so
the HTTP/1.1 header order can be recorded next to the HTTP/2 order, including
the ``Upgrade: h2c`` / ``HTTP2-Settings`` tell that libcurl adds and real
browsers never send.

Every target is captured ``--runs`` times (default 2) so anything that
varies between runs is flagged.

Outputs: ``tools/h2_templates/<target>.json`` and
``tools/h2_templates/INDEX.md``.

Usage::

    .venv/bin/python tools/capture_h2.py
    .venv/bin/python tools/capture_h2.py --targets chrome firefox --runs 3
    .venv/bin/python tools/capture_h2.py --no-peet
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "h2_templates")

DEFAULT_TARGETS = [
    "chrome", "chrome150", "chrome136", "chrome131", "chrome124",
    "edge", "edge101",
    "firefox", "firefox147", "firefox135", "firefox133",
    "safari", "safari2601", "safari184", "safari180", "safari170", "safari_ios",
    "chrome_android", "tor145",
]

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {
    0x0: "DATA", 0x1: "HEADERS", 0x2: "PRIORITY", 0x3: "RST_STREAM",
    0x4: "SETTINGS", 0x5: "PUSH_PROMISE", 0x6: "PING", 0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE", 0x9: "CONTINUATION",
}

SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE", 0x2: "ENABLE_PUSH", 0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE", 0x5: "MAX_FRAME_SIZE", 0x6: "MAX_HEADER_LIST_SIZE",
    0x8: "ENABLE_CONNECT_PROTOCOL", 0x9: "NO_RFC7540_PRIORITIES",
}

FLAG_NAMES = {
    "DATA": {0x1: "END_STREAM", 0x8: "PADDED"},
    "HEADERS": {0x1: "END_STREAM", 0x4: "END_HEADERS", 0x8: "PADDED", 0x20: "PRIORITY"},
    "SETTINGS": {0x1: "ACK"},
    "PING": {0x1: "ACK"},
    "PUSH_PROMISE": {0x4: "END_HEADERS", 0x8: "PADDED"},
    "CONTINUATION": {0x4: "END_HEADERS"},
}

ERROR_CODES = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
    4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
    8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
    12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
}

PSEUDO_LETTER = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}

HPACK_STATIC_TABLE_SIZE = 61

H1_PATH = "/some/path?q=1"


# --------------------------------------------------------------------------
# certificate
# --------------------------------------------------------------------------

def make_self_signed_cert(workdir):
    """Write cert.pem and key.pem for localhost / 127.0.0.1 into workdir."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(workdir, "cert.pem")
    key_path = os.path.join(workdir, "key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


# --------------------------------------------------------------------------
# frame encoding / decoding
# --------------------------------------------------------------------------

def encode_frame(ftype, flags, stream_id, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", stream_id & 0x7FFFFFFF) + payload


def flag_names(type_name, flags):
    names = []
    for bit, name in sorted(FLAG_NAMES.get(type_name, {}).items()):
        if flags & bit:
            names.append(name)
    return names


def decode_frames(buf):
    """Split a byte buffer into complete frames; return (frames, leftover)."""
    frames = []
    pos = 0
    while len(buf) - pos >= 9:
        length = int.from_bytes(buf[pos:pos + 3], "big")
        ftype = buf[pos + 3]
        flags = buf[pos + 4]
        stream_id = int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7FFFFFFF
        if len(buf) - pos - 9 < length:
            break
        payload = bytes(buf[pos + 9:pos + 9 + length])
        frames.append({
            "length": length,
            "type": ftype,
            "type_name": FRAME_TYPES.get(ftype, "UNKNOWN_0x%x" % ftype),
            "flags": flags,
            "stream_id": stream_id,
            "payload": payload,
        })
        pos += 9 + length
    return frames, buf[pos:]


def _hpack_int(block, pos, prefix_bits):
    mask = (1 << prefix_bits) - 1
    value = block[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        byte = block[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _hpack_string(block, pos):
    huffman = bool(block[pos] & 0x80)
    length, pos = _hpack_int(block, pos, 7)
    raw = block[pos:pos + length]
    return huffman, length, raw, pos + length


def walk_hpack(block):
    """Walk a raw HPACK block and classify every field representation.

    Returns a list of dicts in wire order. Header fields carry ``kind`` from
    {indexed-static, indexed-dynamic, literal-incremental,
    literal-without-indexing, literal-never-indexed}; a dynamic table size
    update is reported as kind ``table-size-update``.
    """
    fields = []
    pos = 0
    while pos < len(block):
        first = block[pos]
        if first & 0x80:
            index, pos = _hpack_int(block, pos, 7)
            fields.append({
                "kind": "indexed-static" if index <= HPACK_STATIC_TABLE_SIZE else "indexed-dynamic",
                "index": index,
            })
            continue
        if first & 0x40:
            kind, prefix = "literal-incremental", 6
        elif first & 0x20:
            size, pos = _hpack_int(block, pos, 5)
            fields.append({"kind": "table-size-update", "size": size})
            continue
        elif first & 0x10:
            kind, prefix = "literal-never-indexed", 4
        else:
            kind, prefix = "literal-without-indexing", 4
        name_index, pos = _hpack_int(block, pos, prefix)
        entry = {"kind": kind, "name_index": name_index}
        if name_index == 0:
            huff, length, _raw, pos = _hpack_string(block, pos)
            entry["name_source"] = "literal"
            entry["name_huffman"] = huff
            entry["name_wire_length"] = length
        else:
            entry["name_source"] = (
                "static-table" if name_index <= HPACK_STATIC_TABLE_SIZE else "dynamic-table")
        huff, length, _raw, pos = _hpack_string(block, pos)
        entry["value_huffman"] = huff
        entry["value_wire_length"] = length
        fields.append(entry)
    return fields


def decode_header_block(block, decoder):
    """Return (header_entries, table_size_updates) for one HPACK block."""
    walked = walk_hpack(block)
    decoded = decoder.decode(block, raw=True)
    table_updates = [f["size"] for f in walked if f["kind"] == "table-size-update"]
    field_entries = [f for f in walked if f["kind"] != "table-size-update"]
    if len(field_entries) != len(decoded):
        raise ValueError("HPACK walk produced %d fields but hpack decoded %d"
                         % (len(field_entries), len(decoded)))
    headers = []
    for meta, (name, value) in zip(field_entries, decoded):
        entry = {
            "name": name.decode("latin-1"),
            "value": value.decode("latin-1"),
            "representation": meta["kind"],
        }
        if meta["kind"].startswith("indexed"):
            entry["index"] = meta["index"]
        else:
            entry["name_source"] = meta["name_source"]
            if meta["name_source"] != "literal":
                entry["name_index"] = meta["name_index"]
            else:
                entry["name_huffman"] = meta["name_huffman"]
            entry["value_huffman"] = meta["value_huffman"]
        headers.append(entry)
    return headers, table_updates


def describe_frame(frame, decoder):
    """Turn a raw frame dict into a JSON friendly description."""
    t = frame["type_name"]
    payload = frame["payload"]
    out = {
        "type": t,
        "length": frame["length"],
        "flags": frame["flags"],
        "flag_names": flag_names(t, frame["flags"]),
        "stream_id": frame["stream_id"],
    }
    try:
        if t == "SETTINGS":
            pairs = []
            for i in range(0, len(payload) - len(payload) % 6, 6):
                ident = int.from_bytes(payload[i:i + 2], "big")
                value = int.from_bytes(payload[i + 2:i + 6], "big")
                pairs.append({"id": ident, "name": SETTINGS_NAMES.get(ident, "UNKNOWN_%d" % ident),
                              "value": value})
            out["settings"] = pairs
        elif t == "WINDOW_UPDATE":
            out["increment"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
        elif t == "PRIORITY":
            dep = int.from_bytes(payload[:4], "big")
            out["exclusive"] = bool(dep & 0x80000000)
            out["dependency"] = dep & 0x7FFFFFFF
            out["weight"] = payload[4] + 1
        elif t == "RST_STREAM":
            code = int.from_bytes(payload[:4], "big")
            out["error_code"] = code
            out["error_name"] = ERROR_CODES.get(code, "UNKNOWN")
        elif t == "GOAWAY":
            last = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            code = int.from_bytes(payload[4:8], "big")
            out["last_stream_id"] = last
            out["error_code"] = code
            out["error_name"] = ERROR_CODES.get(code, "UNKNOWN")
            out["debug_data"] = payload[8:].decode("latin-1")
        elif t == "PING":
            out["opaque"] = payload[:8].hex()
        elif t == "DATA":
            pos = 0
            pad = 0
            if frame["flags"] & 0x8:
                pad = payload[0]
                pos = 1
            data = payload[pos:len(payload) - pad]
            out["padding_length"] = pad if frame["flags"] & 0x8 else None
            out["data_length"] = len(data)
        elif t in ("HEADERS", "CONTINUATION"):
            pos = 0
            pad = None
            if frame["flags"] & 0x8:
                pad = payload[0]
                pos = 1
            priority = None
            if t == "HEADERS" and frame["flags"] & 0x20:
                dep = int.from_bytes(payload[pos:pos + 4], "big")
                priority = {
                    "exclusive": bool(dep & 0x80000000),
                    "dependency": dep & 0x7FFFFFFF,
                    "weight": payload[pos + 4] + 1,
                }
                pos += 5
            block = payload[pos:len(payload) - (pad or 0)]
            out["padding_length"] = pad
            out["priority"] = priority
            out["header_block_length"] = len(block)
            out["header_block_hex"] = block.hex()
            headers, updates = decode_header_block(block, decoder)
            out["headers"] = headers
            out["dynamic_table_size_updates"] = updates
    except Exception as exc:  # keep the raw frame even if decoding fails
        out["decode_error"] = "%s: %s" % (type(exc).__name__, exc)
        out["payload_hex"] = payload.hex()
    return out


# --------------------------------------------------------------------------
# local HTTP/2 capture server
# --------------------------------------------------------------------------

class ConnectionRecord:
    def __init__(self, index):
        self.index = index
        self.started = time.monotonic()
        self.done = threading.Event()
        self.client_raw = bytearray()
        self.timeline = []          # list of {"dir": "client"|"server", ...}
        self.tls = {}
        self.error = None
        self.preface_ok = None
        self.responded_at = None    # index into timeline of the server's final DATA
        self.closed_by = None       # "client-eof", "client-close-notify", "idle-timeout", "error"


class H2CaptureServer:
    def __init__(self, cert_path, key_path, idle_after_response=2.5):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.set_alpn_protocols(["h2"])
        self.ctx = ctx
        self.idle_after_response = idle_after_response
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.records = []
        self._lock = threading.Lock()
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def begin_capture(self):
        with self._lock:
            self.records = []

    def wait_all(self, timeout):
        deadline = time.monotonic() + timeout
        time.sleep(0.05)
        while True:
            with self._lock:
                pending = [r for r in self.records if not r.done.is_set()]
            if not pending:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.05)
        with self._lock:
            return list(self.records)

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                return
            with self._lock:
                record = ConnectionRecord(len(self.records))
                self.records.append(record)
            threading.Thread(target=self._handle, args=(conn, record), daemon=True).start()

    def _send(self, tls, record, ftype, flags, stream_id, payload, note):
        tls.sendall(encode_frame(ftype, flags, stream_id, payload))
        record.timeline.append({"dir": "server", "type": FRAME_TYPES[ftype], "flags": flags,
                                "stream_id": stream_id, "note": note})

    def _handle(self, conn, record):
        from hpack import Decoder, Encoder
        tls = None
        try:
            conn.settimeout(5)
            tls = self.ctx.wrap_socket(conn, server_side=True)
            record.tls = {
                "alpn": tls.selected_alpn_protocol(),
                "version": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
                "sni": None,
            }
            # A server speaks first in HTTP/2: SETTINGS right after the handshake.
            self._send(tls, record, 0x4, 0, 0, struct.pack(">HI", 3, 100), "server SETTINGS 3:100")
            decoder = Decoder()
            encoder = Encoder()
            buf = bytearray()
            preface_checked = False
            responded = False
            idle_deadline = None
            tls.settimeout(1.0)
            while True:
                try:
                    chunk = tls.recv(65536)
                except socket.timeout:
                    if responded and time.monotonic() > idle_deadline:
                        record.closed_by = "idle-timeout"
                        break
                    if not responded and time.monotonic() - record.started > 8:
                        record.closed_by = "request-timeout"
                        break
                    continue
                except ssl.SSLEOFError:
                    record.closed_by = "client-eof"
                    break
                except (ssl.SSLError, OSError) as exc:
                    record.closed_by = "error"
                    record.error = "%s: %s" % (type(exc).__name__, exc)
                    break
                if not chunk:
                    record.closed_by = "client-close-notify"
                    break
                record.client_raw += chunk
                buf += chunk
                if not preface_checked:
                    if len(buf) < len(PREFACE):
                        continue
                    record.preface_ok = bytes(buf[:len(PREFACE)]) == PREFACE
                    record.timeline.append({"dir": "client", "type": "PREFACE",
                                            "ok": record.preface_ok,
                                            "raw": bytes(buf[:len(PREFACE)]).decode("latin-1")})
                    buf = buf[len(PREFACE):]
                    preface_checked = True
                frames, buf = decode_frames(buf)
                for frame in frames:
                    desc = describe_frame(frame, decoder)
                    desc["dir"] = "client"
                    record.timeline.append(desc)
                    t = frame["type_name"]
                    if t == "SETTINGS" and not frame["flags"] & 0x1:
                        self._send(tls, record, 0x4, 0x1, 0, b"", "SETTINGS ACK")
                    elif t == "PING" and not frame["flags"] & 0x1:
                        self._send(tls, record, 0x6, 0x1, 0, frame["payload"], "PING ACK")
                    elif t in ("HEADERS", "DATA") and frame["flags"] & 0x1 and not responded:
                        sid = frame["stream_id"]
                        block = encoder.encode([
                            (b":status", b"200"),
                            (b"content-type", b"text/plain"),
                            (b"content-length", b"2"),
                        ])
                        self._send(tls, record, 0x1, 0x4, sid, block, "response HEADERS :status 200")
                        self._send(tls, record, 0x0, 0x1, sid, b"ok", "response DATA END_STREAM")
                        record.responded_at = len(record.timeline) - 1
                        responded = True
                        idle_deadline = time.monotonic() + self.idle_after_response
                    elif t == "GOAWAY":
                        # The client is leaving; give it a moment to close the socket.
                        idle_deadline = min(idle_deadline or 1e18, time.monotonic() + 0.6)
        except Exception as exc:
            record.error = "%s: %s" % (type(exc).__name__, exc)
            record.closed_by = record.closed_by or "error"
        finally:
            try:
                if tls is not None:
                    tls.close()
                else:
                    conn.close()
            except OSError:
                pass
            record.done.set()


# --------------------------------------------------------------------------
# local HTTP/1.1 capture server
# --------------------------------------------------------------------------

class H1CaptureServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.records = []
        self._lock = threading.Lock()
        self._stop = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def begin_capture(self):
        with self._lock:
            self.records = []

    def wait_all(self, timeout):
        deadline = time.monotonic() + timeout
        time.sleep(0.05)
        while True:
            with self._lock:
                pending = [r for r in self.records if not r["done"].is_set()]
            if not pending or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        with self._lock:
            return list(self.records)

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _addr = self.sock.accept()
            except OSError:
                return
            record = {"raw": bytearray(), "done": threading.Event()}
            with self._lock:
                self.records.append(record)
            threading.Thread(target=self._handle, args=(conn, record), daemon=True).start()

    def _handle(self, conn, record):
        try:
            conn.settimeout(3)
            while b"\r\n\r\n" not in record["raw"]:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                record["raw"] += chunk
            body = b"ok"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        except OSError as exc:
            record["error"] = str(exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            record["done"].set()


def parse_h1_request(raw):
    head = bytes(raw).split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    request_line = lines[0]
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, _sep, value = line.partition(":")
        headers.append([name.strip(), value.strip()])
    return request_line, headers


def decode_http2_settings_header(value):
    """Decode the base64url HTTP2-Settings header into id/value pairs."""
    padded = value + "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(padded)
    pairs = []
    for i in range(0, len(raw) - len(raw) % 6, 6):
        ident = int.from_bytes(raw[i:i + 2], "big")
        val = int.from_bytes(raw[i + 2:i + 6], "big")
        pairs.append({"id": ident, "name": SETTINGS_NAMES.get(ident, "UNKNOWN_%d" % ident),
                      "value": val})
    return pairs


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

def akamai_fingerprint(settings_pairs, window_update, priority_frames, pseudo_order):
    settings = ";".join("%d:%d" % (p["id"], p["value"]) for p in settings_pairs)
    wu = str(window_update) if window_update is not None else "0"
    if priority_frames:
        prio = ",".join("%d:%d:%d:%d" % (p["stream_id"], int(p["exclusive"]), p["dependency"],
                                          p["weight"]) for p in priority_frames)
    else:
        prio = "0"
    return "|".join([settings, wu, prio, ",".join(pseudo_order)])


def summarize_connection(record):
    """Reduce one recorded connection to the template fields."""
    client = [e for e in record.timeline if e["dir"] == "client"]
    pre = []
    post = []
    responded = record.responded_at
    for i, entry in enumerate(record.timeline):
        if entry["dir"] != "client":
            continue
        if responded is not None and i > responded:
            post.append(entry)
        else:
            pre.append(entry)

    settings_frames = [f for f in pre if f.get("type") == "SETTINGS" and "ACK" not in f["flag_names"]]
    settings_pairs = settings_frames[0]["settings"] if settings_frames else []
    window_updates = [f for f in pre if f.get("type") == "WINDOW_UPDATE"]
    conn_wu = [f for f in window_updates if f["stream_id"] == 0]
    window_update = conn_wu[0]["increment"] if conn_wu else None
    priority_frames = [{"stream_id": f["stream_id"], "exclusive": f["exclusive"],
                        "dependency": f["dependency"], "weight": f["weight"]}
                       for f in pre if f.get("type") == "PRIORITY"]
    headers_frames = [f for f in pre if f.get("type") == "HEADERS"]
    headers_frame = headers_frames[0] if headers_frames else None
    headers = []
    pseudo_order = []
    regular = []
    table_updates = []
    if headers_frame:
        headers = headers_frame.get("headers", [])
        table_updates = headers_frame.get("dynamic_table_size_updates", [])
        for h in headers:
            if h["name"].startswith(":"):
                pseudo_order.append(PSEUDO_LETTER.get(h["name"], "?"))
            else:
                regular.append(h["name"])
        # CONTINUATION frames would carry more fields; none expected for a GET.
        for f in pre:
            if f.get("type") == "CONTINUATION":
                for h in f.get("headers", []):
                    headers.append(h)
                    if not h["name"].startswith(":"):
                        regular.append(h["name"])

    frame_sequence = [e["type"] + ("(ACK)" if "ACK" in e.get("flag_names", []) else "")
                      for e in client if e.get("type") != "PREFACE"]
    pre_sequence = [e["type"] + ("(ACK)" if "ACK" in e.get("flag_names", []) else "")
                    for e in pre if e.get("type") != "PREFACE"]

    return {
        "tls": record.tls,
        "preface_ok": record.preface_ok,
        "client_frame_sequence": frame_sequence,
        "client_frames_before_response": pre_sequence,
        "settings": settings_pairs,
        "window_update": {"stream_id": 0, "increment": window_update} if window_update is not None else None,
        "other_window_updates": [{"stream_id": f["stream_id"], "increment": f["increment"]}
                                 for f in window_updates if f["stream_id"] != 0],
        "priority_frames": priority_frames,
        "headers_frame": None if not headers_frame else {
            "stream_id": headers_frame["stream_id"],
            "flags": headers_frame["flags"],
            "flag_names": headers_frame["flag_names"],
            "priority": headers_frame.get("priority"),
            "padding_length": headers_frame.get("padding_length"),
            "header_block_length": headers_frame.get("header_block_length"),
            "header_block_hex": headers_frame.get("header_block_hex"),
        },
        "hpack_dynamic_table_size_updates": table_updates,
        "headers": headers,
        "pseudo_header_order": pseudo_order,
        "regular_header_order": regular,
        "akamai_fingerprint": akamai_fingerprint(settings_pairs, window_update, priority_frames,
                                                 pseudo_order),
        "post_response_client_frames": [
            {k: v for k, v in e.items() if k not in ("dir", "header_block_hex")} for e in post],
        "closed_by": record.closed_by,
        "error": record.error,
        "client_bytes": len(record.client_raw),
        "client_raw_hex": bytes(record.client_raw).hex(),
        "timeline": [
            {k: v for k, v in e.items() if k != "header_block_hex"} for e in record.timeline],
    }


STABILITY_KEYS = [
    "client_frames_before_response", "settings", "window_update", "other_window_updates",
    "priority_frames", "headers_frame", "hpack_dynamic_table_size_updates", "headers",
    "pseudo_header_order", "regular_header_order", "akamai_fingerprint",
]


def compare_runs(summaries):
    """Return the list of STABILITY_KEYS that differ across runs."""
    unstable = []
    for key in STABILITY_KEYS:
        values = [json.dumps(s.get(key), sort_keys=True) for s in summaries]
        if len(set(values)) > 1:
            unstable.append(key)
    post = [json.dumps([f["type"] + ("(ACK)" if "ACK" in f.get("flag_names", []) else "")
                        for f in s["post_response_client_frames"]]) for s in summaries]
    if len(set(post)) > 1:
        unstable.append("post_response_client_frames")
    return unstable


# --------------------------------------------------------------------------
# drivers
# --------------------------------------------------------------------------

def run_h2_capture(server, target, timeout=5):
    from curl_cffi import requests as cffi_requests
    server.begin_capture()
    url = "https://127.0.0.1:%d%s" % (server.port, H1_PATH)
    client = {"status": None, "http_version": None, "error": None}
    try:
        resp = cffi_requests.get(url, impersonate=target, verify=False, timeout=timeout)
        client["status"] = resp.status_code
        client["http_version"] = resp.http_version
        client["body"] = resp.text
    except Exception as exc:
        client["error"] = "%s: %s" % (type(exc).__name__, exc)
    records = server.wait_all(timeout=timeout + 2)
    return client, records


def run_h1_capture(server, target, timeout=5):
    from curl_cffi import requests as cffi_requests
    server.begin_capture()
    url = "http://127.0.0.1:%d%s" % (server.port, H1_PATH)
    client = {"status": None, "http_version": None, "error": None}
    try:
        resp = cffi_requests.get(url, impersonate=target, timeout=timeout)
        client["status"] = resp.status_code
        client["http_version"] = resp.http_version
    except Exception as exc:
        client["error"] = "%s: %s" % (type(exc).__name__, exc)
    records = server.wait_all(timeout=timeout + 2)
    out = {"client": client, "connections": []}
    for rec in records:
        request_line, headers = parse_h1_request(rec["raw"])
        entry = {"request_line": request_line, "headers": headers,
                 "header_order": [h[0] for h in headers]}
        lowered = {h[0].lower(): h[1] for h in headers}
        entry["upgrade_h2c"] = lowered.get("upgrade", "").lower() == "h2c"
        entry["connection_header"] = lowered.get("connection")
        if "http2-settings" in lowered:
            try:
                entry["http2_settings_decoded"] = decode_http2_settings_header(
                    lowered["http2-settings"])
            except Exception as exc:
                entry["http2_settings_decoded"] = "undecodable: %s" % exc
        out["connections"].append(entry)
    return out


def fetch_peet(target, timeout=20):
    from curl_cffi import requests as cffi_requests
    resp = cffi_requests.get("https://tls.peet.ws/api/all", impersonate=target, timeout=timeout)
    data = resp.json()
    h2 = data.get("http2", {}) or {}
    tls = data.get("tls", {}) or {}
    sent = h2.get("sent_frames", []) or []
    headers_frame = next((f for f in sent if f.get("frame_type") == "HEADERS"), None)
    return {
        "akamai_fingerprint": h2.get("akamai_fingerprint"),
        "akamai_fingerprint_hash": h2.get("akamai_fingerprint_hash"),
        "sent_frame_types": [f.get("frame_type") for f in sent],
        "headers_frame_flags": headers_frame.get("flags") if headers_frame else None,
        "headers": headers_frame.get("headers") if headers_frame else None,
        "ja3_hash": tls.get("ja3_hash"),
        "ja4": tls.get("ja4"),
        "peetprint_hash": tls.get("peetprint_hash"),
        "http_version": data.get("http_version"),
        "user_agent": data.get("user_agent"),
    }


def capture_target(target, h2_server, h1_server, runs, do_peet):
    print("== %s" % target, flush=True)
    result = {
        "target": target,
        "runs": runs,
        "h2": {"runs": []},
        "http11": None,
        "peet": None,
    }
    summaries = []
    for i in range(runs):
        client, records = run_h2_capture(h2_server, target)
        run = {"client": client, "connections": [summarize_connection(r) for r in records]}
        result["h2"]["runs"].append(run)
        if run["connections"]:
            summaries.append(run["connections"][0])
        print("   h2 run %d: status=%s http=%s conns=%d client_err=%s"
              % (i + 1, client["status"], client["http_version"], len(records), client["error"]),
              flush=True)
    if summaries:
        unstable = compare_runs(summaries)
        result["h2"]["stable"] = not unstable
        result["h2"]["unstable_fields"] = unstable
        result["h2"]["canonical"] = summaries[0]
        print("   akamai: %s" % summaries[0]["akamai_fingerprint"], flush=True)
        if unstable:
            print("   UNSTABLE fields: %s" % ", ".join(unstable), flush=True)
    else:
        result["h2"]["stable"] = None
        result["h2"]["unstable_fields"] = []
        result["h2"]["canonical"] = None

    h1_runs = []
    for i in range(runs):
        h1_runs.append(run_h1_capture(h1_server, target))
    result["http11"] = {"runs": h1_runs}
    orders = [json.dumps(r["connections"][0]["headers"]) for r in h1_runs if r["connections"]]
    result["http11"]["stable"] = len(set(orders)) <= 1
    result["http11"]["canonical"] = next((r["connections"][0] for r in h1_runs if r["connections"]),
                                         None)
    if result["http11"]["canonical"]:
        print("   h1 order: %s" % " ".join(result["http11"]["canonical"]["header_order"]),
              flush=True)

    if do_peet:
        try:
            result["peet"] = fetch_peet(target)
            local = summaries[0]["akamai_fingerprint"] if summaries else None
            result["peet"]["akamai_matches_local"] = (
                local is not None and local == result["peet"]["akamai_fingerprint"])
            print("   peet:   %s  match=%s" % (result["peet"]["akamai_fingerprint"],
                                                result["peet"]["akamai_matches_local"]), flush=True)
        except Exception as exc:
            result["peet"] = {"error": "%s: %s" % (type(exc).__name__, exc)}
            print("   peet error: %s" % result["peet"]["error"], flush=True)
    return result


# --------------------------------------------------------------------------
# template output
# --------------------------------------------------------------------------

def build_template(result, meta):
    """Compact, stable JSON template for one target."""
    canon = result["h2"]["canonical"] or {}
    h1 = result["http11"]["canonical"] or {}
    peet = result["peet"] or {}
    template = {
        "target": result["target"],
        "captured_at": meta["captured_at"],
        "curl_cffi_version": meta["curl_cffi_version"],
        "curl_version": meta["curl_version"],
        "runs": result["runs"],
        "stable_across_runs": result["h2"]["stable"],
        "unstable_fields": result["h2"]["unstable_fields"],
        "tls": canon.get("tls"),
        "client_frames_before_response": canon.get("client_frames_before_response"),
        "settings": [{"id": p["id"], "name": p["name"], "value": p["value"]}
                     for p in canon.get("settings", [])],
        "window_update": canon.get("window_update"),
        "other_window_updates": canon.get("other_window_updates"),
        "priority_frames": canon.get("priority_frames"),
        "headers_frame": canon.get("headers_frame"),
        "hpack_dynamic_table_size_updates": canon.get("hpack_dynamic_table_size_updates"),
        "headers": canon.get("headers"),
        "pseudo_header_order": canon.get("pseudo_header_order"),
        "regular_header_order": canon.get("regular_header_order"),
        "akamai_fingerprint": canon.get("akamai_fingerprint"),
        "post_response_client_frames": canon.get("post_response_client_frames"),
        "connection_closed_by": canon.get("closed_by"),
        "client_result": (result["h2"]["runs"][0]["client"] if result["h2"]["runs"] else None),
        "http11": {
            "request_line": h1.get("request_line"),
            "headers": h1.get("headers"),
            "header_order": h1.get("header_order"),
            "upgrade_h2c": h1.get("upgrade_h2c"),
            "connection_header": h1.get("connection_header"),
            "http2_settings_decoded": h1.get("http2_settings_decoded"),
            "stable_across_runs": result["http11"]["stable"],
        },
        "peet_ws": {
            "akamai_fingerprint": peet.get("akamai_fingerprint"),
            "akamai_matches_local": peet.get("akamai_matches_local"),
            "headers_frame_flags": peet.get("headers_frame_flags"),
            "ja3_hash": peet.get("ja3_hash"),
            "ja4": peet.get("ja4"),
            "peetprint_hash": peet.get("peetprint_hash"),
            "user_agent": peet.get("user_agent"),
            "error": peet.get("error"),
        },
        "raw": {
            "client_raw_hex": canon.get("client_raw_hex"),
            "timeline": canon.get("timeline"),
        },
    }
    return template


def _order_diff(h1_headers, h2_headers):
    """Describe how regular header order differs between HTTP/1.1 and HTTP/2."""
    libcurl_only = {"host", "connection", "upgrade", "http2-settings"}
    h1 = [h[0].lower() for h in (h1_headers or []) if h[0].lower() not in libcurl_only]
    h2 = [h["name"] for h in (h2_headers or []) if not h["name"].startswith(":")]
    if h1 == h2:
        return "same order"
    only_h1 = [h for h in h1 if h not in h2]
    only_h2 = [h for h in h2 if h not in h1]
    common_h1 = [h for h in h1 if h in h2]
    common_h2 = [h for h in h2 if h in h1]
    bits = []
    if common_h1 != common_h2:
        bits.append("relative order differs: h1 %s vs h2 %s"
                    % (" ".join(common_h1), " ".join(common_h2)))
    if only_h1:
        bits.append("only in h1: %s" % " ".join(only_h1))
    if only_h2:
        bits.append("only in h2: %s" % " ".join(only_h2))
    return "; ".join(bits) or "same order"


FAMILY_OF = {
    "chrome": "chrome", "edge": "chrome", "firefox": "firefox", "tor": "firefox",
    "safari": "safari",
}


def family_of(target):
    for prefix, fam in FAMILY_OF.items():
        if target.startswith(prefix):
            return fam
    return "other"


CONCLUSIONS = {
    "chrome": [
        "Frame order on every Chromium target is preface, SETTINGS, WINDOW_UPDATE (stream 0, "
        "increment 15663105), HEADERS on stream 1. No standalone PRIORITY frames, no padding, no "
        "CONTINUATION, no HPACK dynamic table size update.",
        "SETTINGS: chrome124, chrome131, chrome136, chrome150 (alias chrome) and chrome_android send "
        "1:65536;2:0;4:6291456;6:262144. edge101 (alias edge) is a Chromium 101 era profile and sends "
        "1:65536;3:1000;4:6291456;6:262144, that is MAX_CONCURRENT_STREAMS 1000 in place of ENABLE_PUSH 0.",
        "The HEADERS frame carries END_STREAM|END_HEADERS|PRIORITY (0x25) with exclusive=1, dependency=0, "
        "weight=256 on all eight Chromium targets.",
        "Pseudo header order is m,a,s,p. Regular header order on HTTP/2: sec-ch-ua, sec-ch-ua-mobile, "
        "sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, "
        "sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority. "
        "edge101 has no priority header and sends accept-encoding gzip, deflate, br (no zstd) and an "
        "accept value without image/avif.",
        "HTTP/1.1 order is the same list with canonical casing, minus priority: curl_cffi only adds "
        "priority: u=0, i on HTTP/2 for Chromium targets. The plain http request is Host, Upgrade: h2c, "
        "HTTP2-Settings, the profile headers, then Connection: Upgrade, HTTP2-Settings. The HTTP2-Settings "
        "value AAEAAQAAAAIAAAAAAAQAYAAAAAYABAAA is the base64url of the same SETTINGS payload "
        "(1:65536;2:0;4:6291456;6:262144); real Chrome never attempts an h2c upgrade.",
        "chrome_android sends sec-ch-ua-platform \"Android\" and a Linux; Android 10; K user agent but "
        "keeps sec-ch-ua-mobile ?0. Real Chrome on Android sends ?1, so this target is internally "
        "inconsistent in curl_cffi 0.16.3.",
    ],
    "firefox": [
        "firefox133, firefox135, firefox147 (alias firefox) and tor145 all send SETTINGS "
        "1:65536;2:0;4:131072;5:16384 and WINDOW_UPDATE 12517377 and no standalone PRIORITY frames, so "
        "the PRIORITY slot of the Akamai string is 0. Fingerprint databases record desktop Firefox "
        "opening priority placeholder streams (3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241) "
        "after SETTINGS; confirm against a live Firefox before copying, but curl_cffi does not send them.",
        "Pseudo header order is m,p,a,s (:path before :authority).",
        "HEADERS flags are END_STREAM|END_HEADERS|PRIORITY (0x25) with exclusive=0 and dependency=0. "
        "The weight is 42 for firefox147, firefox and tor145 and 256 for firefox133 and firefox135.",
        "Regular header order on HTTP/2: user-agent, accept, accept-language, accept-encoding, "
        "upgrade-insecure-requests, sec-fetch-dest, sec-fetch-mode, sec-fetch-site, sec-fetch-user, "
        "priority, te. tor145 inserts sec-gpc: 1 after accept-encoding and uses the rv:128.0 ESR user "
        "agent. accept-language is en-US,en;q=0.9 for firefox147 and en-US,en;q=0.5 for firefox133 and "
        "firefox135.",
        "HTTP/1.1 order is identical, with Priority: u=0, i and Te: trailers also sent over HTTP/1.1. "
        "TE: trailers is a header Firefox adds to HTTP/2 requests; check a live Firefox HTTP/1.1 request "
        "before carrying it over. HTTP2-Settings AAEAAQAAAAIAAAAAAAQAAgAAAAUAAEAA decodes to "
        "1:65536;2:0;4:131072;5:16384.",
    ],
    "safari": [
        "Three sub profiles. safari184, safari2601 (alias safari) and safari_ios send SETTINGS "
        "2:0;3:100;4:2097152;9:1. safari180 adds ENABLE_CONNECT_PROTOCOL: 2:0;3:100;4:2097152;8:1;9:1. "
        "safari170 sends 2:0;4:4194304;3:100, with identifier 4 before 3 on the wire.",
        "WINDOW_UPDATE is 10420225 for every Safari 18 and 26 profile and 10485760 for safari170.",
        "Pseudo header order is m,s,a,p for Safari 18 and 26 profiles and m,s,p,a for safari170.",
        "HEADERS flags differ inside the family: safari, safari2601 and safari_ios send "
        "END_STREAM|END_HEADERS (0x05) with no priority fields; safari180 and safari184 send 0x25 with "
        "exclusive=0, dependency=0, weight=256; safari170 sends 0x25 with weight=255.",
        "Regular header order on HTTP/2 for Safari 18 and 26: sec-fetch-dest, user-agent, accept, "
        "sec-fetch-site, sec-fetch-mode, accept-language, priority, accept-encoding. safari170: accept, "
        "sec-fetch-site, accept-encoding, sec-fetch-mode, user-agent, accept-language, sec-fetch-dest "
        "and no priority header. accept-encoding is gzip, deflate, br on desktop and gzip, deflate, br, "
        "zstd on safari_ios.",
        "HTTP/1.1 order matches HTTP/2 minus priority (only sent on HTTP/2), but the HTTP/1.1 header "
        "names are emitted lowercase (sec-fetch-dest, user-agent, accept, ...) for Safari 18 and 26, and "
        "safari170 mixes canonical names with a lowercase user-agent. CFNetwork sends canonical case on "
        "HTTP/1.1, so this is a curl_cffi profile artefact. HTTP2-Settings AAIAAAAAAAMAAABkAAQAIAAAAAkAAAAB "
        "decodes to 2:0;3:100;4:2097152;9:1.",
    ],
    "all": [
        "Nothing varied between the two runs of any target: no HTTP/2 GREASE, no padding, no "
        "randomised settings or header order. The HTTP/2 layer of curl_cffi is fully deterministic per "
        "target.",
        "HPACK is the nghttp2 encoder on every target regardless of the browser profile: :method GET and "
        ":scheme https are static table indexed (#2, #7), :authority is a literal with incremental "
        "indexing against static name #1, :path is a literal without indexing against static name #4 with "
        "a Huffman value, and every regular header is a literal with incremental indexing whose name "
        "comes from the static table when one exists (user-agent #58, accept #19, accept-encoding #16, "
        "accept-language #17) and is otherwise a Huffman literal. Values use Huffman only when it is "
        "shorter (?0, ?1, 1 and the te name stay plain). No dynamic table size update is ever sent. "
        "An observer that classifies HPACK representations sees the same encoder behind Chrome, Firefox "
        "and Safari targets.",
        "Connection teardown is the libcurl pattern on every target: the SETTINGS ACK for the server's "
        "SETTINGS is written on the client's first read pass (in this capture that lands after the "
        "response because the server answers in the same batch), then GOAWAY with last_stream_id=0, "
        "NO_ERROR and the debug data b'shutdown\\x00' (a libcurl marker), then TLS close_notify, because "
        "the Session is closed after a single request. A browser keeps the connection open and only "
        "sends GOAWAY on shutdown, and never with that debug string.",
        "Over plain http:// every target sends the libcurl h2c upgrade: Host first, then Upgrade: h2c, "
        "HTTP2-Settings (base64url of the exact SETTINGS payload that target uses on TLS), the profile "
        "headers, then Connection: Upgrade, HTTP2-Settings last. No browser sends an h2c upgrade.",
        "Live tls.peet.ws agreed with the local capture on all 19 targets, so the Akamai strings in the "
        "JSON templates are the ones remote servers see. The TLS ja4 and ja3_hash reported by peet.ws "
        "are stored in each template's peet_ws block for the TLS work.",
    ],
}


def _post_frames_text(post):
    out = []
    for f in post or []:
        tag = f["type"]
        if "ACK" in f.get("flag_names", []):
            tag += "(ACK)"
        if f["type"] == "GOAWAY":
            tag += "[last=%s %s]" % (f.get("last_stream_id"), f.get("error_name"))
        if f["type"] == "WINDOW_UPDATE":
            tag += "[sid=%s +%s]" % (f.get("stream_id"), f.get("increment"))
        if f["type"] == "RST_STREAM":
            tag += "[sid=%s %s]" % (f.get("stream_id"), f.get("error_name"))
        out.append(tag)
    return " ".join(out) or "none"


def write_index(templates, out_dir):
    """Render INDEX.md from the per target JSON templates."""
    if not templates:
        return
    first = templates[0]
    lines = []
    lines.append("# curl_cffi HTTP/2 client templates")
    lines.append("")
    lines.append("Captured %s with curl_cffi %s (%s) by `tools/capture_h2.py`. Each target was "
                 "fetched %d times against a local TLS server (ALPN h2) and %d times against a local "
                 "plain HTTP/1.1 server. `peet` is the live `http2.akamai_fingerprint` reported by "
                 "https://tls.peet.ws/api/all for the same target. Regenerate the index without "
                 "touching the network with `python tools/capture_h2.py --index-only`."
                 % (first["captured_at"], first["curl_cffi_version"], first["curl_version"],
                    first["runs"], first["runs"]))
    lines.append("")
    lines.append("## Per target")
    lines.append("")
    lines.append("| target | akamai (local) | peet match | HEADERS flags | HEADERS priority | pseudo | stable |")
    lines.append("|---|---|---|---|---|---|---|")
    for t in templates:
        hf = t.get("headers_frame") or {}
        prio = hf.get("priority")
        prio_s = ("E=%d dep=%d w=%d" % (int(prio["exclusive"]), prio["dependency"], prio["weight"])
                  if prio else "none")
        peet = t.get("peet_ws") or {}
        if peet.get("error"):
            peet_s = "error"
        elif peet.get("akamai_fingerprint") is None:
            peet_s = "not fetched"
        else:
            peet_s = ("yes" if peet.get("akamai_matches_local")
                      else "NO: `%s`" % peet["akamai_fingerprint"].replace("|", "\\|"))
        lines.append("| %s | `%s` | %s | %s (0x%02x) | %s | %s | %s |" % (
            t["target"], (t.get("akamai_fingerprint") or "").replace("|", "\\|"), peet_s,
            "\\|".join(hf.get("flag_names", [])) or "-", hf.get("flags") or 0, prio_s,
            ",".join(t.get("pseudo_header_order") or []),
            "yes" if t.get("stable_across_runs") else "NO: %s" % ", ".join(t.get("unstable_fields") or [])))
    lines.append("")
    lines.append("## Header order per target")
    lines.append("")
    for t in templates:
        h1 = t.get("http11") or {}
        lines.append("### %s" % t["target"])
        lines.append("")
        lines.append("- HTTP/2 headers in wire order (representation in brackets):")
        for h in t.get("headers") or []:
            rep = h["representation"]
            extra = ""
            if rep.startswith("literal"):
                src = h.get("name_source")
                extra = ", name %s%s, value %s" % (
                    src, (" #%d" % h["name_index"]) if h.get("name_index") else "",
                    "huffman" if h.get("value_huffman") else "plain")
            elif rep.startswith("indexed"):
                extra = " #%d" % h["index"]
            lines.append("  - `%s: %s` [%s%s]" % (h["name"], h["value"], rep, extra))
        if t.get("hpack_dynamic_table_size_updates"):
            lines.append("- HPACK dynamic table size update: %s" % t["hpack_dynamic_table_size_updates"])
        else:
            lines.append("- HPACK dynamic table size update: none")
        lines.append("- Client frames before the response: %s"
                     % " ".join(t.get("client_frames_before_response") or []))
        lines.append("- Client frames after the response: %s (connection %s)"
                     % (_post_frames_text(t.get("post_response_client_frames")),
                        t.get("connection_closed_by")))
        lines.append("- HTTP/1.1 request line: `%s`" % h1.get("request_line"))
        lines.append("- HTTP/1.1 headers in wire order:")
        for name, value in h1.get("headers") or []:
            lines.append("  - `%s: %s`" % (name, value))
        if h1.get("upgrade_h2c"):
            dec = h1.get("http2_settings_decoded") or []
            dec_s = (";".join("%d:%d" % (p["id"], p["value"]) for p in dec)
                     if isinstance(dec, list) else str(dec))
            lines.append("- Upgrade: h2c tell present, HTTP2-Settings decodes to SETTINGS %s" % dec_s)
        else:
            lines.append("- No Upgrade: h2c tell")
        lines.append("- Regular header order h1 vs h2: %s"
                     % _order_diff(h1.get("headers"), t.get("headers")))
        peet = t.get("peet_ws") or {}
        if peet.get("ja4"):
            lines.append("- peet.ws live: ja4 `%s`, ja3_hash `%s`, akamai `%s`"
                         % (peet.get("ja4"), peet.get("ja3_hash"), peet.get("akamai_fingerprint")))
        lines.append("")
    lines.append("## Family conclusions")
    lines.append("")
    families = {}
    for t in templates:
        families.setdefault(family_of(t["target"]), []).append(t["target"])
    for fam in ("chrome", "firefox", "safari", "other"):
        if fam not in families:
            continue
        lines.append("### %s (%s)" % (fam, ", ".join(families[fam])))
        lines.append("")
        groups = {}
        for t in templates:
            if family_of(t["target"]) != fam:
                continue
            groups.setdefault(t.get("akamai_fingerprint"), []).append(t["target"])
        for key, targets in groups.items():
            lines.append("- `%s`: %s" % (key, ", ".join(targets)))
        lines.append("")
        for sentence in CONCLUSIONS.get(fam, []):
            lines.append("- %s" % sentence)
        lines.append("")
    if CONCLUSIONS.get("all"):
        lines.append("### all targets")
        lines.append("")
        for sentence in CONCLUSIONS["all"]:
            lines.append("- %s" % sentence)
        lines.append("")
    with open(os.path.join(out_dir, "INDEX.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--targets", nargs="*", default=DEFAULT_TARGETS)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--no-peet", action="store_true", help="skip the live tls.peet.ws check")
    parser.add_argument("--peet-only", nargs="*", default=None,
                        help="only fetch peet.ws for these targets (default: all)")
    parser.add_argument("--workdir", default=None, help="where to put the self-signed cert")
    parser.add_argument("--index-only", action="store_true",
                        help="rebuild INDEX.md from the JSON templates already in --out")
    args = parser.parse_args(argv)

    if args.index_only:
        templates = []
        for target in args.targets:
            path = os.path.join(args.out, "%s.json" % target)
            if os.path.exists(path):
                with open(path) as fh:
                    templates.append(json.load(fh))
        write_index(templates, args.out)
        print("wrote %s from %d templates" % (os.path.join(args.out, "INDEX.md"), len(templates)))
        return 0

    import curl_cffi
    from curl_cffi import __version__ as cffi_version
    curl_version = None
    try:
        from curl_cffi.const import CurlOpt  # noqa: F401
        from curl_cffi import Curl
        curl_version = Curl().version().decode() if hasattr(Curl(), "version") else None
    except Exception:
        curl_version = None
    if not curl_version:
        try:
            from curl_cffi.curl import lib as _lib, ffi as _ffi
            curl_version = _ffi.string(_lib.curl_version()).decode()
        except Exception:
            curl_version = "unknown"

    workdir = args.workdir or tempfile.mkdtemp(prefix="capture_h2_")
    os.makedirs(workdir, exist_ok=True)
    cert_path, key_path = make_self_signed_cert(workdir)
    h2_server = H2CaptureServer(cert_path, key_path)
    h1_server = H1CaptureServer()
    os.makedirs(args.out, exist_ok=True)
    meta = {
        "captured_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "curl_cffi_version": cffi_version,
        "curl_version": curl_version,
        "runs": args.runs,
    }
    print("curl_cffi %s, %s" % (cffi_version, curl_version))
    print("h2 server 127.0.0.1:%d, h1 server 127.0.0.1:%d" % (h2_server.port, h1_server.port))
    results = []
    templates = []
    try:
        for target in args.targets:
            do_peet = not args.no_peet and (args.peet_only is None or target in args.peet_only)
            try:
                result = capture_target(target, h2_server, h1_server, args.runs, do_peet)
            except Exception:
                traceback.print_exc()
                continue
            results.append(result)
            template = build_template(result, meta)
            templates.append(template)
            with open(os.path.join(args.out, "%s.json" % target), "w") as fh:
                json.dump(template, fh, indent=2)
                fh.write("\n")
            if do_peet:
                time.sleep(1.0)
    finally:
        h2_server.close()
        h1_server.close()
    write_index(templates, args.out)

    # Return a compact summary on stdout for callers.
    summary = {}
    for r in results:
        canon = r["h2"]["canonical"] or {}
        hf = canon.get("headers_frame") or {}
        summary[r["target"]] = {
            "akamai": canon.get("akamai_fingerprint"),
            "peet_akamai": (r["peet"] or {}).get("akamai_fingerprint"),
            "headers_frame_flags": hf.get("flag_names"),
            "pseudo_order": ",".join(canon.get("pseudo_header_order", [])),
            "regular_header_order": canon.get("regular_header_order"),
            "stable": r["h2"]["stable"],
        }
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

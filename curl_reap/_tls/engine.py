"""Sans-IO TLS 1.3 client state machine.

Usage::

    client = TLSClient("example.com", template("chrome"))
    client.start()                        # queues the ClientHello
    sock.sendall(client.data_to_send())
    events = client.receive(sock.recv(65536))
    ...
    client.send(b"GET / HTTP/1.1\\r\\n...")
    sock.sendall(client.data_to_send())

The engine never touches a socket. Bytes go in through :meth:`receive`
(``b""`` means EOF) which returns the events they produced
(:class:`HandshakeDone`, :class:`ApplicationData`, :class:`NewTicket`,
:class:`Closed`); bytes come out through :meth:`data_to_send`. Protocol
failures raise :class:`TLSError` subclasses after queueing the fatal alert so
a driver can flush it before closing.

Implemented: HelloRetryRequest with message_hash transcript and cookie
echo, CertificateRequest answered with an empty Certificate,
CompressedCertificate (zlib, brotli, zstd), ALPS (client
EncryptedExtensions in the second flight), ECH GREASE with retry configs
ignored, KeyUpdate in both directions, NewSessionTicket and PSK resumption
with binders, close_notify, record_size_limit, coalesced and fragmented
handshake messages, zero-length records, middlebox ChangeCipherSpec and
post-handshake messages interleaved with application data.
"""
from __future__ import annotations

import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from cryptography import x509

from . import certs as certs_mod
from . import wire
from .consts import (
    AD_BAD_CERTIFICATE,
    AD_BAD_RECORD_MAC,
    AD_CLOSE_NOTIFY,
    AD_DECODE_ERROR,
    AD_DECRYPT_ERROR,
    AD_HANDSHAKE_FAILURE,
    AD_ILLEGAL_PARAMETER,
    AD_INTERNAL_ERROR,
    AD_RECORD_OVERFLOW,
    AD_UNEXPECTED_MESSAGE,
    AD_UNSUPPORTED_EXTENSION,
    AD_USER_CANCELED,
    ALERT_LEVEL_FATAL,
    ALERT_LEVEL_WARNING,
    CT_ALERT,
    CT_APPLICATION_DATA,
    CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE,
    DOWNGRADE_TLS11,
    DOWNGRADE_TLS12,
    EXT_ALPN,
    EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_OLD,
    EXT_COOKIE,
    EXT_EARLY_DATA,
    EXT_ECH,
    EXT_KEY_SHARE,
    EXT_PRE_SHARED_KEY,
    EXT_RECORD_SIZE_LIMIT,
    EXT_SUPPORTED_VERSIONS,
    GROUP_NAMES,
    HANDSHAKE_NAMES,
    HRR_RANDOM,
    HT_CERTIFICATE,
    HT_CERTIFICATE_REQUEST,
    HT_CERTIFICATE_VERIFY,
    HT_COMPRESSED_CERTIFICATE,
    HT_ENCRYPTED_EXTENSIONS,
    HT_FINISHED,
    HT_KEY_UPDATE,
    HT_MESSAGE_HASH,
    HT_NEW_SESSION_TICKET,
    HT_SERVER_HELLO,
    MAX_CIPHERTEXT,
    MAX_PLAINTEXT,
    MAX_TICKET_LIFETIME,
    SIGALG_NAMES,
    TLS12,
    TLS13,
    TLS13_SUITES,
)
from .errors import CertificateError, TLS12Negotiated, TLSAlertReceived, TLSError, UnsupportedGroupRequested
from .hello import ClientHelloBuilder
from .keyexchange import KeyShare, can_generate
from .keyschedule import SUITES, CipherSuite, KeySchedule, resumption_psk
from .record import RecordCipher, RecordProtectionError
from .session import Ticket
from .templates import HelloTemplate, template as load_template


# ---------------------------------------------------------------------------
# Events


@dataclass
class HandshakeDone:
    cipher: str
    cipher_id: int
    group: str
    group_id: int
    alpn: Optional[str]
    resumed: bool = False
    hello_retry: bool = False
    hello_retry_cookie: bool = False
    cert_compression: Optional[int] = None
    alps: bool = False
    alps_server_settings: Optional[bytes] = None
    certificate_request: bool = False
    cert_verified: Optional[bool] = None
    peer_chain: List[bytes] = field(default_factory=list)
    certificate_verify_scheme: Optional[int] = None
    ech_retry_configs: bool = False
    client_hello_bytes: int = 0
    version: str = "TLSv1.3"


@dataclass
class ApplicationData:
    data: bytes


@dataclass
class Closed:
    reason: str  # "close_notify" or "eof"

    @property
    def clean(self) -> bool:
        return self.reason == "close_notify"


@dataclass
class NewTicket:
    ticket: Ticket


Event = Union[HandshakeDone, ApplicationData, Closed, NewTicket]


# ---------------------------------------------------------------------------
# States

S_START = "START"
S_WAIT_SH = "WAIT_SH"
S_WAIT_EE = "WAIT_EE"
S_WAIT_CERT_CR = "WAIT_CERT_CR"
S_WAIT_CERT = "WAIT_CERT"
S_WAIT_CV = "WAIT_CV"
S_WAIT_FINISHED = "WAIT_FINISHED"
S_CONNECTED = "CONNECTED"
S_CLOSED = "CLOSED"
S_FAILED = "FAILED"


class TLSClient:
    """Sans-IO TLS 1.3 client. See the module docstring."""

    version = "TLSv1.3"

    def __init__(
        self,
        server_name: str,
        template: Union[HelloTemplate, str],
        *,
        verify=True,
        alpn=("h2", "http/1.1"),
        resumption: Optional[Ticket] = None,
        rng=None,
        trust_store=None,
    ):
        if isinstance(template, str):
            template = load_template(template)
        self.server_name = server_name
        self.template = template
        self.verify = verify
        # Resolve the trust store now so a bad bundle path fails before connecting.
        self._trust_store = trust_store if trust_store is not None else certs_mod.trust_store_for(verify)
        self.alpn = tuple(alpn) if alpn else tuple(template.alpn)
        self.builder = ClientHelloBuilder(template, server_name, alpn=self.alpn, rng=rng)
        self.state = S_START

        self._rx = bytearray()
        self._tx = bytearray()
        self._hs_buf = bytearray()
        self._events: List[Event] = []

        self._read_cipher: Optional[RecordCipher] = None
        self._write_cipher: Optional[RecordCipher] = None
        self._suite: Optional[CipherSuite] = None
        self._schedule: Optional[KeySchedule] = None
        self._transcript = bytearray()
        self._record_version = template.record_version
        self._send_limit = MAX_PLAINTEXT

        self._shares: Dict[int, KeyShare] = {}
        self._hrr_received = False
        self._hrr_cookie: Optional[bytes] = None
        self._hrr_group: Optional[int] = None
        self._ccs_sent = False
        self._alps_negotiated = False
        self._alps_server_settings: Optional[bytes] = None
        self._alps_codepoint: Optional[int] = None
        self._cert_request_context: Optional[bytes] = None
        self._chain: List[x509.Certificate] = []
        self._close_sent = False
        self._close_received = False
        self._eof = False

        self._ticket: Optional[Ticket] = None
        if resumption is not None and template.psk_modes and resumption.cipher in SUITES and not resumption.expired():
            self._ticket = resumption
        self._resumed = False

        self.handshake_complete = False
        self.alpn_selected: Optional[str] = None
        self.cipher = ""
        self.cipher_id = 0
        self.group = ""
        self.group_id = 0
        self.peer_chain: List[bytes] = []
        self.cert_verified: Optional[bool] = None
        self.hello_retry = False
        self.cert_compression: Optional[int] = None
        self.certificate_verify_scheme: Optional[int] = None
        self.certificate_request = False
        self.ech_retry_configs = False
        self.server_record_size_limit: Optional[int] = None
        self.tickets: List[Ticket] = []
        self.key_updates_received = 0
        self.key_updates_sent = 0
        self.client_hello_bytes = 0
        self.timings: Dict[str, float] = {"keygen": 0.0, "exchange": 0.0, "cert_verify": 0.0, "engine": 0.0}
        self.stats: Dict[str, int] = {
            "records_in": 0,
            "handshake_records_in": 0,
            "handshake_messages_in": 0,
            "coalesced_records": 0,
            "fragmented_messages": 0,
            "ccs_records_in": 0,
            "zero_length_app_records": 0,
            "largest_record": 0,
            "largest_handshake_message": 0,
            "app_records_out": 0,
        }

    # ------------------------------------------------------------------ API
    @property
    def resumed(self) -> bool:
        return self._resumed

    @property
    def closed(self) -> bool:
        return self.state in (S_CLOSED, S_FAILED)

    @property
    def close_sent(self) -> bool:
        return self._close_sent

    @property
    def offering_psk(self) -> bool:
        return self._ticket is not None

    def start(self) -> None:
        """Queue the ClientHello."""
        if self.state != S_START:
            raise RuntimeError("TLSClient already started")
        t0 = time.perf_counter()
        for group in self.builder.key_share_groups:
            self._share_for(group)
        self.timings["keygen"] += time.perf_counter() - t0
        hello = self.builder.build(self._shares, psk=self._ticket)
        self.client_hello_bytes = len(hello)
        self._transcript += hello
        self._send_plain(CT_HANDSHAKE, hello, self._record_version)
        self._record_version = TLS12
        self.state = S_WAIT_SH
        self.timings["engine"] += time.perf_counter() - t0

    def data_to_send(self) -> bytes:
        out = bytes(self._tx)
        self._tx.clear()
        return out

    def send(self, app_data: bytes) -> None:
        """Queue application data (fragmented to the negotiated record size)."""
        if self.state != S_CONNECTED:
            raise TLSError("cannot send application data in state %s" % self.state, AD_INTERNAL_ERROR)
        if self._close_sent:
            raise TLSError("connection closed by close_notify", AD_INTERNAL_ERROR)
        limit = self._send_limit
        for i in range(0, len(app_data), limit):
            self._send(CT_APPLICATION_DATA, app_data[i:i + limit])
            self.stats["app_records_out"] += 1

    def close(self) -> None:
        """Queue a close_notify (once); the connection is write-closed after it.

        Sent even after the peer's close_notify arrived (RFC 8446 6.1: each
        party sends its own before closing its write side), but not after a
        fatal error, an EOF or before the ClientHello went out.
        """
        if self._close_sent:
            return
        self._close_sent = True
        if self.state in (S_FAILED, S_START) or self._eof:
            return
        self._send(CT_ALERT, bytes((ALERT_LEVEL_WARNING, AD_CLOSE_NOTIFY)))

    def key_update(self, request_peer: bool = False) -> None:
        """Send a KeyUpdate and switch to the next write keys."""
        if self.state != S_CONNECTED:
            raise TLSError("key update only after the handshake", AD_INTERNAL_ERROR)
        if self._close_sent:
            raise TLSError("connection closed by close_notify", AD_INTERNAL_ERROR)
        self._send(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, bytes((1 if request_peer else 0,))))
        self._write_cipher.update()
        self.key_updates_sent += 1

    def receive(self, data: bytes) -> List[Event]:
        """Feed bytes from the peer (``b""`` = EOF) and return the events produced."""
        if self.state in (S_CLOSED, S_FAILED):
            return self._take_events()
        t0 = time.perf_counter()
        try:
            if not data:
                self._eof = True
                self.state = S_CLOSED
                if not self._close_received:
                    self._events.append(Closed("eof"))
                return self._take_events()
            self._rx += data
            self._process_records()
        except TLSError as exc:
            self._fail(exc.alert)
            raise
        except RecordProtectionError as exc:
            self._fail(AD_BAD_RECORD_MAC)
            raise TLSError(str(exc), AD_BAD_RECORD_MAC) from exc
        except wire.DecodeError as exc:
            self._fail(AD_DECODE_ERROR)
            raise TLSError("decode error: %s" % exc, AD_DECODE_ERROR) from exc
        finally:
            self.timings["engine"] += time.perf_counter() - t0
        return self._take_events()

    def _take_events(self) -> List[Event]:
        events = self._events
        self._events = []
        return events

    # ------------------------------------------------------------ records
    def _fail(self, alert: int) -> None:
        if self.state not in (S_CLOSED, S_FAILED):
            try:
                self._send(CT_ALERT, bytes((ALERT_LEVEL_FATAL, alert)))
            except Exception:
                pass
        self.state = S_FAILED

    def _send_plain(self, content_type: int, data: bytes, version: int = TLS12) -> None:
        for i in range(0, len(data), MAX_PLAINTEXT):
            chunk = data[i:i + MAX_PLAINTEXT]
            self._tx += wire.record_header(content_type, version, len(chunk)) + chunk

    def _send(self, content_type: int, data: bytes) -> None:
        if self._write_cipher is None:
            self._send_plain(content_type, data)
        else:
            limit = self._send_limit
            if content_type == CT_HANDSHAKE and len(data) > limit:
                for i in range(0, len(data), limit):
                    self._tx += self._write_cipher.encrypt(content_type, data[i:i + limit])
            else:
                self._tx += self._write_cipher.encrypt(content_type, data)

    def _send_ccs_once(self) -> None:
        if not self._ccs_sent:
            self._tx += wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x01"
            self._ccs_sent = True

    def _process_records(self) -> None:
        rx = self._rx
        while self.state not in (S_CLOSED, S_FAILED):
            if len(rx) < 5:
                return
            content_type = rx[0]
            length = (rx[3] << 8) | rx[4]
            # legacy_record_version (rx[1:3]) is ignored on receipt, RFC 8446 5.1.
            if content_type not in (CT_CHANGE_CIPHER_SPEC, CT_ALERT, CT_HANDSHAKE, CT_APPLICATION_DATA):
                raise TLSError("unknown record content type %d" % content_type, AD_UNEXPECTED_MESSAGE)
            limit = MAX_CIPHERTEXT if self._read_cipher is not None else MAX_PLAINTEXT
            if length > limit:
                raise TLSError("record length %d exceeds %d" % (length, limit), AD_RECORD_OVERFLOW)
            if len(rx) < 5 + length:
                return
            header = bytes(rx[:5])
            body = bytes(rx[5:5 + length])
            del rx[:5 + length]
            self.stats["records_in"] += 1
            if length > self.stats["largest_record"]:
                self.stats["largest_record"] = length

            if content_type == CT_CHANGE_CIPHER_SPEC:
                # Middlebox compatibility: dropped between ClientHello and the
                # server's Finished, an error anywhere else (RFC 8446 5).
                if body != b"\x01":
                    raise TLSError("malformed change_cipher_spec", AD_UNEXPECTED_MESSAGE)
                if self.state in (S_START, S_CONNECTED):
                    raise TLSError("change_cipher_spec outside the handshake", AD_UNEXPECTED_MESSAGE)
                self.stats["ccs_records_in"] += 1
                continue

            if self._read_cipher is not None:
                if content_type == CT_ALERT and length == 2 and self.state != S_CONNECTED:
                    # Some servers abort with a plaintext alert after keys are up.
                    self._handle_alert(body)
                    continue
                if content_type != CT_APPLICATION_DATA:
                    raise TLSError("expected an encrypted record, got type %d" % content_type, AD_UNEXPECTED_MESSAGE)
                inner_type, content = self._read_cipher.decrypt(header, body)
                if len(content) > MAX_PLAINTEXT:
                    raise TLSError("inner plaintext exceeds 2^14", AD_RECORD_OVERFLOW)
            else:
                inner_type, content = content_type, body

            if self._close_received:
                # RFC 8446 6.1: data after close_notify is ignored.
                continue

            if inner_type == CT_HANDSHAKE:
                if not content:
                    raise TLSError("zero-length handshake fragment", AD_UNEXPECTED_MESSAGE)
                self.stats["handshake_records_in"] += 1
                if self._hs_buf:
                    self.stats["fragmented_messages"] += 1
                self._hs_buf += content
                self._drain_handshake()
            elif inner_type == CT_ALERT:
                self._handle_alert(content)
            elif inner_type == CT_APPLICATION_DATA:
                if self.state != S_CONNECTED:
                    raise TLSError("application data before the handshake completed", AD_UNEXPECTED_MESSAGE)
                if content:
                    self._events.append(ApplicationData(content))
                else:
                    self.stats["zero_length_app_records"] += 1
            else:
                raise TLSError("unexpected inner content type %d" % inner_type, AD_UNEXPECTED_MESSAGE)

    def _handle_alert(self, body: bytes) -> None:
        if len(body) != 2:
            raise TLSError("malformed alert", AD_DECODE_ERROR)
        level, desc = body[0], body[1]
        if desc == AD_CLOSE_NOTIFY:
            self._close_received = True
            self.state = S_CLOSED
            self._events.append(Closed("close_notify"))
            return
        if level == ALERT_LEVEL_WARNING and desc == AD_USER_CANCELED:
            return
        self.state = S_FAILED
        raise TLSAlertReceived(level, desc)

    def _drain_handshake(self) -> None:
        buf = self._hs_buf
        consumed = 0
        while len(buf) >= 4 and self.state not in (S_CLOSED, S_FAILED):
            msg_type = buf[0]
            length = (buf[1] << 16) | (buf[2] << 8) | buf[3]
            if len(buf) < 4 + length:
                return  # fragmented across records; wait for more
            raw = bytes(buf[:4 + length])
            del buf[:4 + length]
            consumed += 1
            self.stats["handshake_messages_in"] += 1
            if length > self.stats["largest_handshake_message"]:
                self.stats["largest_handshake_message"] = length
            if consumed == 2:
                self.stats["coalesced_records"] += 1
            self._handle_handshake(msg_type, raw[4:], raw)

    # ---------------------------------------------------------- handshake
    def _share_for(self, group: int) -> KeyShare:
        share = self._shares.get(group)
        if share is None:
            share = KeyShare.generate(group)
            self._shares[group] = share
        return share

    def _transcript_hash(self) -> bytes:
        return self._suite.hash(bytes(self._transcript))

    def _handle_handshake(self, msg_type: int, body: bytes, raw: bytes) -> None:
        name = HANDSHAKE_NAMES.get(msg_type, str(msg_type))
        st = self.state
        if st == S_WAIT_SH:
            self._expect(msg_type, HT_SERVER_HELLO, name)
            self._on_server_hello(body, raw)
        elif st == S_WAIT_EE:
            self._expect(msg_type, HT_ENCRYPTED_EXTENSIONS, name)
            self._on_encrypted_extensions(body, raw)
        elif st in (S_WAIT_CERT_CR, S_WAIT_CERT):
            if msg_type == HT_CERTIFICATE_REQUEST and st == S_WAIT_CERT_CR:
                self._on_certificate_request(body, raw)
            elif msg_type == HT_CERTIFICATE:
                self._transcript += raw
                self._on_certificate(body)
            elif msg_type == HT_COMPRESSED_CERTIFICATE:
                self._transcript += raw
                self._on_compressed_certificate(body)
            else:
                raise TLSError("unexpected %s while waiting for Certificate" % name, AD_UNEXPECTED_MESSAGE)
        elif st == S_WAIT_CV:
            self._expect(msg_type, HT_CERTIFICATE_VERIFY, name)
            self._on_certificate_verify(body, raw)
        elif st == S_WAIT_FINISHED:
            self._expect(msg_type, HT_FINISHED, name)
            self._on_server_finished(body, raw)
        elif st == S_CONNECTED:
            if msg_type == HT_NEW_SESSION_TICKET:
                self._on_new_session_ticket(body)
            elif msg_type == HT_KEY_UPDATE:
                self._on_key_update(body)
            else:
                raise TLSError("unexpected post-handshake message %s" % name, AD_UNEXPECTED_MESSAGE)
        else:
            raise TLSError("handshake message %s in state %s" % (name, st), AD_UNEXPECTED_MESSAGE)

    @staticmethod
    def _expect(got: int, want: int, name: str) -> None:
        if got != want:
            raise TLSError("unexpected %s, wanted %s" % (name, HANDSHAKE_NAMES[want]), AD_UNEXPECTED_MESSAGE)

    def _parse_server_hello(self, body: bytes):
        r = wire.Reader(body)
        legacy_version = r.u16()
        random = r.take(32)
        session_id = r.vec(1)
        cipher = r.u16()
        compression = r.u8()
        exts: Dict[int, bytes] = {}
        if not r.at_end():
            for ext_type, ext_body in r.extensions():
                if ext_type in exts:
                    raise TLSError("duplicate ServerHello extension", AD_ILLEGAL_PARAMETER)
                exts[ext_type] = ext_body
        r.expect_end("ServerHello")
        return legacy_version, random, session_id, cipher, compression, exts

    def _on_server_hello(self, body: bytes, raw: bytes) -> None:
        legacy_version, random, session_id, cipher, compression, exts = self._parse_server_hello(body)
        sv = exts.get(EXT_SUPPORTED_VERSIONS)
        if sv is None:
            # TLS 1.2 or lower: no supported_versions. The caller reconnects
            # through OpenSSL; nothing beyond this record has been consumed.
            tail = random[-8:]
            if tail == DOWNGRADE_TLS12:
                detail = " (TLS 1.2 downgrade sentinel present)"
            elif tail == DOWNGRADE_TLS11:
                detail = " (TLS 1.1 or lower downgrade sentinel present)"
            else:
                detail = ""
            raise TLS12Negotiated(
                "server negotiated %s, not TLS 1.3%s" % ({TLS12: "TLS 1.2"}.get(legacy_version, "TLS %#06x" % legacy_version), detail),
                legacy_version,
            )
        if len(sv) != 2 or wire.Reader(sv).u16() != TLS13:
            raise TLS12Negotiated("server selected version %s" % sv.hex(), int.from_bytes(sv[:2], "big") if len(sv) >= 2 else legacy_version)
        if legacy_version != TLS12:
            raise TLSError("ServerHello legacy_version %#06x" % legacy_version, AD_ILLEGAL_PARAMETER)
        if compression != 0:
            raise TLSError("ServerHello selects compression", AD_ILLEGAL_PARAMETER)
        if random[-8:] in (DOWNGRADE_TLS12, DOWNGRADE_TLS11):
            raise TLSError("downgrade sentinel in a TLS 1.3 ServerHello", AD_ILLEGAL_PARAMETER)
        if session_id != self.builder.session_id:
            raise TLSError("legacy_session_id_echo mismatch", AD_ILLEGAL_PARAMETER)
        if cipher not in self.builder.offered_ciphers or cipher not in TLS13_SUITES:
            raise TLSError("server chose cipher suite %#06x we did not offer" % cipher, AD_ILLEGAL_PARAMETER)
        if self._suite is not None and cipher != self._suite.id:
            raise TLSError("cipher suite changed after HelloRetryRequest", AD_ILLEGAL_PARAMETER)
        for ext_type in exts:
            if ext_type not in (EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_PRE_SHARED_KEY, EXT_COOKIE):
                raise TLSError("unexpected ServerHello extension %#06x" % ext_type, AD_UNSUPPORTED_EXTENSION)
        suite = SUITES[cipher]

        if random == HRR_RANDOM:
            self._on_hello_retry_request(suite, exts, raw)
            return

        if EXT_COOKIE in exts:
            raise TLSError("cookie in ServerHello", AD_UNSUPPORTED_EXTENSION)
        ks = exts.get(EXT_KEY_SHARE)
        if ks is None:
            raise TLSError("ServerHello without key_share", AD_ILLEGAL_PARAMETER)
        kr = wire.Reader(ks)
        group = kr.u16()
        peer_public = kr.vec(2)
        kr.expect_end("key_share")
        if self._hrr_group is not None and group != self._hrr_group:
            raise TLSError("ServerHello group differs from the HelloRetryRequest group", AD_ILLEGAL_PARAMETER)
        share = self._shares.get(group)
        if share is None or group not in self.builder.offered_groups:
            raise TLSError("server key_share group %s not offered" % GROUP_NAMES.get(group, group), AD_ILLEGAL_PARAMETER)

        psk: Optional[bytes] = None
        if EXT_PRE_SHARED_KEY in exts:
            if self._ticket is None:
                raise TLSError("server selected a PSK we did not offer", AD_ILLEGAL_PARAMETER)
            pr = wire.Reader(exts[EXT_PRE_SHARED_KEY])
            selected = pr.u16()
            pr.expect_end("pre_shared_key")
            if selected != 0:
                raise TLSError("server selected PSK identity %d" % selected, AD_ILLEGAL_PARAMETER)
            if SUITES[self._ticket.cipher].hash_name != suite.hash_name:
                raise TLSError("server resumed with a cipher suite of a different hash", AD_ILLEGAL_PARAMETER)
            psk = self._ticket.psk
            self._resumed = True
            self.peer_chain = list(self._ticket.peer_chain)
            self.cert_verified = None

        t0 = time.perf_counter()
        try:
            shared = share.exchange(peer_public)
        except ValueError as exc:
            raise TLSError("bad server key share: %s" % exc, AD_ILLEGAL_PARAMETER) from exc
        self.timings["exchange"] += time.perf_counter() - t0

        self._suite = suite
        self._transcript += raw
        self._schedule = KeySchedule(suite, psk)
        c_hs, s_hs = self._schedule.set_shared_secret(shared, self._transcript_hash())
        if self._hs_buf:
            raise TLSError("handshake data straddles the key change", AD_UNEXPECTED_MESSAGE)
        self._read_cipher = RecordCipher(suite, s_hs)
        self._write_cipher = RecordCipher(suite, c_hs)
        self.cipher = suite.name
        self.cipher_id = suite.id
        self.group = GROUP_NAMES.get(group, str(group))
        self.group_id = group
        self.hello_retry = self._hrr_received
        self.state = S_WAIT_EE

    def _on_hello_retry_request(self, suite: CipherSuite, exts: Dict[int, bytes], raw: bytes) -> None:
        if self._hrr_received:
            raise TLSError("second HelloRetryRequest", AD_UNEXPECTED_MESSAGE)
        self._hrr_received = True
        self._suite = suite
        cookie = None
        if EXT_COOKIE in exts:
            cr = wire.Reader(exts[EXT_COOKIE])
            cookie = cr.vec(2)
            cr.expect_end("cookie")
            if not cookie:
                raise TLSError("empty cookie", AD_DECODE_ERROR)
        group = None
        if EXT_KEY_SHARE in exts:
            kr = wire.Reader(exts[EXT_KEY_SHARE])
            group = kr.u16()
            kr.expect_end("HelloRetryRequest key_share")
            if group not in self.builder.offered_groups:
                raise TLSError("HelloRetryRequest group %s not offered" % GROUP_NAMES.get(group, group), AD_ILLEGAL_PARAMETER)
            if group in self._shares:
                raise TLSError("HelloRetryRequest for a group we already shared", AD_ILLEGAL_PARAMETER)
        if EXT_PRE_SHARED_KEY in exts:
            raise TLSError("pre_shared_key in HelloRetryRequest", AD_UNSUPPORTED_EXTENSION)
        if group is None and cookie is None:
            raise TLSError("HelloRetryRequest changes nothing", AD_ILLEGAL_PARAMETER)
        self._hrr_cookie = cookie
        self._hrr_group = group
        if group is not None and not can_generate(group):
            raise UnsupportedGroupRequested(group, cookie)

        # Transcript: replace ClientHello1 by message_hash(ClientHello1), RFC 8446 4.4.1.
        ch1_hash = suite.hash(bytes(self._transcript))
        self._transcript = bytearray(wire.handshake(HT_MESSAGE_HASH, ch1_hash))
        self._transcript += raw

        if group is not None:
            t0 = time.perf_counter()
            self._share_for(group)
            self.timings["keygen"] += time.perf_counter() - t0
        # The second flight begins with a dummy CCS (compat mode), then CH2.
        self._send_ccs_once()
        hello2 = self.builder.build(
            self._shares,
            key_share_groups=[group] if group is not None else None,
            cookie=cookie,
            psk=self._ticket,
            transcript_prefix=bytes(self._transcript),
        )
        self._transcript += hello2
        self._send_plain(CT_HANDSHAKE, hello2, TLS12)
        # Stay in WAIT_SH for the real ServerHello.

    def _on_encrypted_extensions(self, body: bytes, raw: bytes) -> None:
        self._transcript += raw
        r = wire.Reader(body)
        seen = set()
        for ext_type, ext_body in r.extensions():
            if ext_type in seen:
                raise TLSError("duplicate EncryptedExtensions extension", AD_ILLEGAL_PARAMETER)
            seen.add(ext_type)
            if ext_type == EXT_ALPN:
                lr = wire.Reader(ext_body).sub(2)
                proto = lr.vec(1).decode("ascii", "replace")
                lr.expect_end("alpn")
                if proto not in self.alpn:
                    raise TLSError("server ALPN %r not offered" % proto, AD_ILLEGAL_PARAMETER)
                self.alpn_selected = proto
            elif ext_type in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_OLD):
                if ext_type != self.builder.alps_codepoint:
                    raise TLSError("ALPS on a codepoint we did not offer", AD_UNSUPPORTED_EXTENSION)
                self._alps_negotiated = True
                self._alps_codepoint = ext_type
                self._alps_server_settings = ext_body
            elif ext_type == EXT_ECH:
                # retry_configs answering a GREASE ECH: must be ignored (RFC 9849 6.2).
                self.ech_retry_configs = True
            elif ext_type == EXT_RECORD_SIZE_LIMIT:
                er = wire.Reader(ext_body)
                limit = er.u16()
                er.expect_end("record_size_limit")
                if limit < 64:
                    raise TLSError("record_size_limit %d too small" % limit, AD_ILLEGAL_PARAMETER)
                self.server_record_size_limit = limit
                # RFC 8449: the limit counts the content type byte.
                self._send_limit = max(1, min(MAX_PLAINTEXT, limit - 1))
            elif ext_type == EXT_EARLY_DATA:
                raise TLSError("server accepted early data we did not offer", AD_UNSUPPORTED_EXTENSION)
            elif ext_type in (EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_PRE_SHARED_KEY, EXT_COOKIE):
                raise TLSError("extension %#06x not allowed in EncryptedExtensions" % ext_type, AD_ILLEGAL_PARAMETER)
            # server_name, supported_groups, status_request and the rest: ignored.
        r.expect_end("EncryptedExtensions")
        if self._alps_negotiated and (self.alpn_selected is None or self.alpn_selected not in self.builder.alps_protocols):
            raise TLSError("ALPS negotiated without a matching ALPN", AD_ILLEGAL_PARAMETER)
        self.state = S_WAIT_FINISHED if self._resumed else S_WAIT_CERT_CR

    def _on_certificate_request(self, body: bytes, raw: bytes) -> None:
        self._transcript += raw
        r = wire.Reader(body)
        self._cert_request_context = r.vec(1)
        for _ in r.extensions():
            pass
        r.expect_end("CertificateRequest")
        self.certificate_request = True
        self.state = S_WAIT_CERT

    def _on_compressed_certificate(self, body: bytes) -> None:
        r = wire.Reader(body)
        algorithm = r.u16()
        uncompressed_length = r.u24()
        compressed = r.vec(3)
        r.expect_end("CompressedCertificate")
        if algorithm not in self.builder.compress_algorithms:
            raise TLSError("certificate compression %d not offered" % algorithm, AD_ILLEGAL_PARAMETER)
        plain = certs_mod.decompress_certificate(algorithm, compressed, uncompressed_length)
        self.cert_compression = algorithm
        self._on_certificate(plain)

    def _on_certificate(self, body: bytes) -> None:
        r = wire.Reader(body)
        context = r.vec(1)
        if context:
            raise TLSError("server Certificate with a non-empty context", AD_ILLEGAL_PARAMETER)
        entries = r.sub(3)
        chain_der: List[bytes] = []
        while not entries.at_end():
            chain_der.append(entries.vec(3))
            for _ in entries.extensions():  # status_request / sct per entry: ignored
                pass
        r.expect_end("Certificate")
        if not chain_der:
            raise TLSError("empty server certificate list", AD_DECODE_ERROR)
        t0 = time.perf_counter()
        self._chain = certs_mod.parse_chain(chain_der)
        self.peer_chain = chain_der
        if self._trust_store is not None:
            try:
                certs_mod.verify_chain(self._trust_store, self.server_name, self._chain)
            except CertificateError:
                self.cert_verified = False
                self.timings["cert_verify"] += time.perf_counter() - t0
                raise
            self.cert_verified = True
        else:
            self.cert_verified = None
        self.timings["cert_verify"] += time.perf_counter() - t0
        self.state = S_WAIT_CV

    def _on_certificate_verify(self, body: bytes, raw: bytes) -> None:
        r = wire.Reader(body)
        scheme = r.u16()
        signature = r.vec(2)
        r.expect_end("CertificateVerify")
        if scheme not in self.builder.offered_sigalgs:
            raise TLSError("CertificateVerify scheme %s not offered" % SIGALG_NAMES.get(scheme, hex(scheme)), AD_ILLEGAL_PARAMETER)
        th = self._transcript_hash()  # through Certificate
        t0 = time.perf_counter()
        try:
            certs_mod.verify_certificate_verify(self._chain[0], scheme, signature, th)
        except CertificateError as exc:
            exc.alert = AD_DECRYPT_ERROR
            raise
        finally:
            self.timings["cert_verify"] += time.perf_counter() - t0
        self.certificate_verify_scheme = scheme
        self._transcript += raw
        self.state = S_WAIT_FINISHED

    def _on_server_finished(self, body: bytes, raw: bytes) -> None:
        expected = self._schedule.finished_verify_data(self._schedule.server_handshake_secret, self._transcript_hash())
        if not hmac.compare_digest(expected, body):
            raise TLSError("server Finished verify_data mismatch", AD_DECRYPT_ERROR)
        self._transcript += raw
        c_ap, s_ap = self._schedule.application_secrets(self._transcript_hash())
        if self._hs_buf:
            raise TLSError("handshake data straddles the key change", AD_UNEXPECTED_MESSAGE)
        # Server application keys are live from the very next record.
        self._read_cipher = RecordCipher(self._suite, s_ap)

        # Client second flight: [CCS] [EncryptedExtensions for ALPS] [Certificate] Finished.
        self._send_ccs_once()
        if self._alps_negotiated:
            ee = wire.handshake(
                HT_ENCRYPTED_EXTENSIONS,
                wire.vec16(wire.extension(self._alps_codepoint, b"")),  # Chrome sends empty h2 settings
            )
            self._transcript += ee
            self._send(CT_HANDSHAKE, ee)
        if self._cert_request_context is not None:
            cert = wire.handshake(HT_CERTIFICATE, wire.vec8(self._cert_request_context) + wire.vec24(b""))
            self._transcript += cert
            self._send(CT_HANDSHAKE, cert)
        verify_data = self._schedule.finished_verify_data(self._schedule.client_handshake_secret, self._transcript_hash())
        fin = wire.handshake(HT_FINISHED, verify_data)
        self._transcript += fin
        self._send(CT_HANDSHAKE, fin)
        self._write_cipher = RecordCipher(self._suite, c_ap)
        self._schedule.resumption_secret(self._transcript_hash())
        self.state = S_CONNECTED
        self.handshake_complete = True
        self._events.append(HandshakeDone(
            cipher=self.cipher,
            cipher_id=self.cipher_id,
            group=self.group,
            group_id=self.group_id,
            alpn=self.alpn_selected,
            resumed=self._resumed,
            hello_retry=self._hrr_received,
            hello_retry_cookie=self._hrr_cookie is not None,
            cert_compression=self.cert_compression,
            alps=self._alps_negotiated,
            alps_server_settings=self._alps_server_settings,
            certificate_request=self.certificate_request,
            cert_verified=self.cert_verified,
            peer_chain=list(self.peer_chain),
            certificate_verify_scheme=self.certificate_verify_scheme,
            ech_retry_configs=self.ech_retry_configs,
            client_hello_bytes=self.client_hello_bytes,
        ))

    def _on_new_session_ticket(self, body: bytes) -> None:
        r = wire.Reader(body)
        lifetime = r.u32()
        age_add = r.u32()
        nonce = r.vec(1)
        ticket = r.vec(2)
        max_early_data = 0
        for ext_type, ext_body in r.extensions():
            if ext_type == EXT_EARLY_DATA:
                er = wire.Reader(ext_body)
                max_early_data = er.u32()
                er.expect_end("early_data")
        r.expect_end("NewSessionTicket")
        if not ticket:
            raise TLSError("empty session ticket", AD_DECODE_ERROR)
        if lifetime > MAX_TICKET_LIFETIME:
            raise TLSError("ticket lifetime %d exceeds seven days" % lifetime, AD_ILLEGAL_PARAMETER)
        if lifetime == 0:
            return  # RFC 8446 4.6.1: discard immediately
        psk = resumption_psk(self._suite, self._schedule.resumption_master_secret, nonce)
        t = Ticket(
            ticket=ticket,
            psk=psk,
            cipher=self._suite.id,
            lifetime=lifetime,
            age_add=age_add,
            received=time.time(),
            max_early_data=max_early_data,
            server_name=self.server_name,
            alpn=self.alpn_selected,
            peer_chain=list(self.peer_chain),
            nonce=nonce,
        )
        self.tickets.append(t)
        self._events.append(NewTicket(t))

    def _on_key_update(self, body: bytes) -> None:
        if len(body) != 1 or body[0] not in (0, 1):
            raise TLSError("malformed KeyUpdate", AD_ILLEGAL_PARAMETER)
        self._read_cipher.update()
        self.key_updates_received += 1
        if body[0] == 1 and not self._close_sent:
            self._send(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, b"\x00"))
            self._write_cipher.update()
            self.key_updates_sent += 1

    # ------------------------------------------------------------ helpers
    def info(self) -> Dict[str, Any]:
        """Diagnostics for ``Response.infos``."""
        return {
            "tls_backend": "native",
            "version": self.version,
            "cipher": self.cipher,
            "group": self.group,
            "alpn": self.alpn_selected,
            "resumed": self._resumed,
            "hello_retry": self.hello_retry,
            "cert_compression": self.cert_compression,
            "template": self.template.name,
            "client_hello_bytes": self.client_hello_bytes,
            "timings": dict(self.timings),
        }

    def _raise_handshake_failure(self, message: str) -> None:
        raise TLSError(message, AD_HANDSHAKE_FAILURE)

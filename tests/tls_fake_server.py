"""A scripted TLS 1.3 server for the native engine's tests.

The stdlib ``ssl`` server covers the normal paths; this one exists for the
flows it cannot be told to produce: CompressedCertificate (zlib, brotli,
zstd), CertificateRequest, record_size_limit, ECH retry configs, a
HelloRetryRequest with a cookie, PSK rejection and acceptance with binder
checks, NewSessionTicket on demand, handshake fragmentation and coalescing,
a server-initiated KeyUpdate, ALPS, X25519MLKEM768 and X25519Kyber768Draft00
selection. It is built on the same primitives as the client so it is a
cross-check of framing, not of the key schedule (the OpenSSL tests do that).
"""
from __future__ import annotations

import datetime
import hmac
import os
import socket
import threading
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from curl_reap._tls import certs as certs_mod
from curl_reap._tls import wire
from curl_reap._tls.consts import (
    AD_CLOSE_NOTIFY,
    ALERT_LEVEL_WARNING,
    CT_ALERT,
    CT_APPLICATION_DATA,
    CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE,
    EXT_ALPN,
    EXT_COOKIE,
    EXT_EARLY_DATA,
    EXT_ECH,
    EXT_KEY_SHARE,
    EXT_PRE_SHARED_KEY,
    EXT_RECORD_SIZE_LIMIT,
    EXT_SUPPORTED_VERSIONS,
    GROUP_SECP256R1,
    GROUP_X25519,
    GROUP_X25519KYBER768DRAFT00,
    GROUP_X25519MLKEM768,
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
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    TLS12,
    TLS13,
)
from curl_reap._tls.hello import parse_client_hello
from curl_reap._tls.keyschedule import SUITES, KeySchedule, psk_binder, resumption_psk
from curl_reap._tls.record import RecordCipher


# ---------------------------------------------------------------------------
# Certificates


def make_ca(name: str = "curl_reap test CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(ca_cert, ca_key, hostnames=("localhost",), ips=("127.0.0.1",), rsa=False):
    if rsa:
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

        key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    sans = [x509.DNSName(h) for h in hostnames] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=rsa, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def write_pem(path, *certs, key=None):
    with open(path, "wb") as fh:
        for cert in certs:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        if key is not None:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))


# ---------------------------------------------------------------------------
# The scripted server


class FakeServerError(Exception):
    pass


class FakeTLS13Server:
    """One connection per :meth:`serve` call; see the module docstring."""

    def __init__(
        self,
        chain: List[x509.Certificate],
        key,
        *,
        suite: int = 0x1301,
        group: Optional[int] = None,
        compress: Optional[int] = None,
        cert_request: bool = False,
        record_size_limit: Optional[int] = None,
        ech_retry_configs: bool = False,
        alpn: Optional[str] = "h2",
        alps: bool = False,
        hrr_group: Optional[int] = None,
        hrr_cookie: Optional[bytes] = None,
        tickets: int = 0,
        ticket_lifetime: int = 7200,
        accept_psk: bool = False,
        fragment: Optional[int] = None,
        coalesce: bool = True,
        server_key_update: bool = False,
        echo: bool = True,
        close_notify: bool = True,
        ticket_store: Optional[Dict[bytes, dict]] = None,
    ):
        self.chain = chain
        self.key = key
        self.suite = SUITES[suite]
        self.group = group
        self.compress = compress
        self.cert_request = cert_request
        self.record_size_limit = record_size_limit
        self.ech_retry_configs = ech_retry_configs
        self.alpn = alpn
        self.alps = alps
        self.hrr_group = hrr_group
        self.hrr_cookie = hrr_cookie
        self.tickets = tickets
        self.ticket_lifetime = ticket_lifetime
        self.accept_psk = accept_psk
        self.fragment = fragment
        self.coalesce = coalesce
        self.server_key_update = server_key_update
        self.echo = echo
        self.close_notify = close_notify
        self.ticket_store = ticket_store if ticket_store is not None else {}
        self.log: List[str] = []
        self.client_hellos: List[dict] = []
        self.resumed = False
        self.received: List[bytes] = []
        self.client_finished_ok = False
        self.client_certificate_empty = None

    # -- record plumbing -----------------------------------------------------
    def _recv_record(self, sock) -> tuple:
        header = self._recv_exact(sock, 5)
        if not header:
            return None, None
        length = (header[3] << 8) | header[4]
        body = self._recv_exact(sock, length)
        return header, body

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return buf if buf else b""
            buf += chunk
        return buf

    def _read_handshake_messages(self, sock, read_cipher: Optional[RecordCipher]) -> List[tuple]:
        """Read records until at least one full handshake message is available."""
        buf = self._hs_buf
        msgs = []
        while True:
            while len(buf) >= 4:
                length = (buf[1] << 16) | (buf[2] << 8) | buf[3]
                if len(buf) < 4 + length:
                    break
                raw = bytes(buf[:4 + length])
                del buf[:4 + length]
                msgs.append((raw[0], raw[4:], raw))
            if msgs:
                return msgs
            header, body = self._recv_record(sock)
            if header is None:
                raise FakeServerError("client closed during handshake")
            ctype = header[0]
            if ctype == CT_CHANGE_CIPHER_SPEC:
                self.log.append("ccs")
                continue
            if read_cipher is not None:
                if ctype == CT_ALERT:
                    raise FakeServerError("client alert %r" % body)
                inner, content = read_cipher.decrypt(header, body)
                if inner == CT_ALERT:
                    raise FakeServerError("client alert %r" % content)
                if inner != CT_HANDSHAKE:
                    raise FakeServerError("unexpected inner type %d" % inner)
                buf += content
            else:
                if ctype == CT_ALERT:
                    raise FakeServerError("client alert %r" % body)
                if ctype != CT_HANDSHAKE:
                    raise FakeServerError("unexpected record type %d" % ctype)
                buf += body

    def _send_handshake(self, sock, messages: List[bytes], write_cipher: Optional[RecordCipher]) -> None:
        """Send handshake messages, optionally coalesced into one record or fragmented."""
        blob = b"".join(messages)
        chunks: List[bytes] = []
        if self.fragment:
            for i in range(0, len(blob), self.fragment):
                chunks.append(blob[i:i + self.fragment])
        elif self.coalesce:
            chunks.append(blob)
        else:
            chunks = list(messages)
        out = b""
        for chunk in chunks:
            for i in range(0, len(chunk), 16384):
                piece = chunk[i:i + 16384]
                if write_cipher is None:
                    out += wire.record_header(CT_HANDSHAKE, TLS12, len(piece)) + piece
                else:
                    out += write_cipher.encrypt(CT_HANDSHAKE, piece)
        sock.sendall(out)

    # -- handshake -------------------------------------------------------------
    def _server_share(self, group: int, client_public: bytes) -> tuple:
        if group == GROUP_X25519:
            priv = x25519.X25519PrivateKey.generate()
            return priv.public_key().public_bytes_raw(), priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))
        if group == GROUP_SECP256R1:
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public)
            return pub, priv.exchange(ec.ECDH(), peer)
        if group == GROUP_X25519MLKEM768:
            from curl_reap._tls.mlkem import x25519mlkem768_server_respond

            return x25519mlkem768_server_respond(client_public)
        if group == GROUP_X25519KYBER768DRAFT00:
            from curl_reap._tls.mlkem import kyber768_encaps

            xpub_client, ek = client_public[:32], client_public[32:]
            priv = x25519.X25519PrivateKey.generate()
            x_ss = priv.exchange(x25519.X25519PublicKey.from_public_bytes(xpub_client))
            k_ss, ct = kyber768_encaps(ek)
            return priv.public_key().public_bytes_raw() + ct, x_ss + k_ss
        raise FakeServerError("fake server cannot serve group %#06x" % group)

    def serve(self, sock: socket.socket) -> dict:
        self._hs_buf = bytearray()
        suite = self.suite
        transcript = bytearray()

        msgs = self._read_handshake_messages(sock, None)
        mtype, body, raw = msgs[0]
        if mtype != 1:
            raise FakeServerError("expected ClientHello")
        hello = parse_client_hello(raw)
        self.client_hellos.append(hello)
        transcript += raw

        if self.hrr_group is not None:
            # HelloRetryRequest for hrr_group, optionally with a cookie.
            exts = wire.extension(EXT_SUPPORTED_VERSIONS, wire.u16(TLS13))
            exts += wire.extension(EXT_KEY_SHARE, wire.u16(self.hrr_group))
            if self.hrr_cookie:
                exts += wire.extension(EXT_COOKIE, wire.vec16(self.hrr_cookie))
            hrr_body = wire.u16(TLS12) + HRR_RANDOM + wire.vec8(hello["session_id"]) + wire.u16(suite.id) + b"\x00" + wire.vec16(exts)
            hrr = wire.handshake(HT_SERVER_HELLO, hrr_body)
            ch1_hash = suite.hash(bytes(transcript))
            transcript = bytearray(wire.handshake(HT_MESSAGE_HASH, ch1_hash)) + hrr
            sock.sendall(wire.record_header(CT_HANDSHAKE, TLS12, len(hrr)) + hrr)
            sock.sendall(wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x01")
            msgs = self._read_handshake_messages(sock, None)
            mtype, body, raw = msgs[0]
            if mtype != 1:
                raise FakeServerError("expected second ClientHello")
            hello2 = parse_client_hello(raw)
            self.client_hellos.append(hello2)
            if self.hrr_cookie and hello2.get("cookie") != self.hrr_cookie:
                raise FakeServerError("cookie not echoed")
            if list(hello2["key_shares"]) != [self.hrr_group]:
                raise FakeServerError("second ClientHello key shares %r" % list(hello2["key_shares"]))
            hello = hello2
            transcript += raw

        shares = hello["key_shares"]
        servable = (GROUP_X25519MLKEM768, GROUP_X25519KYBER768DRAFT00, GROUP_X25519, GROUP_SECP256R1)
        if self.group is not None:
            group = self.group
        else:
            group = next((g for g in shares if g in servable), None)
            if group is None:
                raise FakeServerError("no servable key share in %r" % list(shares))
        if group not in shares:
            raise FakeServerError("client did not share group %#06x" % group)
        server_pub, shared = self._server_share(group, shares[group])

        # PSK handling: accept when configured and the binder verifies.
        psk = None
        sh_exts = wire.extension(EXT_SUPPORTED_VERSIONS, wire.u16(TLS13))
        if hello.get("psk_identities"):
            if not self.accept_psk:
                self.log.append("psk rejected")
            else:
                ticket_id, _age = hello["psk_identities"][0]
                info = self.ticket_store.get(ticket_id)
                if info is not None and info["suite"].hash_name == suite.hash_name:
                    binder_len = 2 + 1 + len(hello["psk_binders"][0])
                    truncated = bytes(transcript[:-binder_len])
                    expected = psk_binder(suite, info["psk"], suite.hash(truncated))
                    if hmac.compare_digest(expected, hello["psk_binders"][0]):
                        psk = info["psk"]
                        self.resumed = True
                        sh_exts += wire.extension(EXT_PRE_SHARED_KEY, wire.u16(0))
                        self.log.append("psk accepted")
                    else:
                        raise FakeServerError("binder mismatch")
                else:
                    self.log.append("psk rejected")
        sh_exts += wire.extension(EXT_KEY_SHARE, wire.u16(group) + wire.vec16(server_pub))
        sh_body = wire.u16(TLS12) + os.urandom(32) + wire.vec8(hello["session_id"]) + wire.u16(suite.id) + b"\x00" + wire.vec16(sh_exts)
        sh = wire.handshake(HT_SERVER_HELLO, sh_body)
        transcript += sh
        sock.sendall(wire.record_header(CT_HANDSHAKE, TLS12, len(sh)) + sh)
        sock.sendall(wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x01")

        schedule = KeySchedule(suite, psk)
        c_hs, s_hs = schedule.set_shared_secret(shared, suite.hash(bytes(transcript)))
        write = RecordCipher(suite, s_hs)
        read = RecordCipher(suite, c_hs)

        flight: List[bytes] = []
        ee_exts = b""
        if self.alpn and self.alpn in (hello.get("alpn") or []):
            ee_exts += wire.extension(EXT_ALPN, wire.alpn_list([self.alpn]))
        if self.record_size_limit:
            ee_exts += wire.extension(EXT_RECORD_SIZE_LIMIT, wire.u16(self.record_size_limit))
        if self.ech_retry_configs:
            ee_exts += wire.extension(EXT_ECH, wire.vec16(b"\x00" * 40))
        if self.alps and hello.get("alps_codepoint"):
            ee_exts += wire.extension(hello["alps_codepoint"], b"")
        ee = wire.handshake(HT_ENCRYPTED_EXTENSIONS, wire.vec16(ee_exts))
        transcript += ee
        flight.append(ee)
        if psk is None:
            if self.cert_request:
                cr = wire.handshake(HT_CERTIFICATE_REQUEST, wire.vec8(b"") + wire.vec16(wire.extension(13, wire.u16_list([0x0403, 0x0804], 2))))
                transcript += cr
                flight.append(cr)
            entries = b"".join(wire.vec24(c.public_bytes(serialization.Encoding.DER)) + wire.vec16(b"") for c in self.chain)
            cert_body = wire.vec8(b"") + wire.vec24(entries)
            if self.compress:
                compressed = certs_mod.compress_certificate(self.compress, cert_body)
                cert = wire.handshake(HT_COMPRESSED_CERTIFICATE, wire.u16(self.compress) + wire.u24(len(cert_body)) + wire.vec24(compressed))
            else:
                cert = wire.handshake(HT_CERTIFICATE, cert_body)
            transcript += cert
            flight.append(cert)
            scheme = SIG_ECDSA_SECP256R1_SHA256 if isinstance(self.key, ec.EllipticCurvePrivateKey) else SIG_RSA_PSS_RSAE_SHA256
            sig = certs_mod.sign_certificate_verify(self.key, scheme, suite.hash(bytes(transcript)))
            cv = wire.handshake(HT_CERTIFICATE_VERIFY, wire.u16(scheme) + wire.vec16(sig))
            transcript += cv
            flight.append(cv)
        fin = wire.handshake(HT_FINISHED, schedule.finished_verify_data(schedule.server_handshake_secret, suite.hash(bytes(transcript))))
        transcript += fin
        flight.append(fin)
        self._send_handshake(sock, flight, write)
        c_ap, s_ap = schedule.application_secrets(suite.hash(bytes(transcript)))

        # Client flight: [EE for ALPS] [Certificate] Finished.
        expected_client = schedule.finished_verify_data(schedule.client_handshake_secret, b"")
        while True:
            msgs = self._read_handshake_messages(sock, read)
            done = False
            for mtype, body, raw in msgs:
                if mtype == HT_ENCRYPTED_EXTENSIONS:
                    self.log.append("client alps ee")
                    transcript += raw
                elif mtype == HT_CERTIFICATE:
                    r = wire.Reader(body)
                    r.vec(1)
                    self.client_certificate_empty = r.vec(3) == b""
                    transcript += raw
                elif mtype == HT_FINISHED:
                    expected_client = schedule.finished_verify_data(schedule.client_handshake_secret, suite.hash(bytes(transcript)))
                    if not hmac.compare_digest(expected_client, body):
                        raise FakeServerError("client Finished mismatch")
                    self.client_finished_ok = True
                    transcript += raw
                    done = True
                else:
                    raise FakeServerError("unexpected client message %d" % mtype)
            if done:
                break
        write = RecordCipher(suite, s_ap)
        read = RecordCipher(suite, c_ap)
        rms = schedule.resumption_secret(suite.hash(bytes(transcript)))

        for _ in range(self.tickets):
            nonce = os.urandom(8)
            ticket = os.urandom(32)
            self.ticket_store[ticket] = {"psk": resumption_psk(suite, rms, nonce), "suite": suite}
            nst = wire.handshake(HT_NEW_SESSION_TICKET, wire.u32(self.ticket_lifetime) + wire.u32(int.from_bytes(os.urandom(4), "big")) + wire.vec8(nonce) + wire.vec16(ticket) + wire.vec16(b""))
            sock.sendall(write.encrypt(CT_HANDSHAKE, nst))
        if self.server_key_update:
            sock.sendall(write.encrypt(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, b"\x01")))
            write.update()

        # Application phase: echo until close_notify or EOF.
        self._hs_buf = bytearray()
        while True:
            header, body = self._recv_record(sock)
            if header is None:
                self.log.append("eof")
                break
            if header[0] == CT_CHANGE_CIPHER_SPEC:
                continue
            inner, content = read.decrypt(header, body)
            if inner == CT_ALERT:
                if content[1] == AD_CLOSE_NOTIFY:
                    self.log.append("close_notify")
                    if self.close_notify:
                        try:
                            sock.sendall(write.encrypt(CT_ALERT, bytes((ALERT_LEVEL_WARNING, AD_CLOSE_NOTIFY))))
                        except OSError:
                            pass
                    break
                raise FakeServerError("client alert %r" % content)
            if inner == CT_HANDSHAKE:
                self._hs_buf += content
                while len(self._hs_buf) >= 4:
                    length = (self._hs_buf[1] << 16) | (self._hs_buf[2] << 8) | self._hs_buf[3]
                    if len(self._hs_buf) < 4 + length:
                        break
                    raw = bytes(self._hs_buf[:4 + length])
                    del self._hs_buf[:4 + length]
                    if raw[0] == HT_KEY_UPDATE:
                        read.update()
                        self.log.append("client key_update %d" % raw[4])
                        if raw[4] == 1:
                            sock.sendall(write.encrypt(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, b"\x00")))
                            write.update()
                continue
            if inner == CT_APPLICATION_DATA:
                self.received.append(content)
                if self.echo and content:
                    out = b""
                    for i in range(0, len(content), 16384):
                        out += write.encrypt(CT_APPLICATION_DATA, content[i:i + 16384])
                    sock.sendall(out)
        return {"resumed": self.resumed, "log": list(self.log)}


class FakeServerThread:
    """Listen on 127.0.0.1, serve one connection per accept in a thread."""

    def __init__(self, factory, connections: int = 1):
        self.factory = factory
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.connections = connections
        self.servers: List[FakeTLS13Server] = []
        self.errors: List[BaseException] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        for _ in range(self.connections):
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.settimeout(10)
            server = self.factory()
            self.servers.append(server)
            try:
                server.serve(conn)
            except BaseException as exc:  # noqa: BLE001 - surfaced to the test
                self.errors.append(exc)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def join(self, timeout=10):
        self.thread.join(timeout)
        try:
            self.sock.close()
        except OSError:
            pass

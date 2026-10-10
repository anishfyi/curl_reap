"""Handshake flows the stdlib server cannot be told to produce.

Driven by tests/tls_fake_server.py: compressed certificates, a
CertificateRequest, record_size_limit, ECH retry configs, HelloRetryRequest
with a cookie, PSK acceptance and rejection, tickets, fragmentation and
coalescing, a server KeyUpdate, ALPS, and the post-quantum groups on both
ML-KEM backends. A raw socket server covers malformed server behaviour.
"""
import os
import socket
import sys
import threading

import pytest

from curl_reap._tls import (
    SessionCache,
    TLS12Negotiated,
    TLSAlertReceived,
    TLSError,
    UnsupportedGroupRequested,
    template,
    wrap_socket,
)
from curl_reap._tls import certs as certs_mod
from curl_reap._tls import keyexchange
from curl_reap._tls import wire
from curl_reap._tls.consts import (
    AD_HANDSHAKE_FAILURE,
    AD_ILLEGAL_PARAMETER,
    AD_UNSUPPORTED_EXTENSION,
    CT_ALERT,
    CT_HANDSHAKE,
    EXT_SUPPORTED_VERSIONS,
    HT_SERVER_HELLO,
    TLS12,
)
from curl_reap._tls.hello import parse_client_hello

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import FakeServerThread, FakeTLS13Server, make_ca, make_leaf, write_pem  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fake-pki")
    ca_cert, ca_key = make_ca()
    leaf, key = make_leaf(ca_cert, ca_key)
    rsa_leaf, rsa_key = make_leaf(ca_cert, ca_key, rsa=True)
    ca_path = str(tmp / "ca.pem")
    write_pem(ca_path, ca_cert)
    return {"ca": ca_cert, "leaf": leaf, "key": key, "rsa_leaf": rsa_leaf, "rsa_key": rsa_key, "ca_path": ca_path}


def start(pki, connections=1, **kw):
    chain = kw.pop("chain", None) or [pki["leaf"], pki["ca"]]
    key = kw.pop("key", None) or pki["key"]
    return FakeServerThread(lambda: FakeTLS13Server(chain, key, **kw), connections=connections)


def connect(port, pki, name="chrome", **kw):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    return wrap_socket(sock, "localhost", kw.pop("template", template(name)), verify=kw.pop("verify", pki["ca_path"]), timeout=10, **kw)


def roundtrip(tls, data=b"hello"):
    tls.sendall(data)
    got = b""
    while len(got) < len(data):
        chunk = tls.recv(65536)
        if not chunk:
            break
        got += chunk
    return got


@pytest.mark.parametrize("name,algorithm", [("firefox", 1), ("chrome", 2), ("firefox", 3)])
def test_compressed_certificate(pki, name, algorithm):
    if algorithm == 3 and not certs_mod.has_zstd():
        pytest.skip("no zstd module")
    srv = start(pki, compress=algorithm)
    tls = connect(srv.port, pki, name=name)
    assert tls.handshake_info.cert_compression == algorithm
    assert tls.handshake_info.cert_verified is True
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_compression_not_offered_is_rejected(pki, monkeypatch):
    monkeypatch.setattr(certs_mod, "has_zstd", lambda: False)
    srv = start(pki, compress=3)
    with pytest.raises(TLSError) as info:
        connect(srv.port, pki, name="firefox")
    assert info.value.alert == AD_ILLEGAL_PARAMETER
    srv.join()
    hello = srv.servers[0].client_hellos[0]
    assert hello["compress_certificate"] == [1, 2], "zstd dropped from the offer when it cannot be inflated"


def test_rsa_leaf_with_pss_certificate_verify(pki):
    srv = start(pki, chain=[pki["rsa_leaf"], pki["ca"]], key=pki["rsa_key"])
    tls = connect(srv.port, pki)
    assert tls.handshake_info.certificate_verify_scheme == 0x0804
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_certificate_request_answered_with_empty_certificate(pki):
    srv = start(pki, cert_request=True)
    tls = connect(srv.port, pki)
    assert tls.handshake_info.certificate_request is True
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors and srv.servers[0].client_certificate_empty is True


@pytest.mark.parametrize("limit,records", [(1000, 4), (64, 48), (16385, 1)])
def test_record_size_limit_is_honoured_outbound(pki, limit, records):
    srv = start(pki, record_size_limit=limit)
    tls = connect(srv.port, pki, name="firefox")
    assert tls.client.server_record_size_limit == limit
    assert roundtrip(tls, b"x" * 3000) == b"x" * 3000
    assert tls.client.stats["app_records_out"] == records
    tls.close()
    srv.join()
    assert not srv.errors


def test_record_size_limit_too_small_is_rejected(pki):
    srv = start(pki, record_size_limit=10)
    with pytest.raises(TLSError) as info:
        connect(srv.port, pki)
    assert info.value.alert == AD_ILLEGAL_PARAMETER
    srv.join()


def test_ech_retry_configs_are_ignored(pki):
    srv = start(pki, ech_retry_configs=True)
    tls = connect(srv.port, pki)
    assert tls.handshake_info.ech_retry_configs is True
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_alps_client_encrypted_extensions(pki):
    srv = start(pki, alps=True)
    tls = connect(srv.port, pki)
    assert tls.handshake_info.alps is True and tls.handshake_info.alps_server_settings == b""
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors and "client alps ee" in srv.servers[0].log


def test_hello_retry_request_with_cookie(pki):
    srv = start(pki, hrr_group=23, hrr_cookie=b"cookie-" * 4)
    tls = connect(srv.port, pki)
    info = tls.handshake_info
    assert info.hello_retry and info.hello_retry_cookie and tls.negotiated_group == "P-256"
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors
    ch1, ch2 = srv.servers[0].client_hellos
    assert ch1["random"] == ch2["random"] and ch1["session_id"] == ch2["session_id"]
    assert ch2["cookie"] == b"cookie-" * 4
    assert list(ch2["key_shares"]) == [23]


def test_hello_retry_request_for_a_shared_group_is_rejected(pki):
    srv = start(pki, hrr_group=29)
    with pytest.raises(TLSError) as info:
        connect(srv.port, pki)
    assert info.value.alert == AD_ILLEGAL_PARAMETER
    srv.join()


def test_hello_retry_request_for_ffdhe_is_unsupported(pki):
    srv = start(pki, hrr_group=256)
    with pytest.raises(UnsupportedGroupRequested) as info:
        connect(srv.port, pki, name="firefox")
    assert info.value.group == 256 and info.value.alert == AD_HANDSHAKE_FAILURE
    srv.join()


def test_psk_resumption_accepted_and_binder_verified(pki):
    store = {}
    srv = start(pki, connections=2, tickets=2, accept_psk=True, ticket_store=store)
    cache = SessionCache()
    first = connect(srv.port, pki, session_cache=cache)
    assert roundtrip(first) == b"hello"
    first.close()
    assert len(cache) == 2 and len(first.client.tickets) == 2
    second = connect(srv.port, pki, session_cache=cache)
    assert second.resumed is True and second.handshake_info.cert_verified is None
    assert second.getpeercertchain() == first.getpeercertchain()
    assert roundtrip(second, b"resumed") == b"resumed"
    second.close()
    srv.join()
    assert not srv.errors
    assert srv.servers[1].resumed and "psk accepted" in srv.servers[1].log
    hello = srv.servers[1].client_hellos[0]
    assert hello["extensions"][-1][0] == 41 and len(hello["psk_binders"][0]) == 32


def test_psk_rejected_falls_back_to_full_handshake(pki):
    srv = start(pki, connections=2, tickets=1, accept_psk=False)
    cache = SessionCache()
    first = connect(srv.port, pki, session_cache=cache)
    first.close()
    second = connect(srv.port, pki, session_cache=cache)
    assert second.client.offering_psk and second.resumed is False
    assert second.handshake_info.cert_verified is True
    assert roundtrip(second) == b"hello"
    second.close()
    srv.join()
    assert not srv.errors and "psk rejected" in srv.servers[1].log


def test_psk_with_hrr_recomputes_the_binder(pki):
    store = {}
    srv = start(pki, connections=1, tickets=1, accept_psk=True, ticket_store=store)
    cache = SessionCache()
    first = connect(srv.port, pki, session_cache=cache)
    first.close()
    srv.join()
    srv2 = FakeServerThread(lambda: FakeTLS13Server([pki["leaf"], pki["ca"]], pki["key"], accept_psk=True, ticket_store=store, hrr_group=23, hrr_cookie=b"c"))
    second = connect(srv2.port, pki, session_cache=cache)
    assert second.resumed and second.handshake_info.hello_retry
    assert roundtrip(second) == b"hello"
    second.close()
    srv2.join()
    assert not srv2.errors


def test_ticket_lifetime_zero_is_not_cached(pki):
    srv = start(pki, tickets=2, ticket_lifetime=0)
    cache = SessionCache()
    tls = connect(srv.port, pki, session_cache=cache)
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert len(cache) == 0 and tls.client.tickets == []


@pytest.mark.parametrize("fragment,coalesce", [(5, True), (100, True), (None, False), (None, True)])
def test_fragmented_and_coalesced_server_flight(pki, fragment, coalesce):
    srv = start(pki, fragment=fragment, coalesce=coalesce)
    tls = connect(srv.port, pki, name="safari")
    stats = tls.client.stats
    if fragment:
        assert stats["fragmented_messages"] > 0
    if coalesce and not fragment:
        assert stats["coalesced_records"] >= 1
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_server_initiated_key_update(pki):
    srv = start(pki, server_key_update=True)
    tls = connect(srv.port, pki)
    assert roundtrip(tls, b"after server key update") == b"after server key update"
    assert tls.client.key_updates_received == 1 and tls.client.key_updates_sent == 1
    tls.close()
    srv.join()
    assert not srv.errors and any(entry.startswith("client key_update 0") for entry in srv.servers[0].log)


@pytest.mark.parametrize("backend", ["pure", None])
def test_x25519mlkem768_selected(pki, monkeypatch, backend):
    monkeypatch.setattr(keyexchange, "MLKEM_BACKEND", backend)
    srv = start(pki, group=0x11EC)
    tls = connect(srv.port, pki, name="firefox")
    assert tls.negotiated_group == "X25519MLKEM768"
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_kyber_draft_selected_for_chrome124(pki):
    srv = start(pki, group=0x6399)
    tls = connect(srv.port, pki, name="chrome124")
    assert tls.negotiated_group == "X25519Kyber768Draft00"
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


def test_p256_third_share_of_firefox(pki):
    srv = start(pki, group=23)
    tls = connect(srv.port, pki, name="firefox")
    assert tls.negotiated_group == "P-256" and not tls.handshake_info.hello_retry
    assert roundtrip(tls) == b"hello"
    tls.close()
    srv.join()
    assert not srv.errors


@pytest.mark.parametrize("suite", [0x1302, 0x1303])
def test_other_suites_with_fake_server(pki, suite):
    srv = start(pki, suite=suite, tickets=1)
    tls = connect(srv.port, pki, name="safari")
    assert tls.client.cipher_id == suite
    assert roundtrip(tls, b"z" * 20000) == b"z" * 20000
    tls.close()
    srv.join()
    assert not srv.errors


def test_server_picking_an_unoffered_suite_is_rejected(pki):
    from dataclasses import replace

    tpl = template("chrome")
    tpl = replace(tpl, ciphers=[c for c in tpl.ciphers if c != 0x1302])
    srv = start(pki, suite=0x1302)
    with pytest.raises(TLSError) as info:
        connect(srv.port, pki, template=tpl)
    assert info.value.alert == AD_ILLEGAL_PARAMETER
    srv.join()


def test_eof_after_handshake_without_close_notify(pki):
    srv = start(pki, close_notify=False, echo=False)
    tls = connect(srv.port, pki)
    tls.client.close()
    tls._flush()
    assert tls.recv(10) == b""
    assert tls._closed_event.reason == "eof"
    tls.close()
    srv.join()


# ---------------------------------------------------------------------------
# Raw servers for malformed or legacy behaviour


class RawServer:
    def __init__(self, script):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(2)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.thread = threading.Thread(target=self._run, args=(script,), daemon=True)
        self.thread.start()

    def _run(self, script):
        conn, _ = self.sock.accept()
        conn.settimeout(5)
        try:
            self.received = conn.recv(65536)
            conn.sendall(script(self.received))
            try:
                conn.recv(65536)
            except OSError:
                pass
        finally:
            conn.close()
            self.sock.close()


def server_hello_without_supported_versions(legacy_version=TLS12):
    def script(client_bytes):
        hello = parse_client_hello(client_bytes[5:])
        body = wire.u16(legacy_version) + os.urandom(32) + wire.vec8(b"\x01" * 32) + wire.u16(0xC02B) + b"\x00" + wire.vec16(b"")
        msg = wire.handshake(HT_SERVER_HELLO, body)
        return wire.record_header(CT_HANDSHAKE, legacy_version, len(msg)) + msg

    return script


@pytest.mark.parametrize("legacy", [TLS12, 0x0301])
def test_tls12_and_older_server_hello(pki, legacy):
    srv = RawServer(server_hello_without_supported_versions(legacy))
    with pytest.raises(TLS12Negotiated) as info:
        connect(srv.port, pki)
    assert info.value.negotiated == legacy
    srv.thread.join(5)


def test_fatal_alert_during_handshake(pki):
    srv = RawServer(lambda _: wire.record_header(CT_ALERT, TLS12, 2) + bytes((2, AD_HANDSHAKE_FAILURE)))
    with pytest.raises(TLSAlertReceived) as info:
        connect(srv.port, pki)
    assert info.value.name == "handshake_failure"
    srv.thread.join(5)


def test_garbage_from_server(pki):
    srv = RawServer(lambda _: b"HTTP/1.1 400 Bad Request\r\n\r\n")
    with pytest.raises(TLSError):
        connect(srv.port, pki)
    srv.thread.join(5)


def test_server_hello_with_unknown_extension(pki):
    def script(client_bytes):
        hello = parse_client_hello(client_bytes[5:])
        exts = wire.extension(EXT_SUPPORTED_VERSIONS, wire.u16(0x0304)) + wire.extension(0x1234, b"")
        body = wire.u16(TLS12) + os.urandom(32) + wire.vec8(hello["session_id"]) + wire.u16(0x1301) + b"\x00" + wire.vec16(exts)
        msg = wire.handshake(HT_SERVER_HELLO, body)
        return wire.record_header(CT_HANDSHAKE, TLS12, len(msg)) + msg

    srv = RawServer(script)
    with pytest.raises(TLSError) as info:
        connect(srv.port, pki)
    assert info.value.alert == AD_UNSUPPORTED_EXTENSION
    srv.thread.join(5)
    assert srv.received[0] == CT_HANDSHAKE and srv.received[1:3] == b"\x03\x01", "first record carries version 0x0301"

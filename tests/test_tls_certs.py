"""Trust stores, bundle loading, hostname subjects, certificate compression."""
import os
import sys
import zlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from curl_reap._tls import CertificateError, SessionCache, Ticket
from curl_reap._tls import certs as certs_mod
from curl_reap.exceptions import CertificateVerifyError, SSLError, TransportError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_fake_server import make_ca, make_leaf, write_pem  # noqa: E402


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("pki")
    ca_cert, ca_key = make_ca()
    leaf, key = make_leaf(ca_cert, ca_key, hostnames=("localhost", "alt.example"), ips=("127.0.0.1", "::1"))
    ca_path = str(tmp / "ca.pem")
    write_pem(ca_path, ca_cert)
    der_path = str(tmp / "ca.der")
    with open(der_path, "wb") as fh:
        fh.write(ca_cert.public_bytes(serialization.Encoding.DER))
    other_ca, other_key = make_ca("other CA")
    other_path = str(tmp / "other.pem")
    write_pem(other_path, other_ca)
    both_path = str(tmp / "both.pem")
    write_pem(both_path, other_ca, ca_cert)
    return {"ca": ca_cert, "leaf": leaf, "ca_path": ca_path, "der_path": der_path, "other_path": other_path, "both_path": both_path}


def test_error_hierarchy():
    err = CertificateError("x")
    assert isinstance(err, CertificateVerifyError) and isinstance(err, SSLError) and isinstance(err, TransportError)
    assert err.code == 60 and isinstance(err, OSError)
    from curl_reap._tls import TLSError

    assert TLSError("y").code == 35 and isinstance(TLSError("y"), TransportError)
    assert "curl error 35" in str(TLSError("y"))


def test_default_trust_store_loads_and_is_cached():
    store = certs_mod.default_trust_store()
    assert len(store) > 10
    assert certs_mod.default_trust_store() is store
    assert certs_mod.trust_store_for(True) is store
    assert certs_mod.trust_store_for(False) is None
    assert certs_mod.trust_store_for(None) is None


def test_bundle_loading_pem_der_and_multi(pki):
    pem = certs_mod.trust_store_for(pki["ca_path"])
    assert len(pem) == 1 and pem.source == pki["ca_path"]
    assert certs_mod.trust_store_for(pki["ca_path"]) is pem, "bundles are cached by path and mtime"
    der = certs_mod.load_bundle(pki["der_path"])
    assert len(der) == 1
    both = certs_mod.load_bundle(pki["both_path"])
    assert len(both) == 2
    with pytest.raises(CertificateError):
        certs_mod.load_bundle(pki["ca_path"] + ".missing")


def test_bundle_with_garbage(tmp_path):
    path = tmp_path / "bad.pem"
    path.write_bytes(b"not a certificate")
    with pytest.raises(CertificateError):
        certs_mod.load_bundle(str(path))
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(CertificateError):
        certs_mod.load_bundle(str(empty))


def test_verify_chain_hostnames_and_ips(pki):
    store = certs_mod.load_bundle(pki["ca_path"])
    chain = [pki["leaf"], pki["ca"]]
    assert certs_mod.verify_chain(store, "localhost", chain)
    assert certs_mod.verify_chain(store, "LOCALHOST.", chain)
    assert certs_mod.verify_chain(store, "alt.example", chain)
    assert certs_mod.verify_chain(store, "127.0.0.1", chain)
    assert certs_mod.verify_chain(store, "::1", chain)
    with pytest.raises(CertificateError):
        certs_mod.verify_chain(store, "wrong.example", chain)
    with pytest.raises(CertificateError):
        certs_mod.verify_chain(store, "10.0.0.1", chain)
    other = certs_mod.load_bundle(pki["other_path"])
    with pytest.raises(CertificateError):
        certs_mod.verify_chain(other, "localhost", chain)
    with pytest.raises(CertificateError):
        certs_mod.verify_chain(store, "localhost", [])
    # The leaf alone verifies when the CA is a trust anchor (no intermediates).
    assert certs_mod.verify_chain(store, "localhost", [pki["leaf"]])


def test_subject_for():
    assert isinstance(certs_mod.subject_for("example.com"), x509.DNSName)
    assert isinstance(certs_mod.subject_for("192.0.2.1"), x509.IPAddress)
    assert certs_mod.subject_for("bücher.example").value == "xn--bcher-kva.example"
    assert certs_mod.subject_for("trailing.dot.").value == "trailing.dot"


def test_parse_chain_rejects_garbage():
    with pytest.raises(CertificateError):
        certs_mod.parse_chain([b"\x30\x03\x02\x01\x01"])


@pytest.mark.parametrize("algorithm", [1, 2, 3])
def test_certificate_compression_roundtrip(algorithm):
    if algorithm == 2 and not certs_mod.has_brotli():
        pytest.skip("brotli not installed")
    if algorithm == 3 and not certs_mod.has_zstd():
        pytest.skip("zstd not installed")
    payload = os.urandom(300) + b"\x00" * 2000
    blob = certs_mod.compress_certificate(algorithm, payload)
    assert certs_mod.decompress_certificate(algorithm, blob, len(payload)) == payload
    with pytest.raises(CertificateError):
        certs_mod.decompress_certificate(algorithm, blob, len(payload) + 1)
    with pytest.raises(CertificateError):
        certs_mod.decompress_certificate(algorithm, b"\xff\xfe garbage", 10)


def test_decompress_rejects_unknown_and_oversize():
    with pytest.raises(CertificateError):
        certs_mod.decompress_certificate(9, b"", 1)
    with pytest.raises(CertificateError):
        certs_mod.decompress_certificate(1, zlib.compress(b"x"), 1 << 24)


def test_available_compression_algorithms_filters_missing_modules(monkeypatch):
    assert certs_mod.available_compression_algorithms([1]) == [1]
    monkeypatch.setattr(certs_mod, "has_brotli", lambda: False)
    monkeypatch.setattr(certs_mod, "has_zstd", lambda: False)
    assert certs_mod.available_compression_algorithms([1, 2, 3]) == [1]


def test_session_cache_rules():
    import time

    cache = SessionCache(max_hosts=2, max_tickets_per_host=2)
    now = time.time()

    def ticket(tag, lifetime=3600, received=None):
        return Ticket(ticket=tag, psk=b"p", cipher=0x1301, lifetime=lifetime, age_add=0,
                      received=now if received is None else received)

    cache.put("a.example", ticket(b"1"))
    cache.put("a.example", ticket(b"2"))
    cache.put("A.EXAMPLE.", ticket(b"3"))
    assert len(cache) == 2 and [t.ticket for t in cache.peek("a.example")] == [b"3", b"2"], "newest first, two per host"
    assert cache.get("a.example").ticket == b"3"
    assert cache.get("a.example").ticket == b"2"
    assert cache.get("a.example") is None, "tickets are single use"
    cache.put("b.example", ticket(b"b"))
    cache.put("c.example", ticket(b"c"))
    cache.put("d.example", ticket(b"d"))
    assert "b.example" not in cache and "d.example" in cache, "oldest host evicted"
    cache.put("e.example", ticket(b"e", lifetime=0))
    assert "e.example" not in cache, "lifetime 0 never stored"
    expired = ticket(b"x", lifetime=10, received=0.0)
    assert expired.expired(now)
    cache.put("x.example", expired)
    assert cache.get("x.example") is None
    assert cache.stats()["hits"] == 2
    cache.clear()
    assert len(cache) == 0
    with pytest.raises(ValueError):
        SessionCache(max_hosts=0)


def test_ticket_age_and_expiry():
    t = Ticket(ticket=b"t", psk=b"p", cipher=0x1301, lifetime=7200, age_add=0xFFFFFFF0, received=100.0)
    assert t.obfuscated_age(100.5) == (500 + 0xFFFFFFF0) & 0xFFFFFFFF
    assert not t.expired(100.0 + 7199)
    assert t.expired(100.0 + 7200)
    week = Ticket(ticket=b"t", psk=b"p", cipher=0x1301, lifetime=10 * 86400, age_add=0, received=0.0)
    assert week.expired(7 * 86400 + 1), "clients never keep a ticket beyond seven days"

"""ML-KEM (FIPS 203) known answer tests, X25519 vectors, hybrid glue, Kyber draft.

The ACVP vectors come from usnistgov/ACVP-Server (tests/vectors/). The
Kyber768 round 3 routines, which serve chrome124's X25519Kyber768Draft00
group, are cross-checked against the kyber-py package when it is installed.
"""
import json
import os
import statistics
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from curl_reap._tls import mlkem
from curl_reap._tls import keyexchange
from curl_reap._tls.consts import GROUP_X25519KYBER768DRAFT00, GROUP_X25519MLKEM768

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
LEVELS = {"ML-KEM-512": 512, "ML-KEM-768": 768, "ML-KEM-1024": 1024}


def hx(s):
    return bytes.fromhex(s)


def load(name):
    path = os.path.join(VECTORS, name)
    if not os.path.exists(path):
        pytest.skip("vector file %s missing" % name)
    with open(path) as fh:
        return json.load(fh)


@pytest.mark.parametrize("level", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_keygen_kat(level):
    doc = load("ML-KEM-keyGen-FIPS203.json")
    assert doc["algorithm"] == "ML-KEM" and doc["mode"] == "keyGen" and doc["revision"] == "FIPS203"
    group = [g for g in doc["testGroups"] if g["parameterSet"] == level][0]
    M = mlkem.MLKEM(LEVELS[level])
    for t in group["tests"]:
        ek, dk = M.keygen_internal(hx(t["d"]), hx(t["z"]))
        assert ek == hx(t["ek"]) and dk == hx(t["dk"]), t["tcId"]


@pytest.mark.parametrize("level", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_encaps_decaps_kat(level):
    doc = load("ML-KEM-encapDecap-FIPS203.json")
    assert doc["algorithm"] == "ML-KEM" and doc["mode"] == "encapDecap" and doc["revision"] == "FIPS203"
    M = mlkem.MLKEM(LEVELS[level])
    counts = {}
    for g in doc["testGroups"]:
        if g["parameterSet"] != level:
            continue
        fn = g["function"]
        for t in g["tests"]:
            if fn == "encapsulation":
                k, c = M.encaps_internal(hx(t["ek"]), hx(t["m"]))
                assert k == hx(t["k"]) and c == hx(t["c"]), t["tcId"]
                assert M.decaps(hx(t["dk"]), c) == hx(t["k"])
            elif fn == "decapsulation":
                assert M.decaps(hx(t["dk"]), hx(t["c"])) == hx(t["k"]), (t["tcId"], t["reason"])
            elif fn == "encapsulationKeyCheck":
                try:
                    M.check_ek(hx(t["ek"]))
                    passed = True
                except (ValueError, TypeError):
                    passed = False
                assert passed == t["testPassed"], (t["tcId"], t["reason"])
            elif fn == "decapsulationKeyCheck":
                try:
                    M.check_dk(hx(t["dk"]), bytes(M.ct_len))
                    passed = True
                except (ValueError, TypeError):
                    passed = False
                assert passed == t["testPassed"], (t["tcId"], t["reason"])
            counts[fn] = counts.get(fn, 0) + 1
    assert counts.get("encapsulation", 0) >= 25 and counts.get("decapsulation", 0) >= 10


def test_roundtrip_and_implicit_rejection():
    ek, dk = mlkem.keygen()
    assert len(ek) == 1184 and len(dk) == 2400
    ss, ct = mlkem.encaps(ek)
    assert len(ss) == 32 and len(ct) == 1088
    assert mlkem.decaps(dk, ct) == ss
    bad = bytearray(ct)
    bad[5] ^= 0x40
    other = mlkem.decaps(dk, bytes(bad))
    assert other != ss and len(other) == 32
    with pytest.raises(ValueError):
        mlkem.decaps(dk, ct[:-1])
    with pytest.raises(ValueError):
        mlkem.encaps(ek[:-1])


def test_x25519_rfc7748_vectors_and_cryptography_cross_check():
    k1 = hx("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u1 = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    assert mlkem.x25519(k1, u1) == hx("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    a_priv = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    a_pub = hx("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b_pub = hx("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert mlkem.x25519_public(a_priv) == a_pub
    assert mlkem.x25519(a_priv, b_pub) == hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    for _ in range(10):
        sk = os.urandom(32)
        peer = X25519PrivateKey.generate()
        assert mlkem.x25519_public(sk) == X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
        assert mlkem.x25519(sk, peer.public_key().public_bytes_raw()) == X25519PrivateKey.from_private_bytes(sk).exchange(peer.public_key())


def test_hybrid_glue_lengths_order_and_loopback():
    client_sk = os.urandom(32)
    share, state = mlkem.x25519mlkem768_client_share(mlkem.x25519_public(client_sk))
    assert len(share) == 1216 and share[1184:] == mlkem.x25519_public(client_sk)
    server_share, server_secret = mlkem.x25519mlkem768_server_respond(share)
    assert len(server_share) == 1120
    secret = mlkem.x25519mlkem768_client_finish(state, server_share, client_sk)
    assert secret == server_secret and len(secret) == 64
    assert secret[:32] == mlkem.ML_KEM_768.decaps(state, server_share[:1088]), "ML-KEM secret first, X25519 second"
    with pytest.raises(ValueError):
        mlkem.x25519mlkem768_client_finish(state, server_share[:-1], client_sk)
    with pytest.raises(ValueError):
        mlkem.x25519mlkem768_client_finish(state, server_share[:1088] + bytes(32), client_sk)


def test_kyber768_round3_self_consistency():
    ek, dk = mlkem.keygen()
    ss, ct = mlkem.kyber768_encaps(ek)
    assert len(ss) == 32 and len(ct) == 1088
    assert mlkem.kyber768_decaps(dk, ct) == ss
    assert mlkem.decaps(dk, ct) != ss, "ML-KEM and Kyber derive different secrets from the same ciphertext"
    bad = bytearray(ct)
    bad[0] ^= 1
    assert mlkem.kyber768_decaps(dk, bytes(bad)) != ss


def test_kyber768_round3_matches_kyber_py():
    kyber = pytest.importorskip("kyber_py.kyber")
    Kyber768 = kyber.Kyber768
    pk, sk = Kyber768.keygen()
    key, c = Kyber768.encaps(pk)
    assert mlkem.kyber768_decaps(sk, c) == key
    ek, dk = mlkem.keygen()
    key2, c2 = Kyber768.encaps(ek)
    assert mlkem.kyber768_decaps(dk, c2) == key2, "ML-KEM generated keys serve Kyber round 3"
    key3, c3 = mlkem.kyber768_encaps(pk)
    assert Kyber768.decaps(sk, c3) == key3
    bad = bytearray(c3)
    bad[9] ^= 0x10
    assert Kyber768.decaps(sk, bytes(bad)) == mlkem.kyber768_decaps(sk, bytes(bad)), "implicit rejection agrees"


@pytest.mark.parametrize("backend", ["pure", None])
def test_keyshare_x25519mlkem768_both_backends(monkeypatch, backend):
    monkeypatch.setattr(keyexchange, "MLKEM_BACKEND", backend)
    share = keyexchange.KeyShare.generate(GROUP_X25519MLKEM768)
    assert len(share.public) == 1216
    expected = "pure" if backend == "pure" else keyexchange.mlkem768_backend()
    assert share.backend == expected
    server_share, server_secret = mlkem.x25519mlkem768_server_respond(share.public)
    assert share.exchange(server_share) == server_secret
    with pytest.raises(ValueError):
        share.exchange(server_share[:-1])


def test_keyshare_kyber_draft_group():
    share = keyexchange.KeyShare.generate(GROUP_X25519KYBER768DRAFT00)
    assert len(share.public) == 1216
    xpub, ek = share.public[:32], share.public[32:]
    server = X25519PrivateKey.generate()
    x_ss = server.exchange(__import__("cryptography.hazmat.primitives.asymmetric.x25519", fromlist=["X25519PublicKey"]).X25519PublicKey.from_public_bytes(xpub))
    k_ss, ct = mlkem.kyber768_encaps(ek)
    assert share.exchange(server.public_key().public_bytes_raw() + ct) == x_ss + k_ss, "X25519 secret first for the draft group"


def test_classical_groups_and_unknown():
    for group, pub_len in ((29, 32), (23, 65), (24, 97), (25, 133)):
        share = keyexchange.KeyShare.generate(group)
        assert len(share.public) == pub_len
        peer = keyexchange.KeyShare.generate(group)
        assert share.exchange(peer.public) == peer.exchange(share.public)
    assert not keyexchange.can_generate(256)
    with pytest.raises(NotImplementedError):
        keyexchange.KeyShare.generate(256)
    with pytest.raises(ValueError):
        keyexchange.KeyShare.generate(29).exchange(bytes(32))


def test_pure_mlkem_keygen_plus_decaps_stays_usable():
    # The pure-Python fallback only needs to stay cheap enough that a
    # handshake does not stall (~7 ms median on an M-series laptop under
    # load, ~0.1 ms through `cryptography`). 15 ms catches real regressions
    # without flaking on slow or busy CI runners.
    M = mlkem.ML_KEM_768
    ek, dk = M.keygen()
    ss, ct = M.encaps(ek)
    samples = []
    for _ in range(7):
        t0 = time.perf_counter()
        M.keygen()
        M.decaps(dk, ct)
        samples.append(time.perf_counter() - t0)
    median_ms = statistics.median(samples) * 1000
    assert median_ms < 15.0, "pure ML-KEM keygen+decaps took %.2f ms" % median_ms

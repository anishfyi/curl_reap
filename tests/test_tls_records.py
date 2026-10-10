"""Record-layer and key-schedule edge cases driven offline.

A fake "server" RecordCipher shares the engine's read secret so the tests can
craft encrypted records: fragmented and coalesced handshake messages,
zero-length and all-zero inner plaintexts, oversize records, alerts,
KeyUpdate in both directions, byte-wise TCP segmentation and CCS placement.
"""
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from curl_reap._tls import ApplicationData, Closed, NewTicket, TLSAlertReceived, TLSClient, TLSError, template
from curl_reap._tls import wire
from curl_reap._tls.consts import (
    AD_BAD_RECORD_MAC,
    AD_CLOSE_NOTIFY,
    AD_HANDSHAKE_FAILURE,
    AD_INTERNAL_ERROR,
    AD_RECORD_OVERFLOW,
    AD_UNEXPECTED_MESSAGE,
    CT_ALERT,
    CT_APPLICATION_DATA,
    CT_CHANGE_CIPHER_SPEC,
    CT_HANDSHAKE,
    HT_KEY_UPDATE,
    HT_NEW_SESSION_TICKET,
    MAX_CIPHERTEXT,
    MAX_PLAINTEXT,
    TLS12,
)
from curl_reap._tls.engine import S_CONNECTED
from curl_reap._tls.keyschedule import SUITES, KeySchedule, hkdf_expand_label
from curl_reap._tls.record import RecordCipher


def connected_engine(suite_id=0x1301):
    eng = TLSClient("example.com", template("chrome"), verify=False)
    eng.start()
    eng.data_to_send()
    suite = SUITES[suite_id]
    s_secret, c_secret = os.urandom(suite.hash_len), os.urandom(suite.hash_len)
    eng._suite = suite
    eng._schedule = KeySchedule(suite)
    eng._schedule.resumption_master_secret = os.urandom(suite.hash_len)
    eng._read_cipher = RecordCipher(suite, s_secret)
    eng._write_cipher = RecordCipher(suite, c_secret)
    eng.state = S_CONNECTED
    eng.handshake_complete = True
    server_w = RecordCipher(suite, s_secret)  # encrypts what the engine reads
    server_r = RecordCipher(suite, c_secret)  # decrypts what the engine writes
    return eng, server_w, server_r


def nst(size, lifetime=3600):
    body = wire.u32(lifetime) + wire.u32(1) + wire.vec8(b"\x00") + wire.vec16(os.urandom(size)) + wire.vec16(b"")
    return wire.handshake(HT_NEW_SESSION_TICKET, body)


@pytest.mark.parametrize("suite_id", [0x1301, 0x1302, 0x1303])
def test_fragmented_handshake_message_across_three_records(suite_id):
    eng, sw, sr = connected_engine(suite_id)
    msg = nst(5000)
    events = []
    for i in range(0, len(msg), 1700):
        events += eng.receive(sw.encrypt(CT_HANDSHAKE, msg[i:i + 1700]))
    assert eng.state == S_CONNECTED
    assert eng.stats["fragmented_messages"] == 2 and eng.stats["handshake_messages_in"] == 1
    assert not eng._hs_buf
    assert len(events) == 1 and isinstance(events[0], NewTicket) and len(events[0].ticket.ticket) == 5000


def test_coalesced_messages_and_split_header():
    eng, sw, sr = connected_engine()
    m1 = nst(10)
    m2 = wire.handshake(HT_KEY_UPDATE, b"\x00")
    m3 = nst(300)
    blob = m1 + m2 + m3
    events = eng.receive(sw.encrypt(CT_HANDSHAKE, blob[:len(m1) + len(m2) + 2]))
    sw.update()  # the engine updated its read keys after the KeyUpdate
    events += eng.receive(sw.encrypt(CT_HANDSHAKE, blob[len(m1) + len(m2) + 2:]))
    assert eng.stats["handshake_messages_in"] == 3 and eng.stats["coalesced_records"] == 1
    assert eng.key_updates_received == 1
    assert [type(e).__name__ for e in events] == ["NewTicket", "NewTicket"]


def test_key_update_requested_is_answered_and_write_keys_rotate():
    eng, sw, sr = connected_engine()
    eng.receive(sw.encrypt(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, b"\x01")))
    out = eng.data_to_send()
    t, content = sr.decrypt(out[:5], out[5:])
    assert t == CT_HANDSHAKE and content == wire.handshake(HT_KEY_UPDATE, b"\x00")
    sr.update()
    eng.send(b"hello")
    out2 = eng.data_to_send()
    assert sr.decrypt(out2[:5], out2[5:]) == (CT_APPLICATION_DATA, b"hello")
    assert eng.key_updates_sent == 1 and eng.key_updates_received == 1


def test_client_initiated_key_update():
    eng, sw, sr = connected_engine()
    eng.key_update(request_peer=True)
    out = eng.data_to_send()
    t, content = sr.decrypt(out[:5], out[5:])
    assert content == wire.handshake(HT_KEY_UPDATE, b"\x01")
    sr.update()
    eng.send(b"after")
    out = eng.data_to_send()
    assert sr.decrypt(out[:5], out[5:])[1] == b"after"
    # The peer answers; the engine rotates its read keys without replying again.
    eng.receive(sw.encrypt(CT_HANDSHAKE, wire.handshake(HT_KEY_UPDATE, b"\x00")))
    sw.update()
    assert eng.data_to_send() == b""
    assert eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"ok")) == [ApplicationData(b"ok")]


def test_zero_length_records():
    eng, sw, sr = connected_engine()
    assert eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"")) == []
    assert eng.state == S_CONNECTED and eng.stats["zero_length_app_records"] == 1
    with pytest.raises(TLSError) as info:
        eng.receive(sw.encrypt(CT_HANDSHAKE, b""))
    assert info.value.alert == AD_UNEXPECTED_MESSAGE
    assert eng.state == "FAILED"


def test_all_zero_inner_plaintext_rejected():
    eng, sw, sr = connected_engine()
    inner = bytes(20)
    nonce = sw._nonce()
    aad = wire.record_header(CT_APPLICATION_DATA, TLS12, len(inner) + 16)
    rec = aad + sw.keys.aead.encrypt(nonce, inner, aad)
    with pytest.raises(TLSError) as info:
        eng.receive(rec)
    assert info.value.alert == AD_BAD_RECORD_MAC


def test_padding_stripped_max_size_accepted_and_overflow_rejected():
    eng, sw, sr = connected_engine()
    assert eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"x" * 100, padding=500)) == [ApplicationData(b"x" * 100)]
    ev = eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"y" * (MAX_PLAINTEXT - 1)))
    assert len(ev) == 1 and len(ev[0].data) == MAX_PLAINTEXT - 1
    assert eng.stats["largest_record"] == MAX_PLAINTEXT + 16
    with pytest.raises(TLSError) as info:
        eng.receive(wire.record_header(CT_APPLICATION_DATA, TLS12, MAX_CIPHERTEXT + 1) + bytes(10))
    assert info.value.alert == AD_RECORD_OVERFLOW


def test_inner_plaintext_over_2_14_is_record_overflow():
    eng, sw, sr = connected_engine()
    inner = b"z" * (MAX_PLAINTEXT + 1) + bytes((CT_APPLICATION_DATA,))
    nonce = sw._nonce()
    aad = wire.record_header(CT_APPLICATION_DATA, TLS12, len(inner) + 16)
    rec = aad + sw.keys.aead.encrypt(nonce, inner, aad)
    with pytest.raises(TLSError) as info:
        eng.receive(rec)
    assert info.value.alert == AD_RECORD_OVERFLOW


def test_bad_record_mac_queues_a_fatal_alert():
    eng, sw, sr = connected_engine()
    rec = bytearray(sw.encrypt(CT_APPLICATION_DATA, b"tamper"))
    rec[-1] ^= 1
    with pytest.raises(TLSError) as info:
        eng.receive(bytes(rec))
    assert info.value.alert == AD_BAD_RECORD_MAC
    out = eng.data_to_send()
    assert len(out) == 5 + 2 + 1 + 16
    assert sr.decrypt(out[:5], out[5:]) == (CT_ALERT, bytes((2, AD_BAD_RECORD_MAC)))
    assert eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"ignored")) == []


def test_alerts_and_eof():
    eng, sw, sr = connected_engine()
    ev = eng.receive(sw.encrypt(CT_ALERT, bytes((1, AD_CLOSE_NOTIFY))))
    assert ev == [Closed("close_notify")] and ev[0].clean
    # Data after close_notify is ignored.
    assert eng.receive(sw.encrypt(CT_APPLICATION_DATA, b"late")) == []

    eng, sw, sr = connected_engine()
    with pytest.raises(TLSAlertReceived) as info:
        eng.receive(sw.encrypt(CT_ALERT, bytes((2, AD_HANDSHAKE_FAILURE))))
    assert info.value.name == "handshake_failure" and info.value.code == 35
    assert "handshake_failure" in str(info.value)

    # After the handshake every record must be encrypted: a plaintext alert
    # is an unexpected_message, not an alert we act on.
    eng, sw, sr = connected_engine()
    with pytest.raises(TLSError) as info:
        eng.receive(wire.record_header(CT_ALERT, TLS12, 2) + bytes((2, AD_INTERNAL_ERROR)))
    assert info.value.alert == AD_UNEXPECTED_MESSAGE
    # During the handshake a plaintext alert after the ServerHello is honoured
    # (servers abort that way when they reject something in the hello).
    eng3 = TLSClient("example.com", template("chrome"), verify=False)
    eng3.start()
    eng3._read_cipher = sw  # pretend keys are up but the handshake is not done
    eng3.state = "WAIT_EE"
    with pytest.raises(TLSAlertReceived) as info:
        eng3.receive(wire.record_header(CT_ALERT, TLS12, 2) + bytes((2, AD_INTERNAL_ERROR)))
    assert info.value.name == "internal_error"

    eng, sw, sr = connected_engine()
    ev = eng.receive(b"")
    assert ev == [Closed("eof")] and not ev[0].clean
    assert eng.closed


def test_user_canceled_warning_is_tolerated():
    eng, sw, sr = connected_engine()
    assert eng.receive(sw.encrypt(CT_ALERT, bytes((1, 90)))) == []
    assert eng.state == S_CONNECTED


def test_byte_wise_segmentation():
    eng, sw, sr = connected_engine()
    stream = sw.encrypt(CT_APPLICATION_DATA, b"A" * 3000) + sw.encrypt(CT_APPLICATION_DATA, b"B" * 10)
    got = b""
    for i in range(0, len(stream), 7):
        for e in eng.receive(stream[i:i + 7]):
            got += e.data
    assert got == b"A" * 3000 + b"B" * 10


def test_ccs_after_handshake_rejected():
    eng, sw, sr = connected_engine()
    with pytest.raises(TLSError) as info:
        eng.receive(wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x01")
    assert info.value.alert == AD_UNEXPECTED_MESSAGE


def test_ccs_during_handshake_is_dropped():
    eng = TLSClient("example.com", template("chrome"), verify=False)
    eng.start()
    assert eng.receive(wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x01") == []
    assert eng.state == "WAIT_SH" and eng.stats["ccs_records_in"] == 1
    with pytest.raises(TLSError):
        eng.receive(wire.record_header(CT_CHANGE_CIPHER_SPEC, TLS12, 1) + b"\x02")


def test_unknown_record_type_rejected():
    eng, sw, sr = connected_engine()
    with pytest.raises(TLSError) as info:
        eng.receive(bytes((0x17 + 10, 3, 3, 0, 1, 0)))
    assert info.value.alert == AD_UNEXPECTED_MESSAGE


def test_send_fragments_and_close_notify():
    eng, sw, sr = connected_engine()
    eng.send(b"q" * (MAX_PLAINTEXT * 2 + 5))
    out = eng.data_to_send()
    assert eng.stats["app_records_out"] == 3
    total = b""
    pos = 0
    while pos < len(out):
        length = (out[pos + 3] << 8) | out[pos + 4]
        total += sr.decrypt(out[pos:pos + 5], out[pos + 5:pos + 5 + length])[1]
        pos += 5 + length
    assert total == b"q" * (MAX_PLAINTEXT * 2 + 5)
    eng.close()
    out = eng.data_to_send()
    assert sr.decrypt(out[:5], out[5:]) == (CT_ALERT, bytes((1, AD_CLOSE_NOTIFY)))
    eng.close()
    assert eng.data_to_send() == b""
    with pytest.raises(TLSError):
        eng.send(b"after close")
    with pytest.raises(TLSError):
        eng.key_update()


def test_send_before_handshake_is_an_error():
    eng = TLSClient("example.com", template("chrome"), verify=False)
    with pytest.raises(TLSError):
        eng.send(b"x")
    eng.start()
    with pytest.raises(RuntimeError):
        eng.start()


def test_new_session_ticket_rules():
    eng, sw, sr = connected_engine()
    assert eng.receive(sw.encrypt(CT_HANDSHAKE, nst(16, lifetime=0))) == [], "lifetime 0 is discarded"
    with pytest.raises(TLSError):
        eng.receive(sw.encrypt(CT_HANDSHAKE, nst(16, lifetime=8 * 86400)))


def test_hkdf_expand_label_matches_cryptography():
    secret = os.urandom(32)
    label = b"tls13 c hs traffic"
    ctx = os.urandom(32)
    info = (32).to_bytes(2, "big") + bytes((len(label),)) + label + bytes((len(ctx),)) + ctx
    ref = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(secret)
    assert hkdf_expand_label("sha256", secret, "c hs traffic", ctx, 32) == ref
    info384 = (48).to_bytes(2, "big") + bytes((len(label),)) + label + bytes((len(ctx),)) + ctx
    ref384 = HKDFExpand(algorithm=hashes.SHA384(), length=48, info=info384).derive(secret)
    assert hkdf_expand_label("sha384", secret, "c hs traffic", ctx, 48) == ref384


def test_key_schedule_rfc8448_simple_1rtt():
    """RFC 8448 section 3: the handshake and application secrets from the
    shared secret and transcript hashes recorded in the RFC."""
    suite = SUITES[0x1301]
    shared = bytes.fromhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    ks = KeySchedule(suite)
    assert ks.early_secret == bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    th_sh = bytes.fromhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
    c_hs, s_hs = ks.set_shared_secret(shared, th_sh)
    assert ks.handshake_secret == bytes.fromhex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    assert c_hs == bytes.fromhex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    assert s_hs == bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    assert ks.master_secret == bytes.fromhex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    th_fin = bytes.fromhex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
    c_ap, s_ap = ks.application_secrets(th_fin)
    assert c_ap == bytes.fromhex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    assert s_ap == bytes.fromhex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    th_cfin = bytes.fromhex("2062c5ed05256e73b2a5a5a3e4fa6dbf2d0f0ebf6fe14e08d2b8d4e9e4c2a3ea")
    rms = ks.resumption_secret(th_cfin)
    assert len(rms) == 32

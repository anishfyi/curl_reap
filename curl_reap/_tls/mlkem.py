"""ML-KEM (FIPS 203, final, August 2024) in pure Python, plus the
X25519MLKEM768 TLS 1.3 hybrid glue from draft-ietf-tls-ecdhe-mlkem-05.

Dependencies: hashlib (sha3_256, sha3_512, shake_128, shake_256) and
os.urandom. Nothing else. ML-KEM-768 is the exported parameter set; the
PARAMS table also carries 512 and 1024 and every routine is parameterised
on it, so switching is MLKEM(512) or MLKEM(1024).

Layout of this file:
  1. constants and precomputed tables (zetas, gammas, CBD, compress)
  2. hash wrappers (PRF, H, J, G, XOF)
  3. byte encode/decode fused with compress/decompress for d = 1, 4, 10, 12,
     plus a generic path for d = 5, 11 (ML-KEM-1024)
  4. sampling: SampleNTT (rejection from SHAKE128), SamplePolyCBD
  5. NTT / inverse NTT (flat butterfly tables, lazy reduction, fused tail)
     and the base-case multiply-accumulate
  6. K-PKE and ML-KEM (internal + checked public API)
  7. X25519 (RFC 7748) and the X25519MLKEM768 client share / finish glue

Nothing here is constant time. Python cannot give that guarantee, and the
intended use (a TLS client key share that lives for one handshake) does not
need it: an attacker who can time this process can read its memory.
"""

from __future__ import annotations

import hashlib
import os
from itertools import chain

__all__ = [
    "MLKEM",
    "ML_KEM_768",
    "keygen",
    "encaps",
    "decaps",
    "keygen_internal",
    "encaps_internal",
    "decaps_internal",
    "x25519",
    "x25519_public",
    "x25519mlkem768_client_share",
    "x25519mlkem768_client_finish",
    "x25519mlkem768_server_respond",
    "X25519MLKEM768_GROUP_ID",
    "X25519MLKEM768_CLIENT_SHARE_LEN",
    "X25519MLKEM768_SERVER_SHARE_LEN",
    "X25519MLKEM768_SECRET_LEN",
    "kyber768_encaps",
    "kyber768_decaps",
]

# ----------------------------------------------------------------------------
# 1. constants and tables
# ----------------------------------------------------------------------------

N = 256
Q = 3329
ZETA = 17
N_INV = 3303  # 128^-1 mod q

# level -> (k, eta1, eta2, du, dv)
PARAMS = {
    512: (2, 3, 2, 10, 4),
    768: (3, 2, 2, 10, 4),
    1024: (4, 2, 2, 11, 5),
}


def _bitrev7(i: int) -> int:
    return int(f"{i:07b}"[::-1], 2)


# zetas[i] = zeta^BitRev7(i) mod q (FIPS 203 Appendix A)
ZETAS = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]
# gammas[i] = zeta^(2 BitRev7(i) + 1) mod q (BaseCaseMultiply)
GAMMAS = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def compress(d: int, x: int) -> int:
    """round((2^d / q) x) mod 2^d, rounding half up (FIPS 203 eq. 4.7)."""
    return (((x << (d + 1)) + Q) // (2 * Q)) & ((1 << d) - 1)


def decompress(d: int, y: int) -> int:
    """round((q / 2^d) y) (FIPS 203 eq. 4.8)."""
    return ((Q * y) + (1 << (d - 1))) >> d


# Table-driven compress / decompress. compress tables are indexed by x in
# [0, q); decompress tables by y in [0, 2^d).
_CMP = {d: [compress(d, x) for x in range(Q)] for d in (1, 4, 5, 10, 11)}
_DCMP = {d: [decompress(d, y) for y in range(1 << d)] for d in (1, 4, 5, 10, 11)}

# CBD eta=2: one byte holds two coefficients, 4 bits each
# (x = bits 0,1 ; y = bits 2,3) and (x = bits 4,5 ; y = bits 6,7).
_CBD2_LO = [((b & 1) + ((b >> 1) & 1) - ((b >> 2) & 1) - ((b >> 3) & 1)) % Q for b in range(256)]
_CBD2_HI = [(((b >> 4) & 1) + ((b >> 5) & 1) - ((b >> 6) & 1) - ((b >> 7) & 1)) % Q for b in range(256)]
# CBD eta=3: 6 bits per coefficient
_CBD3 = [(bin(v & 7).count("1") - bin(v >> 3).count("1")) % Q for v in range(64)]

# ByteDecode_1 fused with Decompress_1: a byte expands to 8 values in {0, 1665}
_BITS1_DCMP = [tuple(_DCMP[1][(b >> i) & 1] for i in range(8)) for b in range(256)]

_SH12 = [12 * i for i in range(16)]   # 24-byte chunk -> 16 coefficients
_SH10 = [10 * i for i in range(32)]   # 40-byte chunk -> 32 coefficients


# ----------------------------------------------------------------------------
# 2. hash wrappers (FIPS 203 Section 4.1)
# ----------------------------------------------------------------------------

def _prf(eta: int, s: bytes, b: int) -> bytes:
    return hashlib.shake_256(s + bytes((b,))).digest(64 * eta)


def _h(s: bytes) -> bytes:
    return hashlib.sha3_256(s).digest()


def _j(s: bytes) -> bytes:
    return hashlib.shake_256(s).digest(32)


def _g(c: bytes) -> tuple[bytes, bytes]:
    d = hashlib.sha3_512(c).digest()
    return d[:32], d[32:]


# ----------------------------------------------------------------------------
# 3. ByteEncode / ByteDecode (Algorithms 5, 6) fused with (de)compression
# ----------------------------------------------------------------------------

def _decode12(b: bytes, q: int = Q, sh=_SH12) -> list[int]:
    """ByteDecode_12: 384 bytes -> 256 coefficients, reduced mod q."""
    return [((x >> s) & 0xFFF) % q
            for x in (int.from_bytes(b[i:i + 24], "little") for i in range(0, 384, 24))
            for s in sh]


def _encode12(f: list[int]) -> bytes:
    """ByteEncode_12: 256 coefficients (< 4096) -> 384 bytes."""
    return b"".join(
        (c0 | c1 << 12 | c2 << 24 | c3 << 36 | c4 << 48 | c5 << 60 | c6 << 72 | c7 << 84
         | c8 << 96 | c9 << 108 | c10 << 120 | c11 << 132 | c12 << 144 | c13 << 156
         | c14 << 168 | c15 << 180).to_bytes(24, "little")
        for c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15
        in zip(*[f[i::16] for i in range(16)]))


def _decode10_decompress(b: bytes, t=_DCMP[10], sh=_SH10) -> list[int]:
    """Decompress_10(ByteDecode_10(b)): 320 bytes -> 256 coefficients."""
    return [t[(x >> s) & 1023]
            for x in (int.from_bytes(b[i:i + 40], "little") for i in range(0, 320, 40))
            for s in sh]


def _compress10_encode(f: list[int], t=_CMP[10]) -> bytes:
    """ByteEncode_10(Compress_10(f)): 256 coefficients -> 320 bytes."""
    return b"".join(
        (t[c0] | t[c1] << 10 | t[c2] << 20 | t[c3] << 30).to_bytes(5, "little")
        for c0, c1, c2, c3 in zip(f[0::4], f[1::4], f[2::4], f[3::4]))


def _decode4_decompress(b: bytes, t=_DCMP[4]) -> list[int]:
    """Decompress_4(ByteDecode_4(b)): 128 bytes -> 256 coefficients."""
    f = [0] * N
    f[0::2] = [t[x & 15] for x in b]
    f[1::2] = [t[x >> 4] for x in b]
    return f


def _compress4_encode(f: list[int], t=_CMP[4]) -> bytes:
    """ByteEncode_4(Compress_4(f)): 256 coefficients -> 128 bytes."""
    return bytes(t[a] | (t[b] << 4) for a, b in zip(f[0::2], f[1::2]))


def _decode1_decompress(m: bytes, t=_BITS1_DCMP) -> list[int]:
    """Decompress_1(ByteDecode_1(m)): 32 bytes -> 256 coefficients in {0, 1665}."""
    return list(chain.from_iterable(map(t.__getitem__, m)))


def _compress1_encode(w: list[int], t=_CMP[1]) -> bytes:
    """ByteEncode_1(Compress_1(w)): 256 coefficients -> 32 bytes."""
    b = [t[x] for x in w]
    return bytes(b0 | b1 << 1 | b2 << 2 | b3 << 3 | b4 << 4 | b5 << 5 | b6 << 6 | b7 << 7
                 for b0, b1, b2, b3, b4, b5, b6, b7 in zip(*[b[i::8] for i in range(8)]))


def _decode_generic(d: int, b: bytes, table=None) -> list[int]:
    """ByteDecode_d for any d (optionally mapped through a decompress table)."""
    x = int.from_bytes(b, "little")
    mask = (1 << d) - 1
    vals = [(x >> (d * i)) & mask for i in range(N)]
    if table is not None:
        return [table[v] for v in vals]
    return vals


def _encode_generic(d: int, vals: list[int]) -> bytes:
    """ByteEncode_d for any d (values already < 2^d)."""
    acc = 0
    for i in range(N - 1, -1, -1):
        acc = (acc << d) | vals[i]
    return acc.to_bytes(32 * d, "little")


def byte_encode(d: int, f: list[int]) -> bytes:
    """Plain ByteEncode_d (Algorithm 5), no compression. Public helper."""
    if d == 12:
        return _encode12(f)
    return _encode_generic(d, f)


def byte_decode(d: int, b: bytes) -> list[int]:
    """Plain ByteDecode_d (Algorithm 6), no decompression. Public helper."""
    if len(b) != 32 * d:
        raise ValueError(f"ByteDecode_{d} needs {32 * d} bytes, got {len(b)}")
    if d == 12:
        return _decode12(b)
    return _decode_generic(d, b)


def _decode_decompress(d: int, b: bytes) -> list[int]:
    if d == 10:
        return _decode10_decompress(b)
    if d == 4:
        return _decode4_decompress(b)
    if d == 1:
        return _decode1_decompress(b)
    return _decode_generic(d, b, _DCMP[d])


def _compress_encode(d: int, f: list[int]) -> bytes:
    if d == 10:
        return _compress10_encode(f)
    if d == 4:
        return _compress4_encode(f)
    if d == 1:
        return _compress1_encode(f)
    t = _CMP[d]
    return _encode_generic(d, [t[x] for x in f])


# ----------------------------------------------------------------------------
# 4. sampling (Algorithms 7, 8)
# ----------------------------------------------------------------------------

def sample_ntt(b34: bytes, q: int = Q, sh=_SH12) -> list[int]:
    """SampleNTT: rejection-sample 256 coefficients from SHAKE128(rho || j || i).

    Each 3-byte chunk C yields d1 = C0 + 256 (C1 mod 16) and
    d2 = floor(C1 / 16) + 16 C2, which are exactly the two little-endian
    12-bit fields of the chunk, so we parse 24-byte chunks as integers and
    pull 16 fields each. 504 bytes (3 SHAKE128 blocks) are enough with
    probability about 0.99; otherwise the stream is extended.
    """
    xof = hashlib.shake_128(b34)
    want = 504
    stream = xof.digest(want)
    out: list[int] = []
    pos = 0
    while True:
        vals = [(x >> s) & 0xFFF
                for x in (int.from_bytes(stream[i:i + 24], "little")
                          for i in range(pos, len(stream), 24))
                for s in sh]
        out += [v for v in vals if v < q]
        if len(out) >= N:
            del out[N:]
            return out
        pos = len(stream)
        want *= 2
        stream = xof.digest(want)


def sample_poly_cbd(eta: int, b: bytes) -> list[int]:
    """SamplePolyCBD_eta: 64 eta bytes -> 256 coefficients in [-eta, eta] mod q."""
    if len(b) != 64 * eta:
        raise ValueError(f"SamplePolyCBD_{eta} needs {64 * eta} bytes")
    if eta == 2:
        f = [0] * N
        f[0::2] = [_CBD2_LO[x] for x in b]
        f[1::2] = [_CBD2_HI[x] for x in b]
        return f
    if eta == 3:
        return _decode_generic(6, b, _CBD3)
    # generic (never reached for the three standard parameter sets)
    bits = [(b[i >> 3] >> (i & 7)) & 1 for i in range(8 * len(b))]
    return [(sum(bits[2 * i * eta:2 * i * eta + eta])
             - sum(bits[2 * i * eta + eta:2 * (i + 1) * eta])) % Q for i in range(N)]


# ----------------------------------------------------------------------------
# 5. NTT (Algorithms 9, 10, 11, 12)
# ----------------------------------------------------------------------------
#
# Layers are indexed 0..6 for len = 128, 64, 32, 16, 8, 4, 2. Each layer is a
# flat list of (j, j + len, zeta) butterflies so the hot loop has no nested
# range() bookkeeping. Reduction mod q is lazy: Python ints never overflow,
# so a layer may leave values unreduced (magnitude < q^2 after one layer,
# < q^3 after two) and the next reduced layer brings them back under q. The
# last three layers (len 8, 4, 2) act on disjoint 16-coefficient groups and
# are fused into one straight-line function that reduces once at the end.

def _layer_tables(forward: bool):
    tabs = []
    if forward:
        i = 1
        length = 128
        while length >= 2:
            tab = []
            for start in range(0, N, 2 * length):
                z = ZETAS[i]
                i += 1
                for j in range(start, start + length):
                    tab.append((j, j + length, z))
            tabs.append(tab)
            length >>= 1
    else:
        i = 127
        length = 2
        while length <= 128:
            tab = []
            for start in range(0, N, 2 * length):
                z = ZETAS[i]
                i -= 1
                for j in range(start, start + length):
                    tab.append((j, j + length, z))
            tabs.append(tab)
            length <<= 1
    return tabs


_FWD = _layer_tables(True)     # _FWD[0] is len 128 ... _FWD[6] is len 2
_INV = _layer_tables(False)    # _INV[0] is len 2 ... _INV[6] is len 128

# zetas for the fused tail, per 16-coefficient group g:
#   forward  len 8: ZETAS[16 + g]; len 4: ZETAS[32 + 2g + b]; len 2: ZETAS[64 + 4g + b]
#   inverse  len 2: ZETAS[127 - 4g - b]; len 4: ZETAS[63 - 2g - b]; len 8: ZETAS[31 - g]
_FWD_GROUP_Z = [
    (ZETAS[16 + g], ZETAS[32 + 2 * g], ZETAS[33 + 2 * g],
     ZETAS[64 + 4 * g], ZETAS[65 + 4 * g], ZETAS[66 + 4 * g], ZETAS[67 + 4 * g])
    for g in range(16)
]
_INV_GROUP_Z = [
    (ZETAS[127 - 4 * g], ZETAS[126 - 4 * g], ZETAS[125 - 4 * g], ZETAS[124 - 4 * g],
     ZETAS[63 - 2 * g], ZETAS[62 - 2 * g], ZETAS[31 - g])
    for g in range(16)
]


def _fwd_group16(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15,
                 z8, z4a, z4b, z2a, z2b, z2c, z2d, q=Q):
    # len 8
    t = z8 * a8; a8 = a0 - t; a0 += t
    t = z8 * a9; a9 = a1 - t; a1 += t
    t = z8 * a10; a10 = a2 - t; a2 += t
    t = z8 * a11; a11 = a3 - t; a3 += t
    t = z8 * a12; a12 = a4 - t; a4 += t
    t = z8 * a13; a13 = a5 - t; a5 += t
    t = z8 * a14; a14 = a6 - t; a6 += t
    t = z8 * a15; a15 = a7 - t; a7 += t
    # len 4
    t = z4a * a4; a4 = a0 - t; a0 += t
    t = z4a * a5; a5 = a1 - t; a1 += t
    t = z4a * a6; a6 = a2 - t; a2 += t
    t = z4a * a7; a7 = a3 - t; a3 += t
    t = z4b * a12; a12 = a8 - t; a8 += t
    t = z4b * a13; a13 = a9 - t; a9 += t
    t = z4b * a14; a14 = a10 - t; a10 += t
    t = z4b * a15; a15 = a11 - t; a11 += t
    # len 2
    t = z2a * a2; a2 = a0 - t; a0 += t
    t = z2a * a3; a3 = a1 - t; a1 += t
    t = z2b * a6; a6 = a4 - t; a4 += t
    t = z2b * a7; a7 = a5 - t; a5 += t
    t = z2c * a10; a10 = a8 - t; a8 += t
    t = z2c * a11; a11 = a9 - t; a9 += t
    t = z2d * a14; a14 = a12 - t; a12 += t
    t = z2d * a15; a15 = a13 - t; a13 += t
    return (a0 % q, a1 % q, a2 % q, a3 % q, a4 % q, a5 % q, a6 % q, a7 % q,
            a8 % q, a9 % q, a10 % q, a11 % q, a12 % q, a13 % q, a14 % q, a15 % q)


def _inv_group16(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15,
                 z2a, z2b, z2c, z2d, z4a, z4b, z8, q=Q):
    # len 2
    t = a0; a0 = t + a2; a2 = z2a * (a2 - t)
    t = a1; a1 = t + a3; a3 = z2a * (a3 - t)
    t = a4; a4 = t + a6; a6 = z2b * (a6 - t)
    t = a5; a5 = t + a7; a7 = z2b * (a7 - t)
    t = a8; a8 = t + a10; a10 = z2c * (a10 - t)
    t = a9; a9 = t + a11; a11 = z2c * (a11 - t)
    t = a12; a12 = t + a14; a14 = z2d * (a14 - t)
    t = a13; a13 = t + a15; a15 = z2d * (a15 - t)
    # len 4
    t = a0; a0 = t + a4; a4 = z4a * (a4 - t)
    t = a1; a1 = t + a5; a5 = z4a * (a5 - t)
    t = a2; a2 = t + a6; a6 = z4a * (a6 - t)
    t = a3; a3 = t + a7; a7 = z4a * (a7 - t)
    t = a8; a8 = t + a12; a12 = z4b * (a12 - t)
    t = a9; a9 = t + a13; a13 = z4b * (a13 - t)
    t = a10; a10 = t + a14; a14 = z4b * (a14 - t)
    t = a11; a11 = t + a15; a15 = z4b * (a15 - t)
    # len 8
    t = a0; a0 = t + a8; a8 = z8 * (a8 - t)
    t = a1; a1 = t + a9; a9 = z8 * (a9 - t)
    t = a2; a2 = t + a10; a10 = z8 * (a10 - t)
    t = a3; a3 = t + a11; a11 = z8 * (a11 - t)
    t = a4; a4 = t + a12; a12 = z8 * (a12 - t)
    t = a5; a5 = t + a13; a13 = z8 * (a13 - t)
    t = a6; a6 = t + a14; a14 = z8 * (a14 - t)
    t = a7; a7 = t + a15; a15 = z8 * (a15 - t)
    return (a0 % q, a1 % q, a2 % q, a3 % q, a4 % q, a5 % q, a6 % q, a7 % q,
            a8 % q, a9 % q, a10 % q, a11 % q, a12 % q, a13 % q, a14 % q, a15 % q)


# forward plan: layers 128 (lazy), 64 (reduce), 32 (lazy), 16 (reduce), then fused tail
_FWD_PLAN = ((_FWD[0], False), (_FWD[1], True), (_FWD[2], False), (_FWD[3], True))
# inverse plan: fused head (2, 4, 8), then 16 (lazy), 32 (reduce), 64 (lazy); 128 is
# folded with the n^-1 scaling (and an optional add / subtract) in ntt_inv.
_INV_PLAN = ((_INV[3], False), (_INV[4], True), (_INV[5], False))
_INV_LAST = _INV[6]


def ntt(f: list[int], q: int = Q, plan=_FWD_PLAN, g16=_fwd_group16, gz=_FWD_GROUP_Z) -> list[int]:
    """NTT (Algorithm 9). Input coefficients in [0, q); output in [0, q)."""
    f = list(f)
    for tab, red in plan:
        if red:
            for j, jl, z in tab:
                t = z * f[jl] % q
                f[jl] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        else:
            for j, jl, z in tab:
                t = z * f[jl]
                f[jl] = f[j] - t
                f[j] += t
    for g in range(16):
        s = g * 16
        f[s:s + 16] = g16(*f[s:s + 16], *gz[g])
    return f


def ntt_inv(f: list[int], add: list[int] | None = None, sub_from: list[int] | None = None,
            q: int = Q, ninv: int = N_INV, plan=_INV_PLAN, last=_INV_LAST,
            g16=_inv_group16, gz=_INV_GROUP_Z) -> list[int]:
    """Inverse NTT (Algorithm 10), optionally fused with a final
    `+ add` or `sub_from - result` so callers avoid an extra pass."""
    f = list(f)
    for g in range(16):
        s = g * 16
        f[s:s + 16] = g16(*f[s:s + 16], *gz[g])
    for tab, red in plan:
        if red:
            for j, jl, z in tab:
                t = f[j]
                f[j] = (t + f[jl]) % q
                f[jl] = z * (f[jl] - t) % q
        else:
            for j, jl, z in tab:
                t = f[j]
                f[j] = t + f[jl]
                f[jl] = z * (f[jl] - t)
    if add is not None:
        for j, jl, z in last:
            t = f[j]
            f[j] = ((t + f[jl]) * ninv + add[j]) % q
            f[jl] = (z * (f[jl] - t) * ninv + add[jl]) % q
    elif sub_from is not None:
        for j, jl, z in last:
            t = f[j]
            f[j] = (sub_from[j] - (t + f[jl]) * ninv) % q
            f[jl] = (sub_from[jl] - z * (f[jl] - t) * ninv) % q
    else:
        for j, jl, z in last:
            t = f[j]
            f[j] = (t + f[jl]) * ninv % q
            f[jl] = z * (f[jl] - t) * ninv % q
    return f


def _split(g: list[int], q: int = Q, gam=GAMMAS) -> tuple[list[int], list[int], list[int]]:
    """Pre-split an NTT-domain operand that is reused across several
    products: (even coefficients, odd coefficients, odd * gamma mod q)."""
    g1 = g[1::2]
    return g[0::2], g1, [b * z % q for b, z in zip(g1, gam)]


def multiply_ntts_acc(fs: list[list[int]], gs: list[tuple], add: list[int] | None = None,
                      q: int = Q) -> list[int]:
    """sum_i MultiplyNTTs(fs[i], gs[i]) (+ add), reduced once at the end.

    gs entries come from _split(). Implements Algorithms 11 and 12:
    c0 = a0 b0 + a1 b1 gamma, c1 = a0 b1 + a1 b0, per coefficient pair.
    """
    if add is None:
        acc0 = [0] * 128
        acc1 = [0] * 128
    else:
        acc0 = add[0::2]
        acc1 = add[1::2]
    for f, (g0, g1, g1g) in zip(fs, gs):
        f0 = f[0::2]
        f1 = f[1::2]
        acc0 = [s + a0 * b0 + a1 * b1g for s, a0, a1, b0, b1g in zip(acc0, f0, f1, g0, g1g)]
        acc1 = [s + a0 * b1 + a1 * b0 for s, a0, a1, b0, b1 in zip(acc1, f0, f1, g0, g1)]
    h = [0] * N
    h[0::2] = [x % q for x in acc0]
    h[1::2] = [x % q for x in acc1]
    return h


def multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    """MultiplyNTTs (Algorithm 11). Public helper."""
    return multiply_ntts_acc([f], [_split(g)])


# ----------------------------------------------------------------------------
# 6. K-PKE (Algorithms 13, 14, 15) and ML-KEM (Algorithms 16 to 21)
# ----------------------------------------------------------------------------

class MLKEM:
    """One ML-KEM parameter set. Use ML_KEM_768 unless you need another."""

    def __init__(self, level: int = 768):
        if level not in PARAMS:
            raise ValueError("level must be 512, 768 or 1024")
        self.level = level
        self.k, self.eta1, self.eta2, self.du, self.dv = PARAMS[level]
        k = self.k
        self.ek_len = 384 * k + 32
        self.dk_len = 768 * k + 96
        self.ct_len = 32 * (self.du * k + self.dv)
        self.ss_len = 32

    # -- K-PKE ---------------------------------------------------------------

    def _gen_matrix(self, rho: bytes) -> list[list[list[int]]]:
        """A_hat[i][j] = SampleNTT(rho || j || i) (bytes 33 and 34 are j, i)."""
        k = self.k
        return [[sample_ntt(rho + bytes((j, i))) for j in range(k)] for i in range(k)]

    def k_pke_keygen(self, d: bytes) -> tuple[bytes, bytes]:
        k, eta1 = self.k, self.eta1
        rho, sigma = _g(d + bytes((k,)))
        a_hat = self._gen_matrix(rho)
        s_hat = [ntt(sample_poly_cbd(eta1, _prf(eta1, sigma, n))) for n in range(k)]
        e_hat = [ntt(sample_poly_cbd(eta1, _prf(eta1, sigma, n))) for n in range(k, 2 * k)]
        s_split = [_split(p) for p in s_hat]
        t_hat = [multiply_ntts_acc(a_hat[i], s_split, e_hat[i]) for i in range(k)]
        ek = b"".join(map(_encode12, t_hat)) + rho
        dk = b"".join(map(_encode12, s_hat))
        return ek, dk

    def k_pke_encrypt(self, ek_pke: bytes, m: bytes, r: bytes) -> bytes:
        k, eta1, eta2, du, dv = self.k, self.eta1, self.eta2, self.du, self.dv
        t_hat = [_decode12(ek_pke[384 * i:384 * (i + 1)]) for i in range(k)]
        rho = ek_pke[384 * k:384 * k + 32]
        a_hat = self._gen_matrix(rho)
        y_hat = [ntt(sample_poly_cbd(eta1, _prf(eta1, r, n))) for n in range(k)]
        e1 = [sample_poly_cbd(eta2, _prf(eta2, r, n)) for n in range(k, 2 * k)]
        e2 = sample_poly_cbd(eta2, _prf(eta2, r, 2 * k))
        y_split = [_split(p) for p in y_hat]
        # u = NTT^-1(A_hat^T o y_hat) + e1
        u = [ntt_inv(multiply_ntts_acc([a_hat[j][i] for j in range(k)], y_split), add=e1[i])
             for i in range(k)]
        # v = NTT^-1(t_hat^T o y_hat) + e2 + mu
        mu = _decode1_decompress(m)
        e2mu = [(a + b) % Q for a, b in zip(e2, mu)]
        v = ntt_inv(multiply_ntts_acc(t_hat, y_split), add=e2mu)
        c1 = b"".join(_compress_encode(du, p) for p in u)
        c2 = _compress_encode(dv, v)
        return c1 + c2

    def k_pke_decrypt(self, dk_pke: bytes, c: bytes) -> bytes:
        k, du, dv = self.k, self.du, self.dv
        step = 32 * du
        u_hat = [ntt(_decode_decompress(du, c[step * i:step * (i + 1)])) for i in range(k)]
        v = _decode_decompress(dv, c[step * k:step * k + 32 * dv])
        s_split = [_split(_decode12(dk_pke[384 * i:384 * (i + 1)])) for i in range(k)]
        # w = v - NTT^-1(s_hat^T o NTT(u))
        w = ntt_inv(multiply_ntts_acc(u_hat, s_split), sub_from=v)
        return _compress_encode(1, w)

    # -- ML-KEM internal (Algorithms 16, 17, 18) -----------------------------

    def keygen_internal(self, d: bytes, z: bytes) -> tuple[bytes, bytes]:
        if len(d) != 32 or len(z) != 32:
            raise ValueError("d and z must be 32 bytes each")
        ek, dk_pke = self.k_pke_keygen(d)
        return ek, dk_pke + ek + _h(ek) + z

    def encaps_internal(self, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
        if len(m) != 32:
            raise ValueError("m must be 32 bytes")
        key, r = _g(m + _h(ek))
        return key, self.k_pke_encrypt(ek, m, r)

    def decaps_internal(self, dk: bytes, c: bytes) -> bytes:
        k = self.k
        dk_pke = dk[:384 * k]
        ek_pke = dk[384 * k:768 * k + 32]
        h = dk[768 * k + 32:768 * k + 64]
        z = dk[768 * k + 64:768 * k + 96]
        m2 = self.k_pke_decrypt(dk_pke, c)
        key2, r2 = _g(m2 + h)
        key_bar = _j(z + c)
        c2 = self.k_pke_encrypt(ek_pke, m2, r2)
        # implicit rejection: both candidates are always computed
        return key2 if c == c2 else key_bar

    # -- input checks (Section 7.2, 7.3) -----------------------------------------

    def check_ek(self, ek: bytes) -> None:
        """Encapsulation key check: type check (length) and modulus check
        (every 12-bit coefficient of the encoded t_hat is below q)."""
        if not isinstance(ek, (bytes, bytearray, memoryview)):
            raise TypeError("ek must be bytes")
        if len(ek) != self.ek_len:
            raise ValueError(f"ek must be {self.ek_len} bytes, got {len(ek)}")
        body = bytes(ek[:384 * self.k])
        for i in range(0, len(body), 24):
            x = int.from_bytes(body[i:i + 24], "little")
            for s in _SH12:
                if ((x >> s) & 0xFFF) >= Q:
                    raise ValueError("ek modulus check failed")

    def check_dk(self, dk: bytes, c: bytes) -> None:
        """Decapsulation input check: ciphertext type check, decapsulation
        key type check, and the hash check H(ek) == dk[768k+32 : 768k+64]."""
        if not isinstance(c, (bytes, bytearray, memoryview)):
            raise TypeError("c must be bytes")
        if not isinstance(dk, (bytes, bytearray, memoryview)):
            raise TypeError("dk must be bytes")
        if len(c) != self.ct_len:
            raise ValueError(f"c must be {self.ct_len} bytes, got {len(c)}")
        if len(dk) != self.dk_len:
            raise ValueError(f"dk must be {self.dk_len} bytes, got {len(dk)}")
        k = self.k
        if _h(bytes(dk[384 * k:768 * k + 32])) != bytes(dk[768 * k + 32:768 * k + 64]):
            raise ValueError("dk hash check failed")

    # -- public API (Algorithms 19, 20, 21) ---------------------------------------

    def keygen(self) -> tuple[bytes, bytes]:
        """ML-KEM.KeyGen -> (ek, dk)."""
        return self.keygen_internal(os.urandom(32), os.urandom(32))

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        """ML-KEM.Encaps(ek) -> (shared secret K, ciphertext c)."""
        self.check_ek(ek)
        return self.encaps_internal(bytes(ek), os.urandom(32))

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        """ML-KEM.Decaps(dk, c) -> shared secret K (implicit rejection on bad c)."""
        self.check_dk(dk, c)
        return self.decaps_internal(bytes(dk), bytes(c))


ML_KEM_768 = MLKEM(768)

keygen = ML_KEM_768.keygen
encaps = ML_KEM_768.encaps
decaps = ML_KEM_768.decaps
keygen_internal = ML_KEM_768.keygen_internal
encaps_internal = ML_KEM_768.encaps_internal
decaps_internal = ML_KEM_768.decaps_internal


# ----------------------------------------------------------------------------
# 7. X25519 (RFC 7748) and the X25519MLKEM768 glue (draft-ietf-tls-ecdhe-mlkem-05)
# ----------------------------------------------------------------------------

_P25519 = (1 << 255) - 19
_A24 = 121665


def x25519(scalar: bytes, u: bytes) -> bytes:
    """X25519(k, u) per RFC 7748 Section 5. Pure Python Montgomery ladder.

    Not constant time. If the `cryptography` package is importable, the
    glue below prefers it; this is the dependency-free fallback.
    """
    if len(scalar) != 32 or len(u) != 32:
        raise ValueError("X25519 scalar and u-coordinate must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    p = _P25519
    a24 = _A24
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        s = da + cb
        x3 = s * s % p
        s = da - cb
        z3 = x1 * s * s % p
        x2 = aa * bb % p
        z2 = e * (aa + a24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def x25519_public(private: bytes) -> bytes:
    """X25519 public key for a 32-byte private scalar (u = 9)."""
    return x25519(private, b"\x09" + b"\x00" * 31)


def _x25519_exchange(private, peer_public: bytes) -> bytes:
    """Accepts a 32-byte private scalar or a `cryptography` X25519PrivateKey
    (anything with .exchange())."""
    if hasattr(private, "exchange"):
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        except ImportError as exc:  # pragma: no cover
            raise TypeError("key object given but cryptography is not importable") from exc
        return private.exchange(X25519PublicKey.from_public_bytes(peer_public))
    private = bytes(private)
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    except ImportError:
        return x25519(private, peer_public)
    return X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(peer_public))


X25519MLKEM768_GROUP_ID = 0x11EC  # 4588
X25519MLKEM768_CLIENT_SHARE_LEN = 1184 + 32   # ML-KEM-768 ek || X25519 public
X25519MLKEM768_SERVER_SHARE_LEN = 1088 + 32   # ML-KEM-768 ciphertext || X25519 public
X25519MLKEM768_SECRET_LEN = 32 + 32           # ML-KEM-768 shared secret || X25519 shared secret


def x25519mlkem768_client_share(x25519_public_bytes: bytes) -> tuple[bytes, bytes]:
    """Build the client's X25519MLKEM768 key_exchange value.

    draft-ietf-tls-ecdhe-mlkem-05 Section 4.1: "the client's key_exchange
    value is the concatenation of the client's ML-KEM-768 encapsulation key
    and the client's X25519 ephemeral share. The size of the client share is
    1216 bytes (1184 bytes for the ML-KEM part and 32 bytes for X25519)."

    Returns (share, state). `state` is the ML-KEM decapsulation key (2400
    bytes); keep it with the X25519 private key until the ServerHello.
    """
    x25519_public_bytes = bytes(x25519_public_bytes)
    if len(x25519_public_bytes) != 32:
        raise ValueError("X25519 public share must be 32 bytes")
    ek, dk = ML_KEM_768.keygen()
    return ek + x25519_public_bytes, dk


def x25519mlkem768_client_finish(state: bytes, server_share: bytes, x25519_private) -> bytes:
    """Derive the 64-byte hybrid shared secret from the server's key_exchange.

    draft-ietf-tls-ecdhe-mlkem-05 Section 4.2: "the server's key exchange
    value is the concatenation of an ML-KEM ciphertext returned from
    encapsulation to the client's encapsulation key, and the server's
    ephemeral X25519 share. The size of the server share is 1120 bytes
    (1088 bytes for the ML-KEM part and 32 bytes for X25519)."
    Section 4.3: "the shared secret is the concatenation of the ML-KEM
    shared secret and the X25519 shared secret. The shared secret is 64
    bytes (32 bytes for each part)."

    `x25519_private` is the client's 32-byte X25519 private scalar or a
    `cryptography` X25519PrivateKey. Raises ValueError on a malformed share
    or an all-zero X25519 result (RFC 8446 Section 7.4.2); an ML-KEM
    ciphertext that fails to decapsulate is handled by implicit rejection
    and surfaces later as a Finished mismatch, as the draft requires.
    """
    server_share = bytes(server_share)
    if len(server_share) != X25519MLKEM768_SERVER_SHARE_LEN:
        raise ValueError(
            f"X25519MLKEM768 server share must be {X25519MLKEM768_SERVER_SHARE_LEN} bytes, "
            f"got {len(server_share)}")
    ct = server_share[:1088]
    peer_x25519 = server_share[1088:]
    ss_mlkem = ML_KEM_768.decaps(state, ct)
    ss_x25519 = _x25519_exchange(x25519_private, peer_x25519)
    if ss_x25519 == bytes(32):
        raise ValueError("all-zero X25519 shared secret")
    return ss_mlkem + ss_x25519


def x25519mlkem768_server_respond(client_share: bytes, x25519_private=None) -> tuple[bytes, bytes]:
    """Server side, for tests and loopback: consume a 1216-byte client share,
    return (server_share 1120 bytes, shared_secret 64 bytes)."""
    client_share = bytes(client_share)
    if len(client_share) != X25519MLKEM768_CLIENT_SHARE_LEN:
        raise ValueError(
            f"X25519MLKEM768 client share must be {X25519MLKEM768_CLIENT_SHARE_LEN} bytes, "
            f"got {len(client_share)}")
    ek = client_share[:1184]
    client_x25519 = client_share[1184:]
    ss_mlkem, ct = ML_KEM_768.encaps(ek)
    if x25519_private is None:
        x25519_private = os.urandom(32)
    if hasattr(x25519_private, "public_key"):
        server_pub = x25519_private.public_key().public_bytes_raw()
    else:
        server_pub = x25519_public(bytes(x25519_private))
    ss_x25519 = _x25519_exchange(x25519_private, client_x25519)
    if ss_x25519 == bytes(32):
        raise ValueError("all-zero X25519 shared secret")
    return ct + server_pub, ss_mlkem + ss_x25519


# ----------------------------------------------------------------------------
# 8. Kyber768 round 3 (draft-tls-westerbaan-xyber768d00) on the same K-PKE
# ----------------------------------------------------------------------------
#
# Chrome 124 (curl_cffi's chrome124 target) still offers X25519Kyber768Draft00
# (group 0x6399). Kyber round 3 and FIPS 203 share K-PKE, the encapsulation key
# layout (t || rho) and the decapsulation key layout (s || ek || H(ek) || z);
# they differ only in how the shared secret is derived: Kyber hashes the
# random message first (m = H(m)), derives K_bar with G(m || H(ek)) and then
# outputs K = SHAKE256(K_bar || H(c)); implicit rejection outputs
# SHAKE256(z || H(c)). ML-KEM keys therefore work unchanged for Kyber as long
# as these two routines are used instead of encaps/decaps.


def _kdf(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)


def kyber768_encaps(ek: bytes, m: bytes | None = None) -> tuple[bytes, bytes]:
    """Kyber768.Encaps (round 3): returns (shared secret, ciphertext)."""
    M = ML_KEM_768
    M.check_ek(ek)
    ek = bytes(ek)
    m = _h(os.urandom(32) if m is None else bytes(m))
    k_bar, r = _g(m + _h(ek))
    c = M.k_pke_encrypt(ek, m, r)
    return _kdf(k_bar + _h(c)), c


def kyber768_decaps(dk: bytes, c: bytes) -> bytes:
    """Kyber768.Decaps (round 3) for a decapsulation key in ML-KEM layout."""
    M = ML_KEM_768
    M.check_dk(dk, c)
    dk = bytes(dk)
    c = bytes(c)
    k = M.k
    dk_pke = dk[:384 * k]
    ek_pke = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m2 = M.k_pke_decrypt(dk_pke, c)
    k_bar2, r2 = _g(m2 + h)
    c2 = M.k_pke_encrypt(ek_pke, m2, r2)
    hc = _h(c)
    return _kdf(k_bar2 + hc) if c == c2 else _kdf(z + hc)

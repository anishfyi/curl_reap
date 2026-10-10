"""Wire constants for TLS 1.3 (RFC 8446) plus the extensions browsers emit.

Everything here is a plain integer or a lookup table so the rest of the
package stays free of magic numbers. Names follow the IANA registries.
"""
from __future__ import annotations

# Record layer content types.
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# Handshake message types.
HT_CLIENT_HELLO = 1
HT_SERVER_HELLO = 2
HT_NEW_SESSION_TICKET = 4
HT_END_OF_EARLY_DATA = 5
HT_ENCRYPTED_EXTENSIONS = 8
HT_CERTIFICATE = 11
HT_CERTIFICATE_REQUEST = 13
HT_CERTIFICATE_VERIFY = 15
HT_FINISHED = 20
HT_KEY_UPDATE = 24
HT_COMPRESSED_CERTIFICATE = 25
HT_MESSAGE_HASH = 254

HANDSHAKE_NAMES = {
    HT_CLIENT_HELLO: "client_hello",
    HT_SERVER_HELLO: "server_hello",
    HT_NEW_SESSION_TICKET: "new_session_ticket",
    HT_END_OF_EARLY_DATA: "end_of_early_data",
    HT_ENCRYPTED_EXTENSIONS: "encrypted_extensions",
    HT_CERTIFICATE: "certificate",
    HT_CERTIFICATE_REQUEST: "certificate_request",
    HT_CERTIFICATE_VERIFY: "certificate_verify",
    HT_FINISHED: "finished",
    HT_KEY_UPDATE: "key_update",
    HT_COMPRESSED_CERTIFICATE: "compressed_certificate",
    HT_MESSAGE_HASH: "message_hash",
}

# Extension types.
EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SCT = 18
EXT_PADDING = 21
EXT_EXTENDED_MASTER_SECRET = 23
EXT_COMPRESS_CERTIFICATE = 27
EXT_RECORD_SIZE_LIMIT = 28
EXT_DELEGATED_CREDENTIALS = 34
EXT_SESSION_TICKET = 35
EXT_PRE_SHARED_KEY = 41
EXT_EARLY_DATA = 42
EXT_SUPPORTED_VERSIONS = 43
EXT_COOKIE = 44
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_POST_HANDSHAKE_AUTH = 49
EXT_SIGNATURE_ALGORITHMS_CERT = 50
EXT_KEY_SHARE = 51
EXT_APPLICATION_SETTINGS_OLD = 0x4469
EXT_APPLICATION_SETTINGS = 0x44CD
EXT_ECH = 0xFE0D
EXT_RENEGOTIATION_INFO = 0xFF01

EXT_NAMES = {
    EXT_SERVER_NAME: "server_name",
    EXT_STATUS_REQUEST: "status_request",
    EXT_SUPPORTED_GROUPS: "supported_groups",
    EXT_EC_POINT_FORMATS: "ec_point_formats",
    EXT_SIGNATURE_ALGORITHMS: "signature_algorithms",
    EXT_ALPN: "application_layer_protocol_negotiation",
    EXT_SCT: "signed_certificate_timestamp",
    EXT_PADDING: "padding",
    EXT_EXTENDED_MASTER_SECRET: "extended_master_secret",
    EXT_COMPRESS_CERTIFICATE: "compress_certificate",
    EXT_RECORD_SIZE_LIMIT: "record_size_limit",
    EXT_DELEGATED_CREDENTIALS: "delegated_credentials",
    EXT_SESSION_TICKET: "session_ticket",
    EXT_PRE_SHARED_KEY: "pre_shared_key",
    EXT_EARLY_DATA: "early_data",
    EXT_SUPPORTED_VERSIONS: "supported_versions",
    EXT_COOKIE: "cookie",
    EXT_PSK_KEY_EXCHANGE_MODES: "psk_key_exchange_modes",
    EXT_POST_HANDSHAKE_AUTH: "post_handshake_auth",
    EXT_SIGNATURE_ALGORITHMS_CERT: "signature_algorithms_cert",
    EXT_KEY_SHARE: "key_share",
    EXT_APPLICATION_SETTINGS_OLD: "application_settings_old",
    EXT_APPLICATION_SETTINGS: "application_settings",
    EXT_ECH: "encrypted_client_hello",
    EXT_RENEGOTIATION_INFO: "renegotiation_info",
}
EXT_BY_NAME = {name: value for value, name in EXT_NAMES.items()}

# Cipher suites. Only the TLS 1.3 suites are negotiable by this engine; the
# TLS 1.2 ones are offered so the ClientHello looks like a browser.
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
TLS13_SUITES = (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA",
    0xC008: "ECDHE-ECDSA-DES-CBC3-SHA",
    0xC012: "ECDHE-RSA-DES-CBC3-SHA",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
    0x000A: "DES-CBC3-SHA",
}

# Named groups.
GROUP_SECP256R1 = 23
GROUP_SECP384R1 = 24
GROUP_SECP521R1 = 25
GROUP_X25519 = 29
GROUP_X448 = 30
GROUP_FFDHE2048 = 256
GROUP_FFDHE3072 = 257
GROUP_X25519MLKEM768 = 0x11EC  # 4588, draft-ietf-tls-ecdhe-mlkem
GROUP_X25519KYBER768DRAFT00 = 0x6399  # 25497, draft-tls-westerbaan-xyber768d00

GROUP_NAMES = {
    GROUP_SECP256R1: "P-256",
    GROUP_SECP384R1: "P-384",
    GROUP_SECP521R1: "P-521",
    GROUP_X25519: "X25519",
    GROUP_X448: "X448",
    GROUP_FFDHE2048: "ffdhe2048",
    GROUP_FFDHE3072: "ffdhe3072",
    GROUP_X25519MLKEM768: "X25519MLKEM768",
    GROUP_X25519KYBER768DRAFT00: "X25519Kyber768Draft00",
}

# Signature schemes.
SIG_RSA_PKCS1_SHA1 = 0x0201
SIG_ECDSA_SHA1 = 0x0203
SIG_RSA_PKCS1_SHA256 = 0x0401
SIG_RSA_PKCS1_SHA384 = 0x0501
SIG_RSA_PKCS1_SHA512 = 0x0601
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_ECDSA_SECP384R1_SHA384 = 0x0503
SIG_ECDSA_SECP521R1_SHA512 = 0x0603
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_RSA_PSS_RSAE_SHA384 = 0x0805
SIG_RSA_PSS_RSAE_SHA512 = 0x0806
SIG_ED25519 = 0x0807
SIG_ED448 = 0x0808
SIG_RSA_PSS_PSS_SHA256 = 0x0809
SIG_RSA_PSS_PSS_SHA384 = 0x080A
SIG_RSA_PSS_PSS_SHA512 = 0x080B
SIG_MLDSA44 = 0x0904
SIG_MLDSA65 = 0x0905
SIG_MLDSA87 = 0x0906

SIGALG_NAMES = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
}

# Certificate compression algorithms (RFC 8879).
CERT_COMPRESSION_ZLIB = 1
CERT_COMPRESSION_BROTLI = 2
CERT_COMPRESSION_ZSTD = 3
CERT_COMPRESSION_NAMES = {1: "zlib", 2: "brotli", 3: "zstd"}
CERT_COMPRESSION_BY_NAME = {"zlib": 1, "brotli": 2, "zstd": 3}

# PSK key exchange modes.
PSK_KE = 0
PSK_DHE_KE = 1

# Versions.
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304
VERSION_NAMES = {TLS10: "TLSv1", TLS11: "TLSv1.1", TLS12: "TLSv1.2", TLS13: "TLSv1.3"}

# RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa.
GREASE_VALUES = tuple((((i << 4) | 0x0A) << 8 | ((i << 4) | 0x0A)) for i in range(16))


def is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) == (value & 0xFF))


# SHA-256("HelloRetryRequest"), RFC 8446 section 4.1.3.
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)
DOWNGRADE_TLS12 = bytes.fromhex("444F574E47524401")
DOWNGRADE_TLS11 = bytes.fromhex("444F574E47524400")

# HPKE identifiers used by the ECH GREASE extension.
HPKE_KDF_HKDF_SHA256 = 0x0001
HPKE_AEAD_AES_128_GCM = 0x0001
HPKE_AEAD_CHACHA20_POLY1305 = 0x0003

# Alerts.
ALERT_LEVEL_WARNING = 1
ALERT_LEVEL_FATAL = 2
AD_CLOSE_NOTIFY = 0
AD_UNEXPECTED_MESSAGE = 10
AD_BAD_RECORD_MAC = 20
AD_RECORD_OVERFLOW = 22
AD_HANDSHAKE_FAILURE = 40
AD_BAD_CERTIFICATE = 42
AD_UNSUPPORTED_CERTIFICATE = 43
AD_CERTIFICATE_REVOKED = 44
AD_CERTIFICATE_EXPIRED = 45
AD_CERTIFICATE_UNKNOWN = 46
AD_ILLEGAL_PARAMETER = 47
AD_UNKNOWN_CA = 48
AD_ACCESS_DENIED = 49
AD_DECODE_ERROR = 50
AD_DECRYPT_ERROR = 51
AD_PROTOCOL_VERSION = 70
AD_INSUFFICIENT_SECURITY = 71
AD_INTERNAL_ERROR = 80
AD_INAPPROPRIATE_FALLBACK = 86
AD_USER_CANCELED = 90
AD_MISSING_EXTENSION = 109
AD_UNSUPPORTED_EXTENSION = 110
AD_UNRECOGNIZED_NAME = 112
AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113
AD_UNKNOWN_PSK_IDENTITY = 115
AD_CERTIFICATE_REQUIRED = 116
AD_NO_APPLICATION_PROTOCOL = 120

ALERT_NAMES = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}

MAX_PLAINTEXT = 1 << 14
MAX_CIPHERTEXT = (1 << 14) + 256
MAX_TICKET_LIFETIME = 7 * 24 * 3600

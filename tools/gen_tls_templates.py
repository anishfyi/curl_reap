"""Generate curl_reap/_tls/templates_data.py from tools/hello_templates/*.json.

Every ``<target>.json`` capture (``peet_*.json`` and INDEX.md are skipped) is
reduced to the fields the ClientHello builder needs plus the recorded
fingerprints, and written as one plain dict per target in ``TEMPLATES``. The
output is deterministic: targets and keys are sorted, so a rerun with the same
inputs produces an identical file.

Usage::

    python tools/gen_tls_templates.py            # writes the module
    python tools/gen_tls_templates.py --check    # exit 1 if it would change
"""
from __future__ import annotations

import glob
import json
import os
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE_DIR = os.path.join(HERE, "hello_templates")
OUTPUT = os.path.join(ROOT, "curl_reap", "_tls", "templates_data.py")

# Keys dropped from every extension's params: they are human-facing names of
# the numeric fields kept next to them, or per-connection data (host names).
_DROP_PARAM_KEYS = ("host_names",)
_DROP_PARAM_SUFFIXES = ("_names", "_name")


def family_of(target: str) -> str:
    for family in ("chrome", "edge", "firefox", "safari", "tor"):
        if target.startswith(family):
            return family
    return "custom"


def clean_params(params: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in params.items():
        if key in _DROP_PARAM_KEYS or key.endswith(_DROP_PARAM_SUFFIXES):
            continue
        if key == "shares":
            value = [{"group": s["group"], "key_length": s["key_length"]} for s in value]
        out[key] = value
    return out


def reduce_template(doc: Dict[str, Any]) -> Dict[str, Any]:
    exts: List[Dict[str, Any]] = []
    for ext in doc["extensions"]:
        entry: Dict[str, Any] = {
            "type": ext["type"],
            "name": ext["name"],
            "position": ext["position"],
            "params": clean_params(ext.get("params", {})),
        }
        if ext.get("body_fixed") and ext.get("body_hex") is not None:
            entry["body_hex"] = ext["body_hex"]
        exts.append(entry)
    ech = doc.get("ech")
    if ech:
        ech = {
            "kdf_id": ech["kdf_id"],
            "aead_id": ech["aead_id"],
            "enc_len": ech["enc_len"],
            "payload_len_seen": sorted(ech.get("payload_len_seen", [])),
        }
    padding = doc.get("padding_length")
    if isinstance(padding, dict):
        padding = padding.get("min")
    fp = doc["fingerprints"]
    peet = doc.get("peet_live") or {}
    return {
        "target": doc["target"],
        "alias_of": doc.get("alias_of"),
        "family": family_of(doc["target"]),
        "source": doc.get("source"),
        "captured_at": doc.get("captured_at"),
        "record_version": doc["record_version"],
        "legacy_version": doc["legacy_version"],
        "session_id_len": doc["session_id_len"],
        "compression_methods": doc["compression_methods"],
        "cipher_suites": doc["cipher_suites"],
        "extensions": exts,
        "extension_order_fixed": doc["extension_order_fixed"],
        "extension_fixed_prefix": doc["extension_fixed_prefix"],
        "extension_fixed_suffix": doc["extension_fixed_suffix"],
        "supported_groups": doc["supported_groups"],
        "signature_algorithms": doc["signature_algorithms"],
        "key_share": [{"group": s["group"], "key_length": s["key_length"]} for s in doc["key_share"]],
        "alpn": doc["alpn"],
        "alps": doc.get("alps"),
        "alps_codepoint": doc.get("alps_codepoint"),
        "supported_versions": doc["supported_versions"],
        "psk_key_exchange_modes": doc.get("psk_key_exchange_modes") or [],
        "compress_certificate": doc.get("compress_certificate") or [],
        "ec_point_formats": doc.get("ec_point_formats") or [],
        "record_size_limit": doc.get("record_size_limit"),
        "delegated_credentials": doc.get("delegated_credentials"),
        "padding_length": padding,
        "ech": ech,
        "handshake_length": doc["handshake_length"],
        "fingerprints": {
            "ja3": fp["ja3"],
            "ja3_hash": fp["ja3_hash"],
            "ja3_stable": fp["ja3_stable"],
            "ja4": fp["ja4"],
            "ja4_r": fp["ja4_r"],
        },
        "peet_live": {
            "ja3_hash": peet.get("ja3_hash"),
            "ja4": peet.get("ja4"),
            "ja4_r": peet.get("ja4_r"),
            "peetprint_hash": peet.get("peetprint_hash"),
            "akamai": peet.get("akamai"),
            "http_version": peet.get("http_version"),
        },
    }


def _literal(value: Any, indent: int) -> str:
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = ["{"]
        for key in sorted(value):
            lines.append("%s    %r: %s," % (pad, key, _literal(value[key], indent + 4)))
        lines.append(pad + "}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(v, (dict, list)) for v in value):
            return "[" + ", ".join(repr(v) for v in value) + "]"
        lines = ["["]
        for item in value:
            lines.append("%s    %s," % (pad, _literal(item, indent + 4)))
        lines.append(pad + "]")
        return "\n".join(lines)
    return repr(value)


def load_sources() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for path in sorted(glob.glob(os.path.join(SOURCE_DIR, "*.json"))):
        name = os.path.basename(path)[:-5]
        if name.startswith("peet_"):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        out[name] = reduce_template(doc)
    return out


def render(templates: Dict[str, Dict[str, Any]]) -> str:
    sources = sorted({t["source"] for t in templates.values() if t.get("source")})
    dates = sorted({(t.get("captured_at") or "")[:10] for t in templates.values()})
    header = (
        '"""ClientHello templates captured from curl_cffi, one per impersonate target.\n'
        "\n"
        "Generated by tools/gen_tls_templates.py from tools/hello_templates/*.json.\n"
        "Do not edit by hand: rerun the generator after a new capture.\n"
        "\n"
        "Source: %s, captured %s.\n"
        "Targets: %s.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "\n"
        "TEMPLATES = %s\n"
        "\n"
        "__all__ = [\"TEMPLATES\"]\n"
    ) % (
        ", ".join(sources) or "unknown",
        ", ".join(d for d in dates if d) or "unknown",
        ", ".join(sorted(templates)),
        _literal(templates, 0),
    )
    return header


def main(argv: List[str]) -> int:
    templates = load_sources()
    text = render(templates)
    if "--check" in argv:
        try:
            with open(OUTPUT, "r", encoding="utf-8") as fh:
                current = fh.read()
        except OSError:
            current = ""
        if current != text:
            print("templates_data.py is out of date; rerun tools/gen_tls_templates.py", file=sys.stderr)
            return 1
        print("templates_data.py is up to date (%d targets)" % len(templates))
        return 0
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s with %d targets" % (OUTPUT, len(templates)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

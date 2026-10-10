#!/usr/bin/env python
"""Generate ``curl_reap/_profiles_data.py`` from the curl_cffi captures.

Inputs are the JSON templates written by ``tools/capture_h2.py``
(``tools/h2_templates/<target>.json``: HTTP/1.1 header order, HTTP/2 header
list, SETTINGS and the Akamai string) and ``tools/capture_clienthello.py``
(``tools/hello_templates/<target>.json``: the TLS ClientHello).  The output
is a plain Python module with three tables:

``CONCRETE``
    One entry per captured reference-client target: family, version, platform, the
    HTTP/1.1 header set exactly as curl_cffi sends it minus the libcurl
    artefacts (Host, Upgrade, HTTP2-Settings, Connection), the HTTP/2 header
    set exactly as curl_cffi sends it (lowercase, pseudo headers removed),
    the names of the ClientHello template and the HTTP/2 spec, the
    Accept-Encoding value and the multipart boundary rule.

``ALIASES``
    curl_cffi's alias map (``chrome`` -> ``chrome150`` and so on) plus the
    deprecated spellings the reference client still accepts.  Aliases captured under
    their own name are checked against the concrete target before the module
    is written, so an alias can never drift from its target.

``LEGACY``
    curl_reap 1.x target names that curl_cffi never had (chrome98, edge131,
    firefox127, safari16_0 and friends).  Each one borrows the TLS template,
    the HTTP/2 spec and the header set of the nearest captured target of its
    family and substitutes its own version number into User-Agent and
    sec-ch-ua.  They are approximations and the generated module says so.

Usage::

    .venv/bin/python tools/gen_profiles.py            # writes curl_reap/_profiles_data.py
    .venv/bin/python tools/gen_profiles.py --check    # exit 1 when the file is stale
    .venv/bin/python tools/gen_profiles.py --templates-data   # also emit _tls/_h2 template modules

The generator has no dependency on curl_cffi; when curl_cffi is importable
the family, version and platform of every concrete target are cross-checked
against its native target table and a mismatch aborts the run.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HELLO_DIR = os.path.join(HERE, "hello_templates")
H2_DIR = os.path.join(HERE, "h2_templates")
DEFAULT_OUT = os.path.join(ROOT, "curl_reap", "_profiles_data.py")

HeaderList = List[Tuple[str, str]]

# libcurl adds these on plain-http requests (h2c upgrade) and the transport
# writes its own Host, so they are not part of the browser's header set.
H1_DROP = frozenset(["host", "upgrade", "http2-settings", "connection"])

# curl_cffi 0.16.3 alias map (curl_cffi/requests/impersonate.py REAL_TARGET_MAP
# and resolve_latest_browser_type) plus the deprecated names its BrowserType
# enum and BrowserTypeLiteral still list.  safari18_4, safari18_4_ios, edge_99
# and edge_101 appear in curl_cffi's literal type but its Python layer rejects
# them with ImpersonateError; curl_reap maps them to the obvious target.
ALIASES: Dict[str, str] = {
    "chrome": "chrome150",
    "edge": "edge101",
    "firefox": "firefox147",
    "safari": "safari2601",
    "safari_ios": "safari260_ios",
    "safari_beta": "safari2601",
    "safari_ios_beta": "safari260_ios",
    "chrome_android": "chrome131_android",
    "tor": "tor145",
    "edge_99": "edge99",
    "edge_101": "edge101",
    "safari15_3": "safari153",
    "safari15_5": "safari155",
    "safari17_0": "safari170",
    "safari17_2_ios": "safari172_ios",
    "safari18_0": "safari180",
    "safari18_0_ios": "safari180_ios",
    "safari18_4": "safari184",
    "safari18_4_ios": "safari184_ios",
}

# curl_reap 1.x names.  The nearest captured target is chosen by version
# distance inside the donor family on the same kind of platform (desktop).
# Edge 126+ is Chromium of the same version, so its donor is Chrome, not the
# Chromium 99/101-era Edge captures.
LEGACY_NAMES: Tuple[str, ...] = (
    "chrome98", "chrome126", "chrome128", "chrome129", "chrome130", "chrome133",
    "edge126", "edge128", "edge129", "edge130", "edge131", "edge133",
    "firefox95", "firefox102", "firefox109", "firefox117", "firefox127",
    "firefox128", "firefox132",
    "safari16_0", "safari16_4", "safari17_2",
)
LEGACY_DONOR_FAMILY = {"edge": "chrome"}

FORM_BOUNDARY = {"chrome": "chrome", "edge": "edge", "safari": "safari",
                 "firefox": "firefox", "tor": "firefox"}

_CHROMIUM_BRANDS = ("Chromium", "Google Chrome", "Microsoft Edge")


class GenerationError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _load_json(path: str) -> Dict[str, Any]:
    with open(path) as fh:
        return json.load(fh)


def load_templates(directory: str) -> Dict[str, Dict[str, Any]]:
    """Return {target: template} for every ``<target>.json`` in ``directory``."""
    out: Dict[str, Dict[str, Any]] = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json") or name.startswith("peet_"):
            continue
        tpl = _load_json(os.path.join(directory, name))
        target = tpl.get("target") or name[:-5]
        if target != name[:-5]:
            raise GenerationError("%s: target field %r does not match the file name" % (name, target))
        out[target] = tpl
    return out


# --------------------------------------------------------------------------
# Field derivation
# --------------------------------------------------------------------------

def family_of(target: str) -> str:
    for family in ("chrome", "edge", "firefox", "safari", "tor"):
        if target.startswith(family):
            return family
    raise GenerationError("cannot derive a family from target name %r" % target)


def _header_value(headers: Sequence[Tuple[str, str]], name: str) -> Optional[str]:
    lname = name.lower()
    for key, value in headers:
        if key.lower() == lname:
            return value
    return None


def platform_of(user_agent: str) -> str:
    """Map a User-Agent string onto curl_cffi's platform words."""
    if "Android" in user_agent:
        return "android"
    if "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent:
        return "ios"
    if "Windows" in user_agent:
        return "windows"
    if "Macintosh" in user_agent or "Mac OS X" in user_agent:
        return "macos"
    if "Linux" in user_agent or "X11" in user_agent:
        return "linux"
    raise GenerationError("cannot derive a platform from User-Agent %r" % user_agent)


def version_of(target: str, family: str, user_agent: str) -> str:
    """The version string curl_cffi reports for the target.

    Chrome and Edge use the major number, Firefox ``NNN.0`` as in its
    User-Agent, Safari the ``Version/`` token and Tor the Tor Browser release
    encoded in the target name (``tor145`` is 14.5), whose User-Agent says
    Firefox 128 on purpose.
    """
    if family in ("chrome", "edge"):
        m = re.search(r"Edg/(\d+)" if family == "edge" else r"Chrome/(\d+)", user_agent)
        if not m:
            raise GenerationError("no Chrome/Edg token in User-Agent of %s" % target)
        return m.group(1)
    if family == "firefox":
        m = re.search(r"Firefox/(\d+(?:\.\d+)*)", user_agent)
        if not m:
            raise GenerationError("no Firefox token in User-Agent of %s" % target)
        return m.group(1)
    if family == "safari":
        m = re.search(r"Version/(\d+(?:\.\d+)*)", user_agent)
        if not m:
            raise GenerationError("no Version token in User-Agent of %s" % target)
        return m.group(1)
    if family == "tor":
        digits = re.sub(r"\D", "", target)
        return "%s.%s" % (digits[:2], digits[2:]) if len(digits) > 2 else digits
    raise GenerationError("unknown family %r" % family)


def h1_header_set(template: Dict[str, Any]) -> HeaderList:
    headers = template.get("http11", {}).get("headers") or []
    if not headers:
        raise GenerationError("%s: no HTTP/1.1 capture" % template["target"])
    return [(name, value) for name, value in headers if name.lower() not in H1_DROP]


def h2_header_set(template: Dict[str, Any]) -> HeaderList:
    headers = template.get("headers") or []
    if not headers:
        raise GenerationError("%s: no HTTP/2 HEADERS capture" % template["target"])
    out: HeaderList = []
    for entry in headers:
        name = entry["name"]
        if name.startswith(":"):
            continue
        if name != name.lower():
            raise GenerationError("%s: HTTP/2 header %r is not lowercase" % (template["target"], name))
        out.append((name, entry["value"]))
    return out


def build_concrete(target: str, h2_tpl: Dict[str, Any], hello_names: Sequence[str]) -> Dict[str, Any]:
    if target not in hello_names:
        raise GenerationError("%s: no ClientHello template in %s" % (target, HELLO_DIR))
    h1 = h1_header_set(h2_tpl)
    h2 = h2_header_set(h2_tpl)
    user_agent = _header_value(h1, "User-Agent")
    if user_agent is None:
        raise GenerationError("%s: HTTP/1.1 capture has no User-Agent" % target)
    if _header_value(h2, "user-agent") != user_agent:
        raise GenerationError("%s: HTTP/1.1 and HTTP/2 User-Agent differ" % target)
    family = family_of(target)
    accept_encoding = _header_value(h1, "Accept-Encoding")
    if accept_encoding is None:
        raise GenerationError("%s: HTTP/1.1 capture has no Accept-Encoding" % target)
    if _header_value(h2, "accept-encoding") != accept_encoding:
        raise GenerationError("%s: HTTP/1.1 and HTTP/2 Accept-Encoding differ" % target)
    return {
        "family": family,
        "version": version_of(target, family, user_agent),
        "platform": platform_of(user_agent),
        "h1_headers": h1,
        "h2_headers": h2,
        "tls_template": target,
        "h2_spec": target,
        "accept_encoding": accept_encoding,
        "form_boundary": FORM_BOUNDARY[family],
        "akamai": h2_tpl.get("akamai_fingerprint"),
    }


# --------------------------------------------------------------------------
# Alias verification
# --------------------------------------------------------------------------

def _hello_signature(tpl: Dict[str, Any]) -> Dict[str, Any]:
    exts = [e["type"] for e in tpl["extensions"]]
    return {
        "ciphers": tpl["cipher_suites"],
        "extensions": exts if tpl["extension_order_fixed"] else sorted(exts),
        "groups": tpl["supported_groups"],
        "signature_algorithms": tpl["signature_algorithms"],
        "alpn": tpl["alpn"],
        "ja4": tpl["fingerprints"]["ja4"],
        "ja4_r": tpl["fingerprints"]["ja4_r"],
    }


def _h2_signature(tpl: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "akamai": tpl["akamai_fingerprint"],
        "settings": [(s["id"], s["value"]) for s in tpl["settings"]],
        "headers_frame_flags": (tpl.get("headers_frame") or {}).get("flags"),
        "h1": h1_header_set(tpl),
        "h2": h2_header_set(tpl),
    }


def verify_aliases(aliases: Dict[str, str], hello: Dict[str, Dict[str, Any]],
                   h2: Dict[str, Dict[str, Any]]) -> List[str]:
    """Check every alias that has its own capture against its concrete target.

    Returns the list of aliases that were verified against a capture.  An
    alias without a capture of its own is accepted on the strength of
    curl_cffi's alias table.
    """
    verified: List[str] = []
    for alias, concrete in aliases.items():
        if concrete not in h2 or concrete not in hello:
            raise GenerationError("alias %s points at %s which has no capture" % (alias, concrete))
        checked = False
        if alias in hello:
            if _hello_signature(hello[alias]) != _hello_signature(hello[concrete]):
                raise GenerationError("ClientHello of alias %s differs from %s" % (alias, concrete))
            declared = hello[alias].get("alias_of")
            if declared not in (None, concrete):
                raise GenerationError("hello template %s declares alias_of=%r, expected %r" % (alias, declared, concrete))
            checked = True
        if alias in h2:
            if _h2_signature(h2[alias]) != _h2_signature(h2[concrete]):
                raise GenerationError("HTTP/2 capture of alias %s differs from %s" % (alias, concrete))
            declared = h2[alias].get("alias_of")
            if declared not in (None, concrete):
                raise GenerationError("h2 template %s declares alias_of=%r, expected %r" % (alias, declared, concrete))
            checked = True
        if checked:
            verified.append(alias)
    return verified


# --------------------------------------------------------------------------
# Legacy names
# --------------------------------------------------------------------------

def _version_tuple(text: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)) or (0,)


def _version_distance(a: str, b: str) -> float:
    ta, tb = _version_tuple(a), _version_tuple(b)
    fa = ta[0] + (ta[1] / 10.0 if len(ta) > 1 else 0.0)
    fb = tb[0] + (tb[1] / 10.0 if len(tb) > 1 else 0.0)
    return abs(fa - fb)


def legacy_version(name: str, family: str) -> str:
    digits = name[len(family):]
    if family == "safari":
        return digits.replace("_", ".")
    if family == "firefox":
        return "%s.0" % digits
    return digits


def nearest_target(family: str, version: str, concrete: Dict[str, Dict[str, Any]]) -> str:
    donor = LEGACY_DONOR_FAMILY.get(family, family)
    candidates = [name for name, entry in concrete.items()
                  if entry["family"] == donor and entry["platform"] in ("windows", "macos", "linux")]
    if not candidates:
        raise GenerationError("no desktop capture for family %s" % donor)
    # Closest version wins; on a tie prefer the newer capture.
    candidates.sort(key=lambda n: (_version_distance(concrete[n]["version"], version),
                                   -_version_tuple(concrete[n]["version"])[0]))
    return candidates[0]


def _substitute_sec_ch_ua(value: str, major: str, edge: bool) -> str:
    parts = []
    for entry in value.split(", "):
        m = re.match(r'"([^"]+)";v="(\d+)"', entry)
        if m and m.group(1) in _CHROMIUM_BRANDS:
            brand = m.group(1)
            if edge and brand == "Google Chrome":
                brand = "Microsoft Edge"
            entry = '"%s";v="%s"' % (brand, major)
        parts.append(entry)
    return ", ".join(parts)


def substitute_version(headers: Sequence[Tuple[str, str]], family: str, version: str) -> HeaderList:
    """Rewrite the version tokens of a captured header set for a legacy name."""
    major = str(_version_tuple(version)[0])
    out: HeaderList = []
    for name, value in headers:
        lname = name.lower()
        if lname == "user-agent":
            if family in ("chrome", "edge"):
                value = re.sub(r"Chrome/\d+(?:\.\d+)*", "Chrome/%s.0.0.0" % major, value)
                value = re.sub(r" Edg/\d+(?:\.\d+)*", "", value)
                if family == "edge":
                    value += " Edg/%s.0.0.0" % major
            elif family == "firefox":
                value = re.sub(r"rv:\d+(?:\.\d+)*", "rv:%s" % version, value)
                value = re.sub(r"Firefox/\d+(?:\.\d+)*", "Firefox/%s" % version, value)
            elif family == "safari":
                value = re.sub(r"Version/\d+(?:\.\d+)*", "Version/%s" % version, value)
        elif lname == "sec-ch-ua" and family in ("chrome", "edge"):
            value = _substitute_sec_ch_ua(value, major, edge=(family == "edge"))
        out.append((name, value))
    return out


def build_legacy(name: str, concrete: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    family = family_of(name)
    version = legacy_version(name, family)
    donor = nearest_target(family, version, concrete)
    base = concrete[donor]
    return {
        "family": family,
        "version": version,
        "platform": base["platform"],
        "h1_headers": substitute_version(base["h1_headers"], family, version),
        "h2_headers": substitute_version(base["h2_headers"], family, version),
        "tls_template": base["tls_template"],
        "h2_spec": base["h2_spec"],
        "accept_encoding": base["accept_encoding"],
        "form_boundary": FORM_BOUNDARY[family],
        "nearest": donor,
    }


# --------------------------------------------------------------------------
# Cross-check against curl_cffi when it is installed
# --------------------------------------------------------------------------

_CFFI_OS = {"windows": "windows", "macos": "macos", "android": "android", "ios": "ios", "linux": "linux"}


def crosscheck_curl_cffi(concrete: Dict[str, Dict[str, Any]], aliases: Dict[str, str]) -> Optional[str]:
    """Compare family, version, platform and aliases with curl_cffi's tables.

    Returns the curl_cffi version string, or None when it is not installed.
    """
    try:
        import curl_cffi
        from curl_cffi.fingerprints import NATIVE_IMPERSONATE_TARGETS
        from curl_cffi.requests.impersonate import REAL_TARGET_MAP
    except Exception:  # noqa: BLE001
        return None
    native = {item["target_name"]: item for item in NATIVE_IMPERSONATE_TARGETS}
    missing = sorted(set(native) - set(concrete))
    if missing:
        raise GenerationError("curl_cffi targets without a capture: %s" % ", ".join(missing))
    for target, item in native.items():
        entry = concrete[target]
        if entry["family"] != item["browser"].lower():
            raise GenerationError("%s: family %s but curl_cffi says %s" % (target, entry["family"], item["browser"]))
        if entry["version"] != item["version"]:
            raise GenerationError("%s: version %s but curl_cffi says %s" % (target, entry["version"], item["version"]))
        if entry["platform"] != _CFFI_OS[item["os"].lower()]:
            raise GenerationError("%s: platform %s but curl_cffi says %s" % (target, entry["platform"], item["os"]))
    for alias, concrete_name in REAL_TARGET_MAP.items():
        if aliases.get(alias) != concrete_name:
            raise GenerationError("alias %s -> %s but curl_cffi says %s" % (alias, aliases.get(alias), concrete_name))
    return curl_cffi.__version__


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _render_headers(headers: Sequence[Tuple[str, str]], indent: str) -> str:
    if not headers:
        return "()"
    lines = ["("]
    for name, value in headers:
        lines.append("%s    (%r, %r)," % (indent, name, value))
    lines.append("%s)" % indent)
    return "\n".join(lines)


def _render_entry(name: str, entry: Dict[str, Any], keys: Sequence[str]) -> str:
    lines = ["    %r: {" % name]
    for key in keys:
        value = entry[key]
        if key in ("h1_headers", "h2_headers"):
            lines.append("        %r: %s," % (key, _render_headers(value, "        ")))
        else:
            lines.append("        %r: %r," % (key, value))
    lines.append("    },")
    return "\n".join(lines)


CONCRETE_KEYS = ("family", "version", "platform", "h1_headers", "h2_headers",
                 "tls_template", "h2_spec", "accept_encoding", "form_boundary", "akamai")
LEGACY_KEYS = ("family", "version", "platform", "nearest", "h1_headers", "h2_headers",
               "tls_template", "h2_spec", "accept_encoding", "form_boundary")

_FAMILY_ORDER = {"chrome": 0, "edge": 1, "firefox": 2, "tor": 3, "safari": 4}


def _target_sort_key(name: str, entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (_FAMILY_ORDER[entry["family"]], entry["platform"] in ("android", "ios"),
            _version_tuple(entry["version"]), name)


def render_module(concrete: Dict[str, Dict[str, Any]], aliases: Dict[str, str],
                  legacy: Dict[str, Dict[str, Any]], meta: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = buf.write
    w('"""Impersonate target data for curl_reap.  GENERATED, do not edit.\n\n')
    w("Generated by tools/gen_profiles.py from the curl_cffi captures in\n")
    w("tools/h2_templates/*.json (header sets, HTTP/2 behaviour) and\n")
    w("tools/hello_templates/*.json (TLS ClientHello templates).\n\n")
    w("Source captures: %s.\n" % meta["source"])
    w("Captured between %s and %s.\n" % (meta["captured_min"], meta["captured_max"]))
    w("Generated on %s.\n\n" % meta["generated_at"])
    w("CONCRETE holds one entry per target the reference client ships natively.  The header\n")
    w("sets are exactly what the reference client sends for that target: ``h1_headers`` in\n")
    w("HTTP/1.1 order and spelling without the libcurl artefacts (Host, Upgrade,\n")
    w("HTTP2-Settings, Connection), ``h2_headers`` in HTTP/2 order with lowercase\n")
    w("names and without pseudo headers.  ``tls_template`` and ``h2_spec`` name\n")
    w("the ClientHello template and the HTTP/2 spec of the same target.\n\n")
    w("ALIASES maps curl_cffi's alias names and deprecated spellings onto\n")
    w("concrete targets.\n\n")
    w("LEGACY holds the curl_reap 1.x names that curl_cffi never had.  THESE ARE\n")
    w("APPROXIMATIONS: each borrows the TLS template, HTTP/2 spec and header set\n")
    w("of the nearest captured target (``nearest``) and only substitutes its own\n")
    w("version number into User-Agent and sec-ch-ua.  Their TLS and HTTP/2\n")
    w("fingerprints are therefore those of the donor target, not of the browser\n")
    w("version in the name.  Prefer a CONCRETE name for new code.\n")
    w('"""\n')
    w("from __future__ import annotations\n\n")
    w("from typing import Dict, Tuple\n\n")
    w("HeaderPairs = Tuple[Tuple[str, str], ...]\n\n")
    w("SOURCE = %r\n" % meta["source"])
    w("GENERATED_AT = %r\n\n" % meta["generated_at"])
    w("CONCRETE: Dict[str, dict] = {\n")
    for name in sorted(concrete, key=lambda n: _target_sort_key(n, concrete[n])):
        w(_render_entry(name, concrete[name], CONCRETE_KEYS))
        w("\n")
    w("}\n\n")
    w("ALIASES: Dict[str, str] = {\n")
    for alias in sorted(aliases, key=lambda a: (_FAMILY_ORDER[family_of(a)], a)):
        w("    %r: %r,\n" % (alias, aliases[alias]))
    w("}\n\n")
    w("# Approximations: see the module docstring.\n")
    w("LEGACY: Dict[str, dict] = {\n")
    for name in sorted(legacy, key=lambda n: _target_sort_key(n, legacy[n])):
        w(_render_entry(name, legacy[name], LEGACY_KEYS))
        w("\n")
    w("}\n\n")
    w('__all__ = ["CONCRETE", "ALIASES", "LEGACY", "SOURCE", "GENERATED_AT", "HeaderPairs"]\n')
    return buf.getvalue()


# --------------------------------------------------------------------------
# Optional: raw template modules for the TLS and HTTP/2 engines
# --------------------------------------------------------------------------

_HELLO_BULK_KEYS = ("captures",)
_H2_BULK_KEYS = ("raw", "client_result", "post_response_client_frames")


def render_templates_module(kind: str, templates: Dict[str, Dict[str, Any]], aliases: Dict[str, str]) -> str:
    """Render ``TEMPLATES = {name: json dict}`` for the engines, bulky keys dropped."""
    bulk = _HELLO_BULK_KEYS if kind == "hello" else _H2_BULK_KEYS
    buf = io.StringIO()
    w = buf.write
    w('"""%s templates captured from curl_cffi.  GENERATED by tools/gen_profiles.py, do not edit."""\n'
      % ("ClientHello" if kind == "hello" else "HTTP/2"))
    w("from __future__ import annotations\n\nfrom typing import Dict\n\n")
    w("TEMPLATES: Dict[str, dict] = {\n")
    for name in sorted(templates):
        if name in aliases and templates[name].get("alias_of"):
            continue
        tpl = {k: v for k, v in templates[name].items() if k not in bulk}
        w("    %r: %s,\n" % (name, _pretty(tpl, 1)))
    w("}\n\n")
    w("ALIASES: Dict[str, str] = %s\n" % _pretty(dict(sorted(aliases.items())), 0))
    w("\n\ndef template(name: str) -> dict:\n")
    w('    """Return the template dict for ``name``, following aliases."""\n')
    w("    return TEMPLATES[ALIASES.get(name, name)]\n")
    return buf.getvalue()


def _pretty(value: Any, depth: int) -> str:
    pad = "    " * depth
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = ["%s    %r: %s," % (pad, k, _pretty(v, depth + 1)) for k, v in value.items()]
        return "{\n%s\n%s}" % ("\n".join(items), pad)
    if isinstance(value, list):
        if not value or all(isinstance(v, (str, int, float, bool, type(None))) for v in value):
            return repr(value)
        items = ["%s    %s," % (pad, _pretty(v, depth + 1)) for v in value]
        return "[\n%s\n%s]" % ("\n".join(items), pad)
    return repr(value)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def generate(hello_dir: str = HELLO_DIR, h2_dir: str = H2_DIR,
             generated_at: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """Build the module text and a report dict without writing anything."""
    hello = load_templates(hello_dir)
    h2 = load_templates(h2_dir)
    alias_names = set(ALIASES)
    concrete: Dict[str, Dict[str, Any]] = {}
    for target, tpl in h2.items():
        if target in alias_names:
            continue
        if tpl.get("alias_of"):
            raise GenerationError("%s declares alias_of=%r but is not in ALIASES" % (target, tpl["alias_of"]))
        concrete[target] = build_concrete(target, tpl, list(hello))
    for target, tpl in hello.items():
        if target not in alias_names and target not in concrete:
            raise GenerationError("%s has a ClientHello template but no HTTP/2 capture" % target)
    verified = verify_aliases(ALIASES, hello, h2)
    legacy = {name: build_legacy(name, concrete) for name in LEGACY_NAMES}
    for name in legacy:
        if name in concrete or name in ALIASES:
            raise GenerationError("legacy name %s collides with a captured target" % name)
    cffi_version = crosscheck_curl_cffi(concrete, ALIASES)
    captured = sorted(t["captured_at"] for t in h2.values())
    first = next(iter(h2.values()))
    meta = {
        "source": "curl_cffi %s, %s" % (first["curl_cffi_version"], first["curl_version"]),
        "captured_min": captured[0],
        "captured_max": captured[-1],
        "generated_at": generated_at or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d"),
    }
    text = render_module(concrete, ALIASES, legacy, meta)
    report = {
        "concrete": sorted(concrete),
        "aliases": dict(ALIASES),
        "aliases_verified_by_capture": verified,
        "legacy": {name: legacy[name]["nearest"] for name in legacy},
        "curl_cffi_crosscheck": cffi_version,
        "hello": hello,
        "h2": h2,
    }
    return text, report


def _strip_generated_at(text: str) -> str:
    return re.sub(r"GENERATED_AT = '[^']*'", "GENERATED_AT = ''", re.sub(r"Generated on [^\n]*\n", "", text))


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=DEFAULT_OUT, help="output module (default curl_reap/_profiles_data.py)")
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 when --out is stale")
    ap.add_argument("--templates-data", action="store_true",
                    help="also write curl_reap/_tls/templates_data.py and curl_reap/_h2/templates_data.py")
    ap.add_argument("--templates-dir", default=os.path.join(ROOT, "curl_reap"),
                    help="package directory for --templates-data (default curl_reap/)")
    ap.add_argument("--hello-dir", default=HELLO_DIR)
    ap.add_argument("--h2-dir", default=H2_DIR)
    args = ap.parse_args(argv)

    try:
        text, report = generate(args.hello_dir, args.h2_dir)
    except GenerationError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.check:
        if not os.path.exists(args.out):
            print("%s does not exist" % args.out)
            return 1
        with open(args.out) as fh:
            current = fh.read()
        if _strip_generated_at(current) != _strip_generated_at(text):
            print("%s is stale; rerun tools/gen_profiles.py" % args.out)
            return 1
        print("%s is up to date" % args.out)
        return 0

    with open(args.out, "w") as fh:
        fh.write(text)
    print("wrote %s: %d concrete targets, %d aliases (%d verified by capture), %d legacy names%s" % (
        args.out, len(report["concrete"]), len(report["aliases"]),
        len(report["aliases_verified_by_capture"]), len(report["legacy"]),
        ", cross-checked against curl_cffi %s" % report["curl_cffi_crosscheck"]
        if report["curl_cffi_crosscheck"] else ", curl_cffi not installed (no cross-check)"))
    if args.templates_data:
        for kind, sub, templates in (("hello", "_tls", report["hello"]), ("h2", "_h2", report["h2"])):
            directory = os.path.join(args.templates_dir, sub)
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, "templates_data.py")
            with open(path, "w") as fh:
                fh.write(render_templates_module(kind, templates, ALIASES))
            print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

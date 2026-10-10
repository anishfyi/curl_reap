#!/usr/bin/env python
"""Generate ``curl_reap/_h2/templates_data.py`` from ``tools/h2_templates/*.json``.

Each JSON file is a curl_cffi capture made by ``tools/capture_h2.py``.  The
generated module holds ``SPECS``, one entry per target with everything the
HTTP/2 engine needs to reproduce the capture: the SETTINGS pairs in wire
order, the connection WINDOW_UPDATE increment, PRIORITY frames, the HEADERS
frame flags and priority field, the pseudo header order as a four letter
string (``masp`` for ``:method :authority :scheme :path``), the regular
header order, and the HPACK representation observed for every header so the
encoder's choices can be checked against the capture.

Output is deterministic: targets are sorted, dictionary keys are emitted in
a fixed order and the file carries a header comment naming this script.
Run ``python tools/gen_h2_templates.py`` after a new capture.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TEMPLATES = os.path.join(HERE, "h2_templates")
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "curl_reap", "_h2", "templates_data.py")

PSEUDO_LETTERS = {":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}

ENTRY_KEYS = (
    "settings", "window_update", "priority_frames", "headers_flags", "headers_priority",
    "pseudo_order", "akamai", "client_frames_before_response", "header_order",
    "header_rules", "dynamic_table_size_updates", "headers",
)


def pseudo_order_string(order):
    letters = []
    for item in order:
        letters.append(PSEUDO_LETTERS.get(item, item))
    text = "".join(letters)
    if sorted(text) != ["a", "m", "p", "s"]:
        raise ValueError("pseudo header order %r is not a permutation of m,a,s,p" % (order,))
    return text


def priority_frame_tuple(frame):
    if isinstance(frame, dict):
        return [int(frame["stream_id"]), bool(frame["exclusive"]),
                int(frame["dependency"]), int(frame["weight"])]
    stream_id, exclusive, dependency, weight = frame
    return [int(stream_id), bool(exclusive), int(dependency), int(weight)]


def header_rule(entry):
    """Compact (name, representation, name_source, index, name_huffman, value_huffman)."""
    representation = entry["representation"]
    if representation.startswith("indexed"):
        return [entry["name"], representation, "table", int(entry["index"]), None, None]
    name_source = entry.get("name_source", "literal")
    index = entry.get("name_index")
    return [entry["name"], representation, name_source,
            int(index) if index is not None else None,
            entry.get("name_huffman"), bool(entry.get("value_huffman"))]


def build_entry(template):
    frame = template["headers_frame"]
    priority = frame.get("priority")
    headers = template["headers"]
    pseudo = [h["name"] for h in headers if h["name"].startswith(":")]
    pseudo_order = pseudo_order_string(template.get("pseudo_header_order") or pseudo)
    window_update = template.get("window_update") or {}
    return {
        "settings": [[int(s["id"]), int(s["value"])] for s in template["settings"]],
        "window_update": int(window_update.get("increment", 0) or 0),
        "priority_frames": [priority_frame_tuple(p) for p in template.get("priority_frames", [])],
        "headers_flags": int(frame["flags"]),
        "headers_priority": ([bool(priority["exclusive"]), int(priority["dependency"]),
                              int(priority["weight"])] if priority else None),
        "pseudo_order": pseudo_order,
        "akamai": template["akamai_fingerprint"],
        "client_frames_before_response": list(template.get("client_frames_before_response", [])),
        "header_order": [h["name"] for h in headers if not h["name"].startswith(":")],
        "header_rules": [header_rule(h) for h in headers],
        "dynamic_table_size_updates": list(template.get("hpack_dynamic_table_size_updates", [])),
        "headers": [[h["name"], h["value"]] for h in headers],
    }


def literal(value, indent):
    """Render a JSON-like value as a Python literal with stable formatting."""
    pad = " " * indent
    if isinstance(value, dict):
        lines = ["{"]
        for key in value:
            lines.append("%s    %r: %s," % (pad, key, literal(value[key], indent + 4)))
        lines.append(pad + "}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        simple = all(not isinstance(v, (dict, list)) for v in value)
        if simple:
            return "[" + ", ".join(repr(v) for v in value) + "]"
        lines = ["["]
        for item in value:
            lines.append("%s    %s," % (pad, literal(item, indent + 4)))
        lines.append(pad + "]")
        return "\n".join(lines)
    return repr(value)


def load_templates(directory):
    templates = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        target = data.get("target") or os.path.splitext(os.path.basename(path))[0]
        if target != os.path.splitext(os.path.basename(path))[0]:
            raise ValueError("%s: target %r does not match the file name" % (path, target))
        templates[target] = data
    if not templates:
        raise SystemExit("no templates found in %s" % directory)
    return templates


def render(templates, source_dir):
    first = templates[sorted(templates)[0]]
    info = {
        "captured_at": first.get("captured_at"),
        "curl_cffi_version": first.get("curl_cffi_version"),
        "curl_version": first.get("curl_version"),
        "targets": sorted(templates),
    }
    specs = {}
    for target in sorted(templates):
        entry = build_entry(templates[target])
        specs[target] = {key: entry[key] for key in ENTRY_KEYS}
    rel = os.path.relpath(os.path.abspath(source_dir), os.path.dirname(HERE))
    lines = [
        '"""HTTP/2 client templates captured from curl_cffi.',
        "",
        "Generated by tools/gen_h2_templates.py from %s/*.json. Do not edit by hand;" % rel.replace(os.sep, "/"),
        "re-run the generator after a new capture. Captured %s with curl_cffi %s (%s)."
        % (info["captured_at"], info["curl_cffi_version"], info["curl_version"]),
        "",
        "SPECS maps a target name to: settings (pairs in wire order), window_update",
        "(stream 0 increment), priority_frames ([stream_id, exclusive, dependency,",
        "weight]), headers_flags, headers_priority ([exclusive, dependency, weight] or",
        "None), pseudo_order (m=:method a=:authority s=:scheme p=:path), akamai,",
        "client_frames_before_response, header_order, header_rules ([name,",
        "representation, name_source, index, name_huffman, value_huffman]),",
        "dynamic_table_size_updates and headers ([name, value] as captured).",
        '"""',
        "",
        "CAPTURE_INFO = %s" % literal(info, 0),
        "",
        "SPECS = %s" % literal(specs, 0),
        "",
        "__all__ = [\"CAPTURE_INFO\", \"SPECS\"]",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--templates", default=DEFAULT_TEMPLATES)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the output file is out of date instead of writing it")
    args = parser.parse_args(argv)
    text = render(load_templates(args.templates), args.templates)
    if args.check:
        try:
            with open(args.out, "r", encoding="utf-8") as fh:
                current = fh.read()
        except OSError:
            current = None
        if current != text:
            print("%s is out of date" % args.out, file=sys.stderr)
            return 1
        print("%s is up to date" % args.out)
        return 0
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote %s (%d targets)" % (args.out, text.count("'pseudo_order'")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

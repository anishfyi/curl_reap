"""multipart/form-data bodies shaped like a browser's ``FormData``.

The encoder reproduces what Chrome's form submission code emits (Blink,
``third_party/blink/renderer/platform/network/form_data_encoder.cc``), which
is also what the WHATWG HTML standard specifies under "multipart/form-data
encoding algorithm" and what libcurl's mime code has produced since 7.81.0:

* every part starts with ``--<boundary>`` and a CRLF, then
  ``Content-Disposition: form-data; name="<name>"`` with
  ``; filename="<filename>"`` appended for file parts;
* ``Content-Type`` follows for file parts (the given type, else a guess from
  the filename, else ``application/octet-stream``) and for any part whose
  type was set explicitly;
* a blank line, the raw content, a CRLF, and finally ``--<boundary>--`` with
  a trailing CRLF;
* names and filenames are percent-escaped the way the standard says: ``"``
  becomes ``%22``, CR becomes ``%0D`` and LF becomes ``%0A``.  A lone CR or
  LF inside a field name is first normalised to CRLF (so it is sent as
  ``%0D%0A``); filenames are not normalised.  Backslashes are not escaped,
  which is what Chrome, Firefox and libcurl do.

Boundaries follow the browser family (see :func:`boundary_for`):

* ``chrome``, ``edge``, ``safari`` (any WebKit or Blink browser):
  ``----WebKitFormBoundary`` followed by 16 characters from ``[A-Za-z0-9]``.
  Source: Blink ``FormDataEncoder::GenerateUniqueBoundaryString`` and the
  identical WebKit ``FormDataBuilder::generateUniqueBoundaryString`` (the
  prefix is 22 characters, then four 32-bit random words are mapped through
  a 64-entry alphanumeric table).  the reference browser-impersonation client sends the prefix with
  six leading dashes instead of four; that is a curl-impersonate artefact
  and curl_reap follows the browsers.
* ``firefox`` (Gecko, Firefox 111 and later): ``----geckoformboundary``
  followed by 32 lowercase hexadecimal digits (a UUID without separators).
  Source: Gecko ``FSMultipartFormData`` in ``dom/html/HTMLFormSubmission.cpp``
  and the reference browser-impersonation client's firefox fingerprint, which emits
  ``------geckoformboundary`` plus 32 hex digits (again with two extra
  dashes).  The older Gecko shape, 27 dashes followed by random digits, is
  available as ``firefox_legacy`` for targets older than Firefox 111.
* ``curl``: libcurl's own shape, 24 dashes followed by 22 alphanumerics.
* anything else: 32 hexadecimal digits.

Memory bound: the whole body is built in memory, so the peak is roughly the
sum of all part sizes plus their headers.  Streaming very large uploads is
out of scope for this module; ``Content-Length`` is the caller's job and is
simply ``len(body)``.
"""
from __future__ import annotations

import mimetypes
import os
import re
import secrets
import string
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

__all__ = [
    "boundary_for", "encode_multipart", "guess_content_type",
    "escape_name", "escape_filename", "MultipartPart", "Multipart", "CurlMime",
    "DEFAULT_CONTENT_TYPE", "BOUNDARY_FAMILIES",
]

#: Content type a file part gets when none is given and none can be guessed.
DEFAULT_CONTENT_TYPE = "application/octet-stream"

_ALNUM = string.ascii_uppercase + string.ascii_lowercase + string.digits
_WEBKIT_PREFIX = "----WebKitFormBoundary"
_GECKO_PREFIX = "----geckoformboundary"

#: Family rule names and the families that map to them.  ``Profile.form_boundary``
#: in the registry is one of the keys of this mapping (or an alias listed here).
BOUNDARY_FAMILIES = {
    "chrome": "webkit", "chromium": "webkit", "edge": "webkit", "safari": "webkit",
    "safari_ios": "webkit", "chrome_android": "webkit", "webkit": "webkit",
    "blink": "webkit", "opera": "webkit", "brave": "webkit",
    "firefox": "gecko", "gecko": "gecko", "tor": "gecko",
    "firefox_legacy": "gecko_legacy", "gecko_legacy": "gecko_legacy",
    "curl": "curl",
    "other": "hex", "custom": "hex", "": "hex",
}

# RFC 2046 section 5.1.1: 1 to 70 characters from bchars, not ending in a space.
_BOUNDARY_RE = re.compile(r"^[A-Za-z0-9'()+_,\-./:=? ]{1,70}$")

# Extensions where CPython's mimetypes table and Chromium's net/base/mime_util.cc
# disagree or where platform tables (/etc/mime.types) commonly drift.  These win
# over mimetypes so the guess does not depend on the host operating system.
_BROWSER_TYPES = {
    ".txt": "text/plain", ".csv": "text/csv", ".md": "text/markdown",
    ".xml": "text/xml", ".js": "text/javascript", ".mjs": "text/javascript",
    ".json": "application/json", ".svg": "image/svg+xml", ".webp": "image/webp",
    ".avif": "image/avif", ".ico": "image/x-icon", ".webm": "video/webm",
    ".flac": "audio/flac", ".wasm": "application/wasm", ".woff": "font/woff",
    ".woff2": "font/woff2", ".gz": "application/gzip", ".tgz": "application/gzip",
    ".7z": "application/x-7z-compressed", ".apk": "application/vnd.android.package-archive",
    ".crx": "application/x-chrome-extension",
}

_CRLF = b"\r\n"
_NEWLINE_RE = re.compile(rb"\r\n|\r|\n")


def boundary_for(family: str = "chrome") -> str:
    """Return a fresh random boundary in the shape the browser family uses.

    ``family`` is a profile family or boundary rule name (case-insensitive):
    ``chrome``, ``edge``, ``safari`` and the other WebKit or Blink names give
    ``----WebKitFormBoundary`` plus 16 alphanumerics; ``firefox`` (and ``tor``)
    gives ``----geckoformboundary`` plus 32 hex digits; ``firefox_legacy``
    gives 27 dashes plus 20 digits; ``curl`` gives libcurl's 24 dashes plus 22
    alphanumerics; any other value gives 32 hex digits.  The module docstring
    records the sources for each rule.
    """
    key = (family or "").strip().lower()
    rule = BOUNDARY_FAMILIES.get(key, "hex")
    if rule == "webkit":
        return _WEBKIT_PREFIX + "".join(secrets.choice(_ALNUM) for _ in range(16))
    if rule == "gecko":
        return _GECKO_PREFIX + secrets.token_hex(16)
    if rule == "gecko_legacy":
        return "-" * 27 + "".join(secrets.choice(string.digits) for _ in range(20))
    if rule == "curl":
        return "-" * 24 + "".join(secrets.choice(_ALNUM) for _ in range(22))
    return secrets.token_hex(16)


def guess_content_type(filename: Union[str, bytes, None]) -> str:
    """Guess a part's ``Content-Type`` from its filename the way a browser does.

    A small table of browser choices wins over :mod:`mimetypes`; when neither
    knows the extension the result is ``application/octet-stream``.
    """
    if filename is None:
        return DEFAULT_CONTENT_TYPE
    if isinstance(filename, bytes):
        filename = filename.decode("utf-8", "replace")
    lowered = filename.lower()
    for ext, ctype in _BROWSER_TYPES.items():
        if lowered.endswith(ext):
            return ctype
    guessed, _encoding = mimetypes.guess_type(filename, strict=False)
    return guessed or DEFAULT_CONTENT_TYPE


def _to_bytes(value: Union[str, bytes, bytearray, memoryview], what: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("%s must be str or bytes, not %s" % (what, type(value).__name__))


def _escape(raw: bytes, normalize_newlines: bool) -> bytes:
    if normalize_newlines:
        raw = _NEWLINE_RE.sub(_CRLF, raw)
    return raw.replace(b'"', b"%22").replace(b"\r", b"%0D").replace(b"\n", b"%0A")


def escape_name(name: Union[str, bytes]) -> bytes:
    """Escape a field name for ``Content-Disposition`` (lone CR/LF become CRLF first)."""
    return _escape(_to_bytes(name, "name"), True)


def escape_filename(filename: Union[str, bytes]) -> bytes:
    """Escape a filename for ``Content-Disposition`` (no newline normalisation)."""
    return _escape(_to_bytes(filename, "filename"), False)


def _check_header_text(value: bytes, what: str) -> bytes:
    if b"\r" in value or b"\n" in value or b"\x00" in value:
        raise ValueError("%s must not contain CR, LF or NUL" % what)
    return value


def _read_content(value: Any) -> Optional[bytes]:
    """Turn a part value into bytes: bytes-like, str (UTF-8), or a readable object."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview, str)):
        return _to_bytes(value, "content")
    if hasattr(value, "read"):
        data = value.read()
        if data is None:
            return b""
        return _to_bytes(data, "content")
    return str(value).encode("utf-8")


class MultipartPart(object):
    """One part of a multipart body.

    ``name`` and ``filename`` are stored as given (str or bytes); ``data`` is
    the content as bytes, or ``None`` when ``local_path`` names a file that is
    read when the body is rendered.  ``headers`` is a list of extra
    ``(name, value)`` pairs emitted after ``Content-Type``; an entry named
    ``Content-Type`` or ``Content-Disposition`` (any case) replaces the
    generated header in place instead of duplicating it.
    """

    __slots__ = ("name", "filename", "content_type", "headers", "data", "local_path")

    def __init__(self, name, data=None, filename=None, content_type=None,
                 headers=None, local_path=None):
        if name is None:
            raise ValueError("a multipart part needs a name")
        self.name = name
        self.filename = filename
        self.content_type = content_type
        self.headers = list(_iter_pairs(headers, "headers")) if headers else []
        self.data = data
        self.local_path = local_path

    @property
    def is_file(self) -> bool:
        """True when the part carries a filename (file parts always get a type)."""
        return self.filename is not None or self.local_path is not None

    def content(self) -> bytes:
        """The part's bytes; a ``local_path`` part is read from disk each call."""
        if self.local_path is not None:
            with open(self.local_path, "rb") as fh:
                return fh.read()
        return self.data if self.data is not None else b""

    def effective_filename(self) -> Optional[Union[str, bytes]]:
        if self.filename is not None:
            return self.filename
        if self.local_path is not None:
            return os.path.basename(os.fspath(self.local_path))
        return None

    def effective_content_type(self) -> Optional[Union[str, bytes]]:
        if self.content_type is not None:
            return self.content_type
        if self.is_file:
            return guess_content_type(self.effective_filename())
        return None

    def render(self, boundary: bytes) -> bytes:
        """Render ``--boundary``, the headers, the content and the trailing CRLF."""
        filename = self.effective_filename()
        disposition = b'form-data; name="' + escape_name(self.name) + b'"'
        if filename is not None:
            disposition += b'; filename="' + escape_filename(filename) + b'"'
        content_type = self.effective_content_type()
        lines = [(b"Content-Disposition", disposition)]
        if content_type is not None:
            lines.append((b"Content-Type",
                          _check_header_text(_to_bytes(content_type, "content_type"),
                                             "content_type")))
        for key, value in self.headers:
            key_b = _check_header_text(_to_bytes(key, "header name").strip(), "header name")
            value_b = _check_header_text(_to_bytes(value, "header value"), "header value")
            lowered = key_b.lower()
            for index, (existing, _old) in enumerate(lines):
                if existing.lower() == lowered:
                    lines[index] = (existing, value_b)
                    break
            else:
                lines.append((key_b, value_b))
        out = bytearray(b"--" + boundary + _CRLF)
        for key, value in lines:
            out += key + b": " + value + _CRLF
        out += _CRLF
        out += self.content()
        out += _CRLF
        return bytes(out)

    def __repr__(self):
        return "MultipartPart(name=%r, filename=%r, content_type=%r)" % (
            self.name, self.effective_filename(), self.effective_content_type())


def _iter_pairs(obj: Any, what: str) -> Iterable[Tuple[Any, Any]]:
    """Yield ``(key, value)`` pairs from a mapping, a sequence of pairs, or ``None``."""
    if obj is None:
        return []
    if isinstance(obj, (str, bytes, bytearray, memoryview)):
        raise ValueError("%s must be a mapping or a sequence of pairs, not a string"
                         % what)
    if hasattr(obj, "items"):
        return list(obj.items())
    pairs = []
    for item in obj:
        try:
            key, value = item
        except (TypeError, ValueError):
            raise ValueError("%s entries must be (name, value) pairs" % what)
        pairs.append((key, value))
    return pairs


def _guess_filename(obj: Any) -> Optional[Union[str, bytes]]:
    """The basename of a file object's ``name`` when it looks like a path."""
    name = getattr(obj, "name", None)
    if isinstance(name, (str, bytes)) and name:
        first, last = name[:1], name[-1:]
        if first not in ("<", b"<") and last not in (">", b">"):
            return os.path.basename(name)
    return None


def _validate_boundary(boundary: Union[str, bytes, None]) -> bytes:
    if boundary is None:
        boundary = boundary_for("chrome")
    raw = _to_bytes(boundary, "boundary")
    text = raw.decode("ascii", "replace")
    if not _BOUNDARY_RE.fullmatch(text) or text.endswith(" "):
        raise ValueError("invalid multipart boundary %r: 1 to 70 characters from "
                         "letters, digits and '()+_,-./:=? not ending in a space"
                         % boundary)
    return raw


class Multipart(object):
    """A multipart/form-data body builder compatible with the reference client's ``CurlMime``.

    Parts are rendered in the order they were added.  ``family`` picks the
    boundary shape used when :meth:`to_body` is called without a boundary.
    ``close()`` exists for the reference client parity and does nothing; a ``local_path``
    part is opened and read only while the body is rendered.
    """

    def __init__(self, parts: Optional[Iterable[MultipartPart]] = None,
                 family: str = "chrome"):
        self.family = family
        self._parts = []  # type: List[MultipartPart]
        for part in parts or ():
            self.add(part)

    @property
    def parts(self) -> List[MultipartPart]:
        """The parts added so far, in order (a copy of the list)."""
        return list(self._parts)

    def __len__(self):
        return len(self._parts)

    def __iter__(self):
        return iter(self._parts)

    def add(self, part: MultipartPart) -> MultipartPart:
        if not isinstance(part, MultipartPart):
            raise TypeError("expected a MultipartPart, not %s" % type(part).__name__)
        self._parts.append(part)
        return part

    def addpart(self, name, content_type=None, filename=None, local_path=None,
                data=None, headers=None) -> MultipartPart:
        """Add a part the way ``CurlMime.addpart`` does.

        ``data`` is the content (bytes, or str encoded as UTF-8; other values
        are converted with ``str()``); ``local_path`` names a file to upload
        instead and defaults the filename to its basename.  Passing both is an
        error.  ``filename`` makes the part a file part, which always carries a
        ``Content-Type`` (``content_type``, else a guess from the filename, else
        ``application/octet-stream``); a part without a filename carries one
        only when ``content_type`` is given.  ``headers`` adds extra part
        headers (a mapping or pairs).
        """
        if local_path is not None and data is not None:
            raise ValueError("pass either local_path or data, not both")
        path = None
        if local_path is not None:
            path = os.fspath(local_path)
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if not os.path.isfile(path):
                raise FileNotFoundError("File not found at %s" % path)
        content = None
        if data is not None:
            content = _read_content(data)
        elif path is None:
            content = b""
        part = MultipartPart(name, data=content, filename=filename,
                             content_type=content_type, headers=headers,
                             local_path=path)
        self._parts.append(part)
        return part

    @classmethod
    def from_list(cls, files: Iterable[Dict[str, Any]], family: str = "chrome") -> "Multipart":
        """Build from a list of ``addpart`` keyword dicts, like ``CurlMime.from_list``."""
        form = cls(family=family)
        for spec in files:
            form.addpart(**spec)
        return form

    def to_body(self, boundary: Union[str, bytes, None] = None) -> Tuple[bytes, str]:
        """Render the body; returns ``(body, content_type)``.

        ``content_type`` is ``multipart/form-data; boundary=<boundary>`` with
        the boundary unquoted, as browsers send it.  Without ``boundary`` a
        fresh one in this builder's family shape is used.
        """
        if boundary is None:
            boundary = boundary_for(self.family)
        raw = _validate_boundary(boundary)
        out = bytearray()
        for part in self._parts:
            out += part.render(raw)
        out += b"--" + raw + b"--" + _CRLF
        return bytes(out), "multipart/form-data; boundary=" + raw.decode("ascii")

    def close(self) -> None:
        """No-op kept for the reference client parity (nothing is held open between renders)."""

    def attach(self, curl=None) -> None:
        raise NotImplementedError(
            "curl_reap has no curl handle to attach to; pass multipart= to request()")

    def __repr__(self):
        return "Multipart(%d parts, family=%r)" % (len(self._parts), self.family)


CurlMime = Multipart


_SINGLE_VALUE_TYPES = (str, bytes, bytearray, memoryview)


def _data_parts(data: Any) -> List[MultipartPart]:
    parts = []
    for name, value in _iter_pairs(data, "data"):
        if value is None:
            continue
        if isinstance(value, _SINGLE_VALUE_TYPES) or not hasattr(value, "__iter__"):
            values = [value]
        else:
            values = list(value)
        for item in values:
            if item is None:
                continue
            parts.append(MultipartPart(name, data=_read_content(item)))
    return parts


def _file_parts(files: Any) -> List[MultipartPart]:
    parts = []
    for name, spec in _iter_pairs(files, "files"):
        content_type = None
        headers = None
        if isinstance(spec, (tuple, list)):
            if len(spec) < 2 or len(spec) > 4:
                raise ValueError(
                    "file spec for %r must be (filename, content[, content_type[, headers]])"
                    % (name,))
            filename, fileobj = spec[0], spec[1]
            if len(spec) > 2:
                content_type = spec[2]
            if len(spec) > 3:
                headers = spec[3]
        else:
            filename = _guess_filename(spec)
            if filename is None:
                filename = name
            fileobj = spec
        content = _read_content(fileobj)
        if content is None:
            continue
        parts.append(MultipartPart(name, data=content, filename=filename,
                                   content_type=content_type, headers=headers))
    return parts


def encode_multipart(data: Any = None, files: Any = None,
                     boundary: Union[str, bytes, None] = None) -> Tuple[bytes, str]:
    """Encode ``data`` fields and ``files`` as one multipart/form-data body.

    Returns ``(body, content_type)``.  Data fields come first in their given
    order, then files in theirs, which is how a browser form with the text
    inputs before the file inputs submits.

    ``data`` is a mapping or a sequence of ``(name, value)`` pairs; a value
    that is a list or tuple repeats the name once per item, ``None`` values
    are skipped, bytes are sent as they are and anything else goes through
    ``str()`` and UTF-8.

    ``files`` is a mapping or a sequence of ``(name, spec)`` pairs where spec
    is a file object (filename from its ``name``, read fully), bytes or str
    (the field name doubles as the filename), or a tuple ``(filename,
    content[, content_type[, headers]])`` whose content may again be a file
    object, bytes or str.  A tuple with ``filename=None`` is a plain field.
    Every file part carries a ``Content-Type``: the one given, else a guess
    from the filename, else ``application/octet-stream``.

    ``boundary`` defaults to a Chrome-shaped one; pass
    :func:`boundary_for` of the impersonated family to match other browsers.
    The body is built in memory; ``Content-Length`` is ``len(body)``.
    """
    if isinstance(data, (str, bytes, bytearray, memoryview)):
        raise ValueError("data must be a mapping or pairs when encoding multipart, "
                         "not a string")
    form = Multipart(_data_parts(data) + _file_parts(files))
    return form.to_body(boundary)

"""Blocking and asyncio drivers for :class:`TLSClient`.

:class:`TLSSocket` behaves like a blocking socket for the transport:
``sendall``, ``recv(n)`` (``b""`` after close_notify or EOF),
``settimeout``/``gettimeout`` plus an optional absolute ``deadline``
(``time.monotonic()`` seconds) that turns every operation into a
:class:`curl_reap.exceptions.ConnectTimeout` during the handshake and a
:class:`curl_reap.exceptions.ReadTimeout` afterwards. :func:`wrap_socket`
performs the handshake on a connected socket and raises
:class:`TLS12Negotiated` as soon as the ServerHello shows the server did not
pick TLS 1.3, so the caller can reconnect through OpenSSL.
"""
from __future__ import annotations

import asyncio
import select
import socket
import time
from typing import List, Optional, Sequence, Tuple, Union

from curl_reap.exceptions import ConnectTimeout, ReadTimeout

from .engine import ApplicationData, Closed, HandshakeDone, NewTicket, TLSClient
from .errors import TLSError
from .session import SessionCache
from .templates import HelloTemplate, template as load_template

RECV_SIZE = 65536


def _resolve_template(template: Union[HelloTemplate, str]) -> HelloTemplate:
    return load_template(template) if isinstance(template, str) else template


class _Base:
    """Event bookkeeping shared by the sync and async drivers."""

    def __init__(self, client: TLSClient, session_cache: Optional[SessionCache]):
        self.client = client
        self.session_cache = session_cache
        self._buffer = bytearray()
        self._closed_event: Optional[Closed] = None
        self._handshake: Optional[HandshakeDone] = None
        self.bytes_sent = 0
        self.bytes_received = 0
        self.handshake_seconds = 0.0
        self.handshake_cpu_seconds = 0.0

    def _collect(self, events) -> None:
        for ev in events:
            if isinstance(ev, ApplicationData):
                self._buffer += ev.data
            elif isinstance(ev, HandshakeDone):
                self._handshake = ev
            elif isinstance(ev, NewTicket):
                if self.session_cache is not None:
                    self.session_cache.put(self.client.server_name, ev.ticket)
            elif isinstance(ev, Closed):
                self._closed_event = ev

    # -- introspection -------------------------------------------------------
    @property
    def handshake_info(self) -> Optional[HandshakeDone]:
        return self._handshake

    def selected_alpn_protocol(self) -> Optional[str]:
        return self.client.alpn_selected

    def version(self) -> str:
        return self.client.version

    def cipher(self) -> Tuple[str, str, int]:
        from .keyschedule import SUITES

        suite = SUITES.get(self.client.cipher_id)
        return (self.client.cipher, self.client.version, suite.bits if suite else 0)

    def getpeercert(self, binary_form: bool = True):
        chain = self.client.peer_chain
        if not chain:
            return None
        if binary_form:
            return chain[0]
        from cryptography import x509

        cert = x509.load_der_x509_certificate(chain[0])
        return {
            "subject": ((("commonName", cert.subject.rfc4514_string()),),),
            "issuer": ((("commonName", cert.issuer.rfc4514_string()),),),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "serialNumber": "%X" % cert.serial_number,
        }

    def getpeercertchain(self) -> List[bytes]:
        return list(self.client.peer_chain)

    @property
    def negotiated_group(self) -> str:
        return self.client.group

    @property
    def resumed(self) -> bool:
        return self.client.resumed

    @property
    def closed(self) -> bool:
        return self._closed_event is not None or self.client.closed

    def pending(self) -> int:
        """Application bytes already decrypted and waiting in the buffer."""
        return len(self._buffer)


class TLSSocket(_Base):
    """Blocking socket-like object over a :class:`TLSClient`."""

    def __init__(
        self,
        sock: socket.socket,
        client: TLSClient,
        *,
        timeout: Optional[float] = None,
        deadline: Optional[float] = None,
        session_cache: Optional[SessionCache] = None,
    ):
        super().__init__(client, session_cache)
        self._sock = sock
        self._timeout = timeout
        self.deadline = deadline
        self._sock_closed = False

    # -- timeouts -------------------------------------------------------------
    def settimeout(self, value: Optional[float]) -> None:
        self._timeout = value

    def gettimeout(self) -> Optional[float]:
        return self._timeout

    def setblocking(self, flag: bool) -> None:
        if not flag:
            raise ValueError("TLSSocket is always blocking")

    def _timeout_error(self, message: str):
        if self.client.handshake_complete:
            return ReadTimeout(message)
        return ConnectTimeout(message)

    def _arm(self) -> None:
        """Apply the per-operation timeout bounded by the deadline."""
        timeout = self._timeout
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise self._timeout_error("deadline exceeded")
            timeout = remaining if timeout is None else min(timeout, remaining)
        self._sock.settimeout(timeout)

    # -- plumbing -------------------------------------------------------------
    def _flush(self) -> None:
        out = self.client.data_to_send()
        if out:
            self._arm()
            try:
                self._sock.sendall(out)
            except socket.timeout as exc:
                raise self._timeout_error("send timed out") from exc
            except ConnectionError as exc:
                if not self.client.handshake_complete:
                    raise TLSError("connection reset during the TLS handshake: %s" % exc) from exc
                raise
            self.bytes_sent += len(out)

    def _read_once(self) -> bool:
        self._arm()
        try:
            data = self._sock.recv(RECV_SIZE)
        except socket.timeout as exc:
            raise self._timeout_error("read timed out") from exc
        except ConnectionError as exc:
            if not self.client.handshake_complete:
                raise TLSError("connection reset during the TLS handshake: %s" % exc) from exc
            raise
        self.bytes_received += len(data)
        try:
            events = self.client.receive(data)
        except TLSError:
            self._flush_quietly()
            raise
        self._collect(events)
        self._flush()
        return bool(data)

    def _flush_quietly(self) -> None:
        out = self.client.data_to_send()
        if out:
            try:
                self._sock.settimeout(1.0)
                self._sock.sendall(out)
            except OSError:
                pass

    # -- lifecycle ------------------------------------------------------------
    def do_handshake(self) -> HandshakeDone:
        t0 = time.perf_counter()
        c0 = time.process_time()
        self.client.start()
        self._flush()
        while self._handshake is None:
            if self._closed_event is not None:
                raise TLSError("connection closed during the TLS handshake")
            if not self._read_once() and self._handshake is None:
                raise TLSError("EOF during the TLS handshake")
        self.handshake_seconds = time.perf_counter() - t0
        self.handshake_cpu_seconds = time.process_time() - c0
        return self._handshake

    def sendall(self, data: bytes) -> None:
        if self._sock_closed:
            raise OSError("socket is closed")
        if not data:
            return
        self.client.send(bytes(data))
        self._flush()

    def send(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    def key_update(self, request_peer: bool = False) -> None:
        """Rotate our write keys (and ask the peer to rotate theirs)."""
        self.client.key_update(request_peer)
        self._flush()

    def recv(self, n: int = RECV_SIZE) -> bytes:
        if n <= 0:
            return b""
        while not self._buffer:
            if self._closed_event is not None or self._sock_closed:
                return b""
            if not self._read_once() and not self._buffer:
                return b""
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out

    def recv_into(self, buffer, nbytes: int = 0) -> int:
        n = nbytes or len(buffer)
        data = self.recv(n)
        buffer[:len(data)] = data
        return len(data)

    def shutdown(self, how: int = socket.SHUT_RDWR) -> None:
        """Send close_notify, then shut the TCP socket down."""
        if not self._sock_closed and not self.client.close_sent:
            try:
                self.client.close()
                self._flush_quietly()
            except Exception:
                pass
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def unwrap(self) -> socket.socket:
        """Send close_notify and return the underlying socket."""
        if not self.client.close_sent:
            self.client.close()
            self._flush_quietly()
        return self._sock

    def _drain_pending(self, budget: float = 0.25) -> None:
        """Collect readable post-handshake records before close_notify.

        Servers send NewSessionTicket immediately after their Finished; a
        caller that closes the socket right after the handshake would
        otherwise lose the ticket and never resume. Bounded, best effort,
        only when a session cache is attached.
        """
        if self.session_cache is None or not self.client.handshake_complete or self._sock_closed:
            return
        deadline = time.monotonic() + budget
        try:
            while self._closed_event is None:
                timeout = min(0.05, deadline - time.monotonic())
                if timeout <= 0:
                    break
                ready, _, _ = select.select([self._sock], [], [], timeout)
                if not ready:
                    break
                self._sock.settimeout(max(timeout, 0.01))
                try:
                    data = self._sock.recv(RECV_SIZE)
                except OSError:
                    break
                if not data:
                    break
                self.bytes_received += len(data)
                try:
                    events = self.client.receive(data)
                except TLSError:
                    break
                self._collect(events)
                out = self.client.data_to_send()
                if out:
                    try:
                        self._sock.sendall(out)
                    except OSError:
                        break
        except Exception:
            pass

    def close(self) -> None:
        """Send close_notify (also after receiving one, RFC 8446 6.1) and close."""
        if self._sock_closed:
            return
        try:
            if self.client.handshake_complete and not self.client.close_sent and self.client.state != "FAILED":
                self._drain_pending()
                self.client.close()
                self._flush_quietly()
        except Exception:
            pass
        finally:
            self._sock_closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- socket passthroughs -------------------------------------------------
    def fileno(self) -> int:
        return self._sock.fileno()

    def getpeername(self):
        return self._sock.getpeername()

    def getsockname(self):
        return self._sock.getsockname()

    def setsockopt(self, *args):
        return self._sock.setsockopt(*args)

    @property
    def socket(self) -> socket.socket:
        return self._sock


def wrap_socket(
    sock: socket.socket,
    server_name: str,
    template: Union[HelloTemplate, str],
    *,
    verify=True,
    alpn: Sequence[str] = ("h2", "http/1.1"),
    timeout: Optional[float] = None,
    deadline: Optional[float] = None,
    session_cache: Optional[SessionCache] = None,
    rng=None,
) -> TLSSocket:
    """Handshake over a connected socket and return a :class:`TLSSocket`.

    Raises :class:`TLS12Negotiated` when the server does not pick TLS 1.3
    (the caller reconnects through OpenSSL), :class:`CertificateError` on
    verification failure, :class:`ConnectTimeout` on the timeout or deadline,
    and other :class:`TLSError` subclasses for protocol failures. The socket
    is left to the caller in every error case.
    """
    tpl = _resolve_template(template)
    resumption = session_cache.get(server_name) if session_cache is not None else None
    client = TLSClient(server_name, tpl, verify=verify, alpn=alpn, resumption=resumption, rng=rng)
    tls = TLSSocket(sock, client, timeout=timeout, deadline=deadline, session_cache=session_cache)
    tls.do_handshake()
    return tls


class AsyncTLSSocket(_Base):
    """asyncio twin of :class:`TLSSocket` over a StreamReader/StreamWriter."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: TLSClient,
        *,
        timeout: Optional[float] = None,
        deadline: Optional[float] = None,
        session_cache: Optional[SessionCache] = None,
    ):
        super().__init__(client, session_cache)
        self.reader = reader
        self.writer = writer
        self._timeout = timeout
        self.deadline = deadline
        self._closed = False

    def settimeout(self, value: Optional[float]) -> None:
        self._timeout = value

    def gettimeout(self) -> Optional[float]:
        return self._timeout

    def _timeout_error(self, message: str):
        if self.client.handshake_complete:
            return ReadTimeout(message)
        return ConnectTimeout(message)

    def _remaining(self) -> Optional[float]:
        timeout = self._timeout
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise self._timeout_error("deadline exceeded")
            timeout = remaining if timeout is None else min(timeout, remaining)
        return timeout

    async def _flush(self) -> None:
        out = self.client.data_to_send()
        if out:
            self.writer.write(out)
            try:
                await asyncio.wait_for(self.writer.drain(), self._remaining())
            except asyncio.TimeoutError as exc:
                raise self._timeout_error("send timed out") from exc
            self.bytes_sent += len(out)

    async def _read_once(self) -> bool:
        try:
            data = await asyncio.wait_for(self.reader.read(RECV_SIZE), self._remaining())
        except asyncio.TimeoutError as exc:
            raise self._timeout_error("read timed out") from exc
        except ConnectionError as exc:
            if not self.client.handshake_complete:
                raise TLSError("connection reset during the TLS handshake: %s" % exc) from exc
            raise
        self.bytes_received += len(data)
        try:
            events = self.client.receive(data)
        except TLSError:
            out = self.client.data_to_send()
            if out:
                try:
                    self.writer.write(out)
                    await asyncio.wait_for(self.writer.drain(), 1.0)
                except Exception:
                    pass
            raise
        self._collect(events)
        await self._flush()
        return bool(data)

    async def do_handshake(self) -> HandshakeDone:
        t0 = time.perf_counter()
        self.client.start()
        await self._flush()
        while self._handshake is None:
            if self._closed_event is not None:
                raise TLSError("connection closed during the TLS handshake")
            if not await self._read_once() and self._handshake is None:
                raise TLSError("EOF during the TLS handshake")
        self.handshake_seconds = time.perf_counter() - t0
        return self._handshake

    async def sendall(self, data: bytes) -> None:
        if not data:
            return
        self.client.send(bytes(data))
        await self._flush()

    async def send(self, data: bytes) -> int:
        await self.sendall(data)
        return len(data)

    async def key_update(self, request_peer: bool = False) -> None:
        self.client.key_update(request_peer)
        await self._flush()

    async def recv(self, n: int = RECV_SIZE) -> bytes:
        if n <= 0:
            return b""
        while not self._buffer:
            if self._closed_event is not None or self._closed:
                return b""
            if not await self._read_once() and not self._buffer:
                return b""
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out

    async def shutdown(self) -> None:
        if not self.client.close_sent and self.client.handshake_complete:
            self.client.close()
            try:
                await self._flush()
            except Exception:
                pass
        try:
            self.writer.write_eof()
        except Exception:
            pass

    async def _drain_pending(self, budget: float = 0.25) -> None:
        """Async twin of :meth:`TLSSocket._drain_pending` (tickets on close)."""
        if self.session_cache is None or not self.client.handshake_complete or self._closed:
            return
        deadline = time.monotonic() + budget
        try:
            while self._closed_event is None:
                timeout = min(0.05, deadline - time.monotonic())
                if timeout <= 0:
                    break
                try:
                    data = await asyncio.wait_for(self.reader.read(RECV_SIZE), timeout)
                except (asyncio.TimeoutError, OSError, ValueError):
                    break
                if not data:
                    break
                self.bytes_received += len(data)
                try:
                    events = self.client.receive(data)
                except TLSError:
                    break
                self._collect(events)
                out = self.client.data_to_send()
                if out:
                    try:
                        self.writer.write(out)
                        await asyncio.wait_for(self.writer.drain(), timeout)
                    except Exception:
                        break
        except Exception:
            pass

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.client.handshake_complete and not self.client.close_sent and self.client.state != "FAILED":
                await self._drain_pending()
                self.client.close()
                out = self.client.data_to_send()
                if out:
                    self.writer.write(out)
                    await asyncio.wait_for(self.writer.drain(), 1.0)
        except Exception:
            pass
        self.writer.close()
        try:
            await asyncio.wait_for(self.writer.wait_closed(), 1.0)
        except Exception:
            pass

    def fileno(self) -> int:
        sock = self.writer.get_extra_info("socket")
        return sock.fileno() if sock is not None else -1

    def getpeername(self):
        return self.writer.get_extra_info("peername")

    def getsockname(self):
        return self.writer.get_extra_info("sockname")


async def async_wrap_socket(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    server_name: str,
    template: Union[HelloTemplate, str],
    *,
    verify=True,
    alpn: Sequence[str] = ("h2", "http/1.1"),
    timeout: Optional[float] = None,
    deadline: Optional[float] = None,
    session_cache: Optional[SessionCache] = None,
    rng=None,
) -> AsyncTLSSocket:
    """asyncio counterpart of :func:`wrap_socket` over an open stream pair."""
    tpl = _resolve_template(template)
    resumption = session_cache.get(server_name) if session_cache is not None else None
    client = TLSClient(server_name, tpl, verify=verify, alpn=alpn, resumption=resumption, rng=rng)
    tls = AsyncTLSSocket(reader, writer, client, timeout=timeout, deadline=deadline, session_cache=session_cache)
    await tls.do_handshake()
    return tls

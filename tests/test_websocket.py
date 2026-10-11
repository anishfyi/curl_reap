"""WebSocket client tests against a stdlib loopback server."""
import base64
import hashlib
import json
import socket
import struct
import threading

import pytest

import curl_reap
from curl_reap.exceptions import WebSocketClosed, WebSocketError
from curl_reap.websocket import _pack_frame


def _unpack(data):
    """Server-side frame parse (client frames are always masked)."""
    first, second = data[0], data[1]
    opcode = first & 0x0F
    fin = bool(first & 0x80)
    length = second & 0x7F
    offset = 2
    if length == 126:
        length = struct.unpack(">H", data[2:4])[0]
        offset = 4
    elif length == 127:
        length = struct.unpack(">Q", data[2:10])[0]
        offset = 10
    key = data[offset:offset + 4]
    offset += 4
    payload = bytes(b ^ key[i % 4] for i, b in enumerate(data[offset:offset + length]))
    return opcode, fin, payload


class EchoServer:
    """Handshakes, echoes text/binary, answers ping with pong, closes on demand."""

    def __init__(self, script=()):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.script = list(script)
        self.events = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(65536)
            head, _, rest = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            headers = {}
            for line in lines[1:]:
                name, _, value = line.partition(b":")
                headers[name.decode().strip().lower()] = value.decode().strip()
            key = headers["sec-websocket-key"]
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                             ).digest()).decode()
            conn.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
            if rest:
                self._serve_frames(conn, rest)
            else:
                self._serve_frames(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve_frames(self, conn, initial=b""):
        buf = bytearray(initial)
        while True:
            if self.script:
                opcode, payload = self.script.pop(0)
                conn.sendall(_pack_frame(opcode, payload, mask=False))
            while len(buf) < 2:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            length = buf[1] & 0x7F
            header = 2
            if length == 126:
                while len(buf) < 4:
                    buf += conn.recv(65536)
                length = struct.unpack(">H", bytes(buf[2:4]))[0]
                header = 4
            elif length == 127:
                while len(buf) < 10:
                    buf += conn.recv(65536)
                length = struct.unpack(">Q", bytes(buf[2:10]))[0]
                header = 10
            total = header + 4 + length          # client frames are masked
            while len(buf) < total:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            opcode, fin, payload = _unpack(bytes(buf[:total]))
            del buf[:total]
            self.events.append((opcode, payload))
            if opcode == 0x9:  # ping -> pong
                conn.sendall(_pack_frame(0xA, payload, mask=False))
            elif opcode == 0x8:  # close -> echo close
                conn.sendall(_pack_frame(0x8, payload, mask=False, fin=True))
                return
            elif opcode in (0x0, 0x1, 0x2):  # data + continuation frames echo back
                conn.sendall(_pack_frame(opcode, payload, mask=False, fin=fin))
            # keep serving: the next iteration blocks on recv again

    @staticmethod
    def _frame_len(buf):
        length = buf[1] & 0x7F
        offset = 2
        if length == 126:
            offset = 4
        elif length == 127:
            offset = 10
        return offset + 4 + length  # client frames always masked

    def url(self):
        return "ws://127.0.0.1:%d/socket" % self.port



def test_handshake_echo_and_close():
    server = EchoServer()
    with curl_reap.WebSocket.connect(server.url(), timeout=5) as ws:
        assert ws.subprotocol is None
        ws.send("hello")
        assert ws.recv() == "hello"
        ws.send(b"\x00\x01binary")
        assert ws.recv() == b"\x00\x01binary"
        ws.send_json({"a": 1})
        assert json.loads(ws.recv()) == {"a": 1}
    assert ws.closed


def test_ping_is_answered_and_pong_silent():
    server = EchoServer()
    with curl_reap.WebSocket.connect(server.url(), timeout=5) as ws:
        ws.ping("ka")
        ws.send("after-ping")
        assert ws.recv() == "after-ping"      # ping/pong never surface
        pings = [e for e in server.events if e[0] == 0x9]
        assert pings and pings[0][1] == b"ka"


def test_server_close_frame_raises_with_code():
    server = EchoServer(script=[(0x8, struct.pack(">H", 1008) + b"policy")])
    ws = curl_reap.WebSocket.connect(server.url(), timeout=5)
    with pytest.raises(WebSocketClosed) as info:
        ws.recv()
    assert info.value.close_code == 1008
    assert info.value.reason == "policy"
    assert ws.close_code == 1008


def test_fragmented_message_assembles():
    server = EchoServer()
    with curl_reap.WebSocket.connect(server.url(), timeout=5) as ws:
        big = "x" * 200000
        ws.send(big, chunk_size=65536)         # three fragments
        assert ws.recv() == big


def test_large_single_frame_round_trips():
    server = EchoServer()
    with curl_reap.WebSocket.connect(server.url(), timeout=5) as ws:
        payload = bytes(range(256)) * 300      # 76800 bytes -> 16-bit length
        ws.send(payload)
        assert ws.recv() == payload


def test_close_handshake_completes():
    server = EchoServer()
    ws = curl_reap.WebSocket.connect(server.url(), timeout=5)
    ws.send("before")
    ws.recv()
    ws.close(code=1000, reason="done", timeout=5)
    assert ws.closed
    closes = [e for e in server.events if e[0] == 0x8]
    assert closes and struct.unpack(">H", closes[0][1][:2])[0] == 1000


def test_bad_scheme_rejected():
    with pytest.raises(Exception):
        curl_reap.WebSocket.connect("http://127.0.0.1/x")


def test_handshake_rejection_surfaces():
    class Rejecter:
        def __init__(self):
            self.sock = socket.socket()
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(2)
            self.port = self.sock.getsockname()[1]
            threading.Thread(target=self._run, daemon=True).start()

        def _run(self):
            conn, _ = self.sock.accept()
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            conn.close()

    bad = Rejecter()
    with pytest.raises(WebSocketError):
        curl_reap.WebSocket.connect("ws://127.0.0.1:%d/x" % bad.port, timeout=5)


def test_async_websocket_round_trip():
    import asyncio
    server = EchoServer()

    async def main():
        async with await curl_reap.AsyncWebSocket.connect(server.url(), timeout=5) as ws:
            await ws.send("async")
            return await ws.recv()

    assert asyncio.run(main()) == "async"


def test_session_ws_connect():
    server = EchoServer()
    with curl_reap.Session() as session:
        ws = session.ws_connect(server.url(), timeout=5)
        ws.send("via-session")
        assert ws.recv() == "via-session"
        ws.close()

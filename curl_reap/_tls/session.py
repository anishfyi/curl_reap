"""Resumption tickets and the per-process session cache.

A :class:`Ticket` holds what a NewSessionTicket conveyed plus the derived
PSK; :class:`SessionCache` keeps at most ``max_tickets_per_host`` of them per
server name (newest first), drops expired ones, hands each out once (tickets
are single use, RFC 8446 appendix C.4) and bounds the number of hosts.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .consts import MAX_TICKET_LIFETIME


@dataclass
class Ticket:
    """One resumption ticket and its pre-shared key."""

    ticket: bytes
    psk: bytes
    cipher: int
    lifetime: int
    age_add: int
    received: float = field(default_factory=time.time)
    max_early_data: int = 0
    server_name: str = ""
    alpn: Optional[str] = None
    peer_chain: List[bytes] = field(default_factory=list)
    nonce: bytes = b""

    def age_seconds(self, now: Optional[float] = None) -> float:
        return max(0.0, (time.time() if now is None else now) - self.received)

    def expired(self, now: Optional[float] = None) -> bool:
        if self.lifetime <= 0:
            return True
        return self.age_seconds(now) >= min(self.lifetime, MAX_TICKET_LIFETIME)

    def obfuscated_age(self, now: Optional[float] = None) -> int:
        age_ms = int(self.age_seconds(now) * 1000)
        return (age_ms + self.age_add) & 0xFFFFFFFF


class SessionCache:
    """Thread-safe ``{server_name: [Ticket, ...]}`` with bounded size."""

    def __init__(self, max_hosts: int = 256, max_tickets_per_host: int = 2):
        if max_hosts < 1 or max_tickets_per_host < 1:
            raise ValueError("cache sizes must be at least 1")
        self.max_hosts = max_hosts
        self.max_tickets_per_host = max_tickets_per_host
        self._hosts: "OrderedDict[str, List[Ticket]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(server_name: str) -> str:
        return server_name.rstrip(".").lower()

    def put(self, server_name: str, ticket: Ticket) -> None:
        if ticket.expired():
            return
        key = self._key(server_name)
        with self._lock:
            tickets = self._hosts.pop(key, None) or []
            tickets = [t for t in tickets if not t.expired()]
            tickets.insert(0, ticket)
            del tickets[self.max_tickets_per_host:]
            self._hosts[key] = tickets
            while len(self._hosts) > self.max_hosts:
                self._hosts.popitem(last=False)

    def get(self, server_name: str) -> Optional[Ticket]:
        """Take the newest unexpired ticket for ``server_name`` (single use)."""
        key = self._key(server_name)
        with self._lock:
            tickets = self._hosts.get(key)
            if not tickets:
                self.misses += 1
                return None
            while tickets:
                ticket = tickets.pop(0)
                if not ticket.expired():
                    if tickets:
                        self._hosts.move_to_end(key)
                    else:
                        del self._hosts[key]
                    self.hits += 1
                    return ticket
            del self._hosts[key]
            self.misses += 1
            return None

    def peek(self, server_name: str) -> List[Ticket]:
        with self._lock:
            return [t for t in self._hosts.get(self._key(server_name), []) if not t.expired()]

    def discard(self, server_name: str) -> None:
        with self._lock:
            self._hosts.pop(self._key(server_name), None)

    def clear(self) -> None:
        with self._lock:
            self._hosts.clear()

    def hosts(self) -> List[str]:
        with self._lock:
            return list(self._hosts)

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._hosts.values())

    def __contains__(self, server_name: str) -> bool:
        with self._lock:
            return bool(self._hosts.get(self._key(server_name)))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"hosts": len(self._hosts), "tickets": sum(len(v) for v in self._hosts.values()),
                    "hits": self.hits, "misses": self.misses}

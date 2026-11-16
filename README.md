# CodeAlpha_NetworkSniffer

A packet sniffer in Python (Scapy) that decodes traffic, summarises it, and flags suspicious activity.
Built for CodeAlpha Cyber Security Internship, Task 1.

Only capture traffic on networks you own or have permission to monitor.

## What it does

- Captures live traffic or reads a `.pcap`
- Decodes Ethernet, IPv4/IPv6, TCP (with flags), UDP, ICMP, ARP, DNS, HTTP, TLS
- Shows source/destination, ports, protocol and a hex/ASCII payload dump
- Pulls out DNS queries and answers, HTTP method/host/path, and the server name from TLS handshakes (SNI), so you can see which sites are visited even over HTTPS
- Tracks conversations and reports the busiest flows
- Runs five detectors while capturing:

| Detector | Triggers on |
|---|---|
| `cleartext-credentials` | HTTP Basic auth, password/token form fields, FTP/POP3/IMAP logins. The secret itself is never printed, only its length |
| `port-scan` | One source sending SYNs to 15+ ports within 10 seconds |
| `ping-sweep` | One source pinging 10+ hosts within 10 seconds |
| `arp-spoofing` | An IP address whose MAC changes between ARP replies |
| `dns-tunnel?` | Very long or random-looking DNS names |

Detectors use timestamps from the packets, so results are the same on live traffic and on a replayed capture. They are heuristics and can produce false positives.

## Setup

```bash
pip install -r requirements.txt
```

Windows needs [Npcap](https://npcap.com). Live capture needs root or Administrator.

## Usage

```bash
python3 sniffer.py -r samples/sample_traffic.pcap       # demo, no root needed
sudo python3 sniffer.py --list                          # show interfaces
sudo python3 sniffer.py -i wlan0 -f "tcp port 80"       # live, HTTP only
sudo python3 sniffer.py -q -w capture.pcap --json out.json
```

| Option | Meaning |
|---|---|
| `-i`, `-f` | interface, BPF filter |
| `-c`, `-t` | stop after N packets / N seconds |
| `-r`, `-w` | read from / write to a pcap file |
| `-p BYTES` | payload bytes to dump (default 48, `0` hides) |
| `-q` | only alerts and the summary |
| `--json FILE` | save the summary as JSON |
| `--no-detect` | disable the detectors |

## Example output

Full run on the demo capture: [samples/sample_output.txt](samples/sample_output.txt)

```
22:13:20.150  HTTP    192.168.1.10:40000 > 93.184.216.34:80  [PA]  POST example.com/login  146B
  !! cleartext-credentials: field 'password' (13 chars) sent to example.com/login from 192.168.1.10
22:13:20.250  TLS     192.168.1.10:40001 > 142.250.1.1:443  [PA]  ClientHello sni=www.google.com  129B
  !! arp-spoofing: 192.168.1.1 moved from aa:aa:aa:aa:aa:aa to bb:bb:bb:bb:bb:bb
```

## Layout

```
sniffer.py          command line and capture loop
netsniff/decode.py  packet -> Frame (protocols, HTTP, TLS SNI, DNS)
netsniff/detect.py  detectors and alert engine
netsniff/report.py  console output, statistics, summary
tools/              generates the demo capture
tests/              unit tests
samples/            demo capture with a fake login, scan, sweep, ARP spoof and DNS tunnel
```

## Tests

```bash
python3 -m unittest discover -t . -s tests
```

## What I learned

- Packets are layered (Ethernet, IP, TCP/UDP, application data), and each layer adds the fields a sniffer reads
- TCP flags show intent: a burst of lone SYN packets to many ports is what a port scan looks like on the wire
- Plain HTTP exposes logins to anyone on the network, while HTTPS hides the content but still leaks the site name in the handshake
- Detection rules need time windows and thresholds, otherwise normal traffic causes false alarms
- Writing tests with crafted packets is the easiest way to check a detector works and stays quiet when it should

## Limits

- TLS payloads are encrypted, so only handshake metadata (like SNI) is visible
- No TCP stream reassembly, so a request split across packets is not parsed
- Encrypted DNS (DoH/DoT) is invisible to the DNS features

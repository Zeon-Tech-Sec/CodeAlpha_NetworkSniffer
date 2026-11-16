#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys

from scapy.all import PcapReader, PcapWriter, get_if_list, sniff

from netsniff.decode import decode
from netsniff.detect import Engine
from netsniff.report import Stats, format_alert, format_frame, hexdump, render_summary


class Session:
    def __init__(self, args):
        self.args = args
        self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.stats = Stats()
        self.engine = None if args.no_detect else Engine()
        self.pcap = PcapWriter(args.write, sync=True) if args.write else None
        self.skipped = 0

    def handle(self, pkt) -> None:
        try:
            frame = decode(pkt)
        except Exception:
            self.skipped += 1
            return
        self.stats.add(frame)
        if not self.args.quiet:
            print(format_frame(frame, self.color))
            if frame.payload and self.args.payload:
                print(hexdump(frame.payload, self.args.payload))
        if self.engine:
            for alert in self.engine.inspect(frame):
                print(format_alert(alert, self.color))
        if self.pcap:
            self.pcap.write(pkt)

    def finish(self) -> None:
        if self.pcap:
            self.pcap.close()
        alerts = self.engine.alerts if self.engine else []
        if self.stats.packets:
            print("\n" + render_summary(self.stats, alerts))
        else:
            print("\nno packets captured")
        if self.skipped:
            print(f"\n{self.skipped} packets could not be decoded")
        if self.args.json:
            with open(self.args.json, "w") as fh:
                json.dump(self.stats.as_dict(alerts), fh, indent=2)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="sniffer", description="Packet sniffer with traffic summaries and threat hints")
    ap.add_argument("-i", "--iface", help="interface to capture on")
    ap.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after this many packets")
    ap.add_argument("-t", "--timeout", type=int, help="stop after this many seconds")
    ap.add_argument("-r", "--read", metavar="PCAP", help="analyse a capture file instead of sniffing")
    ap.add_argument("-w", "--write", metavar="PCAP", help="save raw packets to a capture file")
    ap.add_argument("-p", "--payload", type=int, default=48, metavar="BYTES", help="payload bytes to dump (0 hides)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print alerts and the summary only")
    ap.add_argument("--json", metavar="FILE", help="write the summary as JSON")
    ap.add_argument("--no-detect", action="store_true", help="turn the threat detectors off")
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    return ap.parse_args(argv)


def main() -> int:
    args = parse_args()
    if args.list:
        print("\n".join(get_if_list()))
        return 0

    session = Session(args)
    try:
        if args.read:
            with PcapReader(args.read) as reader:
                for pkt in reader:
                    session.handle(pkt)
        else:
            where = args.iface or "default interface"
            print(f"capturing on {where}, filter: {args.filter or 'none'} (Ctrl+C to stop)")
            sniff(iface=args.iface, filter=args.filter or None, prn=session.handle,
                  store=False, count=args.count, timeout=args.timeout)
    except FileNotFoundError:
        print(f"cannot open {args.read}", file=sys.stderr)
        return 1
    except (PermissionError, RuntimeError, OSError) as exc:
        print(f"capture failed: {exc}\nrun as root/Administrator and make sure Npcap (Windows) or libpcap is installed",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        session.finish()
    return 0


if __name__ == "__main__":
    sys.exit(main())

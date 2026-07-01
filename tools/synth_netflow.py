#!/usr/bin/env python3
"""Gerador de flows NetFlow v9 sintéticos — útil para testar o pipeline sem hardware real.

Uso:
  synth_netflow.py normal --dst 177.86.18.5 --count 20
  synth_netflow.py dns_amp --dst 177.86.20.5 --sources 10 --packets 500
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

TEMPLATE_ID = 256
SOURCE_ID = 100
TEMPLATE_FIELDS = [
    (8, 4),   # IPV4_SRC_ADDR
    (12, 4),  # IPV4_DST_ADDR
    (7, 2),   # L4_SRC_PORT
    (11, 2),  # L4_DST_PORT
    (4, 1),   # PROTOCOL
    (6, 1),   # TCP_FLAGS
    (1, 4),   # IN_BYTES
    (2, 4),   # IN_PKTS
    (21, 4),  # LAST_SWITCHED
    (22, 4),  # FIRST_SWITCHED
]


def build_template_packet(unix_secs: int) -> bytes:
    body = struct.pack("!HH", TEMPLATE_ID, len(TEMPLATE_FIELDS))
    for ftype, flen in TEMPLATE_FIELDS:
        body += struct.pack("!HH", ftype, flen)
    flowset = struct.pack("!HH", 0, 4 + len(body)) + body
    header = struct.pack("!HHIIII", 9, 1, 0, unix_secs, 1, SOURCE_ID)
    return header + flowset


def build_record(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                  protocol: int, tcp_flags: int, n_bytes: int, n_packets: int) -> bytes:
    return (
        socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
        + struct.pack("!H", src_port) + struct.pack("!H", dst_port)
        + struct.pack("!B", protocol) + struct.pack("!B", tcp_flags)
        + struct.pack("!I", n_bytes) + struct.pack("!I", n_packets)
        + struct.pack("!I", 5000) + struct.pack("!I", 1000)
    )


def build_data_packet(records: list[bytes], unix_secs: int, seq: int) -> bytes:
    body = b"".join(records)
    flowset = struct.pack("!HH", TEMPLATE_ID, 4 + len(body)) + body
    header = struct.pack("!HHIIII", 9, 1, 0, unix_secs, seq, SOURCE_ID)
    return header + flowset


def send(sock: socket.socket, host: str, port: int, packets: list[bytes]) -> None:
    for pkt in packets:
        sock.sendto(pkt, (host, port))


def cmd_normal(args: argparse.Namespace) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now = int(time.time())
    send(sock, args.host, args.port, [build_template_packet(now)])
    time.sleep(0.1)
    records = [
        build_record(f"10.0.{i % 255}.{i % 255}", args.dst, 443, 51000 + i, 6, 0x18, 1200, 4)
        for i in range(args.count)
    ]
    send(sock, args.host, args.port, [build_data_packet(records, now, 2)])
    print(f"enviados {args.count} flows normais (TCP/443) para {args.dst}")


def cmd_dns_amp(args: argparse.Namespace) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now = int(time.time())
    send(sock, args.host, args.port, [build_template_packet(now)])
    time.sleep(0.1)
    records = []
    for i in range(args.sources):
        src_ip = f"203.0.{i % 255}.{(i * 7) % 255}"
        total_bytes = args.packets * args.pkt_size
        records.append(build_record(src_ip, args.dst, 53, 33000 + i, 17, 0, total_bytes, args.packets))
    send(sock, args.host, args.port, [build_data_packet(records, now, 2)])
    print(f"enviados {args.sources} origens simulando amplificação DNS (UDP/53) para {args.dst}")


def cmd_syn_flood(args: argparse.Namespace) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    now = int(time.time())
    send(sock, args.host, args.port, [build_template_packet(now)])
    time.sleep(0.1)
    tcp_syn = 0x02
    records = []
    for i in range(args.sources):
        src_ip = f"198.51.{i % 255}.{(i * 13) % 255}"
        records.append(build_record(src_ip, args.dst, 40000 + i, args.dst_port, 6, tcp_syn,
                                     args.pkts_per_src * 60, args.pkts_per_src))
    send(sock, args.host, args.port, [build_data_packet(records, now, 2)])
    print(f"enviados {args.sources} origens simulando SYN flood (TCP SYN puro) para {args.dst}:{args.dst_port}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2055)
    sub = parser.add_subparsers(dest="mode", required=True)

    p_normal = sub.add_parser("normal", help="tráfego TCP/443 normal")
    p_normal.add_argument("--dst", default="177.86.18.5")
    p_normal.add_argument("--count", type=int, default=20)
    p_normal.set_defaults(func=cmd_normal)

    p_dns = sub.add_parser("dns_amp", help="simula amplificação DNS (UDP/53, pacotes grandes)")
    p_dns.add_argument("--dst", default="177.86.20.5")
    p_dns.add_argument("--sources", type=int, default=10)
    p_dns.add_argument("--packets", type=int, default=500, help="pacotes por origem")
    p_dns.add_argument("--pkt-size", type=int, default=600, help="bytes por pacote (resposta DNS amplificada)")
    p_dns.set_defaults(func=cmd_dns_amp)

    p_syn = sub.add_parser("syn_flood", help="simula SYN flood (TCP SYN puro, muitas origens, pacotes pequenos)")
    p_syn.add_argument("--dst", default="177.86.18.50")
    p_syn.add_argument("--dst-port", type=int, default=443)
    p_syn.add_argument("--sources", type=int, default=200)
    p_syn.add_argument("--pkts-per-src", type=int, default=2000, help="pacotes SYN por origem")
    p_syn.set_defaults(func=cmd_syn_flood)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

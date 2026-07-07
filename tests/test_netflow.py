"""Testes de collector/netflow.py: parser NetFlow v9 (template flowset + data flowset).

Monta pacotes byte a byte (RFC 3954) em vez de usar capturas reais, pra cobrir
os casos de borda do protocolo sem depender de um exportador de verdade:
template chega antes/depois do data flowset, IPv4/IPv6, campos ausentes,
pacote truncado/malformado.
"""

from __future__ import annotations

import socket
import struct

from collector.netflow import TemplateStore, parse_packet
from collector.netflow import (
    F_IN_BYTES,
    F_IN_PKTS,
    F_IPV4_DST_ADDR,
    F_IPV4_SRC_ADDR,
    F_IPV6_DST_ADDR,
    F_IPV6_SRC_ADDR,
    F_L4_DST_PORT,
    F_L4_SRC_PORT,
    F_PROTOCOL,
    F_TCP_FLAGS,
)

HEADER_FMT = "!HHIIII"
PEER = "10.77.10.1"


def _header(count: int, unix_secs: int = 1_700_000_000, source_id: int = 1) -> bytes:
    return struct.pack(HEADER_FMT, 9, count, 0, unix_secs, 1, source_id)


def _template_flowset(template_id: int, fields: list[tuple[int, int]]) -> bytes:
    body = struct.pack("!HH", template_id, len(fields))
    for field_type, field_len in fields:
        body += struct.pack("!HH", field_type, field_len)
    return struct.pack("!HH", 0, len(body) + 4) + body


def _data_flowset(template_id: int, records: list[bytes]) -> bytes:
    body = b"".join(records)
    return struct.pack("!HH", template_id, len(body) + 4) + body


IPV4_TEMPLATE_FIELDS = [
    (F_IPV4_SRC_ADDR, 4),
    (F_IPV4_DST_ADDR, 4),
    (F_L4_SRC_PORT, 2),
    (F_L4_DST_PORT, 2),
    (F_PROTOCOL, 1),
    (F_TCP_FLAGS, 1),
    (F_IN_BYTES, 4),
    (F_IN_PKTS, 4),
]


def _ipv4_record(src="177.86.16.10", dst="1.2.3.4", sport=54321, dport=80,
                  proto=6, flags=2, nbytes=1500, npkts=1) -> bytes:
    return (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!H", sport)
        + struct.pack("!H", dport)
        + struct.pack("!B", proto)
        + struct.pack("!B", flags)
        + struct.pack("!I", nbytes)
        + struct.pack("!I", npkts)
    )


def test_parse_packet_with_template_and_data_in_same_datagram():
    store = TemplateStore()
    template = _template_flowset(256, IPV4_TEMPLATE_FIELDS)
    data = _data_flowset(256, [_ipv4_record()])
    packet = _header(count=2) + template + data

    records = parse_packet(packet, PEER, store)

    assert len(records) == 1
    rec = records[0]
    assert rec.src_ip == "177.86.16.10"
    assert rec.dst_ip == "1.2.3.4"
    assert rec.src_port == 54321
    assert rec.dst_port == 80
    assert rec.protocol == 6
    assert rec.tcp_flags == 2
    assert rec.bytes == 1500
    assert rec.packets == 1


def test_data_flowset_before_known_template_is_dropped_silently():
    store = TemplateStore()
    data = _data_flowset(256, [_ipv4_record()])
    packet = _header(count=1) + data

    assert parse_packet(packet, PEER, store) == []


def test_template_learned_from_earlier_packet_is_reused():
    store = TemplateStore()
    template_packet = _header(count=1) + _template_flowset(256, IPV4_TEMPLATE_FIELDS)
    parse_packet(template_packet, PEER, store)

    data_packet = _header(count=1) + _data_flowset(256, [_ipv4_record(dst="8.8.8.8")])
    records = parse_packet(data_packet, PEER, store)

    assert len(records) == 1
    assert records[0].dst_ip == "8.8.8.8"


def test_template_is_scoped_per_peer_source_id_and_template_id():
    store = TemplateStore()
    parse_packet(_header(count=1, source_id=1) + _template_flowset(256, IPV4_TEMPLATE_FIELDS), PEER, store)

    other_peer_packet = _header(count=1) + _data_flowset(256, [_ipv4_record()])
    assert parse_packet(other_peer_packet, "10.70.70.1", store) == []


def test_multiple_records_in_one_data_flowset():
    store = TemplateStore()
    parse_packet(_header(count=1) + _template_flowset(256, IPV4_TEMPLATE_FIELDS), PEER, store)

    data_packet = _header(count=1) + _data_flowset(
        256, [_ipv4_record(dst="1.1.1.1"), _ipv4_record(dst="2.2.2.2"), _ipv4_record(dst="3.3.3.3")]
    )
    records = parse_packet(data_packet, PEER, store)

    assert [r.dst_ip for r in records] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_ipv6_fields_decoded_correctly():
    store = TemplateStore()
    fields = [(F_IPV6_SRC_ADDR, 16), (F_IPV6_DST_ADDR, 16)]
    parse_packet(_header(count=1) + _template_flowset(300, fields), PEER, store)

    record_bytes = socket.inet_pton(socket.AF_INET6, "2001:db8::1") + socket.inet_pton(
        socket.AF_INET6, "2001:db8::2"
    )
    data_packet = _header(count=1) + _data_flowset(300, [record_bytes])
    records = parse_packet(data_packet, PEER, store)

    assert len(records) == 1
    assert records[0].src_ip == "2001:db8::1"
    assert records[0].dst_ip == "2001:db8::2"


def test_missing_optional_fields_default_to_zero():
    store = TemplateStore()
    fields = [(F_IPV4_SRC_ADDR, 4), (F_IPV4_DST_ADDR, 4)]
    parse_packet(_header(count=1) + _template_flowset(256, fields), PEER, store)

    record_bytes = socket.inet_aton("177.86.16.10") + socket.inet_aton("1.2.3.4")
    data_packet = _header(count=1) + _data_flowset(256, [record_bytes])
    records = parse_packet(data_packet, PEER, store)

    assert len(records) == 1
    rec = records[0]
    assert rec.src_port == 0
    assert rec.dst_port == 0
    assert rec.protocol == 0
    assert rec.bytes == 0
    assert rec.packets == 0


def test_wrong_version_returns_empty():
    store = TemplateStore()
    packet = struct.pack(HEADER_FMT, 5, 0, 0, 1_700_000_000, 1, 1)
    assert parse_packet(packet, PEER, store) == []


def test_packet_shorter_than_header_returns_empty():
    store = TemplateStore()
    assert parse_packet(b"\x00" * 10, PEER, store) == []


def test_truncated_flowset_length_does_not_crash():
    store = TemplateStore()
    # flowset_len aponta além do fim real do pacote — deve parar, não estourar.
    packet = _header(count=1) + struct.pack("!HH", 256, 9999)
    assert parse_packet(packet, PEER, store) == []


def test_flowset_len_below_minimum_stops_parsing():
    store = TemplateStore()
    packet = _header(count=1) + struct.pack("!HH", 256, 2)
    assert parse_packet(packet, PEER, store) == []


def test_options_template_flowset_is_ignored_without_error():
    store = TemplateStore()
    options_body = b"\x00" * 8
    packet = _header(count=1) + struct.pack("!HH", 1, len(options_body) + 4) + options_body
    assert parse_packet(packet, PEER, store) == []


def test_template_store_get_returns_none_when_unknown():
    store = TemplateStore()
    assert store.get(PEER, 1, 999) is None


def test_template_flowset_with_multiple_templates():
    store = TemplateStore()
    body = struct.pack("!HH", 256, 1) + struct.pack("!HH", F_IPV4_SRC_ADDR, 4)
    body += struct.pack("!HH", 257, 1) + struct.pack("!HH", F_IPV4_DST_ADDR, 4)
    template_flowset = struct.pack("!HH", 0, len(body) + 4) + body
    parse_packet(_header(count=1) + template_flowset, PEER, store)

    assert store.get(PEER, 1, 256) == [(F_IPV4_SRC_ADDR, 4)]
    assert store.get(PEER, 1, 257) == [(F_IPV4_DST_ADDR, 4)]

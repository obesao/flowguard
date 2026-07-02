"""Parser de NetFlow v9 (RFC 3954) — templates dinâmicos + data sets, normalizado para FlowRecord."""

from __future__ import annotations

import socket
import struct

from .models import FlowRecord

HEADER_LEN = 20
HEADER_FMT = "!HHIIII"  # version, count, sys_uptime, unix_secs, sequence, source_id

# Tipos de campo NetFlow v9 relevantes (IANA IPFIX Information Elements)
F_IN_BYTES = 1
F_IN_PKTS = 2
F_PROTOCOL = 4
F_TCP_FLAGS = 6
F_L4_SRC_PORT = 7
F_IPV4_SRC_ADDR = 8
F_INPUT_SNMP = 10
F_L4_DST_PORT = 11
F_IPV4_DST_ADDR = 12
F_OUTPUT_SNMP = 14
F_IPV4_NEXT_HOP = 15
F_SRC_AS = 16
F_DST_AS = 17
F_LAST_SWITCHED = 21
F_FIRST_SWITCHED = 22
F_OUT_BYTES = 23
F_OUT_PKTS = 24
F_IPV6_SRC_ADDR = 27
F_IPV6_DST_ADDR = 28
F_SAMPLING_INTERVAL = 34
F_FLOW_DIRECTION = 61  # 0=ingress, 1=egress (IANA IE 61)

IPV4_FIELDS = {F_IPV4_SRC_ADDR, F_IPV4_DST_ADDR, F_IPV4_NEXT_HOP}
IPV6_FIELDS = {F_IPV6_SRC_ADDR, F_IPV6_DST_ADDR}

TemplateKey = tuple  # (peer_ip, source_id, template_id)
Template = list  # list[tuple[field_type, field_length]]


class TemplateStore:
    """Cache de templates por (peer, source_id, template_id), como exige o protocolo."""

    def __init__(self) -> None:
        self._templates: dict[TemplateKey, Template] = {}

    def set(self, peer: str, source_id: int, template_id: int, fields: Template) -> None:
        self._templates[(peer, source_id, template_id)] = fields

    def get(self, peer: str, source_id: int, template_id: int) -> Template | None:
        return self._templates.get((peer, source_id, template_id))


def _decode_field(field_type: int, chunk: bytes) -> int | str:
    if field_type in IPV4_FIELDS and len(chunk) == 4:
        return socket.inet_ntoa(chunk)
    if field_type in IPV6_FIELDS and len(chunk) == 16:
        return socket.inet_ntop(socket.AF_INET6, chunk)
    if not chunk:
        return 0
    return int.from_bytes(chunk, "big")


def _parse_template_flowset(body: bytes, peer: str, source_id: int, store: TemplateStore) -> None:
    pos = 0
    while pos + 4 <= len(body):
        template_id, field_count = struct.unpack_from("!HH", body, pos)
        pos += 4
        fields: Template = []
        for _ in range(field_count):
            if pos + 4 > len(body):
                break
            field_type, field_len = struct.unpack_from("!HH", body, pos)
            fields.append((field_type, field_len))
            pos += 4
        if fields:
            store.set(peer, source_id, template_id, fields)


def _build_flow_record(fields: dict, ts: float, sampling_rate: int) -> FlowRecord:
    first_sw = fields.get(F_FIRST_SWITCHED, 0)
    last_sw = fields.get(F_LAST_SWITCHED, 0)
    duration_ms = max(0, last_sw - first_sw) if (first_sw or last_sw) else 0
    return FlowRecord(
        src_ip=str(fields.get(F_IPV4_SRC_ADDR, fields.get(F_IPV6_SRC_ADDR, "0.0.0.0"))),
        dst_ip=str(fields.get(F_IPV4_DST_ADDR, fields.get(F_IPV6_DST_ADDR, "0.0.0.0"))),
        src_port=int(fields.get(F_L4_SRC_PORT, 0)),
        dst_port=int(fields.get(F_L4_DST_PORT, 0)),
        protocol=int(fields.get(F_PROTOCOL, 0)),
        tcp_flags=int(fields.get(F_TCP_FLAGS, 0)),
        bytes=int(fields.get(F_IN_BYTES, fields.get(F_OUT_BYTES, 0))),
        packets=int(fields.get(F_IN_PKTS, fields.get(F_OUT_PKTS, 0))),
        duration_ms=int(duration_ms),
        ts=ts,
        ingress_if=int(fields.get(F_INPUT_SNMP, 0)),
        egress_if=int(fields.get(F_OUTPUT_SNMP, 0)),
        src_asn=int(fields.get(F_SRC_AS, 0)),
        dst_asn=int(fields.get(F_DST_AS, 0)),
        nexthop=str(fields.get(F_IPV4_NEXT_HOP, "")),
        sampling_rate=int(fields.get(F_SAMPLING_INTERVAL, sampling_rate)) or sampling_rate,
        flow_direction=int(fields.get(F_FLOW_DIRECTION, 0)),
    )


def _parse_data_flowset(body: bytes, template: Template, ts: float, sampling_rate: int) -> list[FlowRecord]:
    record_len = sum(flen for _, flen in template)
    if record_len <= 0:
        return []
    records = []
    pos = 0
    while pos + record_len <= len(body):
        raw = body[pos:pos + record_len]
        fields: dict[int, int | str] = {}
        off = 0
        for field_type, field_len in template:
            chunk = raw[off:off + field_len]
            fields[field_type] = _decode_field(field_type, chunk)
            off += field_len
        records.append(_build_flow_record(fields, ts, sampling_rate))
        pos += record_len
    return records


def parse_packet(data: bytes, peer: str, store: TemplateStore, default_sampling_rate: int = 1) -> list[FlowRecord]:
    """Faz o parse de um datagrama NetFlow v9 completo, retornando os FlowRecord decodificados.

    Data flowsets que chegam antes do template correspondente ser conhecido são
    descartados silenciosamente (comportamento esperado do protocolo: o exportador
    reenvia templates periodicamente).
    """
    if len(data) < HEADER_LEN:
        return []
    version, _count, _sys_uptime, unix_secs, _seq, source_id = struct.unpack_from(HEADER_FMT, data, 0)
    if version != 9:
        return []

    records: list[FlowRecord] = []
    offset = HEADER_LEN
    while offset + 4 <= len(data):
        flowset_id, flowset_len = struct.unpack_from("!HH", data, offset)
        if flowset_len < 4 or offset + flowset_len > len(data):
            break
        body = data[offset + 4: offset + flowset_len]

        if flowset_id == 0:
            _parse_template_flowset(body, peer, source_id, store)
        elif flowset_id == 1:
            pass  # options template — não necessário para FlowRecord
        elif flowset_id >= 256:
            template = store.get(peer, source_id, flowset_id)
            if template:
                records.extend(_parse_data_flowset(body, template, float(unix_secs), default_sampling_rate))

        offset += flowset_len

    return records

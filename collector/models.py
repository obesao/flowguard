"""Estruturas de dados centrais do FlowGuard: FlowRecord, AttackEvent, FlowspecRule."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int        # 6=TCP, 17=UDP, 1=ICMP
    tcp_flags: int        # bitmask
    bytes: int
    packets: int
    duration_ms: int
    ts: float              # UNIX timestamp
    ingress_if: int
    egress_if: int
    src_asn: int
    dst_asn: int
    nexthop: str
    sampling_rate: int
    # Enriquecimento pós-parse:
    src_country: str = ""
    src_category: str = ""    # cliente|transito|peering|desconhecido
    dst_prefix: str = ""
    is_bogon: bool = False
    threat_score: float = 0.0

    @property
    def real_bytes(self) -> int:
        return self.bytes * self.sampling_rate

    @property
    def real_packets(self) -> int:
        return self.packets * self.sampling_rate


@dataclass
class AttackEvent:
    dst_prefix: str
    attack_type: str          # ddos_udp, dns_amp, syn_flood, etc.
    severity: str              # critical, high, medium, info
    ts_start: float = 0.0
    ts_end: float | None = None
    customer: str = ""
    bps_peak: int = 0
    pps_peak: int = 0
    top_sources: list[str] = field(default_factory=list)
    mitigated: bool = False
    ai_analysis: str | None = None
    dismissed: bool = False
    id: int | None = None

    @property
    def duration_s(self) -> float:
        end = self.ts_end if self.ts_end is not None else time.time()
        return max(0.0, end - self.ts_start)


@dataclass
class FlowspecRule:
    dst_prefix: str
    action: str                # discard, rate-limit:N, rtbh
    src_prefix: str | None = None
    protocol: str | None = None
    dst_port: str | None = None
    src_port: str | None = None
    tcp_flags: str | None = None
    pkt_len: str | None = None
    attack_id: int | None = None
    label: str | None = None
    created_at: float = 0.0
    expires_at: float = 0.0
    active: bool = True
    id: int | None = None

"""Walk a capture and collect indicators of compromise from it."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

from . import app, layers
from .pcap import Packet, PcapFile, read_packets

DNS_PORT = 53
HTTP_PORTS = (80, 8080, 8000, 8888)
TLS_PORTS = (443, 8443)


def _is_external(addr: str) -> bool:
    """True for addresses worth treating as an indicator.

    Private, loopback, link-local and multicast addresses are internal to the
    capture and would be noise in an IOC list.
    """
    try:
        ip = ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


@dataclass
class Hit:
    """One indicator value plus how often and how early it showed up."""

    value: str
    first_seen: float
    count: int = 1
    meta: str = ""

    def touch(self, ts: float) -> None:
        self.count += 1
        if ts < self.first_seen:
            self.first_seen = ts


@dataclass
class Stats:
    packets_total: int = 0
    packets_decoded: int = 0
    packets_skipped: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    tcp_segments: int = 0
    udp_datagrams: int = 0

    def skip(self, reason: str) -> None:
        self.packets_skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1


@dataclass
class IocReport:
    dns_queries: dict[str, Hit] = field(default_factory=dict)
    dns_answers: dict[str, Hit] = field(default_factory=dict)
    http_hosts: dict[str, Hit] = field(default_factory=dict)
    http_uris: dict[str, Hit] = field(default_factory=dict)
    tls_sni: dict[str, Hit] = field(default_factory=dict)
    external_ips: dict[str, Hit] = field(default_factory=dict)
    stats: Stats = field(default_factory=Stats)
    source: str = ""

    def as_dict(self) -> dict:
        def dump(hits: dict[str, Hit]) -> list[dict]:
            return [
                {
                    "value": h.value,
                    "first_seen": round(h.first_seen, 6),
                    "count": h.count,
                    **({"meta": h.meta} if h.meta else {}),
                }
                for h in sorted(hits.values(), key=lambda x: (-x.count, x.value))
            ]

        return {
            "source": self.source,
            "stats": {
                "packets_total": self.stats.packets_total,
                "packets_decoded": self.stats.packets_decoded,
                "packets_skipped": self.stats.packets_skipped,
                "tcp_segments": self.stats.tcp_segments,
                "udp_datagrams": self.stats.udp_datagrams,
                "skip_reasons": self.stats.skip_reasons,
            },
            "dns_queries": dump(self.dns_queries),
            "dns_answers": dump(self.dns_answers),
            "http_hosts": dump(self.http_hosts),
            "http_uris": dump(self.http_uris),
            "tls_sni": dump(self.tls_sni),
            "external_ips": dump(self.external_ips),
        }

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.dns_queries,
                self.dns_answers,
                self.http_hosts,
                self.http_uris,
                self.tls_sni,
                self.external_ips,
            )
        )


def _touch(store: dict[str, Hit], value: str, ts: float, meta: str = "") -> None:
    if not value:
        return
    hit = store.get(value)
    if hit is None:
        store[value] = Hit(value=value, first_seen=ts, meta=meta)
    else:
        hit.touch(ts)


def _base_ts(packets: tuple[Packet, ...]) -> float:
    return packets[0].ts if packets else 0.0


def analyse(pcap: PcapFile, source: str = "") -> IocReport:
    """Extract indicators from an already-parsed capture."""
    report = IocReport(source=source)
    stats = report.stats
    base = _base_ts(pcap.packets)

    for packet in pcap.packets:
        stats.packets_total += 1
        rel_ts = packet.ts - base

        ip = layers.parse_frame(pcap.linktype, packet.data)
        if ip is None:
            stats.skip("not IPv4/IPv6 or unreadable link layer")
            continue
        if ip.skip_reason:
            stats.skip(ip.skip_reason)
            continue

        stats.packets_decoded += 1

        for addr in (ip.src, ip.dst):
            if _is_external(addr):
                _touch(report.external_ips, addr, rel_ts)

        transport = ip.transport
        if transport is None:
            continue

        if isinstance(transport, layers.TcpSegment):
            stats.tcp_segments += 1
            if not transport.has_payload:
                continue
            payload = transport.payload

            if transport.dport in TLS_PORTS or transport.sport in TLS_PORTS:
                hello = app.parse_tls_client_hello(payload)
                if hello:
                    _touch(report.tls_sni, hello.sni, rel_ts)

            if transport.dport in HTTP_PORTS or transport.sport in HTTP_PORTS:
                request = app.parse_http_request(payload)
                if request:
                    _touch(report.http_hosts, request.host, rel_ts)
                    if request.uri and request.uri != "/":
                        _touch(report.http_uris, request.uri, rel_ts)

        elif isinstance(transport, layers.UdpDatagram):
            stats.udp_datagrams += 1
            if DNS_PORT not in (transport.sport, transport.dport):
                continue
            query, answers = app.parse_dns(transport.payload)
            if query and query.name:
                _touch(report.dns_queries, query.name, rel_ts, meta=query.qtype)
            for answer in answers:
                _touch(report.dns_answers, answer.value, rel_ts, meta=answer.qtype)

    return report


def analyse_file(path: str | Path) -> IocReport:
    pcap = read_packets(path)
    return analyse(pcap, source=str(path))

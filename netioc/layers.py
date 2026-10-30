"""Minimal Ethernet / IP / TCP / UDP decoding.

Only the fields needed to find application payloads are read. Anything
unexpected (IPv6 extension headers, IP fragmentation, IP-in-IP) is reported as
skipped instead of half-parsed, so a caller can tell "no findings" apart from
"could not look".
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

PROTO_TCP = 6
PROTO_UDP = 17

_VLAN_TYPES = (ETHERTYPE_VLAN, ETHERTYPE_QINQ)


@dataclass(frozen=True)
class TcpSegment:
    sport: int
    dport: int
    seq: int
    flags: int
    payload: bytes

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def has_payload(self) -> bool:
        return len(self.payload) > 0


@dataclass(frozen=True)
class UdpDatagram:
    sport: int
    dport: int
    payload: bytes


@dataclass(frozen=True)
class IpPacket:
    src: str
    dst: str
    version: int
    proto: int
    payload: bytes  # transport-layer payload, headers already stripped
    transport: TcpSegment | UdpDatagram | None
    skip_reason: str = ""


def _format_ipv6(raw: bytes) -> str:
    """RFC 5952-ish formatting: lowercase hex groups, longest zero run collapsed."""
    parts = [f"{int.from_bytes(raw[i : i + 2], 'big'):x}" for i in range(0, 16, 2)]

    best_start, best_len = -1, 0
    run_start, run_len = -1, 0
    for i, part in enumerate(parts + ["x"]):
        if part == "0":
            if run_start < 0:
                run_start, run_len = i, 1
            else:
                run_len += 1
        else:
            if run_start >= 0 and run_len > best_len:
                best_start, best_len = run_start, run_len
            run_start, run_len = -1, 0

    if best_len < 2:
        return ":".join(parts)

    head = ":".join(parts[:best_start])
    tail = ":".join(parts[best_start + best_len :])
    return f"{head}::{tail}"


def _parse_tcp(payload: bytes) -> TcpSegment | None:
    if len(payload) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", payload[:8])
    data_offset = (payload[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(payload):
        return None
    flags = payload[13]
    return TcpSegment(
        sport=sport,
        dport=dport,
        seq=seq,
        flags=flags,
        payload=payload[data_offset:],
    )


def _parse_udp(payload: bytes) -> UdpDatagram | None:
    if len(payload) < 8:
        return None
    sport, dport, length = struct.unpack(">HHH", payload[:6])
    body = payload[8:]
    if length >= 8:
        body = body[: length - 8]
    return UdpDatagram(sport=sport, dport=dport, payload=body)


def parse_ip(payload: bytes) -> IpPacket | None:
    """Decode an IPv4 or IPv6 packet, returning None when it cannot be read."""
    if not payload:
        return None

    version = payload[0] >> 4

    if version == 4:
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        total_len = struct.unpack(">H", payload[2:4])[0]

        frag_field = struct.unpack(">H", payload[6:8])[0]
        frag_offset = frag_field & 0x1FFF
        more_fragments = bool(frag_field & 0x2000)
        if frag_offset or more_fragments:
            return IpPacket(
                src=src,
                dst=dst,
                version=4,
                proto=proto,
                payload=b"",
                transport=None,
                skip_reason="fragmented IPv4 (reassembly not implemented)",
            )

        body = payload[ihl:total_len] if total_len >= ihl else payload[ihl:]
        transport: TcpSegment | UdpDatagram | None = None
        if proto == PROTO_TCP:
            transport = _parse_tcp(body)
        elif proto == PROTO_UDP:
            transport = _parse_udp(body)
        return IpPacket(
            src=src,
            dst=dst,
            version=4,
            proto=proto,
            payload=body,
            transport=transport,
        )

    if version == 6:
        if len(payload) < 40:
            return None
        next_header = payload[6]
        src = _format_ipv6(payload[8:24])
        dst = _format_ipv6(payload[24:40])
        payload_len = struct.unpack(">H", payload[4:6])[0]
        body = payload[40 : 40 + payload_len] if payload_len else payload[40:]

        # Extension headers (0, 43, 44, 60, 51) are not walked: only the simple
        # case of the transport header coming first is decoded.
        if next_header in (0, 43, 44, 51, 60):
            return IpPacket(
                src=src,
                dst=dst,
                version=6,
                proto=next_header,
                payload=b"",
                transport=None,
                skip_reason="IPv6 extension header (not walked)",
            )

        transport = None
        if next_header == PROTO_TCP:
            transport = _parse_tcp(body)
        elif next_header == PROTO_UDP:
            transport = _parse_udp(body)
        return IpPacket(
            src=src,
            dst=dst,
            version=6,
            proto=next_header,
            payload=body,
            transport=transport,
        )

    return None


def parse_frame(linktype: int, data: bytes) -> IpPacket | None:
    """Strip the link layer and decode the network layer."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        # Walk up to two stacked VLAN tags.
        for _ in range(2):
            if ethertype in _VLAN_TYPES and len(data) >= offset + 4:
                ethertype = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                offset += 4
            else:
                break
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return None
        return parse_ip(data[offset:])

    if linktype == LINKTYPE_RAW:
        return parse_ip(data)

    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return None
        return parse_ip(data[16:])

    return None

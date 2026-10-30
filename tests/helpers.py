"""Builders for synthetic captures.

Tests construct their own bytes instead of shipping binary fixtures: the file is
reviewable, the packets are obvious, and there is no long-lived blob nobody dares
touch. Portions of pcap that a builder here cannot produce are as important as
the ones it can - there is no pcapng writer, so that path is tested with a
hand-made header.
"""

from __future__ import annotations

import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

PROTO_TCP = 6
PROTO_UDP = 17


def ipv4(value: str) -> bytes:
    return bytes(int(part) for part in value.split("."))


def eth(payload: bytes, ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(
        ">H", ethertype
    ) + payload


def vlan_eth(payload: bytes, ethertype: int = ETHERTYPE_IPV4, vlan: int = 100) -> bytes:
    inner = struct.pack(">HH", vlan, ethertype) + payload
    return eth(inner, ethertype=0x8100)


def ip4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH",
        0x45,
        0,
        total,
        0,
        0,
        64,
        proto,
        0,
    )
    return header + ipv4(src) + ipv4(dst) + payload


def ip6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    header = struct.pack(">IHBB", 0x60000000, len(payload), next_header, 64)
    return header + bytes.fromhex(src.replace(":", "").rjust(32, "0")) + bytes.fromhex(
        dst.replace(":", "").rjust(32, "0")
    ) + payload


def tcp(sport: int, dport: int, payload: bytes = b"", flags: int = 0x18) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def dns_response(name: str, address: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    """A response with one A record. Compression is not used."""
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    answer = (
        b"\xc0\x0c"  # pointer to the question name
        + struct.pack(">HHIH", qtype, 1, 60, 4)
        + ipv4(address)
    )
    return header + question + answer


def http_request(host: str, uri: str = "/", method: str = "GET", ua: str = "netioc-test") -> bytes:
    return (
        f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
        "Accept: */*\r\n\r\n"
    ).encode()


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(name)) + name  # host_name entry
    server_name_list = struct.pack(">H", len(server_name)) + server_name
    sni_ext = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list

    extensions = sni_ext
    body = (
        b"\x03\x03"  # client_version TLS 1.2
        + b"\x00" * 32  # random
        + b"\x00"  # session id length
        + struct.pack(">H", 2)
        + b"\x13\x01"  # one cipher suite
        + b"\x01\x00"  # compression methods
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    """Wrap frames in a little-endian microsecond pcap container."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)]
    for index, frame in enumerate(frames):
        out.append(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(frame), len(frame)))
        out.append(frame)
    return b"".join(out)


def pcapng_stub() -> bytes:
    return struct.pack("<I", 0x0A0D0D0A) + b"\x00" * 40

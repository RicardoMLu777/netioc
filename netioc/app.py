"""Application-layer extraction: DNS names, HTTP hosts/URIs, TLS SNI.

Each helper takes a transport payload and returns findings or an empty list. TCP
streams are not reassembled, so a request split across segments will not be
seen whole; that limitation is deliberate for a first version and documented in
the README.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}

_HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
)


@dataclass(frozen=True)
class DnsQuery:
    name: str
    qtype: str
    qtype_code: int

    @property
    def is_response(self) -> bool:
        return False


@dataclass(frozen=True)
class DnsAnswer:
    name: str
    qtype: str
    value: str


@dataclass(frozen=True)
class HttpRequest:
    method: str
    host: str
    uri: str
    user_agent: str = ""


@dataclass(frozen=True)
class TlsClientHello:
    sni: str


def _read_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name.

    Returns the decoded name and the offset just past the name in the *original*
    position, which is what callers need to continue parsing.
    """
    labels: list[str] = []
    jumped = False
    end_offset = offset

    while True:
        if offset >= len(data):
            return ".".join(labels), end_offset
        length = data[offset]

        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ".".join(labels), end_offset
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            if depth > 8 or pointer >= len(data):
                return ".".join(labels), end_offset
            nested, _ = _read_dns_name(data, pointer, depth + 1)
            if nested:
                labels.append(nested)
            jumped = True
            break

        offset += 1
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length

    return ".".join(labels), end_offset


def parse_dns(payload: bytes) -> tuple[DnsQuery | None, list[DnsAnswer]]:
    """Parse a DNS message into a query (when present) and its answers."""
    if len(payload) < 12:
        return None, []

    _ident, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", payload[:12])
    is_response = bool(flags & 0x8000)
    offset = 12
    query: DnsQuery | None = None

    for _ in range(qdcount):
        name, offset = _read_dns_name(payload, offset)
        if offset + 4 > len(payload):
            break
        qtype, _qclass = struct.unpack(">HH", payload[offset : offset + 4])
        offset += 4
        if query is None:
            query = DnsQuery(name=name, qtype=DNS_TYPES.get(qtype, str(qtype)), qtype_code=qtype)

    answers: list[DnsAnswer] = []
    if is_response:
        for _ in range(ancount):
            name, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", payload[offset : offset + 10])
            offset += 10
            rdata = payload[offset : offset + rdlength]
            offset += rdlength

            value = ""
            if rtype == 1 and len(rdata) == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and len(rdata) == 16:
                value = ":".join(f"{rdata[i:i + 2].hex()}" for i in range(0, 16, 2))
            elif rtype in (2, 5, 12) and rdata:
                value, _ = _read_dns_name(payload, offset - rdlength)
            if value:
                answers.append(
                    DnsAnswer(name=name, qtype=DNS_TYPES.get(rtype, str(rtype)), value=value)
                )

    return (None if is_response else query), answers


def parse_http_request(payload: bytes) -> HttpRequest | None:
    """Parse the head of an HTTP request. Only the first 8 KiB are inspected."""
    head = payload[:8192]
    if not any(head.startswith(method) for method in _HTTP_METHODS):
        return None

    try:
        text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except UnicodeDecodeError:
        return None

    lines = text.split("\r\n")
    if len(lines[0].split(" ")) < 2:
        return None
    method, uri = lines[0].split(" ")[0], lines[0].split(" ")[1]

    host = ""
    user_agent = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_lower = key.strip().lower()
        if key_lower == "host":
            host = value.strip()
        elif key_lower == "user-agent":
            user_agent = value.strip()

    return HttpRequest(method=method, host=host, uri=uri, user_agent=user_agent)


def parse_tls_client_hello(payload: bytes) -> TlsClientHello | None:
    """Extract the SNI from a TLS ClientHello.

    Walks the fixed-size fields by hand: record header, handshake header,
    version, random, session id, cipher suites, compression methods, then the
    extension block where server_name (0x0000) lives.
    """
    try:
        if len(payload) < 43 or payload[0] != 0x16:
            return None  # not a handshake record

        record_len = struct.unpack(">H", payload[3:5])[0]
        handshake = payload[5 : 5 + record_len]
        if len(handshake) < 38 or handshake[0] != 0x01:
            return None  # not a ClientHello

        body = handshake[4:]

        pos = 0
        pos += 2  # client_version
        pos += 32  # random

        if pos >= len(body):
            return None
        session_id_len = body[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(body):
            return None
        cipher_len = struct.unpack(">H", body[pos : pos + 2])[0]
        pos += 2 + cipher_len

        if pos >= len(body):
            return None
        comp_len = body[pos]
        pos += 1 + comp_len

        if pos + 2 > len(body):
            return None
        ext_total = struct.unpack(">H", body[pos : pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(body))

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", body[pos : pos + 4])
            pos += 4
            ext_data = body[pos : pos + ext_len]
            pos += ext_len

            if ext_type != 0x0000 or len(ext_data) < 5:
                continue

            # server_name_list
            list_len = struct.unpack(">H", ext_data[:2])[0]
            inner = ext_data[2 : 2 + list_len]
            p = 0
            while p + 3 <= len(inner):
                name_type = inner[p]
                name_len = struct.unpack(">H", inner[p + 1 : p + 3])[0]
                p += 3
                if name_type == 0:
                    # SNI is already in its wire form (punycode for IDNs), and
                    # that form is what an analyst wants in the report, so it is
                    # not re-decoded.
                    name = inner[p : p + name_len].decode("ascii", errors="replace").strip()
                    if name:
                        return TlsClientHello(sni=name)
                p += name_len
        return None
    except (struct.error, IndexError, UnicodeDecodeError):
        return None

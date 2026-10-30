"""Reader for the classic pcap container format.

Deliberately dependency-free: a pcap file is a 24-byte global header followed by
records of (16-byte header + captured bytes), and every field is a fixed-width
integer. Parsing it with ``struct`` is a dozen lines, which is cheaper than
adding a dependency to a tool that is meant to drop into incident-response
scripts and CI jobs.

PCAPNG (the default format of modern tcpdump and Wireshark) is a different
container and is not handled here; ``read_packets`` raises on it rather than
guessing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Magic numbers. The byte order of the file is encoded in how the magic reads
# back, and the nanosecond variants use a different constant entirely.
_MAGIC_USEC = {0xA1B2C3D4: ">", 0xD4C3B2A1: "<"}
_MAGIC_NSEC = {0xA1B23C4D: ">", 0x4D3CB2A1: "<"}
_PCAPNG_MAGIC = 0x0A0D0D0A

# Link types we can walk into. Everything else is counted and skipped.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

LINKTYPE_NAMES = {
    LINKTYPE_ETHERNET: "ethernet",
    LINKTYPE_RAW: "raw-ip",
    LINKTYPE_LINUX_SLL: "linux-sll",
}


class PcapError(Exception):
    """Raised when a file is not a pcap we can read."""


@dataclass(frozen=True)
class Packet:
    """One captured frame."""

    index: int
    ts_usec: int
    data: bytes

    @property
    def ts(self) -> float:
        return self.ts_usec / 1_000_000


@dataclass(frozen=True)
class PcapFile:
    """Container metadata plus the packets it holds."""

    linktype: int
    snaplen: int
    byte_order: str
    nanosecond: bool
    packets: tuple[Packet, ...]

    @property
    def linktype_name(self) -> str:
        return LINKTYPE_NAMES.get(self.linktype, f"linktype-{self.linktype}")


def _read_global_header(blob: bytes) -> tuple[str, bool, int, int]:
    if len(blob) < 24:
        raise PcapError("file is shorter than a pcap global header (24 bytes)")

    magic = struct.unpack(">I", blob[:4])[0]
    if magic == _PCAPNG_MAGIC:
        raise PcapError(
            "this is a pcapng file; convert it first: "
            "editcap -F pcap in.pcapng out.pcap"
        )

    if magic in _MAGIC_USEC:
        order, nanosecond = _MAGIC_USEC[magic], False
    elif magic in _MAGIC_NSEC:
        order, nanosecond = _MAGIC_NSEC[magic], True
    else:
        raise PcapError(f"not a pcap file (magic 0x{magic:08x})")

    _major, _minor, _zone, _sigfigs, snaplen, network = struct.unpack(
        order + "HHiIII", blob[4:24]
    )
    return order, nanosecond, snaplen, network


def read_packets(path: str | Path) -> PcapFile:
    """Parse a pcap file into records.

    Truncated trailing bytes are dropped rather than raising: captures cut short
    by a killed tcpdump are common, and losing the last partial record is not a
    reason to refuse the first million.
    """
    blob = Path(path).read_bytes()
    order, nanosecond, snaplen, network = _read_global_header(blob)

    packets: list[Packet] = []
    offset = 24
    index = 0
    header = struct.Struct(order + "IIII")
    total = len(blob)

    while offset + 16 <= total:
        ts_sec, ts_frac, incl_len, _orig_len = header.unpack_from(blob, offset)
        offset += 16

        if incl_len > total - offset:
            break  # truncated record at end of file

        data = blob[offset : offset + incl_len]
        offset += incl_len

        fraction = ts_frac if nanosecond else ts_frac
        packets.append(Packet(index=index, ts_usec=ts_sec * 1_000_000 + fraction // (1000 if nanosecond else 1), data=data))
        index += 1

    return PcapFile(
        linktype=network,
        snaplen=snaplen,
        byte_order=order,
        nanosecond=nanosecond,
        packets=tuple(packets),
    )


def iter_packets(path: str | Path) -> Iterator[Packet]:
    """Convenience wrapper for callers that only want the frames."""
    yield from read_packets(path).packets

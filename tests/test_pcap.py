"""Container-level tests: does the pcap reader survive real-world shapes?"""

import atexit
import shutil
import struct
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import dns_query, eth, ip4, pcap, pcapng_stub, udp

from netioc.pcap import PcapError, read_packets

_WORKDIR = Path(tempfile.mkdtemp(prefix="netioc-test-"))
atexit.register(shutil.rmtree, _WORKDIR, True)
_counter = {"n": 0}


def _write(data: bytes, suffix: str = ".pcap") -> Path:
    _counter["n"] += 1
    path = _WORKDIR / f"case{_counter['n']}{suffix}"
    path.write_bytes(data)
    return path


def _one_dns_frame() -> bytes:
    payload = udp(40000, 53, dns_query("example.com"))
    return eth(ip4("10.0.0.1", "10.0.0.2", 17, payload))


def test_reads_global_header_and_records():
    blob = pcap([_one_dns_frame(), _one_dns_frame()])
    capture = read_packets(_write(blob))
    assert capture.linktype == 1
    assert capture.snaplen == 65535
    assert len(capture.packets) == 2
    assert capture.linktype_name == "ethernet"


def test_timestamps_are_relative_ordered():
    capture = read_packets(_write(pcap([_one_dns_frame(), _one_dns_frame()])))
    first, second = capture.packets
    assert second.ts > first.ts


def test_truncated_final_record_is_dropped_not_fatal():
    blob = pcap([_one_dns_frame(), _one_dns_frame()])
    truncated = blob[:-20]
    capture = read_packets(_write(truncated))
    assert len(capture.packets) == 1


def test_header_only_file_has_no_packets():
    capture = read_packets(_write(pcap([])))
    assert capture.packets == ()


def test_pcapng_is_rejected_with_a_hint():
    with pytest.raises(PcapError) as excinfo:
        read_packets(_write(pcapng_stub(), ".pcapng"))
    assert "pcapng" in str(excinfo.value)


def test_non_pcap_magic_is_rejected():
    with pytest.raises(PcapError):
        read_packets(_write(b"\x00" * 64))


def test_short_file_is_rejected():
    with pytest.raises(PcapError):
        read_packets(_write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8))


def test_nanosecond_magic_is_accepted():
    frame = _one_dns_frame()
    header = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1_700_000_000, 500_000_000, len(frame), len(frame))
    capture = read_packets(_write(header + record + frame))
    assert capture.nanosecond is True
    assert capture.packets[0].ts_usec == 1_700_000_000 * 1_000_000 + 500_000


def test_big_endian_file_is_accepted():
    frame = _one_dns_frame()
    header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(">IIII", 1_700_000_000, 0, len(frame), len(frame))
    capture = read_packets(_write(header + record + frame))
    assert capture.byte_order == ">"
    assert len(capture.packets) == 1

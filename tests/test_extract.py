"""End-to-end extraction over synthetic captures."""

import atexit
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (
    dns_query,
    dns_response,
    eth,
    http_request,
    ip4,
    ip6,
    pcap,
    tcp,
    tls_client_hello,
    udp,
    vlan_eth,
)

from netioc.extract import analyse, analyse_file
from netioc.pcap import read_packets

_VICTIM = "10.0.0.1"
_RESOLVER = "8.8.8.8"
_C2 = "93.184.216.34"
_V6_ULA = "fd00" + "0" * 28  # fd00:: - private
_V6_PUBLIC = "26064700" + "0" * 24  # 2606:4700:: - Cloudflare, genuinely public

_WORKDIR = Path(tempfile.mkdtemp(prefix="netioc-extract-"))
atexit.register(shutil.rmtree, _WORKDIR, True)
_counter = {"n": 0}


def _write(blob: bytes) -> Path:
    _counter["n"] += 1
    path = _WORKDIR / f"capture{_counter['n']}.pcap"
    path.write_bytes(blob)
    return path


def _report(frames: list[bytes]):
    return analyse(read_packets(_write(pcap(frames))), source="synthetic.pcap")


def _dns_query_frame(name: str) -> bytes:
    payload = udp(53000, 53, dns_query(name))
    return eth(ip4(_VICTIM, _RESOLVER, 17, payload))


def _dns_response_frame(name: str, address: str) -> bytes:
    payload = udp(53, 53000, dns_response(name, address))
    return eth(ip4(_RESOLVER, _VICTIM, 17, payload))


def _http_frame(host: str, uri: str) -> bytes:
    payload = tcp(49152, 80, http_request(host, uri))
    return eth(ip4(_VICTIM, _C2, 6, payload))


def _tls_frame(sni: str) -> bytes:
    payload = tcp(49153, 443, tls_client_hello(sni))
    return eth(ip4(_VICTIM, _C2, 6, payload))


def test_dns_query_is_captured():
    report = _report([_dns_query_frame("c2.evil.example")])
    assert "c2.evil.example" in report.dns_queries
    assert report.dns_queries["c2.evil.example"].meta == "A"


def test_dns_answer_is_captured():
    report = _report([_dns_response_frame("c2.evil.example", _C2)])
    assert _C2 in report.dns_answers
    assert report.dns_answers[_C2].meta == "A"


def test_http_host_and_uri_are_captured():
    report = _report([_http_frame("gate.evil.example", "/panel/login.php")])
    assert "gate.evil.example" in report.http_hosts
    assert "/panel/login.php" in report.http_uris


def test_tls_sni_is_captured():
    report = _report([_tls_frame("beacon.evil.example")])
    assert "beacon.evil.example" in report.tls_sni


def test_external_addresses_only():
    report = _report([_http_frame("gate.evil.example", "/")])
    assert _C2 in report.external_ips
    assert _VICTIM not in report.external_ips, "private address leaked into IOC list"


def test_internal_only_capture_reports_no_indicators():
    frame = eth(ip4("10.0.0.1", "10.0.0.2", 6, tcp(40000, 445, b"")))
    report = _report([frame])
    assert report.is_empty


def test_repeated_indicator_is_counted():
    report = _report([_http_frame("gate.evil.example", "/") for _ in range(3)])
    assert report.http_hosts["gate.evil.example"].count == 3


def test_stats_count_decoded_and_skipped():
    not_ip = b"\xff" * 12 + b"\x08\x06" + b"\x00" * 28  # ARP, no IP header
    report = _report([_http_frame("gate.evil.example", "/"), not_ip])
    assert report.stats.packets_total == 2
    assert report.stats.packets_decoded == 1
    assert report.stats.packets_skipped == 1


def test_vlan_tagged_frame_is_decoded():
    payload = udp(53000, 53, dns_query("vlan.evil.example"))
    frame = vlan_eth(ip4(_VICTIM, _RESOLVER, 17, payload))
    report = _report([frame])
    assert "vlan.evil.example" in report.dns_queries


def test_ipv6_frame_is_decoded():
    payload = tcp(50000, 80, http_request("v6.evil.example", "/x"))
    frame = eth(ip6(_V6_ULA, _V6_PUBLIC, 6, payload), ethertype=0x86DD)
    report = _report([frame])
    assert "v6.evil.example" in report.http_hosts


def test_ipv6_public_destination_is_external():
    payload = tcp(50000, 80, b"")
    frame = eth(ip6(_V6_ULA, _V6_PUBLIC, 6, payload), ethertype=0x86DD)
    report = _report([frame])
    externals = list(report.external_ips)
    assert any(value.startswith("2606:4700") for value in externals), externals


def test_as_dict_is_json_serialisable():
    report = _report([_dns_query_frame("c2.evil.example")])
    blob = json.dumps(report.as_dict())
    assert '"dns_queries"' in blob
    assert "c2.evil.example" in blob


def test_analyse_file_reads_from_disk():
    path = _write(pcap([_http_frame("gate.evil.example", "/x")]))
    report = analyse_file(path)
    assert "gate.evil.example" in report.http_hosts
    assert report.source.endswith(".pcap")

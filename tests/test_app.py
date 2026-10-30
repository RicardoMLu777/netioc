"""Application-layer parsers, exercised on hand-built bytes."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import dns_query, dns_response, http_request, tls_client_hello

from netioc.app import parse_dns, parse_http_request, parse_tls_client_hello


def test_dns_query_name_and_type():
    query, answers = parse_dns(dns_query("cdn.evil.example", qtype=1))
    assert query is not None
    assert query.name == "cdn.evil.example"
    assert query.qtype == "A"
    assert answers == []


def test_dns_query_aaaa():
    query, _ = parse_dns(dns_query("v6.example", qtype=28))
    assert query is not None
    assert query.qtype == "AAAA"


def test_dns_response_has_no_query_and_one_answer():
    query, answers = parse_dns(dns_response("c2.example", "203.0.113.9"))
    assert query is None
    assert len(answers) == 1
    assert answers[0].value == "203.0.113.9"
    assert answers[0].qtype == "A"


def test_dns_response_resolves_compressed_name():
    _query, answers = parse_dns(dns_response("compressed.example", "198.51.100.7"))
    assert answers[0].name == "compressed.example"


def test_short_dns_payload_is_ignored():
    query, answers = parse_dns(b"\x00\x01\x02")
    assert query is None
    assert answers == []


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00" * 12,
        b"GARBAGE " + b"\x00" * 40,
    ],
)
def test_dns_garbage_does_not_raise(payload):
    query, answers = parse_dns(payload)
    assert answers == []


def test_http_request_host_and_uri():
    request = parse_http_request(http_request("gate.evil.example", "/panel/login.php"))
    assert request is not None
    assert request.method == "GET"
    assert request.host == "gate.evil.example"
    assert request.uri == "/panel/login.php"
    assert request.user_agent == "netioc-test"


def test_http_post_is_recognised():
    request = parse_http_request(http_request("upload.example", "/put", method="POST"))
    assert request is not None
    assert request.method == "POST"


def test_non_http_payload_returns_none():
    assert parse_http_request(b"\x16\x03\x01\x02\x00 binary") is None
    assert parse_http_request(b"") is None


def test_tls_client_hello_sni():
    hello = parse_tls_client_hello(tls_client_hello("bad.example.com"))
    assert hello is not None
    assert hello.sni == "bad.example.com"


def test_tls_non_handshake_is_ignored():
    assert parse_tls_client_hello(b"\x17\x03\x03\x00\x10 application-data") is None


def test_tls_truncated_hello_is_ignored():
    blob = tls_client_hello("truncated.example")
    assert parse_tls_client_hello(blob[:20]) is None

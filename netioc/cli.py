"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .extract import IocReport, analyse_file
from .pcap import PcapError

CATEGORIES = ("dns", "http", "tls", "ip")


def _sections(report: IocReport) -> list[tuple[str, dict]]:
    return [
        ("DNS queries", report.dns_queries),
        ("DNS answers", report.dns_answers),
        ("HTTP hosts", report.http_hosts),
        ("HTTP URIs", report.http_uris),
        ("TLS SNI", report.tls_sni),
        ("External IPs", report.external_ips),
    ]


def _wanted(category: str, only: set[str]) -> bool:
    if not only:
        return True
    mapping = {
        "DNS queries": "dns",
        "DNS answers": "dns",
        "HTTP hosts": "http",
        "HTTP URIs": "http",
        "TLS SNI": "tls",
        "External IPs": "ip",
    }
    return mapping.get(category, "") in only


def render_text(report: IocReport, min_count: int, only: set[str]) -> str:
    lines: list[str] = []
    stats = report.stats
    lines.append(f"netioc {__version__}  {report.source}")
    lines.append(
        f"  packets {stats.packets_total}  decoded {stats.packets_decoded}  "
        f"skipped {stats.packets_skipped}  tcp {stats.tcp_segments}  udp {stats.udp_datagrams}"
    )
    if stats.skip_reasons:
        reasons = ", ".join(f"{k} ({v})" for k, v in sorted(stats.skip_reasons.items()))
        lines.append(f"  skipped: {reasons}")

    if report.is_empty:
        lines.append("")
        lines.append("no indicators found")
        return "\n".join(lines)

    for title, hits in _sections(report):
        if not _wanted(title, only):
            continue
        rows = [h for h in hits.values() if h.count >= min_count]
        if not rows:
            continue
        rows.sort(key=lambda h: (-h.count, h.value))
        width = min(max(max((len(h.value) for h in rows), default=0), 20), 48)

        lines.append("")
        lines.append(f"{title} ({len(rows)})")
        for hit in rows[:50]:
            meta = f" {hit.meta}" if hit.meta else ""
            lines.append(
                f"  {hit.value[:48]:<{width}}  x{hit.count:<4}{meta:<8} first seen +{hit.first_seen:.3f}s"
            )
        if len(rows) > 50:
            lines.append(f"  ... {len(rows) - 50} more")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netioc",
        description="Extract DNS names, HTTP hosts, TLS SNI and external IPs from a pcap file.",
    )
    parser.add_argument("pcap", type=Path, help="path to a classic pcap file")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--min-count",
        type=int,
        default=1,
        metavar="N",
        help="only report indicators seen at least N times (default: 1)",
    )
    parser.add_argument(
        "--only",
        default="",
        metavar="KINDS",
        help=f"comma separated subset of: {','.join(CATEGORIES)}",
    )
    parser.add_argument(
        "--fail-on-ioc",
        action="store_true",
        help="exit 1 when any indicator is found (useful as a CI gate)",
    )
    parser.add_argument("--version", action="version", version=f"netioc {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    only: set[str] = set()
    if args.only:
        only = {part.strip().lower() for part in args.only.split(",") if part.strip()}
        unknown = only - set(CATEGORIES)
        if unknown:
            print(f"error: unknown category {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2

    try:
        report = analyse_file(args.pcap)
    except FileNotFoundError:
        print(f"error: no such file: {args.pcap}", file=sys.stderr)
        return 2
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(render_text(report, args.min_count, only))

    if args.fail_on_ioc and not report.is_empty:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

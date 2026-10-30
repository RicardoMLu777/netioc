"""netioc - pull indicators of compromise out of a packet capture.

Zero third-party dependencies on purpose: this is meant to drop into an
incident-response script or a CI job without dragging a dependency tree along.
"""

from .extract import Hit, IocReport, analyse, analyse_file
from .pcap import PcapError, PcapFile, Packet, read_packets

__version__ = "0.1.0"
__all__ = [
    "Hit",
    "IocReport",
    "PcapError",
    "PcapFile",
    "Packet",
    "analyse",
    "analyse_file",
    "read_packets",
    "__version__",
]

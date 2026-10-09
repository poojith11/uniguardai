import socket
from pathlib import Path
from typing import Iterator, Union, Optional
import dpkt

from .models import TrafficPacket, TCPFlags

# Standard PCAP Data Link Types
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229


def _inet_to_str(inet: bytes) -> str:
    """Convert raw byte socket address to standard human-readable IP string."""
    try:
        if len(inet) == 4:
            return socket.inet_ntop(socket.AF_INET, inet)
        elif len(inet) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet)
        return ""
    except Exception:
        return ""


def _parse_tcp_flags(flags: int) -> TCPFlags:
    """Extract standard TCP header flags from 8-bit / 16-bit flag integer."""
    return TCPFlags(
        fin=bool(flags & dpkt.tcp.TH_FIN),
        syn=bool(flags & dpkt.tcp.TH_SYN),
        rst=bool(flags & dpkt.tcp.TH_RST),
        psh=bool(flags & dpkt.tcp.TH_PUSH),
        ack=bool(flags & dpkt.tcp.TH_ACK),
        urg=bool(flags & dpkt.tcp.TH_URG),
        ece=bool(flags & dpkt.tcp.TH_ECE),
        cwr=bool(flags & dpkt.tcp.TH_CWR),
    )


def parse_raw_packet(ts: float, raw_buf: bytes, datalink: int = DLT_EN10MB) -> Optional[TrafficPacket]:
    """
    Parses an individual raw packet into a standardized TrafficPacket model.
    Handles Ethernet (EN10MB), Linux Cooked (SLL), BSD Loopback (NULL), and Raw IPv4/IPv6 linktypes.
    """
    if not raw_buf:
        return None

    try:
        ip_layer = None

        # 1. Inspect by declared datalink type
        if datalink == DLT_EN10MB:
            try:
                eth = dpkt.ethernet.Ethernet(raw_buf)
                if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    ip_layer = eth.data
            except Exception:
                pass

        elif datalink == DLT_LINUX_SLL:
            try:
                sll = dpkt.sll.SLL(raw_buf)
                if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    ip_layer = sll.data
            except Exception:
                pass

        elif datalink in (DLT_NULL, DLT_LOOP):
            try:
                # 4-byte protocol family header
                family = int.from_bytes(raw_buf[:4], byteorder='little')
                if family == socket.AF_INET:
                    ip_layer = dpkt.ip.IP(raw_buf[4:])
                elif family == socket.AF_INET6:
                    ip_layer = dpkt.ip6.IP6(raw_buf[4:])
            except Exception:
                pass

        elif datalink in (DLT_RAW, DLT_IPV4, DLT_IPV6):
            version = raw_buf[0] >> 4
            if version == 4:
                try:
                    ip_layer = dpkt.ip.IP(raw_buf)
                except Exception:
                    pass
            elif version == 6:
                try:
                    ip_layer = dpkt.ip6.IP6(raw_buf)
                except Exception:
                    pass

        # 2. Universal Heuristic Fallback (if datalink decoding did not identify IP)
        if ip_layer is None:
            # Check if buffer begins directly with IPv4 or IPv6 header
            version = raw_buf[0] >> 4
            if version == 4 and len(raw_buf) >= 20:
                try:
                    candidate = dpkt.ip.IP(raw_buf)
                    if candidate.v == 4:
                        ip_layer = candidate
                except Exception:
                    pass
            elif version == 6 and len(raw_buf) >= 40:
                try:
                    candidate = dpkt.ip6.IP6(raw_buf)
                    if candidate.v == 6:
                        ip_layer = candidate
                except Exception:
                    pass

            # Check if 14-byte Ethernet header was prepended
            if ip_layer is None and len(raw_buf) > 14:
                try:
                    eth = dpkt.ethernet.Ethernet(raw_buf)
                    if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        ip_layer = eth.data
                except Exception:
                    pass

        if ip_layer is None:
            return None

        # 3. Extract Layer-3 and Layer-4 fields
        if isinstance(ip_layer, dpkt.ip.IP):
            src_ip = _inet_to_str(ip_layer.src)
            dst_ip = _inet_to_str(ip_layer.dst)
            ip_version = 4
            transport = ip_layer.data

            if isinstance(transport, dpkt.tcp.TCP):
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(transport.sport),
                    dst_port=int(transport.dport),
                    protocol="TCP",
                    length=len(raw_buf),
                    payload_length=len(transport.data) if hasattr(transport, "data") else 0,
                    tcp_flags=_parse_tcp_flags(transport.flags),
                    ip_version=ip_version,
                )
            elif isinstance(transport, dpkt.udp.UDP):
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(transport.sport),
                    dst_port=int(transport.dport),
                    protocol="UDP",
                    length=len(raw_buf),
                    payload_length=len(transport.data) if hasattr(transport, "data") else 0,
                    tcp_flags=None,
                    ip_version=ip_version,
                )
            elif isinstance(transport, dpkt.icmp.ICMP):
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol="ICMP",
                    length=len(raw_buf),
                    payload_length=len(transport.data) if hasattr(transport, "data") else 0,
                    tcp_flags=None,
                    ip_version=ip_version,
                )
            else:
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol=f"IP_PROTO_{getattr(ip_layer, 'p', 'UNKNOWN')}",
                    length=len(raw_buf),
                    payload_length=0,
                    tcp_flags=None,
                    ip_version=ip_version,
                )

        elif isinstance(ip_layer, dpkt.ip6.IP6):
            src_ip = _inet_to_str(ip_layer.src)
            dst_ip = _inet_to_str(ip_layer.dst)
            ip_version = 6
            transport = ip_layer.data

            if isinstance(transport, dpkt.tcp.TCP):
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(transport.sport),
                    dst_port=int(transport.dport),
                    protocol="TCP",
                    length=len(raw_buf),
                    payload_length=len(transport.data) if hasattr(transport, "data") else 0,
                    tcp_flags=_parse_tcp_flags(transport.flags),
                    ip_version=ip_version,
                )
            elif isinstance(transport, dpkt.udp.UDP):
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(transport.sport),
                    dst_port=int(transport.dport),
                    protocol="UDP",
                    length=len(raw_buf),
                    payload_length=len(transport.data) if hasattr(transport, "data") else 0,
                    tcp_flags=None,
                    ip_version=ip_version,
                )
            else:
                return TrafficPacket(
                    timestamp=float(ts),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol="IPV6_OTHER",
                    length=len(raw_buf),
                    payload_length=0,
                    tcp_flags=None,
                    ip_version=ip_version,
                )

        return None
    except Exception:
        return None


def read_pcap_packets(pcap_path: Union[str, Path]) -> Iterator[TrafficPacket]:
    """
    Generator streaming parsed TrafficPacket objects from an offline PCAP/PCAPNG file.
    Deterministic and passive.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found at: {path}")

    with open(path, "rb") as f:
        # Standard PCAP Reader
        try:
            pcap = dpkt.pcap.Reader(f)
            datalink = pcap.datalink()
            for ts, buf in pcap:
                pkt = parse_raw_packet(ts, buf, datalink=datalink)
                if pkt is not None:
                    yield pkt
            return
        except Exception:
            f.seek(0)

        # PCAPNG Reader
        try:
            pcapng = dpkt.pcapng.Reader(f)
            for ts, buf in pcapng:
                pkt = parse_raw_packet(ts, buf, datalink=DLT_EN10MB)
                if pkt is not None:
                    yield pkt
            return
        except Exception:
            f.seek(0)

        # Scapy fallback for rare encapsulation modes
        try:
            from scapy.all import PcapReader
            with PcapReader(str(path)) as scapy_pcap:
                for scapy_pkt in scapy_pcap:
                    ts = float(scapy_pkt.time)
                    raw_bytes = bytes(scapy_pkt)
                    pkt = parse_raw_packet(ts, raw_bytes, datalink=DLT_EN10MB)
                    if pkt is not None:
                        yield pkt
        except Exception as e:
            raise ValueError(f"Unable to parse PCAP file '{path.name}': {str(e)}")

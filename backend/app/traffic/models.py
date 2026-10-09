from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class TCPFlags(BaseModel):
    """Parsed TCP header flag state."""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False

    def as_dict(self) -> Dict[str, bool]:
        return self.model_dump()


class TrafficPacket(BaseModel):
    """Standardized representation of a single passive network packet."""
    timestamp: float = Field(..., description="Epoch timestamp in seconds with microsecond precision")
    src_ip: str = Field(..., description="Source IP address (IPv4 or IPv6)")
    dst_ip: str = Field(..., description="Destination IP address (IPv4 or IPv6)")
    src_port: Optional[int] = Field(None, description="Source Layer-4 transport port (if applicable)")
    dst_port: Optional[int] = Field(None, description="Destination Layer-4 transport port (if applicable)")
    protocol: str = Field(..., description="Transport/Network protocol name (e.g. TCP, UDP, ICMP, OTHER)")
    length: int = Field(..., description="Total wire packet length in bytes")
    payload_length: int = Field(0, description="Transport payload length in bytes")
    tcp_flags: Optional[TCPFlags] = Field(None, description="TCP control flags if TCP protocol")
    ip_version: int = Field(4, description="IP version: 4 or 6")


class FlowKey(BaseModel):
    """
    Unidirectional 5-Tuple Flow Identifier.
    In passive unidirectional threat monitoring, (A->B) is monitored strictly independent of (B->A).
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    def to_string(self) -> str:
        s_port = self.src_port if self.src_port is not None else 0
        d_port = self.dst_port if self.dst_port is not None else 0
        return f"{self.src_ip}:{s_port}->{self.dst_ip}:{d_port}:{self.protocol.upper()}"


class TrafficFlow(BaseModel):
    """Aggregated unidirectional stream of packets sharing the same 5-tuple."""
    flow_id: str = Field(..., description="Unique flow instance identifier")
    key: FlowKey = Field(..., description="Unidirectional 5-tuple key")
    start_time: float = Field(..., description="Timestamp of first observed packet in seconds")
    end_time: float = Field(..., description="Timestamp of last observed packet in seconds")
    duration: float = Field(0.0, description="Flow duration in seconds")
    packet_count: int = Field(0, description="Total packet count in flow")
    byte_count: int = Field(0, description="Total byte volume in flow")
    packets: List[TrafficPacket] = Field(default_factory=list, description="Ordered list of packets in this flow")


class FlowFeatures(BaseModel):
    """
    Comprehensive numerical feature vector extracted from a unidirectional IP flow.
    Total fields: 35 (8 Metadata/Identifiers + 27 ML Predictive Features).
    """
    # 1. Identifiers & Non-Predictive Metadata (8 fields - EXCLUDED from ML training)
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    start_time: float
    end_time: float

    # 2. Predictive Volume & Timing Features (5 fields)
    duration_seconds: float
    packet_count: int
    byte_count: int
    packets_per_second: float
    bytes_per_second: float

    # 3. Predictive Packet Size Distribution Features (5 fields)
    mean_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int
    packet_size_entropy: float

    # 4. Predictive Inter-Arrival Time (IAT) Dynamics Features (6 fields)
    mean_iat_seconds: float
    std_iat_seconds: float
    min_iat_seconds: float
    max_iat_seconds: float
    iat_jitter_seconds: float
    burstiness_ratio: float

    # 5. Predictive TCP Control Flag Features (9 fields)
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    urg_count: int
    syn_ratio: float
    ack_ratio: float
    rst_ratio: float

    # 6. Predictive Contextual Categorical Features (2 fields)
    is_well_known_dst_port: bool
    is_ephemeral_src_port: bool

    def as_vector(self) -> List[float]:
        """
        Returns the exact 27-dimensional numerical feature vector for ML model inference.
        Identifiers (IPs, Ports, Timestamps, Flow IDs) are strictly excluded.
        """
        return [
            # Volume & Timing (5)
            float(self.duration_seconds),
            float(self.packet_count),
            float(self.byte_count),
            float(self.packets_per_second),
            float(self.bytes_per_second),
            # Packet Size (5)
            float(self.mean_packet_size),
            float(self.std_packet_size),
            float(self.min_packet_size),
            float(self.max_packet_size),
            float(self.packet_size_entropy),
            # IAT Dynamics (6)
            float(self.mean_iat_seconds),
            float(self.std_iat_seconds),
            float(self.min_iat_seconds),
            float(self.max_iat_seconds),
            float(self.iat_jitter_seconds),
            float(self.burstiness_ratio),
            # TCP Flags (9)
            float(self.syn_count),
            float(self.ack_count),
            float(self.fin_count),
            float(self.rst_count),
            float(self.psh_count),
            float(self.urg_count),
            float(self.syn_ratio),
            float(self.ack_ratio),
            float(self.rst_ratio),
            # Contextual Binary (2)
            float(1.0 if self.is_well_known_dst_port else 0.0),
            float(1.0 if self.is_ephemeral_src_port else 0.0),
        ]


class PCAPAnalysisResult(BaseModel):
    """Structured response container for PCAP analysis pipeline."""
    pcap_filename: str
    total_packets_parsed: int
    total_unidirectional_flows: int
    total_bytes: int
    capture_duration_seconds: float
    flows: List[FlowFeatures]
    summary: Dict[str, Any] = Field(default_factory=dict)

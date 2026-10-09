from enum import Enum
from typing import List, Dict, Set


class ThreatClass(str, Enum):
    """Standardized UNIGUARD AI canonical threat taxonomy (SIH26145)."""
    BENIGN = "BENIGN"
    DDOS = "DDOS"
    C2_BEACONING = "C2_BEACONING"
    RECON_SCAN = "RECON_SCAN"
    EXFILTRATION = "EXFILTRATION"


# The 25 exact numerical features strictly derived by our Phase 2 deterministic extractor
CANONICAL_NUMERICAL_FEATURES: List[str] = [
    # 1. Volume & Timing (5)
    "duration_seconds",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    # 2. Packet Size Distribution (5)
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "packet_size_entropy",
    # 3. Inter-Arrival Dynamics (6)
    "mean_iat_seconds",
    "std_iat_seconds",
    "min_iat_seconds",
    "max_iat_seconds",
    "iat_jitter_seconds",
    "burstiness_ratio",
    # 4. TCP Flags (9)
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
]

# Binary contextual port classifications (2)
CANONICAL_CATEGORICAL_FEATURES: List[str] = [
    "is_well_known_dst_port",
    "is_ephemeral_src_port",
]

# EXACT authoritative predictive features for model training (27 dimensions)
ALL_PREDICTIVE_FEATURES: List[str] = CANONICAL_NUMERICAL_FEATURES + CANONICAL_CATEGORICAL_FEATURES

# Forbidden identifiers & metadata (8 items - MUST NEVER BE USED AS ML FEATURES TO PREVENT MEMORIZATION LEAKAGE)
FORBIDDEN_LEAKAGE_COLUMNS: Set[str] = {
    "flow_id",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_mac",
    "dst_mac",
    "start_time",
    "end_time",
    "timestamp",
}

# Metadata fields retained for analysis and triage (8 fields)
FLOW_METADATA_COLUMNS: List[str] = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_time",
    "end_time",
]

# Mapping table from external dataset columns (e.g. CIC-IDS2018 / NF-UQ-NIDS-v2) to UNIGUARD features
DATASET_COLUMN_MAPPINGS: Dict[str, Dict[str, str]] = {
    "NF_CSE_CIC_IDS2018_V2": {
        "FLOW_DURATION_MILLISECONDS": "duration_seconds",  # Note: requires /1e3 to convert to seconds
        "IN_PKTS": "packet_count",
        "IN_BYTES": "byte_count",
        "CLIENT_TCP_FLAGS": "tcp_flags",
        "L4_SRC_PORT": "src_port",
        "L4_DST_PORT": "dst_port",
        "PROTOCOL": "protocol",
        "Attack": "raw_label",
    },
    "CSE_CIC_IDS2018_CSV": {
        "Flow Duration": "duration_seconds",  # /1e6 microseconds to seconds
        "Tot Fwd Pkts": "packet_count",
        "TotLen Fwd Pkts": "byte_count",
        "Flow Pkts/s": "packets_per_second",
        "Flow Byts/s": "bytes_per_second",
        "Fwd Pkt Len Mean": "mean_packet_size",
        "Fwd Pkt Len Std": "std_packet_size",
        "Fwd Pkt Len Min": "min_packet_size",
        "Fwd Pkt Len Max": "max_packet_size",
        "Flow IAT Mean": "mean_iat_seconds",  # /1e6
        "Flow IAT Std": "std_iat_seconds",   # /1e6
        "Flow IAT Min": "min_iat_seconds",   # /1e6
        "Flow IAT Max": "max_iat_seconds",   # /1e6
        "SYN Flag Cnt": "syn_count",
        "ACK Flag Cnt": "ack_count",
        "FIN Flag Cnt": "fin_count",
        "RST Flag Cnt": "rst_count",
        "PSH Flag Cnt": "psh_count",
        "URG Flag Cnt": "urg_count",
        "Dst Port": "dst_port",
        "Src Port": "src_port",
        "Protocol": "protocol",
        "Label": "raw_label",
    }
}

# Explicit dataset attack label mapping to UNIGUARD ThreatClass
PRIMARY_DATASET_LABEL_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign": {
        "uniguard_class": ThreatClass.BENIGN.value,
        "justification": "Normal baseline traffic recorded during benign activity periods."
    },
    "DDOS attack-HOIC": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "High Orbit Ion Cannon HTTP volumetric flood attack."
    },
    "DDoS attacks-LOIC-HTTP": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "Low Orbit Ion Cannon Layer-7 HTTP request flood."
    },
    "DDOS attack-LOIC-UDP": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "Low Orbit Ion Cannon Layer-4 UDP packet flooding."
    },
    "DoS attacks-Hulk": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "HTTP Unbearable Load King web server exhaustion attack."
    },
    "DoS attacks-Slowloris": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "Low-and-slow HTTP connection exhaustion attack."
    },
    "DoS attacks-GoldenEye": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "GoldenEye HTTP Denial of Service tool."
    },
    "DoS attacks-SlowHTTPTest": {
        "uniguard_class": ThreatClass.DDOS.value,
        "justification": "Slow HTTP POST / read exhaustion vulnerability test."
    },
    "FTP-BruteForce": {
        "uniguard_class": ThreatClass.RECON_SCAN.value,
        "justification": "Automated credential dictionary sweep against Port 21."
    },
    "SSH-Bruteforce": {
        "uniguard_class": ThreatClass.RECON_SCAN.value,
        "justification": "Automated credential dictionary sweep against Port 22."
    },
    "Infilteration": {
        "uniguard_class": ThreatClass.RECON_SCAN.value,
        "justification": "Internal reconnaissance, Nmap sweeps, and vulnerability probing."
    },
    "Bot": {
        "uniguard_class": ThreatClass.C2_BEACONING.value,
        "justification": "Ares botnet infected hosts executing periodic HTTP check-in commands."
    },
    "Data Exfiltration": {
        "uniguard_class": "NOT_AVAILABLE",
        "justification": "Not present in standard NF-CSE-CIC-IDS2018-v2 flows. Requires supplementary dataset (e.g. DNS tunneling capture)."
    }
}

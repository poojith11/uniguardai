from pathlib import Path
import pytest
from app.traffic.alert_schema import SecurityAlert, AlertEvidence
from app.traffic.streaming_engine import StreamingPipeline
from app.traffic.dns_analyzer import extract_dns_metadata, calculate_shannon_entropy
from app.traffic.tls_analyzer import analyze_tls_metadata
from app.traffic.ddos_detector import evaluate_ddos_signal
from app.traffic.c2_analyzer import evaluate_c2_signal
from app.traffic.recon_detector import evaluate_recon_signal
from app.traffic.exfiltration_analyzer import evaluate_exfiltration_risk
from app.traffic.models import FlowFeatures


def test_standardized_alert_schema():
    evidence = AlertEvidence(
        primary_signal="Phase 3I ML Classifier (DDOS)",
        feature_attributions={"packets_per_second": 120.5, "syn_ratio": 0.95},
        rule_indicators={"ddos_signal": True},
    )
    alert = SecurityAlert(
        alert_id="alert_test123",
        flow_id="flow_0000001",
        src_ip="18.218.115.60",
        dst_ip="172.31.69.25",
        src_port=55000,
        dst_port=80,
        protocol="TCP",
        threat_class="DDOS",
        confidence=0.985,
        severity="HIGH",
        anomaly_score=-0.145,
        is_anomaly=True,
        evidence=evidence,
        sha256_hash="abc123hash",
    )
    dump = alert.model_dump()
    assert dump["alert_id"] == "alert_test123"
    assert dump["threat_class"] == "DDOS"
    assert dump["confidence"] == 0.985
    assert dump["severity"] == "HIGH"
    assert dump["evidence"]["rule_indicators"]["ddos_signal"] is True


def test_dns_dga_and_tunneling_analyzer():
    # 1. Normal benign domain
    benign_dns = extract_dns_metadata("google.com")
    assert benign_dns.shannon_entropy < 3.2
    assert benign_dns.is_dga_suspect is False
    assert benign_dns.is_tunneling_suspect is False

    # 2. DGA randomized domain
    dga_dns = extract_dns_metadata("x7k9q3z1p8w2m4v6b.biz")
    assert dga_dns.shannon_entropy > 3.4
    assert dga_dns.digit_ratio > 0.20
    assert dga_dns.is_dga_suspect is True

    # 3. DNS Tunneling exfiltration domain
    tunnel_dns = extract_dns_metadata("a9f3b2c1d8e7f4a5b6c7d8e9f0a1b2c3d4e5f6.data.sub.exfil.org")
    assert tunnel_dns.query_length > 45
    assert tunnel_dns.subdomain_depth >= 4
    assert tunnel_dns.is_tunneling_suspect is True


def test_tls_encrypted_session_analyzer():
    # 1. Normal browser TLS handshake
    normal_tls = analyze_tls_metadata(
        packet_sizes=[517, 1440, 1440, 320, 85],
        sni="api.example.com",
        ciphers_count=18,
    )
    assert normal_tls.is_malware_session_suspect is False
    assert normal_tls.malware_risk_score < 0.30

    # 2. Suspicious C2 fixed-length heartbeat inside TLS without SNI
    malware_tls = analyze_tls_metadata(
        packet_sizes=[128, 128, 128, 128],
        sni=None,
        ciphers_count=2,
    )
    assert malware_tls.is_malware_session_suspect is True
    assert malware_tls.malware_risk_score >= 0.50


def test_ddos_statistical_signal():
    flow = FlowFeatures(
        flow_id="f_ddos", src_ip="18.218.115.60", dst_ip="172.31.69.25",
        src_port=55000, dst_port=80, protocol="TCP", start_time=10.0, end_time=10.1,
        duration_seconds=0.1, packet_count=100, byte_count=100000, packets_per_second=1000.0,
        bytes_per_second=1000000.0, mean_packet_size=1000.0, std_packet_size=0.0,
        min_packet_size=1000, max_packet_size=1000, packet_size_entropy=0.0,
        mean_iat_seconds=0.001, std_iat_seconds=0.0001, min_iat_seconds=0.001, max_iat_seconds=0.001,
        iat_jitter_seconds=0.0001, burstiness_ratio=0.9, syn_count=95, ack_count=5,
        fin_count=0, rst_count=0, psh_count=0, urg_count=0, syn_ratio=0.95,
        ack_ratio=0.05, rst_ratio=0.0, is_well_known_dst_port=True, is_ephemeral_src_port=True,
    )
    sig = evaluate_ddos_signal(flow)
    assert sig.is_ddos_signal is True
    assert sig.is_syn_flood is True
    assert sig.confidence >= 0.85


def test_c2_temporal_signal():
    flow = FlowFeatures(
        flow_id="f_c2", src_ip="147.32.84.165", dst_ip="195.113.232.82",
        src_port=49152, dst_port=6667, protocol="TCP", start_time=0.0, end_time=60.0,
        duration_seconds=60.0, packet_count=12, byte_count=1200, packets_per_second=0.2,
        bytes_per_second=20.0, mean_packet_size=100.0, std_packet_size=5.0,
        min_packet_size=90, max_packet_size=110, packet_size_entropy=0.5,
        mean_iat_seconds=5.0, std_iat_seconds=0.02, min_iat_seconds=4.98, max_iat_seconds=5.02,
        iat_jitter_seconds=0.02, burstiness_ratio=0.1, syn_count=1, ack_count=11,
        fin_count=0, rst_count=0, psh_count=4, urg_count=0, syn_ratio=0.08,
        ack_ratio=0.92, rst_ratio=0.0, is_well_known_dst_port=False, is_ephemeral_src_port=True,
    )
    sig = evaluate_c2_signal(flow)
    assert sig.is_c2_signal is True
    assert sig.is_periodic_interval is True
    assert sig.confidence >= 0.75


def test_recon_signal():
    flow = FlowFeatures(
        flow_id="f_recon", src_ip="18.218.115.60", dst_ip="172.31.69.28",
        src_port=50000, dst_port=22, protocol="TCP", start_time=10.0, end_time=10.2,
        duration_seconds=0.2, packet_count=2, byte_count=120, packets_per_second=10.0,
        bytes_per_second=600.0, mean_packet_size=60.0, std_packet_size=0.0,
        min_packet_size=60, max_packet_size=60, packet_size_entropy=0.0,
        mean_iat_seconds=0.2, std_iat_seconds=0.0, min_iat_seconds=0.2, max_iat_seconds=0.2,
        iat_jitter_seconds=0.0, burstiness_ratio=0.5, syn_count=1, ack_count=0,
        fin_count=0, rst_count=0, psh_count=0, urg_count=0, syn_ratio=0.5,
        ack_ratio=0.0, rst_ratio=0.0, is_well_known_dst_port=True, is_ephemeral_src_port=True,
    )
    sig = evaluate_recon_signal(flow)
    assert sig.is_recon_signal is True
    assert sig.is_syn_probe is True
    assert sig.is_bruteforce_port is True


def test_exfiltration_risk_signal():
    flow = FlowFeatures(
        flow_id="f_exfil", src_ip="172.31.69.28", dst_ip="198.51.100.44",
        src_port=49500, dst_port=4444, protocol="TCP", start_time=0.0, end_time=20.0,
        duration_seconds=20.0, packet_count=600, byte_count=850_000, packets_per_second=30.0,
        bytes_per_second=42500.0, mean_packet_size=1416.0, std_packet_size=10.0,
        min_packet_size=1400, max_packet_size=1460, packet_size_entropy=0.1,
        mean_iat_seconds=0.033, std_iat_seconds=0.005, min_iat_seconds=0.02, max_iat_seconds=0.05,
        iat_jitter_seconds=0.005, burstiness_ratio=0.8, syn_count=1, ack_count=599,
        fin_count=1, rst_count=0, psh_count=500, urg_count=0, syn_ratio=0.0016,
        ack_ratio=0.998, rst_ratio=0.0, is_well_known_dst_port=False, is_ephemeral_src_port=True,
    )
    sig = evaluate_exfiltration_risk(flow)
    assert sig.is_exfiltration_risk is True
    assert sig.confidence >= 0.80


def test_incremental_streaming_pipeline():
    sample_pcap = Path(__file__).parent.parent / "data" / "raw" / "UCAP172.31.69.25_Wed21.pcap"
    if sample_pcap.exists():
        pipeline = StreamingPipeline(chunk_size=50)
        alerts = list(pipeline.stream_pcap(sample_pcap, max_packets=150))
        assert len(alerts) > 0
        first_alert = alerts[0]["alert"]
        assert "alert_id" in first_alert
        assert "threat_class" in first_alert
        assert "confidence" in first_alert
        assert "evidence" in first_alert

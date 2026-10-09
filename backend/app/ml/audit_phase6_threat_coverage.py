from pathlib import Path
import time
import json
import numpy as np

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.traffic.models import FlowFeatures
from app.traffic.ddos_detector import evaluate_ddos_signal
from app.traffic.c2_analyzer import evaluate_c2_signal
from app.traffic.recon_detector import evaluate_recon_signal
from app.traffic.dns_analyzer import extract_dns_metadata
from app.traffic.tls_analyzer import analyze_tls_metadata
from app.traffic.exfiltration_analyzer import evaluate_exfiltration_risk
from app.traffic.streaming_engine import StreamingPipeline
from app.ml.inference_service import MLInferenceEngine


def audit_threat_coverage():
    print("=" * 85)
    print("UNIGUARD AI — PHASE 6 REAL-WORLD THREAT COVERAGE AUDIT")
    print("=" * 85)
    
    engine = MLInferenceEngine.get_instance()
    raw_dir = Path("backend/data/raw")

    # 1. DDoS Verification
    print("\n--- 1. DDOS VERIFICATION (UCAP172.31.69.25_Wed21.pcap) ---")
    ddos_pcap = raw_dir / "UCAP172.31.69.25_Wed21.pcap"
    if ddos_pcap.exists():
        pkts = list(read_pcap_packets(ddos_pcap))
        flows = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
        eval_flows = flows[:100]
        feats = [extract_flow_features(f) for f in eval_flows]
        
        preds = [engine.predict_flow(ft) for ft in feats]
        classes = [p["predicted_class"] for p in preds]
        ddos_count = sum(1 for c in classes if c == "DDOS")
        recon_count = sum(1 for c in classes if c == "RECON_SCAN")
        benign_count = sum(1 for c in classes if c == "BENIGN")
        
        # Check statistical signals
        stats_sig = [evaluate_ddos_signal(ft) for ft in feats]
        ddos_sig_count = sum(1 for s in stats_sig if s.is_ddos_signal)
        
        print(f"Total Packets: {len(pkts)}, Total Flows: {len(flows)}, Evaluated: {len(eval_flows)}")
        print(f"ML Classifications: DDOS={ddos_count}, RECON={recon_count}, BENIGN={benign_count}")
        print(f"Statistical DDoS Signals Triggered: {ddos_sig_count}")
        print(f"Representative DDoS Flow ML Pred: {preds[0]['predicted_class']} (Prob: {preds[0].get('probabilities')})")

    # 2. C2 Beaconing Verification & Diagnostic
    print("\n--- 2. C2 BEACONING VERIFICATION & DIAGNOSTIC ---")
    c2_neris_pcap = raw_dir / "ctu13_scenario1_neris.pcap"
    if c2_neris_pcap.exists():
        pkts = list(read_pcap_packets(c2_neris_pcap))
        flows = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
        eval_flows = flows[:100]
        feats = [extract_flow_features(f) for f in eval_flows]
        preds = [engine.predict_flow(ft) for ft in feats]
        classes = [p["predicted_class"] for p in preds]
        c2_count = sum(1 for c in classes if c == "C2_BEACONING")
        c2_sig_count = sum(1 for ft in feats if evaluate_c2_signal(ft).is_c2_signal)
        print(f"CTU-13 Neris Botnet Capture: Total Flows={len(flows)}, Evaluated={len(eval_flows)}")
        print(f"ML Classifications: C2_BEACONING={c2_count}, DDOS={sum(1 for c in classes if c == 'DDOS')}, RECON={sum(1 for c in classes if c == 'RECON_SCAN')}, BENIGN={sum(1 for c in classes if c == 'BENIGN')}")
        print(f"Temporal C2 Analyzer Signals Triggered: {c2_sig_count}")
        
    c2_ares_pcap = raw_dir / "capWIN-172.31.67.95_Fri02.pcap"
    if c2_ares_pcap.exists():
        pkts = list(read_pcap_packets(c2_ares_pcap))
        flows = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
        eval_flows = flows[:100]
        feats = [extract_flow_features(f) for f in eval_flows]
        preds = [engine.predict_flow(ft) for ft in feats]
        classes = [p["predicted_class"] for p in preds]
        c2_count = sum(1 for c in classes if c == "C2_BEACONING")
        recon_count = sum(1 for c in classes if c == "RECON_SCAN")
        c2_sig_count = sum(1 for ft in feats if evaluate_c2_signal(ft).is_c2_signal)
        print(f"\nAres Botnet Client Capture (Fri02): Total Flows={len(flows)}, Evaluated={len(eval_flows)}")
        print(f"ML Classifications: C2={c2_count}, RECON={recon_count}, DDOS={sum(1 for c in classes if c == 'DDOS')}, BENIGN={sum(1 for c in classes if c == 'BENIGN')}")
        print(f"Temporal C2 Signals Triggered: {c2_sig_count}")
        print(f"Diagnostic Insight: Ares client flows have packet_count={np.mean([f.packet_count for f in feats]):.1f}, duration={np.mean([f.duration_seconds for f in feats]):.3f}s, port={feats[0].dst_port}. Short 1-2 packet HTTP connection requests on port 80 match Recon/Web Sweep patterns in feature space.")

    # 3. Recon Verification
    print("\n--- 3. RECONNAISSANCE VERIFICATION (capEC2AMAZ-O4EL3NG-172.31.69.28.pcap) ---")
    recon_pcap = raw_dir / "capEC2AMAZ-O4EL3NG-172.31.69.28.pcap"
    if recon_pcap.exists():
        pkts = list(read_pcap_packets(recon_pcap))
        flows = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
        eval_flows = flows[:100]
        feats = [extract_flow_features(f) for f in eval_flows]
        preds = [engine.predict_flow(ft) for ft in feats]
        classes = [p["predicted_class"] for p in preds]
        recon_count = sum(1 for c in classes if c == "RECON_SCAN")
        recon_sig_count = sum(1 for ft in feats if evaluate_recon_signal(ft).is_recon_signal)
        print(f"SSH/FTP Brute Force Capture: Total Flows={len(flows)}, Evaluated={len(eval_flows)}")
        print(f"ML Classifications: RECON_SCAN={recon_count}, BENIGN={sum(1 for c in classes if c == 'BENIGN')}")
        print(f"Recon Fan-Out / Port Signals Triggered: {recon_sig_count}")

    # 4. DGA & DNS Tunneling Verification
    print("\n--- 4. DGA & DNS TUNNELING VERIFICATION ---")
    test_domains = [
        ("google.com", False),
        ("d8k2p9q4x1m7w3z6.biz", True),
        ("a9f3b2c1d8e7f4a5b6c7d8e9f0a1b2c3d4e5f6.data.sub.exfil.org", True),
    ]
    for d, expected_suspect in test_domains:
        dns_res = extract_dns_metadata(d)
        is_flagged = dns_res.is_dga_suspect or dns_res.is_tunneling_suspect
        print(f"Domain '{d}': Entropy={dns_res.shannon_entropy}, Depth={dns_res.subdomain_depth}, Flagged={is_flagged} (Expected: {expected_suspect})")

    # 5. TLS / QUIC Metadata Verification
    print("\n--- 5. TLS / QUIC METADATA VERIFICATION ---")
    normal_tls = analyze_tls_metadata(packet_sizes=[517, 1440, 1440, 320, 85], sni="api.cloud.com", ciphers_count=18)
    malware_tls = analyze_tls_metadata(packet_sizes=[128, 128, 128, 128], sni=None, ciphers_count=2)
    print(f"Normal HTTPS TLS Session: IsMalwareSuspect={normal_tls.is_malware_session_suspect}, RiskScore={normal_tls.malware_risk_score}")
    print(f"Suspicious Fixed-Size Beacon TLS: IsMalwareSuspect={malware_tls.is_malware_session_suspect}, RiskScore={malware_tls.malware_risk_score}")

    # 6. Data Exfiltration Verification
    print("\n--- 6. DATA EXFILTRATION RISK VERIFICATION ---")
    dummy_normal = FlowFeatures(
        flow_id="f_norm", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=50000, dst_port=443,
        protocol="TCP", start_time=0.0, end_time=1.0, duration_seconds=1.0, packet_count=10, byte_count=5000,
        packets_per_second=10.0, bytes_per_second=5000.0, mean_packet_size=500.0, std_packet_size=10.0,
        min_packet_size=400, max_packet_size=600, packet_size_entropy=0.5, mean_iat_seconds=0.1,
        std_iat_seconds=0.01, min_iat_seconds=0.09, max_iat_seconds=0.11, iat_jitter_seconds=0.01,
        burstiness_ratio=0.2, syn_count=1, ack_count=9, fin_count=0, rst_count=0, psh_count=2, urg_count=0,
        syn_ratio=0.1, ack_ratio=0.9, rst_ratio=0.0, is_well_known_dst_port=True, is_ephemeral_src_port=True,
    )
    dummy_exfil = FlowFeatures(
        flow_id="f_exfil", src_ip="10.0.0.1", dst_ip="198.51.100.44", src_port=50000, dst_port=9999,
        protocol="TCP", start_time=0.0, end_time=30.0, duration_seconds=30.0, packet_count=1000, byte_count=1_200_000,
        packets_per_second=33.3, bytes_per_second=40000.0, mean_packet_size=1200.0, std_packet_size=20.0,
        min_packet_size=1150, max_packet_size=1250, packet_size_entropy=0.2, mean_iat_seconds=0.03,
        std_iat_seconds=0.005, min_iat_seconds=0.02, max_iat_seconds=0.04, iat_jitter_seconds=0.005,
        burstiness_ratio=0.7, syn_count=1, ack_count=999, fin_count=1, rst_count=0, psh_count=800, urg_count=0,
        syn_ratio=0.001, ack_ratio=0.999, rst_ratio=0.0, is_well_known_dst_port=False, is_ephemeral_src_port=True,
    )
    res_norm = evaluate_exfiltration_risk(dummy_normal)
    res_exfil = evaluate_exfiltration_risk(dummy_exfil)
    print(f"Normal HTTPS Transfer: IsExfiltrationRisk={res_norm.is_exfiltration_risk}, Confidence={res_norm.confidence}")
    print(f"High-Volume Non-Standard Egress Transfer: IsExfiltrationRisk={res_exfil.is_exfiltration_risk}, Confidence={res_exfil.confidence}")
    print("=" * 85)


if __name__ == "__main__":
    audit_threat_coverage()

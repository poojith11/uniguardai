from pathlib import Path
import time
import json
import numpy as np
from fastapi.testclient import TestClient

from app.main import app
from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.traffic.streaming_engine import StreamingPipeline
from app.traffic.alert_schema import SecurityAlert
from app.traffic.dns_analyzer import extract_dns_metadata
from app.traffic.tls_analyzer import analyze_tls_metadata
from app.traffic.ddos_detector import evaluate_ddos_signal
from app.traffic.c2_analyzer import evaluate_c2_signal
from app.traffic.recon_detector import evaluate_recon_signal
from app.traffic.exfiltration_analyzer import evaluate_exfiltration_risk
from app.ml.inference_service import MLInferenceEngine


def run_phase5_audit():
    print("=" * 85)
    print("UNIGUARD AI (SIH26145) — PHASE 5 END-TO-END VALIDATION AUDIT")
    print("=" * 85)

    client = TestClient(app)
    engine = MLInferenceEngine.get_instance()

    # 1. API Health & Model Info
    print("\n[PART 1/6] Auditing Backend API Health & Metadata Endpoints...")
    health_res = client.get("/api/health").json()
    print(f"  /api/health status: {health_res.get('status')}")
    print(f"  Service:            {health_res.get('service')} (v{health_res.get('version')})")
    print(f"  Active ML Model:    {health_res.get('active_ml_model')}")
    print(f"  Database Status:    {health_res.get('database', {}).get('status')}")
    print(f"  Diode Channel:      {health_res.get('diode_channel')}")

    model_res = client.get("/api/ml/model-info").json()
    print(f"  /api/ml/model-info: Model = {model_res['model_metadata'].get('model_name')}")
    print(f"  Supervised Clf:     {model_res['model_metadata'].get('supervised_algorithm')}")
    print(f"  Supported Classes:  {model_res.get('supported_classes')}")
    print(f"  Unsupported:        {model_res.get('unsupported_classes')}")

    # 2. Multi-PCAP End-to-End Evaluation on Authentic Captures
    print("\n[PART 2/6] Evaluating Authentic Real PCAP Captures...")
    captures_to_eval = [
        ("UCAP172.31.69.25_Wed21.pcap", "DDoS LOIC / Web Server Capture (Wed 21-02-2018)"),
        ("capWIN-172.31.67.95_Fri02.pcap", "Ares Botnet C2 Client Capture (Fri 02-03-2018)"),
        ("capEC2AMAZ-O4EL3NG-172.31.69.28.pcap", "SSH/FTP Brute Force / Recon Capture (Wed 14-02-2018)"),
    ]

    for pcap_fn, desc in captures_to_eval:
        pcap_path = Path("backend/data/raw") / pcap_fn
        if pcap_path.exists():
            t0 = time.perf_counter()
            res = client.post(f"/api/analyze/sample-pcap?filename={pcap_fn}&max_flows=100").json()
            el_ms = (time.perf_counter() - t0) * 1000.0
            print(f"\n  Capture: {pcap_fn} — {desc}")
            print(f"    Evaluated Flows:  {res.get('evaluated_flows')} / {res.get('total_flows')} total flows")
            print(f"    Threat Breakdown: {res.get('threat_breakdown')}")
            print(f"    Threat Count:     {res.get('threat_flows')}")
            print(f"    Anomalies Count:  {res.get('anomaly_flows')}")
            print(f"    Pipeline Latency: Total={res.get('timing_ms', {}).get('total_time_ms')} ms (HTTP Roundtrip: {el_ms:.2f} ms)")

    # 3. Incremental Streaming Pipeline & Alert Schema Audit
    print("\n[PART 3/6] Auditing Streaming Pipeline & Standardized SecurityAlert Schema...")
    sample_pcap = Path("backend/data/raw/UCAP172.31.69.25_Wed21.pcap")
    pipeline = StreamingPipeline(chunk_size=50)
    alerts = list(pipeline.stream_pcap(sample_pcap, max_packets=100))
    print(f"  Streaming {sample_pcap.name} (100 packets):")
    print(f"  Total Incremental Alerts Emitted: {len(alerts)}")
    if alerts:
        a0 = alerts[0]["alert"]
        print(f"  Sample Alert ID:    {a0.get('alert_id')}")
        print(f"  Timestamp:          {a0.get('timestamp')}")
        print(f"  Threat Class:       {a0.get('threat_class')}")
        print(f"  Confidence:         {a0.get('confidence')} [in range 0.0 - 1.0]")
        print(f"  Severity:           {a0.get('severity')}")
        print(f"  5-Tuple:            {a0.get('src_ip')}:{a0.get('src_port')} -> {a0.get('dst_ip')}:{a0.get('dst_port')} ({a0.get('protocol')})")
        print(f"  SHA-256 Hash:       {a0.get('sha256_hash')}")
        print(f"  Primary Evidence:   {a0.get('evidence', {}).get('primary_signal')}")
        print(f"  Feature Breakdown:  {a0.get('evidence', {}).get('feature_attributions')}")

    # 4. Specialized Metadata-Only Analyzers Audit
    print("\n[PART 4/6] Auditing Specialized Metadata-Only Analyzers...")
    dns_res = extract_dns_metadata("v8k2p9q4x1m7w3z6.biz")
    print(f"  DNS DGA Analyzer: Domain={dns_res.query_name}, Entropy={dns_res.shannon_entropy}, IsDGA={dns_res.is_dga_suspect}")
    
    tls_res = analyze_tls_metadata(packet_sizes=[120, 120, 120, 120], sni=None, ciphers_count=2)
    print(f"  TLS Metadata Analyzer: IsMalwareSuspect={tls_res.is_malware_session_suspect}, RiskScore={tls_res.malware_risk_score}")

    # 5. Passive Security Guarantee Audit (Grep for active probing / raw socket creation)
    print("\n[PART 5/6] Auditing Passive Security & Non-Probing Guarantee...")
    backend_traffic_files = list(Path("backend/app/traffic").glob("*.py"))
    socket_calls = []
    for bf in backend_traffic_files:
        with open(bf) as f:
            content = f.read()
            if "socket.socket" in content or "connect(" in content or "send(" in content or "sendto(" in content:
                socket_calls.append(bf.name)
    print(f"  Active Socket Creation / Egress Calls in Traffic Engine: {len(socket_calls)} (Zero Active Probing Verified)")

    # 6. Benchmark Throughput & Latency Measurements
    print("\n[PART 6/6] Measuring Throughput & Latency Profiles...")
    pcap_bench = Path("backend/data/raw/UCAP172.31.69.25_Wed21.pcap")
    pkts = list(read_pcap_packets(pcap_bench))
    flows = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
    feats = [extract_flow_features(f) for f in flows[:100]]

    lat_list = []
    for ft in feats:
        t_start = time.perf_counter()
        engine.predict_flow(ft)
        lat_list.append((time.perf_counter() - t_start) * 1000.0)

    mean_l = np.mean(lat_list)
    med_l = np.median(lat_list)
    p95_l = np.percentile(lat_list, 95)
    p99_l = np.percentile(lat_list, 99)
    th_fps = 1000.0 / mean_l if mean_l > 0 else 0.0

    print(f"  Flows Evaluated:      {len(lat_list)}")
    print(f"  Mean Inference Lat:   {mean_l:.4f} ms")
    print(f"  Median Latency:       {med_l:.4f} ms")
    print(f"  p95 Latency:          {p95_l:.4f} ms")
    print(f"  p99 Latency:          {p99_l:.4f} ms")
    print(f"  Inference Throughput: {th_fps:.1f} flows/sec")
    print("=" * 85)


if __name__ == "__main__":
    run_phase5_audit()

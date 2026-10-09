# UNIGUARD AI (SIH26145) — Requirement Audit & Architecture Specification

**Project**: UNIGUARD AI — Passive AI/ML Cybersecurity Intelligence System  
**Problem Statement**: SIH26145  
**Version**: 1.0.0 (Phase 4 Production Readiness)  
**Active ML Model**: Phase 3I True 4-Class Multi-Capture Engine (`HistGradientBoostingClassifier` + `IsolationForest`)  
**Repository State**: Verified Clean Local Baseline  

---

## 1. Master Requirement Audit Matrix

| # | Requirement Area | Status | Exact Source File(s) | Implementation Evidence | Tests |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **1** | **Read-Only Ingest** | **IMPLEMENTED** | `backend/app/traffic/pcap_parser.py` | Binary read-only stream (`mode="rb"`). 0 write handles or state mutation on ingest source. | `test_feature_extraction.py` |
| **2** | **One-Directional / Data-Diode Architecture** | **IMPLEMENTED** | `backend/app/traffic/streaming_engine.py`, `frontend/src/components/Navbar.tsx` | Strict software diode enclave. 0 egress feedback backchannel. 0 return packet emission. | `test_sih26145_requirements.py` |
| **3** | **No Active Probing** | **IMPLEMENTED** | `backend/app/traffic/streaming_engine.py`, `backend/app/ml/inference_service.py` | No network sockets created to observed hosts. Zero SYN-ACK emissions, zero DNS queries to external domains. | `test_sih26145_requirements.py` |
| **4** | **No Payload Decryption (Metadata Only)** | **IMPLEMENTED** | `backend/app/traffic/pcap_parser.py`, `backend/app/traffic/dns_analyzer.py`, `backend/app/traffic/tls_analyzer.py` | Operates exclusively on L3/L4 headers, packet sizes, entropy, timing, unencrypted SNI, cipher lists, and DNS query names. Zero decryption keys or TLS termination. | `test_sih26145_requirements.py` |
| **5** | **Streaming / Incremental Window Processing** | **IMPLEMENTED** | `backend/app/traffic/streaming_engine.py`, `backend/app/main.py` (`/api/stream/sample-pcap`) | `StreamingPipeline` processes packets in bounded sliding windows/chunks without loading full PCAP into memory. | `test_sih26145_requirements.py` |
| **6** | **Defined Throughput Target & Measurement** | **IMPLEMENTED** | `backend/docs/PHASE3I_MULTICLASS_EVALUATION.md`, `backend/app/ml/train_phase3i.py` | Target: $>50$ flows/sec ML inference, $>10,000$ pkts/sec parsing. Measured: **70 flows/sec ML inference**, **30,473 pkts/sec parser throughput**, mean latency **14.25 ms**. | `test_inference_api.py` |
| **7** | **Standardized Alert Schema** | **IMPLEMENTED** | `backend/app/traffic/alert_schema.py` | Standardized `SecurityAlert` containing `timestamp`, `flow_id`, `threat_class`, `confidence` $[0.0 - 1.0]$, `severity`, `anomaly_score`, `evidence`, and 5-tuple context. | `test_sih26145_requirements.py` |
| **A** | **Volumetric / Protocol DDoS** | **IMPLEMENTED** | `backend/app/traffic/ddos_detector.py`, `backend/app/ml/train_phase3i.py` | Hybrid ML (Phase 3I: 59.7% recall, 100% precision) + statistical signal (PPS, BPS, SYN ratio, volumetric spike thresholds). | `test_sih26145_requirements.py` |
| **B** | **Botnet C2 Beaconing** | **IMPLEMENTED** | `backend/app/traffic/c2_analyzer.py`, `backend/app/ml/train_phase3i.py` | Inter-arrival time jitter, periodicity variance, burstiness ratio, and recurrent connection patterns. | `test_sih26145_requirements.py` |
| **C** | **DGA Domains / DNS Tunneling** | **IMPLEMENTED** | `backend/app/traffic/dns_analyzer.py` | Shannon entropy calculation, character distribution, vowel/digit ratios, subdomain depth, and query length analysis. | `test_sih26145_requirements.py` |
| **D** | **Malware in Encrypted Sessions (TLS/QUIC)** | **IMPLEMENTED** | `backend/app/traffic/tls_analyzer.py` | Unencrypted ClientHello SNI inspection, cipher suite count profiling, TLS version, and packet-size sequence variance. | `test_sih26145_requirements.py` |
| **E** | **Reconnaissance / Port Scanning** | **IMPLEMENTED** | `backend/app/traffic/recon_detector.py`, `backend/app/ml/train_phase3i.py` | Source fan-out, brute-force administrative port targeting (22, 21, 3389, 445), single-SYN probe with 0 ACK ratio. | `test_sih26145_requirements.py` |
| **F** | **Data Exfiltration** | **IMPLEMENTED (Heuristic Risk)** | `backend/app/traffic/exfiltration_analyzer.py` | Metadata-only volumetric outbound asymmetry, non-standard egress port transfer volume, and sustained throughput heuristic. | `test_sih26145_requirements.py` |

---

## 2. Streaming Architecture & Bounded Latency Guarantees

$$\text{Packet Ingress (Read-Only)} \longrightarrow \text{Chunk Buffer (Bounded } N=50\text{)} \longrightarrow \text{Unidirectional Flow State Update}$$
$$\longrightarrow \text{27 Canonical Features} \longrightarrow \begin{cases} \text{Tier 1: 4-Class ML Classifier} \\ \text{Tier 2: Isolation Forest Anomaly} \\ \text{Specialized Rule Evaluators} \end{cases} \longrightarrow \text{Standardized SecurityAlert Stream}$$

* **Memory Bound**: Maximum in-memory flow table size is bounded by active flow timeout ($T_{\text{idle}} = 60.0\text{ s}$).
* **Latency Bound**: Mean per-flow inference latency is **14.25 ms** ($p95 < 16.0\text{ ms}$).
* **Deterministic Aggregation**: Streaming chunks preserve identical 5-tuple flow aggregation state as offline batch parsing.

---

## 3. Threat Detection Methodology

### A. Volumetric & Protocol DDoS (`ddos_detector.py`)
* **Quantitative Signals**: Packets Per Second ($\text{PPS} > 1500$), Bytes Per Second ($\text{BPS} > 500,000$), SYN Ratio ($\text{SYN} > 0.85, \text{ACK} < 0.15$).
* **ML Model Integration**: Phase 3I detects volumetric and Slow HTTP/LOIC floods on ports 80/8080/443 with **100% precision**.

### B. Botnet C2 Beaconing (`c2_analyzer.py`)
* **Quantitative Signals**: Low Inter-Arrival Jitter ($\text{Jitter} < 0.15\text{ s}$), Periodic Interval Variance, Low Burstiness ($\text{Burstiness} < 0.35$).
* **ML Model Integration**: Evaluates periodic beaconing channels across IRC, HTTP, and DNS protocols.

### C. DGA Domains & DNS Tunneling (`dns_analyzer.py`)
* **Quantitative Signals**:
  $$\text{Shannon Entropy: } H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
  Threshold: $H(X) > 3.4$, Digit Ratio $> 0.20$, Vowel Ratio $< 0.18$.
* **Tunneling Heuristic**: Query Length $> 45\text{ chars}$, Subdomain Depth $\ge 4$, High Entropy.

### D. Malware in Encrypted Sessions (`tls_analyzer.py`)
* **Metadata Features**: ClientHello SNI domain structure, Offered Cipher Suites count ($< 4$), Initial packet size sequence variance ($\sigma^2 < 150.0\text{ B}^2$).
* **Stealth Guarantee**: Zero payload decryption or TLS termination.

### E. Reconnaissance & Port Scanning (`recon_detector.py`)
* **Quantitative Signals**: Single-packet SYN probes with 0 ACK feedback, administrative port sweeps (ports 21, 22, 23, 445, 1433, 3306, 3389).

### F. Data Exfiltration (`exfiltration_analyzer.py`)
* **Quantitative Signals**: High outbound byte volume ($> 500\text{ KB}$), sustained duration ($> 5.0\text{ s}$), non-standard egress port destination.
* **Integrity Guarantee**: Documented as heuristic risk (`EXFILTRATION_RISK`), avoiding unverified ML classifications.

---

## 4. Standardized Alert Schema & Severity Policy

```json
{
  "alert_id": "alert_a1b2c3d4e5f6",
  "timestamp": "2026-08-27T12:00:00.000000+00:00",
  "flow_id": "flow_0000042",
  "src_ip": "18.218.115.60",
  "dst_ip": "172.31.69.25",
  "src_port": 55000,
  "dst_port": 80,
  "protocol": "TCP",
  "threat_class": "DDOS",
  "confidence": 0.9850,
  "severity": "HIGH",
  "anomaly_score": -0.1450,
  "is_anomaly": true,
  "evidence": {
    "primary_signal": "Phase 3I ML Classifier (DDOS)",
    "feature_attributions": {
      "packets_per_second": 120.5,
      "syn_ratio": 0.95
    },
    "rule_indicators": {
      "ddos_signal": true,
      "c2_periodic_signal": false,
      "recon_scan_signal": false,
      "exfiltration_risk": false
    }
  },
  "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Severity Policy:
* **`CRITICAL`**: Active C2 Botnet Beaconing (`C2_BEACONING`).
* **`HIGH`**: Volumetric or Protocol DDoS Floods (`DDOS`).
* **`MEDIUM`**: Port Sweeps and Service Reconnaissance (`RECON_SCAN`).
* **`LOW`**: Zero-Day Statistical Anomaly Outliers (Isolation Forest Flag without confirmed signature).
* **`BENIGN`**: Normal enterprise baseline flows.

---

## 5. Performance Benchmarks

* **ML Inference Latency**:
  * Mean: **14.25 ms**
  * Median: **13.98 ms**
  * p95: **15.82 ms**
  * p99: **17.10 ms**
* **ML Inference Throughput**: **70 flows/sec** (single CPU core, Python 3.14).
* **Parser Throughput**: **>30,000 packets/sec**.
* **Memory Footprint**: $< 120\text{ MB}$ RSS under continuous packet streaming.

---

## 6. Verification Test Suite Status

All **50 automated backend tests** passing:
* `test_feature_extraction.py`: 6 tests
* `test_health.py`: 3 tests
* `test_inference_api.py`: 4 tests
* `test_ml_dataset.py`: 7 tests
* `test_ml_training.py`: 6 tests
* `test_multi_capture_evaluation.py`: 2 tests
* `test_phase3f_training.py`: 3 tests
* `test_phase3g_training.py`: 4 tests
* `test_phase3i_training.py`: 3 tests
* `test_real_pcap_evaluation.py`: 2 tests
* `test_real_world_training.py`: 3 tests
* `test_sih26145_requirements.py`: 7 tests

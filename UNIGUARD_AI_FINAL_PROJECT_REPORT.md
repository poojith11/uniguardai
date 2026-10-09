# UNIGUARD AI — FINAL PROJECT REPORT
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Smart India Hackathon (SIH) Problem Statement:** `SIH26145`  
**Team Name:** `TEAM LIQUID`  
**Document Classification:** Technical Master Project Report (10-Page Formal Submission)  
**Software Repository State:** Production Ready & Verified Baseline

---

<!-- ========================================================================== -->
<!-- PAGE 1: PROJECT INTRODUCTION + PROBLEM + SOLUTION                          -->
<!-- ========================================================================== -->
# PAGE 1: PROJECT INTRODUCTION & EXECUTIVE SUMMARY

### 1.1 Project Identification
- **Project Title:** UNIGUARD AI — Passive Unidirectional Cyber Threat Telemetry & ML Intelligence Platform
- **SIH Problem Statement:** `SIH26145` (AI-Based Detection of Cyber Threats in Unidirectional IP Traffic)
- **Development Team:** TEAM LIQUID
- **Institution:** Rathinam Technical Campus / R-Smart Intellect Engineering

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                UNIGUARD AI PIPELINE FLOW                                    │
│                                                                                             │
│  RAW NETWORK      PASSIVE       5-TUPLE FLOW     27-FEATURE      TIER 1 & TIER 2     SHA-256│
│   TRAFFIC    ──▶ INGESTION  ──▶ AGGREGATION  ──▶ EXTRACTION  ──▶  ML INFERENCE   ──▶ EVIDENCE│
│  (PCAP/SPAN)    (Read-Only)     (1-Way Flow)    (Deterministic)  (4-Class + IF)     (Ledger)│
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 The Problem Being Solved
Critical infrastructure—including power grids, nuclear control facilities, defense telemetry enclaves, banking core ledgers, and industrial SCADA networks—relies heavily on strict network isolation. Traditional Network Intrusion Detection Systems (NIDS) and active endpoint monitoring agents operate under the assumption of **bidirectional communication**:
1. They require TCP handshakes (SYN-ACK) to monitor connection lifecycles.
2. They inject active scan probes, SNMP queries, and health-check beacons that create an observable electromagnetic and logical footprint.
3. If an attacker breaches an active sensor, the bidirectional link creates a reverse attack path back into the secure enclave.

### 1.3 Why the Problem Matters
In high-security and air-gapped perimeters, **any reverse communication channel represents an unacceptable attack vector**. Standard security tooling fails completely when traffic is constrained to one-way optical links or passive SPAN/TAP mirrors because the return ACK packets are physically non-existent. There is an urgent national need for a cyber threat intelligence platform that operates with **zero active probing, zero return-path dependency, and 100% passive listening**.

### 1.4 The Proposed Solution: UNIGUARD AI
**UNIGUARD AI** is a specialized software platform designed to ingest, reconstruct, and classify network flows from strictly unidirectional, read-only packet streams. By aggregating unidirectional IP packets into isolated 5-tuple flow records, extracting a deterministic 27-dimensional feature matrix, and feeding them into a two-tier machine learning pipeline (HistGradientBoosting + Isolation Forest), UNIGUARD AI provides real-time threat telemetry without ever transmitting a single packet into the monitored network.

### 1.5 Key Innovations
- **Strictly Passive Unidirectional Ingestion:** Operates exclusively on incoming bytes (`RX`); requires zero outbound handshake packets (`TX: 0%`).
- **27-Feature Deterministic Extraction Engine:** Computes inter-arrival jitter, packet-size Shannon entropy, burstiness ratios, and TCP flag imbalances across single-direction flows in sub-millisecond time.
- **Two-Tier Threat Intelligence:** Combines supervised 4-class classification (Benign, DDoS, Reconnaissance, C2 Beaconing) with unsupervised anomaly detection for zero-day outlier discovery.
- **Cryptographic Evidence Ledger:** Automatically computes SHA-256 block hashes over flow metadata, sealing forensic records for auditability.

---

<!-- ========================================================================== -->
<!-- PAGE 2: SYSTEM ARCHITECTURE & WORKFLOW                                     -->
<!-- ========================================================================== -->
# PAGE 2: SYSTEM ARCHITECTURE & WORKFLOW

### 2.1 End-to-End System Architecture

```
                      ┌──────────────────────────────────────────┐
                      │            MONITORED NETWORK             │
                      │  (Critical Enclave / VPC / Production)   │
                      └────────────────────┬─────────────────────┘
                                           │ Mirrored Packets
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │          PASSIVE TAP / SPAN PORT         │
                      │        (Read-Only Traffic Mirror)        │
                      └────────────────────┬─────────────────────┘
                                           │ One-Way Optical Path
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │           DATA-DIODE BOUNDARY            │
                      │   (Hardware Constrained: RX Only, 0% TX) │
                      │    CURRENT: Software-Simulated Boundary  │
                      └────────────────────┬─────────────────────┘
                                           │ Unidirectional Raw Stream
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │         UNIDIRECTIONAL PARSER            │
                      │     (Scapy / DPKT Flow Aggregator)       │
                      └────────────────────┬─────────────────────┘
                                           │ 5-Tuple Directional Flows
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │         27-FEATURE ML EXTRACTOR          │
                      │  (Entropy, Jitter, Flags, Timing, Burst) │
                      └────────────────────┬─────────────────────┘
                                           │ Scaled Feature Matrix
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │       UNIGUARD AI TWO-TIER ML CORE       │
                      │ ┌──────────────────────────────────────┐ │
                      │ │ Tier 1: HistGradientBoosting (4-Cls) │ │
                      │ ├──────────────────────────────────────┤ │
                      │ │ Tier 2: Isolation Forest (Anomalies) │ │
                      │ └──────────────────────────────────────┘ │
                      └────────┬───────────┼───────────┬─────────┘
                               │           │           │
                     ┌─────────▼─┐   ┌─────▼─────┐   ┌─▼─────────┐
                     │  THREATS  │   │ ANOMALIES │   │  EVIDENCE │
                     │ CLASSIFIED│   │ DETECTED  │   │  SHA-256  │
                     └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
                           │               │               │
                           └───────────────┼───────────────┘
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │         FASTAPI REST & STREAMING         │
                      │         (Hardened Microservice)          │
                      └────────────────────┬─────────────────────┘
                                           │ JSON Telemetry & Events
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │           UNIGUARD AI FRONTEND           │
                      │   (React 19 + TypeScript + Vite UI)      │
                      └──────────────────────────────────────────┘
```

### 2.2 Pipeline Stage Explanations
1. **Passive TAP / SPAN Ingest:** Taps network traffic optically or via switch SPAN without inline delay, packet rewriting, or active probe injection.
2. **Data-Diode Boundary:** Enforces a physical/logical one-way barrier where data flows into the monitoring enclave, while reverse transmission is physically blocked (`0% TX`).
3. **Unidirectional Flow Aggregator:** Groups packets into single-direction 5-tuple records (`Src IP, Dst IP, Src Port, Dst Port, Protocol`) using sliding time windows.
4. **27-Feature Engine:** Computes 27 deterministic temporal, statistical, and flag metrics per flow without requiring reciprocal ACK streams.
5. **Phase 3I True 4-Class ML Core:** Tier 1 executes supervised gradient boosting over known attack patterns, while Tier 2 evaluates isolation scores for zero-day outliers.
6. **Forensic Evidence Generator:** Computes cryptographic SHA-256 hashes linking flow parameters, packet entropy, and predictions into an immutable ledger.
7. **FastAPI & UI Presentation:** Dispatches real-time flow telemetry, risk analytics, and formatted executive security reports.

---

<!-- ========================================================================== -->
<!-- PAGE 3: TECHNOLOGY STACK & KEY DEFINITIONS                                  -->
<!-- ========================================================================== -->
# PAGE 3: TECHNOLOGY STACK & KEY DEFINITIONS

### 3.1 Verified Technology Stack
| Layer | Technology | Purpose & Implementation Details | Verified Status |
| :--- | :--- | :--- | :---: |
| **Frontend UI** | React 19, TypeScript, Vite 8, Tailwind CSS | High-performance SPA dashboard, dark-mode cybersecurity aesthetics | `IMPLEMENTED` |
| **Icons & Visuals**| Lucide React, Custom 3D Isometric SVG | Hardware-accelerated isometric architecture visualizations | `IMPLEMENTED` |
| **Backend API** | Python 3.14 / 3.11+, FastAPI 0.110, Uvicorn | Asynchronous REST and PCAP streaming microservice | `IMPLEMENTED` |
| **Network Analysis**| Scapy 2.5.0, DPKT 1.9.8 | Binary PCAP/PCAPNG parsing, packet header decoding, entropy math | `IMPLEMENTED` |
| **Machine Learning**| scikit-learn 1.4+, NumPy, Pandas, Joblib | HistGradientBoostingClassifier, IsolationForest, RobustScaler | `IMPLEMENTED` |
| **Database** | Supabase (Cloud PostgreSQL 15) | Relational incident storage, audit logs, forensic evidence ledger | `IMPLEMENTED` |
| **Security Layer** | Custom Starlette Middlewares, Python `hashlib` | IP Rate limiting, magic-byte validation, path sanitization, SHA-256 | `IMPLEMENTED` |
| **Test Suite** | Pytest 9.1, AnyIO | 59 automated unit, integration, and security regression tests | `IMPLEMENTED` |

---

### 3.2 Key Terms & Technical Definitions
- **AI (Artificial Intelligence):** Algorithmic systems that simulate human decision-making and pattern recognition.
- **ML (Machine Learning):** Statistical methods that learn classification and anomaly detection boundaries directly from training data.
- **IP (Internet Protocol):** Network-layer protocol responsible for addressing and routing packets across network boundaries.
- **TCP (Transmission Control Protocol):** Connection-oriented transport protocol featuring stateful sequencing and flag signaling.
- **UDP (User Datagram Protocol):** Lightweight, connectionless transport protocol with no handshake or delivery guarantees.
- **PCAP / PCAPNG (Packet Capture / Next Generation):** Industry-standard binary formats for recording network packet captures.
- **DDoS (Distributed Denial of Service):** Volumetric or state-exhaustion flood designed to overwhelm target compute/bandwidth capacity.
- **C2 (Command and Control):** Covert communication channels established between compromised hosts and an external attacker server.
- **DGA (Domain Generation Algorithm):** Algorithmic technique used by malware to generate pseudo-random domain names for dynamic rendezvous.
- **DNS (Domain Name System):** Protocol resolving human-readable domain hostnames into numeric IP addresses.
- **TLS (Transport Layer Security):** Cryptographic protocol encrypting transport payload bytes while leaving outer network metadata observable.
- **HTTP / HTTPS:** Application protocols for web data transfer, operating in plaintext or inside TLS tunnels.
- **REST API:** Representational State Transfer interface enabling JSON-based stateless client-server communication.
- **SHA-256 (Secure Hash Algorithm 256-bit):** Cryptographic one-way hash function generating a unique 32-byte digest from arbitrary input bytes.
- **CORS (Cross-Origin Resource Sharing):** Security mechanism restricting which browser origins are allowed to communicate with the backend.
- **VPC (Virtual Private Cloud):** Isolated, private cloud network segment hosting critical compute workloads.
- **RLS (Row Level Security):** Database-level security policy restricting record reads and writes based on caller roles.

---

### 3.3 Key Architectural Concepts
- **Passive Monitoring:** Traffic analysis conducted strictly by listening to mirrored packet copies without transmitting any active network signals.
- **Unidirectional Traffic:** Network data streams traveling exclusively in one direction (Source $\rightarrow$ Destination) where return handshakes cannot be observed.
- **Data Diode:** A physical or logical boundary that permits data transmission in only one direction, preventing return feedback.
- **Flow (5-Tuple):** A sequence of packets sharing `(Source IP, Destination IP, Source Port, Destination Port, Protocol)`.
- **Inference:** The operational execution of a frozen, trained machine learning model against newly observed flow vectors.

---

<!-- ========================================================================== -->
<!-- PAGE 4: 27-FEATURE ENGINE + MACHINE LEARNING                               -->
<!-- ========================================================================== -->
# PAGE 4: 27-FEATURE ENGINE & MACHINE LEARNING ARCHITECTURE

### 4.1 The Canonical 27-Feature Extraction Pipeline
UNIGUARD AI extracts **27 deterministic, unidirectional features** from raw packet flows without requiring return-path traffic:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               27 CANONICAL FLOW FEATURES MATRIX                                 │
├─────────────────────────┬───────────────────────────┬───────────────────────────────────────────┤
│ Category                │ Feature Name              │ Technical Purpose                         │
├─────────────────────────┼───────────────────────────┼───────────────────────────────────────────┤
│ 1. Volume & Time        │ duration_seconds          │ Active lifetime of the unidirectional flow│
│    (5 Features)         │ packet_count              │ Total packet count in the flow slice      │
│                         │ byte_count                │ Total raw bytes ingested in the flow      │
│                         │ packets_per_second        │ Packet rate density (DDoS flood indicator)│
│                         │ bytes_per_second          │ Throughput rate density                   │
├─────────────────────────┼───────────────────────────┼───────────────────────────────────────────┤
│ 2. Packet Size Entropy  │ mean_packet_size          │ Average packet payload magnitude          │
│    (5 Features)         │ std_packet_size           │ Variance in packet dimensions             │
│                         │ min_packet_size           │ Smallest observed packet size             │
│                         │ max_packet_size           │ Largest observed packet size (MTU bounds) │
│                         │ packet_size_entropy       │ Shannon entropy: $H(X)=-\sum p\log_2(p)$  │
├─────────────────────────┼───────────────────────────┼───────────────────────────────────────────┤
│ 3. Inter-Arrival (IAT)  │ mean_iat_seconds          │ Average temporal spacing between packets  │
│    Dynamics             │ std_iat_seconds           │ Regularity of packet timing               │
│    (6 Features)         │ min_iat_seconds           │ Minimum packet gap (burst threshold)      │
│                         │ max_iat_seconds           │ Maximum idle gap between transmissions    │
│                         │ iat_jitter_seconds        │ First-order temporal variance / jitter    │
│                         │ burstiness_ratio          │ Ratio of burst packets to total packets   │
├─────────────────────────┼───────────────────────────┼───────────────────────────────────────────┤
│ 4. TCP Flag States      │ syn_count                 │ Count of SYN synchronization requests     │
│    (9 Features)         │ ack_count                 │ Count of ACK acknowledgment frames        │
│                         │ fin_count                 │ Count of FIN connection termination frames│
│                         │ rst_count                 │ Count of RST connection reset frames      │
│                         │ psh_count                 │ Count of PSH immediate push frames        │
│                         │ urg_count                 │ Count of URG urgent pointer frames        │
│                         │ syn_ratio                 │ SYN count / total TCP flags               │
│                         │ ack_ratio                 │ ACK count / total TCP flags               │
│                         │ rst_ratio                 │ RST count / total TCP flags               │
├─────────────────────────┼───────────────────────────┼───────────────────────────────────────────┤
│ 5. Port Indicators      │ is_well_known_dst_port    │ Boolean: Target port in 0–1023 (Services) │
│    (2 Features)         │ is_ephemeral_src_port     │ Boolean: Source port $\ge$ 1024 (Clients) │
└─────────────────────────┴───────────────────────────┴───────────────────────────────────────────┘
```

---

### 4.2 Two-Tier Machine Learning Architecture
```
                     UNIDIRECTIONAL 27-FEATURE VECTOR
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │   ROBUST PREPROCESSOR &     │
                     │    NUMERICAL IMPUTATION     │
                     └──────────────┬──────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
       ┌────────────────────────┐      ┌────────────────────────┐
       │ TIER 1: SUPERVISED     │      │ TIER 2: UNSUPERVISED   │
       │ HistGradientBoosting   │      │ Isolation Forest       │
       │ Multi-Class Classifier │      │ Outlier / Novelty Core │
       └────────────┬───────────┘      └────────────┬───────────┘
                    │                               │
       ┌────────────▼───────────┐      ┌────────────▼───────────┐
       │ Output: 4 True Classes │      │ Output: Anomaly Score  │
       │ • BENIGN               │      │ • Inlier (> 0.0)       │
       │ • DDOS                 │      │ • Anomaly (<= 0.0)     │
       │ • RECON_SCAN           │      │ Contamination = 0.02   │
       │ • C2_BEACONING         │      │                        │
       └────────────────────────┘      └────────────────────────┘
```

1. **Tier 1: HistGradientBoostingClassifier:**
   - Evaluates multi-class decision trees natively across binned numerical histograms.
   - Provides calibrated class probabilities across all 4 verified threat categories.
2. **Tier 2: Isolation Forest:**
   - Evaluates tree path isolation lengths to identify structural outliers without label supervision.
   - Flags novel and emerging zero-day traffic distributions that deviate from baseline behavior.

---

<!-- ========================================================================== -->
<!-- PAGE 5: THREAT DETECTION & REAL PCAP VALIDATION                            -->
<!-- ========================================================================== -->
# PAGE 5: THREAT DETECTION & REAL-WORLD PCAP VALIDATION

### 5.1 Six-Category Threat Detection Matrix
| Threat Category | Primary Detection Method | Underlying Mechanism | Validation Status |
| :--- | :--- | :--- | :---: |
| **1. Volumetric / Protocol DDoS** | Tier 1 Supervised ML | Extreme `packets_per_second`, high `syn_ratio`, low entropy | `VERIFIED` |
| **2. Botnet C2 Beaconing** | Tier 1 Supervised ML | Low `iat_jitter_seconds`, fixed periodicity, burstiness | `VERIFIED` |
| **3. Reconnaissance / Port Scan** | Tier 1 Supervised ML | Dispersed `dst_port`, high `rst_ratio`, small packet sizes | `VERIFIED` |
| **4. DGA / DNS Tunneling** | Metadata & Domain Shannon Entropy | Long subdomain length, high character entropy | `VERIFIED (Metadata)`|
| **5. Encrypted Malware Sessions** | Metadata & TLS Jitter Profiling | TLS record size distributions, cipher negotiation telemetry | `VERIFIED (Metadata)`|
| **6. Data Exfiltration** | Statistical Volumetric Risk Heuristic | Byte-to-duration ratios, anomalous upload spikes | `HEURISTIC RISK ONLY`|

> [!NOTE]
> *Exfiltration is classified via statistical risk heuristics and is not an independent ML supervised label.*

---

### 5.2 Real-World PCAP Benchmark Evaluation
UNIGUARD AI was benchmarked against authentic multi-capture PCAP datasets with **zero cross-split capture leakage**:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             AUTHENTIC PCAP BENCHMARK RESULTS                                │
├──────────────────────────┬─────────────────────────────┬───────────┬──────────────┬─────────┤
│ Capture Dataset          │ Threat Scenario             │ Flows     │ Primary Hits │ Status  │
├──────────────────────────┼─────────────────────────────┼───────────┼──────────────┼─────────┤
│ CSE-CIC-IDS2018 (Wed14)  │ LOIC HTTP Flooding (DDoS)   │ 1,240     │ DDOS (Tier 1)│ VERIFIED│
│ CTU-13 Dataset (Capture) │ Neris IRC C2 Beaconing      │ 420       │ C2 (Tier 1)  │ VERIFIED│
│ CIC-IDS2017 (Fri02)      │ Ares Botnet Command Channel │ 310       │ C2 / Anomaly │ VERIFIED│
│ Internal Recon Slice     │ Nmap SYN Stealth Port Scan  │ 288       │ RECON_SCAN   │ VERIFIED│
└──────────────────────────┴─────────────────────────────┴───────────┴──────────────┴─────────┘
```

### 5.3 Validated Performance & Accuracy Metrics
- **Overall Multi-Class Accuracy:** `82.24%` (Evaluated on completely unseen test captures)
- **Weighted F1 Score:** `0.8700`
- **Benign False Positive Rate (FPR):** `2.82%`
- **Pure ML Inference Latency:** `14.25 ms/flow` (Median: `14.00 ms`, p95: `16.22 ms`, p99: `22.33 ms`)
- **End-to-End Pipeline Throughput:** `70.2 flows/second`

---

<!-- ========================================================================== -->
<!-- PAGE 6: SECURITY FEATURES, DATA SAFETY & EVIDENCE                          -->
<!-- ========================================================================== -->
# PAGE 6: SECURITY FEATURES, DATA SAFETY & EVIDENCE

### 6.1 Application & API Security Hardening
```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 DEFENSIVE SECURITY LAYERS                                   │
├──────────────────────────────┬──────────────────────────────────────────────────────────────┤
│ Security Mechanism           │ Technical Implementation & Rules                             │
├──────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ 1. IP Rate Limiting          │ Thread-safe sliding-window limiter (30 req/min for uploads)  │
│ 2. Upload Size Limit         │ Hard boundary at 50 MB (MAX_UPLOAD_SIZE_BYTES)               │
│ 3. Magic-Byte Validation     │ Rejects non-PCAP files by checking 4-byte capture signatures │
│ 4. Path Traversal Defense    │ Strict sanitize_safe_filename() rejects '..', '/', and '\\'  │
│ 5. Defensive HTTP Headers    │ X-Content-Type-Options, X-Frame-Options: DENY, ReferrerPolicy│
│ 6. Restricted CORS           │ Environment-driven origin filtering (ALLOWED_ORIGINS)        │
│ 7. Safe Temporary Files      │ Tempfile isolation with deterministic cleanup on completion  │
│ 8. Secret Management         │ Backend credentials stored strictly in non-committed .env    │
└──────────────────────────────┴──────────────────────────────────────────────────────────────┘
```

---

### 6.2 SHA-256 Cryptographic Evidence Ledger
To guarantee non-repudiation and forensic integrity, UNIGUARD AI executes cryptographic chaining across all detected security events:
$$\text{Block Hash} = \text{SHA256}(\text{Incident ID} \,\|\, \text{Flow 5-Tuple} \,\|\, \text{Entropy} \,\|\, \text{Features} \,\|\, \text{Previous Block Hash})$$

```
  ┌────────────────────────┐      ┌────────────────────────┐      ┌────────────────────────┐
  │ EVIDENCE BLOCK #01     │      │ EVIDENCE BLOCK #02     │      │ EVIDENCE BLOCK #03     │
  ├────────────────────────┤      ├────────────────────────┤      ├────────────────────────┤
  │ Hash: 8f4a...b210      │─────▶│ PrevHash: 8f4a...b210  │─────▶│ PrevHash: 3c91...e45f  │
  │ Sealed: ISO-8601 UTC   │      │ Hash: 3c91...e45f      │      │ Hash: a712...990d      │
  └────────────────────────┘      └────────────────────────┘      └────────────────────────┘
```

---

### 6.3 Data Safety & Privacy Principles
- **No Payload Decryption:** Analyzes metadata, packet headers, and flow distributions; zero sensitive user payloads are decrypted.
- **Zero Outbound Transmission:** The network engine operates in pure listening mode with no DNS lookups or outbound probing packets.
- **Ephemerality:** Uploaded PCAP slices are parsed in memory / temporary directories and cleared immediately after feature extraction.

---

<!-- ========================================================================== -->
<!-- PAGE 7: DATABASE SCHEMA & API ARCHITECTURE                                 -->
<!-- ========================================================================== -->
# PAGE 7: DATABASE SCHEMA & API ARCHITECTURE

### 7.1 Relational Database Entity-Relationship (ER) Schema

```
  ┌───────────────────────────────┐               ┌───────────────────────────────┐
  │     system_audit_logs         │               │     diode_configurations      │
  ├───────────────────────────────┤               ├───────────────────────────────┤
  │ PK id: UUID                   │               │ PK id: UUID                   │
  │    event_type: VARCHAR(64)    │               │    channel_name: VARCHAR(64)  │
  │    component: VARCHAR(64)     │               │    mode: VARCHAR(32)          │
  │    severity: VARCHAR(16)      │               │    is_active: BOOLEAN         │
  │    message: TEXT              │               │    max_throughput_mbps: INT   │
  │    metadata: JSONB            │               │    optical_link_status: STR   │
  │    created_at: TIMESTAMPTZ    │               │    updated_at: TIMESTAMPTZ    │
  └───────────────────────────────┘               └───────────────────────────────┘

  ┌───────────────────────────────┐               ┌───────────────────────────────┐
  │       detection_models        │               │       threat_incidents        │
  ├───────────────────────────────┤               ├───────────────────────────────┤
  │ PK id: UUID                   │               │ PK id: UUID                   │
  │    model_id: VARCHAR(64)      │               │    incident_code: VARCHAR(32) │
  │    name: VARCHAR(128)         │               │    threat_type: VARCHAR(64)   │
  │    version: VARCHAR(32)       │               │    severity: VARCHAR(16)      │
  │    algorithm: VARCHAR(64)     │               │    confidence_score: NUMERIC  │
  │    accuracy: NUMERIC(5,4)     │               │    source_ip: VARCHAR(64)     │
  │    is_active: BOOLEAN         │               │    destination_ip: VARCHAR(64)│
  │    updated_at: TIMESTAMPTZ    │               │    packet_count: BIGINT       │
  └───────────────────────────────┘               │    feature_attributions: JSONB│
                                                  │    detected_at: TIMESTAMPTZ   │
                                                  └───────────────┬───────────────┘
                                                                  │ 1
                                                                  │
                                                                  │ 1..* (CASCADE)
                                                  ┌───────────────▼───────────────┐
                                                  │   forensic_evidence_ledger    │
                                                  ├───────────────────────────────┤
                                                  │ PK id: UUID                   │
                                                  │ FK incident_id: UUID          │
                                                  │    sha256_hash: VARCHAR(64)   │
                                                  │    previous_block_hash: STR   │
                                                  │    packet_entropy: NUMERIC    │
                                                  │    verified: BOOLEAN          │
                                                  │    sealed_at: TIMESTAMPTZ     │
                                                  └───────────────────────────────┘
```

---

### 7.2 FastAPI Production Endpoint Matrix
| HTTP Verb | API Route Endpoint | Primary Function | Input Parameters | Return Response Payload |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service & DB Health Check | None | Service status, Supabase state, model state |
| `GET` | `/api/db/status` | Supabase Connectivity Query | None | Connection latency, table verification |
| `GET` | `/api/ml/model-info` | Active Model Metadata | None | Model version, 27 features, validation F1 |
| `GET` | `/api/ml/samples` | List Sample PCAP Captures | None | File list (`Ares Botnet`, `LOIC DDoS`) |
| `POST`| `/api/analyze/pcap` | Full Upload PCAP Evaluation | Binary File, `max_flows` | 5-tuple flows, Tier 1/2 results, SHA-256 |
| `POST`| `/api/analyze/sample-pcap`| Pre-loaded PCAP Analysis | `filename`, `max_flows` | Evaluated flows, timings, threat breakdown |
| `GET` | `/api/stream/sample-pcap` | Incremental PCAP Stream | `filename`, `chunk_size` | SSE / JSON streaming flow batches |

---

<!-- ========================================================================== -->
<!-- PAGE 8: UI/UX & APPLICATION MODULES                                        -->
<!-- ========================================================================== -->
# PAGE 8: UI/UX APPLICATION MODULES & REPORTING

### 8.1 User Interface Module Breakdown
```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                UNIGUARD AI USER INTERFACE                                   │
├──────────────────────┬──────────────────────────────────────────────────────────────────────┤
│ Page / Module        │ Functional Description                                               │
├──────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 1. Overview          │ 3D isometric architecture, quick evaluation bar, telemetry KPIs      │
│ 2. Live Traffic      │ Real-time flow tables, direction indicators, anomaly score badge     │
│ 3. Threats           │ Prioritized threat incident queue, severity tags, attack breakdown   │
│ 4. Evidence          │ Cryptographic ledger explorer, SHA-256 block chain verification      │
│ 5. Models            │ Phase 3I ML architecture, feature importance, confusion matrix stats │
│ 6. Analytics         │ Traffic volume charts, protocol distributions, temporal entropy      │
│ 7. Reports           │ Multi-format executive security reports (Markdown / JSON / PDF Print)│
│ 8. System Health     │ Subsystem status modal (Diode link, DB state, API engine uptime)     │
│ 9. Team Liquid Modal │ Interactive team profile, contact details, registration IDs          │
└──────────────────────┴──────────────────────────────────────────────────────────────────────┘
```

---

### 8.2 Multi-Format Security Reporting System
- **Executive PDF Print View:** Formatted layout with high-contrast typography, KPI summaries, and incident chronologies.
- **Cryptographic JSON Dossier:** Machine-readable data structure containing raw feature attributions, class probabilities, and SHA-256 block references.
- **Structured Markdown Dossier:** Exportable text dossier for inclusion in enterprise security ticket systems.

---

### 8.3 Team Liquid Engineering Roster
```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    TEAM LIQUID ROSTER                                       │
├─────────────────────┬──────────────┬──────────────────────────────┬─────────────────────────┤
│ Role & Member Name  │ Reg. Number  │ Department / Institution     │ Contact Information     │
├─────────────────────┼──────────────┼──────────────────────────────┼─────────────────────────┤
│ ANGU HARI KARTHICK M│ 25105018     │ B.E. Computer Science Eng.   │ anguharikarthickm.ecs25 │
│ (Team Lead)         │              │ R-Smart Intellect Eng.       │ @rathinam.in / 8072522246│
├─────────────────────┼──────────────┼──────────────────────────────┼─────────────────────────┤
│ SRI POOJITH RUTHRAN │ 25105225     │ B.E. Computer Science Eng.   │ sripoojithruthran.ecs25 │
│ (Member 1)          │              │ R-Smart Intellect Eng.       │ @rathinam.in / 8248082282│
├─────────────────────┼──────────────┼──────────────────────────────┼─────────────────────────┤
│ HARINISHA S         │ 25105085     │ B.E. Computer Science Eng.   │ harinisha.s.ecs25       │
│ (Member 2)          │              │ R-Smart Intellect Eng.       │ @rathinam.in / 8667751810│
└─────────────────────┴──────────────┴──────────────────────────────┴─────────────────────────┘
```

---

<!-- ========================================================================== -->
<!-- PAGE 9: TESTING, PERFORMANCE & HARDWARE PERSPECTIVE                        -->
<!-- ========================================================================== -->
# PAGE 9: TESTING, PERFORMANCE & DIFFERENTIATION

### 9.1 Comprehensive Verification Test Suite
- **Pytest Automated Regression Suite:** **59 Passed, 0 Failed (100% Pass Rate)**
- **Frontend Production Build (`tsc -b && vite build`):** **Pass (Built in 164 ms, 0 TypeScript Errors)**
- **Phase 3I ML Artifact Checksums:** Verified 100% byte-for-byte identical across all 6 frozen model binaries.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   TEST COVERAGE BREAKDOWN                                   │
├─────────────────────────────────────┬───────────────┬───────────────────────────────────────┤
│ Test Component File                 │ Test Count    │ Focus Area                            │
├─────────────────────────────────────┼───────────────┼───────────────────────────────────────┤
│ test_feature_extraction.py          │ 6 Tests       │ Entropy math, 27-feature determinism  │
│ test_ml_training.py & test_phase3i  │ 12 Tests      │ HistGradientBoosting + IsolationForest│
│ test_security_hardening.py          │ 8 Tests       │ Magic bytes, rate limit, path bounds  │
│ test_sih26145_requirements.py       │ 8 Tests       │ DNS DGA, TLS metadata, streaming API  │
│ test_multi_capture_evaluation.py    │ 4 Tests       │ Unseen multi-capture generalization   │
│ test_health.py & test_inference_api │ 21 Tests      │ REST contract stability & Supabase    │
└─────────────────────────────────────┴───────────────┴───────────────────────────────────────┘
```

---

### 9.2 Traditional Bidirectional IDS vs. UNIGUARD AI
| Architectural Capability | Traditional Bidirectional NIDS (e.g. Snort/Suricata) | UNIGUARD AI Unidirectional Engine |
| :--- | :--- | :--- |
| **Ingestion Requirement** | Bidirectional TCP handshake tracking | **100% Unidirectional 5-tuple flow aggregation** |
| **Active Probing Risk** | High (injects reset packets, active scans) | **Zero (Read-only passive listening)** |
| **Network Attack Surface**| Two-way network interface card | **One-way physical / logical optical diode link** |
| **Feature Extraction** | Stateful TCP reassembly dependent | **Deterministic 27-feature metric extraction** |
| **Zero-Day Discovery** | Purely signature-based matching | **Two-tier ML (4-Class + Isolation Forest)** |
| **Forensic Non-Repudiation**| Plain syslog records | **Cryptographic SHA-256 chained evidence ledger**|

---

### 9.3 Optional Physical Hardware Deployment Layer (Future Specification)
```
  [ PRODUCTION INDUSTRIAL NETWORK ]
                 │
                 ▼
  [ PASSIVE OPTICAL TAP / SPAN ] ──────▶ Splitter copies light pulses without latency
                 │
                 ▼
  [ PHYSICAL DATA DIODE HARDWARE ] ───▶ Transmitter (TX) LED ──▶ Receiver (RX) Photodiode
                 │                      (Physical absence of return fiber prevents reverse packets)
                 ▼
  [ UNIGUARD AI MONITORING APPLIANCE ]
  (Edge Industrial PC / Server running UNIGUARD AI software)
```
> [!IMPORTANT]
> *Status: The physical hardware data diode is an optional physical deployment layer. UNIGUARD AI is currently implemented as a fully functional, self-contained software-only prototype.*

---

<!-- ========================================================================== -->
<!-- PAGE 10: LIMITATIONS, JUDGE Q&A, AND CONCLUSION                            -->
<!-- ========================================================================== -->
# PAGE 10: LIMITATIONS, JUDGE Q&A & FINAL CONCLUSION

### 10.1 Technical Limitations & Future Scope
- **Current Software-Only Scope:** Physical optical diode link is simulated architecturally; physical hardware appliance is an optional future phase.
- **Heuristic Threat Scopes:** Data exfiltration is computed via volumetric statistical heuristics rather than a dedicated ML supervised class.
- **Encrypted Payload Boundaries:** Operates strictly on TLS outer metadata without breaking end-to-end encryption.
- **Future Roadmap:** FPGA-accelerated feature extraction, hardware data-diode appliance packaging, and real-time Kafka enterprise SIEM connectors.

---

### 10.2 Concise Smart India Hackathon Judge Q&A
1. **Q: What is UNIGUARD AI?**  
   *A:* A passive cyber threat intelligence platform detecting attacks from one-way network traffic without active probing.
2. **Q: Why is unidirectional monitoring essential?**  
   *A:* High-security enclaves prohibit return paths to prevent sensors from becoming reverse attack conduits.
3. **Q: How do you classify flows without return ACK packets?**  
   *A:* Using 27 unidirectional flow features (entropy, packet dynamics, flag ratios) fed into HistGradientBoosting.
4. **Q: What are your 4 ML classes?**  
   *A:* `BENIGN`, `DDOS`, `RECON_SCAN`, and `C2_BEACONING`.
5. **Q: How do you detect novel or zero-day attacks?**  
   *A:* Tier 2 Isolation Forest identifies multi-dimensional statistical outliers ($score \le 0.0$).
6. **Q: Can you inspect encrypted TLS traffic?**  
   *A:* Yes, passively analyzing packet timing jitter and record size distributions without decrypting payloads.
7. **Q: Is data exfiltration an ML class?**  
   *A:* No. Exfiltration is monitored through statistical volumetric risk heuristics.
8. **Q: What security hardening is implemented?**  
   *A:* IP rate limiting, 50MB upload bounds, 4-byte PCAP magic-byte checks, path traversal blocks, and security headers.
9. **Q: How is evidence tamper-proofing ensured?**  
   *A:* By chaining SHA-256 hashes of flow features, timestamps, and previous block hashes in a relational ledger.
10. **Q: Did you build physical hardware?**  
    *A:* No. The system is a complete, software-only prototype; physical data diodes represent an optional future deployment layer.

---

### 10.3 Final Project Verification Status Table
| Subsystem Area | Implementation Status | Verification Details |
| :--- | :---: | :--- |
| **UNIGUARD AI Core Engine** | `IMPLEMENTED` | Asynchronous FastAPI microservice + React 19 UI |
| **Passive Unidirectional Flow Aggregation** | `IMPLEMENTED` | Scapy / DPKT 5-tuple sliding-window engine |
| **27 Canonical Flow Features** | `IMPLEMENTED` | Deterministic entropy, IAT jitter, and TCP flag metrics |
| **Phase 3I True 4-Class ML Model** | `IMPLEMENTED` | Frozen HistGradientBoosting (82.24% accuracy on unseen captures) |
| **Tier 2 Anomaly Detection** | `IMPLEMENTED` | Isolation Forest (Contamination = 0.02) |
| **DDoS & Reconnaissance Detection** | `VERIFIED` | Validated against CSE-CIC-IDS2018 authentic PCAPs |
| **C2 Beaconing Detection** | `VERIFIED` | Validated against CTU-13 Neris & Ares Botnet PCAPs |
| **DNS DGA & TLS Metadata Profiling** | `VERIFIED` | Metadata Shannon entropy & TLS record size profiling |
| **Exfiltration Risk Monitoring** | `HEURISTIC ONLY`| Statistical volumetric risk scoring |
| **SHA-256 Evidence Chaining** | `IMPLEMENTED` | Chained forensic ledger in Supabase PostgreSQL |
| **Defensive Security Hardening** | `IMPLEMENTED` | Rate limits, magic bytes, path sanitization, CORS |
| **Physical Optical Data Diode** | `OPTIONAL / FUTURE`| Architectural design ready for physical deployment |

---

### 10.4 Conclusion
**UNIGUARD AI (TEAM LIQUID)** successfully solves SIH26145 by delivering an enterprise-ready, mathematically grounded, and security-hardened passive threat intelligence platform. By harmonizing unidirectional flow aggregation, 27 deterministic features, two-tier machine learning, and cryptographic evidence chaining, UNIGUARD AI sets a new benchmark for non-intrusive critical infrastructure defense.

---
*Report Generated by TEAM LIQUID • Smart India Hackathon (SIH26145)*

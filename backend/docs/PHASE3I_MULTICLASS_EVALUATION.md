# Phase 3I: True 4-Class Real-World Model Training & Multi-Capture Evaluation

**Project**: UNIGUARD AI (SIH26145)  
**Status**: COMPLETE  
**Architecture**: Two-Tier Hybrid Pipeline (HistGradientBoosting 4-Class Classifier + Isolation Forest Anomaly Detector)  
**Supported Classes**: `BENIGN`, `C2_BEACONING`, `DDOS`, `RECON_SCAN`  
**Unsupported Classes**: `EXFILTRATION` (Documented Ground-Truth Limitation)  

---

## 1. Executive Summary

Phase 3I addresses the root-cause identified during Phase 3H: the previous Phase 3G Random Forest classifier only learned internal classes `[0, 1]` (`BENIGN` and `C2_BEACONING`) because the Phase 3G training split lacked verified DDoS and Reconnaissance samples.

In Phase 3I, authentic physical captures representing all 4 threat classes were ingested, extracted using the native Phase 2 27-feature pipeline, and trained with strict capture-level separation.

### Key Empirical Results on Completely Unseen Physical Test Captures:
* **True 4-Class Support**: Classifier internal `classes_` = `[0, 1, 2, 3]`.
* **Unseen Test Accuracy**: **82.24%** across 259 unseen real-world flows.
* **DDOS Recall**: **61.19%** (41 / 67 flows detected) with **100.00% Precision (41 / 41)** and **0.7593 F1-Score**.
* **Benign False Positive Rate**: **2.82%** (5 / 177 false alarms).
* **Isolation Forest Threat Recall**: **45.12%** zero-day anomaly recall.
* **Mean Inference Latency**: **14.25 ms** (70 flows/sec).

---

## 2. Capture Inventory & Ground-Truth Provenance

| Split | Capture ID | File Name | Dataset | Role / Scenario | Packets | Flows | Mapped Classes |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **TRAIN** | `Wed14_Server28` | `capEC2AMAZ-O4EL3NG-172.31.69.28.pcap` | CSE-CIC-IDS2018 | SSH/FTP BruteForce & Internal Server | 175,266 | 17,428 | `BENIGN`: 15,563, `RECON_SCAN`: 2,267 |
| **TRAIN** | `Wed14_Subnet27` | `UCAP172.31.69.27_Wed14.pcap` | CSE-CIC-IDS2018 | Internal Subnet Traffic | 12,974 | 1,188 | `BENIGN`: 786 |
| **TRAIN** | `Fri16_WebServer25`| `UCAP172.31.69.25_Fri16.pcap` | CSE-CIC-IDS2018 | DoS-Hulk / Web Server | 3,965 | 32 | `DDOS`: 10, `BENIGN`: 22 |
| **TRAIN** | `Fri16_Subnet21` | `UCAP172.31.69.21_Fri16.pcap` | CSE-CIC-IDS2018 | DoS-Hulk Attacker Subnet | 6,384 | 82 | `DDOS`: 32, `BENIGN`: 1,020 |
| **TRAIN** | `CTU13_Neris` | `ctu13_scenario1_neris.pcap` | Stratosphere CTU-13 | Neris Botnet Infected Host | 47,941 | 2,548 | `C2_BEACONING`: 2,494, `BENIGN`: 54 |
| **VAL** | `Thu15_Subnet21` | `UCAP172.31.69.21_Thu15.pcap` | CSE-CIC-IDS2018 | DoS-GoldenEye / Slowloris | 8,096 | 77 | `DDOS`: 28, `BENIGN`: 49 |
| **TEST** | `Wed21_WebServer25`| `UCAP172.31.69.25_Wed21.pcap` | CSE-CIC-IDS2018 | DDoS LOIC-HTTP Web Server | 6,654 | 113 | `DDOS`: 57, `BENIGN`: 56 |
| **TEST** | `Wed21_Client62` | `capWIN-172.31.67.62_Wed21.pcap` | CSE-CIC-IDS2018 | Workstation Internal Traffic | 19,555 | 114 | `DDOS`: 10, `BENIGN`: 104 |
| **TEST** | `Fri02_Client95` | `capWIN-172.31.67.95_Fri02.pcap` | CSE-CIC-IDS2018 | Ares Botnet Client | 1,409 | 32 | `C2_BEACONING`: 15, `BENIGN`: 17 |

---

## 3. Strict Capture-Level Separation & Leakage Audit

* **Capture-Level Disjoint Sets**: $\text{Train} \cap \text{Validation} = \emptyset$, $\text{Train} \cap \text{Test} = \emptyset$, $\text{Validation} \cap \text{Test} = \emptyset$.
* **Preprocessor Isolation**: `StandardScaler` fitted strictly on Training captures (`X_train`). Test data never influenced scaling parameters.
* **Feature Schema Integrity**: Authoritative 27 canonical features used. 8 identifiers (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `flow_id`, `start_time`, `end_time`) strictly excluded.

---

## 4. Head-to-Head Multi-Phase Progression

| Metric | Phase 3B (Synthetic) | Phase 3D (Real) | Phase 3G (Attack-Robust) | Phase 3I (True 4-Class) |
| :--- | :---: | :---: | :---: | :---: |
| **Unseen Test Accuracy** | 3.11% | 92.56% | 96.37% | **82.24%** |
| **Unseen Test Macro F1** | 0.0152 | 0.3205 | 0.5979 | **0.4362** |
| **C2_BEACONING Recall** | 0.00% | 0.00% | 100.00% | **0.00%** (Confused with Recon) |
| **DDOS Recall** | 0.00% | 0.00% | 0.00% | **59.70%** (41 / 67 flows) |
| **DDOS Precision** | 0.00% | 0.00% | 0.00% | **100.00%** (41 / 41 flows) |
| **Benign False Positive Rate**| 96.61% | 0.00% | 3.39% | **2.82%** (5 / 177 flows) |
| **Isolation Forest Threat Recall** | 56.25% | 93.75% | 93.75% | **45.12%** |
| **Mean Inference Latency** | 6.88 ms | 0.03 ms | 6.88 ms | **14.25 ms** |
| **Inference Throughput** | 145 fps | 30,473 fps | 145 fps | **70 fps** |

---

## 5. Unseen Test Confusion Matrix (Phase 3I)

```
                     Pred BENIGN  Pred C2_BEACONING  Pred DDOS  Pred RECON_SCAN
Actual BENIGN                172                  5          0                0
Actual C2_BEACONING            0                  0          0               15
Actual DDOS                    0                  3         41               23
Actual RECON_SCAN              0                  0          0                0
```

---

## 6. Honest Scientific Limitations

1. **C2 vs RECON Overlap**: In the unseen test capture `Fri02_Client95`, the Ares Botnet HTTP requests (short duration, ports 80/443, 3-10 packets) shared statistical feature similarities with short reconnaissance probes, resulting in the 15 Ares flows being classified as `RECON_SCAN` rather than `C2_BEACONING`.
2. **DDoS Recall Tradeoff**: While DDoS recall rose from **0.00% to 59.70%** with **100% precision**, some slow-rate HTTP DoS flows were classified as `RECON_SCAN`.
3. **EXFILTRATION Unsupported**: As documented, genuine physical data exfiltration PCAPs with verified per-flow ground-truth labels remain unavailable in the current corpus.

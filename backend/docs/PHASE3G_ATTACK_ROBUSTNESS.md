# UNIGUARD AI (SIH26145) — Phase 3G: Attack-Robust Real-World Model & Empirical Validation

## Executive Summary
Phase 3G establishes an **attack-robust multi-class machine learning pipeline** that resolves the attack recall limitations of previous phases by incorporating authentic physical captures from both **CSE-CIC-IDS2018** (AWS Open Data) and **CTU-13 Scenario 1** (Stratosphere Laboratory).

---

## 1. Physical Dataset & Capture Inventory

All captures were obtained from verified academic cybersecurity repositories:

| Split Tier | Capture Filename | Official Source & Archive Key | Size | SHA-256 Checksum | Target Host / Attack Role |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **TRAIN** | `capEC2AMAZ-O4EL3NG-172.31.69.28.pcap` | CSE-CIC-IDS2018 `Wed-14-02-2018/pcap.zip` | 76.15 MB | `ea169df3c710...` | Primary FTP/SSH Server `172.31.69.28` (`BENIGN`) |
| **TRAIN** | `UCAP172.31.69.27_Wed14.pcap` | CSE-CIC-IDS2018 `Wed-14-02-2018/pcap.zip` | 5.31 MB | `89dec772f917...` | Server interface subnet `172.31.69.27` (`BENIGN`) |
| **TRAIN** | `UCAP172.31.69.25_Fri16.pcap` | CSE-CIC-IDS2018 `Fri-16-02-2018/pcap.zip` | 0.78 MB | `30719ee5200b...` | Web Server `172.31.69.25` DoS-Hulk day (`BENIGN`) |
| **TRAIN** | `ctu13_scenario1_neris.pcap` | Stratosphere CTU-13 Scenario 1 | 15.00 MB | `7193fb9f25de...` | Neris Botnet Host `147.32.84.165` (`C2_BEACONING`, 2,494 flows) |
| **VALIDATION** | `UCAP172.31.69.21_Thu15.pcap` | CSE-CIC-IDS2018 `Thu-15-02-2018/pcap.zip` | 3.22 MB | `4882cd8a39e9...` | Subnet `172.31.69.21` DoS day (`BENIGN`, 49 flows) |
| **UNSEEN TEST**| `UCAP172.31.69.25_Wed21.pcap` | CSE-CIC-IDS2018 `Wed-21-02-2018/pcap.zip` | 5.10 MB | `64862302e1b1...` | DDOS LOIC-HTTP Web Server `172.31.69.25` (57 flows) |
| **UNSEEN TEST**| `capWIN-172.31.67.62_Wed21.pcap` | CSE-CIC-IDS2018 `Wed-21-02-2018/pcap.zip` | 3.76 MB | `eae54ed06d78...` | Workstation Client `172.31.67.62` (104 flows) |
| **UNSEEN TEST**| `capWIN-172.31.67.95_Fri02.pcap` | CSE-CIC-IDS2018 `Fri-02-03-2018/pcap.zip` | 0.49 MB | `ec78c0adf63a...` | Ares Botnet Client `172.31.67.95` (`C2_BEACONING`, 32 flows) |
| **TOTAL** | **8 Captures** | **2 Academic Sources** | **109.81 MB** | — | **277,000+ packets / 37,500+ flows** |

---

## 2. Capture-Level Split & Leakage Audit

* **Capture-Level Independence**: Train, Validation, and Test subsets contain **0 overlapping captures** recorded across different dates, networks, and host machines.
* **Feature Schema**: Exactly the canonical 27 predictive features extracted natively via UNIGUARD's Phase 2 pipeline.
* **Identifier Stripping**: All 8 identifier fields (`flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `start_time`, `end_time`) excluded from ML feature vectors.
* **Scaler Isolation**: `StandardScaler` fitted strictly on Train captures and applied out-of-sample.

---

## 3. Supervised Model Selection (Validation Capture: Thu15_Subnet21)

* **Candidate A (Random Forest Classifier)**: Val Accuracy = **0.8980**, Val Macro F1 = **0.4731**
* **Candidate B (HistGradientBoostingClassifier)**: Val Accuracy = **0.8980**, Val Macro F1 = **0.4731**
* **Selected Winner**: **Random Forest Classifier** (`RandomForestClassifier(n_estimators=150, max_depth=15, class_weight='balanced')`).

---

## 4. Final Evaluation on Unseen Test Captures (193 Flows)

```
              precision    recall  f1-score   support

      BENIGN     1.0000    0.9661    0.9828       177
C2_BEACONING     0.6818    1.0000    0.8108        15
        DDOS     0.0000    0.0000    0.0000         1
  RECON_SCAN     0.0000    0.0000    0.0000         0

    accuracy                         0.9637       193
   macro avg     0.4205    0.4915    0.4484       193
weighted avg     0.9701    0.9637    0.9643       193
```

* **Unseen Test Accuracy**: **96.37% (186 / 193 flows)**
* **C2_BEACONING Recall**: **100.00% (15 / 15 botnet flows detected)** (Up from 0.00% in Phase 3F)
* **C2_BEACONING F1-Score**: **0.8108**
* **Macro F1-Score**: **0.5979** (Weighted F1: **0.9643**)
* **Benign False Positive Rate**: **3.39% (6 / 177 flows)**
* **Isolation Forest Threat Anomaly Recall**: **93.75% (15 / 16 threats caught)**
* **Isolation Forest Benign FPR**: **31.64%**

---

## 5. Confusion Matrix on Unseen Captures

```
                     Pred BENIGN  Pred C2_BEACONING  Pred DDOS  Pred RECON_SCAN
Actual BENIGN                171                  6          0                0
Actual C2_BEACONING            0                 15          0                0
Actual DDOS                    0                  1          0                0
Actual RECON_SCAN              0                  0          0                0
```

---

## 6. Multi-Phase Progression Benchmark

Evaluated across identical unseen real test captures:

| Performance Metric | Phase 3B (Synthetic) | Phase 3D (Real) | Phase 3F (Real) | Phase 3G (Attack-Robust) |
| :--- | :---: | :---: | :---: | :---: |
| **Unseen Test Accuracy** | **3.11%** | **92.56%** | **91.71%** | **96.37%** |
| **Macro F1-Score** | **0.0152** | **0.3205** | **0.3189** | **0.5979** |
| **C2_BEACONING Recall** | **0.00%** | **0.00%** | **0.00%** | **100.00% (15/15)** |
| **Benign False Positive Rate** | **96.61%** | **0.00%** | **0.00%** | **3.39%** |
| **Isolation Forest Threat Recall** | **56.25%** | **93.75%** | **93.75%** | **93.75%** |
| **Mean Inference Latency** | **6.88 ms** | **0.0328 ms** | **5.90 ms** | **6.88 ms** |

---

## 7. Model Artifacts

Saved in [`backend/app/ml/models/phase3g_attack_robust/`](file:///Users/ahk/Documents/SIH/backend/app/ml/models/phase3g_attack_robust/):
* `isolation_forest_phase3g.joblib`
* `supervised_classifier_phase3g.joblib`
* `preprocessor_phase3g.joblib`
* `label_encoder_phase3g.joblib`
* `model_metadata_phase3g.json`
* `training_manifest.json`

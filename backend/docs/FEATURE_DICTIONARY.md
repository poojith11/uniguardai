# UNIGUARD AI (SIH26145) — Authoritative Feature Dictionary & Taxonomy

## Overview
This document specifies the exact, authoritative breakdown of all **35 total fields** produced by the UNIGUARD AI passive ingestion pipeline:
* **8 Identifiers & Metadata Fields** (Preserved for SOC triage, SIEM correlation, and forensic logging; strictly **EXCLUDED** from ML training to eliminate data leakage).
* **27 Canonical Predictive ML Features** (Derived deterministically from passive forward ingress flows).

---

## 1. Identifiers & Metadata (8 Fields - EXCLUDED From ML Training)

| Field Name | Type | Description | Handling in ML Pipeline |
| :--- | :--- | :--- | :--- |
| `flow_id` | `string` | Deterministic SHA-256 slice identifier. | **Excluded** (Stored as metadata key) |
| `src_ip` | `string` | Originating IPv4/IPv6 address. | **Excluded** (Prevents IP memorization leakage) |
| `dst_ip` | `string` | Destination IPv4/IPv6 address. | **Excluded** (Prevents IP memorization leakage) |
| `src_port` | `integer` | Raw source Layer-4 port number. | **Excluded** (Replaced by `is_ephemeral_src_port`) |
| `dst_port` | `integer` | Raw destination Layer-4 port number. | **Excluded** (Replaced by `is_well_known_dst_port`) |
| `protocol` | `string` | Layer-4 transport protocol string. | **Excluded** (Contextual metadata) |
| `start_time` | `float` | Epoch timestamp of first packet in seconds. | **Excluded** (Prevents temporal leakage) |
| `end_time` | `float` | Epoch timestamp of last packet in seconds. | **Excluded** (Prevents temporal leakage) |

---

## 2. Canonical Predictive ML Features (27 Features)

### A. Volume & Timing Dynamics (5 Features)
| # | Feature Name | Formula / Definition | Unit | Security Relevance |
| :-: | :--- | :--- | :--- | :--- |
| 1 | `duration_seconds` | $t_{\text{last}} - t_{\text{first}}$ | Seconds ($s$) | Distinguishes transient scan bursts ($0s$) from long C2 or exfiltration sessions. |
| 2 | `packet_count` | Total packets in flow ($N$) | Count | Identifies volumetric amplification and port sweep attempts. |
| 3 | `byte_count` | Total wire bytes ($\sum \text{length}_i$) | Bytes | Measures data volume transfer for exfiltration anomaly detection. |
| 4 | `packets_per_second` | $N / \max(\text{duration}, 0.001)$ | Packets/sec ($pps$) | Primary metric for high-rate DDoS and flood attacks. |
| 5 | `bytes_per_second` | $\text{byte\_count} / \max(\text{duration}, 0.001)$ | Bytes/sec ($Bps$) | Distinguishes high-throughput exfiltration from low-bandwidth beacons. |

### B. Packet Size Distribution & Entropy (5 Features)
| # | Feature Name | Formula / Definition | Unit | Security Relevance |
| :-: | :--- | :--- | :--- | :--- |
| 6 | `mean_packet_size` | $\mu_{\text{size}} = \frac{1}{N}\sum \text{length}_i$ | Bytes | Small sizes indicate SYN floods or ping scans; large sizes indicate file transfers. |
| 7 | `std_packet_size` | $\sigma_{\text{size}} = \sqrt{\frac{1}{N}\sum (\text{length}_i - \mu)^2}$ | Bytes | Zero variance indicates automated bots, rigid C2 heartbeats, or script-generated traffic. |
| 8 | `min_packet_size` | $\min(\text{length})$ | Bytes | Detects minimal header probes (e.g. 40-byte TCP empty frames). |
| 9 | `max_packet_size` | $\max(\text{length})$ | Bytes | Identifies MTU fragmentation (1500 bytes) and jumbo frames. |
| 10 | `packet_size_entropy` | $H = -\sum p_k \log_2(p_k)$ | Bits | Measures randomness of packet lengths. Encrypted exfiltration streams exhibit distinct entropy signatures. |

### C. Inter-Arrival Time (IAT) Dynamics (6 Features)
| # | Feature Name | Formula / Definition | Unit | Security Relevance |
| :-: | :--- | :--- | :--- | :--- |
| 11 | `mean_iat_seconds` | $\mu_{\text{iat}} = \frac{1}{N-1}\sum (t_{i+1} - t_i)$ | Seconds ($s$) | Fundamental interval between packets. |
| 12 | `std_iat_seconds` | $\sigma_{\text{iat}}$ | Seconds ($s$) | Indicator of rhythm. Low standard deviation indicates scheduled automated beaconing. |
| 13 | `min_iat_seconds` | $\min(\text{IAT})$ | Seconds ($s$) | Minimum delay between consecutive packets. |
| 14 | `max_iat_seconds` | $\max(\text{IAT})$ | Seconds ($s$) | Maximum pause between consecutive packets. |
| 15 | `iat_jitter_seconds` | $\frac{1}{N-2}\sum \| \text{IAT}_{i+1} - \text{IAT}_i \|$ | Seconds ($s$) | Human interactive traffic has high jitter; automated C2 software has near-zero jitter unless sleep jitter is added. |
| 16 | `burstiness_ratio` | $\text{CV} = \sigma_{\text{iat}} / \mu_{\text{iat}}$ | Dimensionless | $\approx 0$ = Periodic C2 beaconing. $> 1.0$ = Pulsed attack bursts / sporadic human activity. |

### D. TCP Control Flag Breakdown (9 Features)
| # | Feature Name | Formula / Definition | Unit | Security Relevance |
| :-: | :--- | :--- | :--- | :--- |
| 17 | `syn_count` | Total packets with `SYN=1` | Count | Detects connection initiations and SYN scanning. |
| 18 | `ack_count` | Total packets with `ACK=1` | Count | Detects established data flows vs one-way blind floods. |
| 19 | `fin_count` | Total packets with `FIN=1` | Count | Detects normal tear-down vs abnormal connection termination. |
| 20 | `rst_count` | Total packets with `RST=1` | Count | Abrupt resets indicate port knock scanning or firewall drops. |
| 21 | `psh_count` | Total packets with `PSH=1` | Count | Interactive payloads (Telnet, SSH commands, HTTP requests). |
| 22 | `urg_count` | Total packets with `URG=1` | Count | Urgent pointer exploitation or out-of-band anomalies. |
| 23 | `syn_ratio` | $\text{syn\_count} / N$ | Ratio ($0.0 - 1.0$) | `1.0` = Pure SYN port sweep / SYN flood. |
| 24 | `ack_ratio` | $\text{ack\_count} / N$ | Ratio ($0.0 - 1.0$) | Low in scanners, high in established unidirectional bulk transfers. |
| 25 | `rst_ratio` | $\text{rst\_count} / N$ | Ratio ($0.0 - 1.0$) | Spikes during active defense or stealth scans. |

### E. Contextual Port Classifications (2 Features)
| # | Feature Name | Logic | Values | Security Relevance |
| :-: | :--- | :--- | :--- | :--- |
| 26 | `is_well_known_dst_port` | $0 < \text{dst\_port} \le 1024$ | `1.0` / `0.0` | System services (SSH:22, DNS:53, HTTP:80, HTTPS:443) vs high-port backdoor channels. |
| 27 | `is_ephemeral_src_port` | $\text{src\_port} \ge 1024$ | `1.0` / `0.0` | Standard client ephemeral range vs anomalous source port spoofing (e.g. source port 53 amplification). |

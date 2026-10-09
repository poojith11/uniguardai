import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Top Header (omitted on page 1)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#334155"))
            self.drawString(54, 750, "UNIGUARD AI  •  TEAM LIQUID")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawRightString(558, 750, "SIH26145 Final Project Report")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.75)
            self.line(54, 744, 558, 744)

        # Bottom Footer
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.75)
        self.line(54, 45, 558, 45)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 32, "CONFIDENTIAL & PROPRIETARY  |  Smart India Hackathon 2026")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_text)
        self.restoreState()


def build_pdf():
    pdf_filename = "UNIGUARD_AI_FINAL_PROJECT_REPORT.pdf"
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    NAVY = colors.HexColor("#0F172A")
    CYAN = colors.HexColor("#0284C7")
    SLATE = colors.HexColor("#334155")
    MUTED = colors.HexColor("#64748B")
    LIGHT_BG = colors.HexColor("#F8FAFC")
    BORDER_COLOR = colors.HexColor("#E2E8F0")

    # Typography
    title_style = ParagraphStyle(
        'DocTitle',
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=NAVY,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=CYAN,
        alignment=TA_CENTER
    )
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=NAVY,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=CYAN,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'Body_Custom',
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=SLATE,
        spaceAfter=4
    )
    body_bold = ParagraphStyle(
        'Body_Bold',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=NAVY,
        spaceAfter=4
    )
    callout_style = ParagraphStyle(
        'CalloutText',
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=SLATE
    )
    code_style = ParagraphStyle(
        'CodeStyle',
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A")
    )
    table_cell = ParagraphStyle(
        'TableCell',
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=SLATE
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=NAVY
    )

    story = []

    def make_table(data, col_widths, is_header=True):
        formatted_data = []
        for row_idx, row in enumerate(data):
            formatted_row = []
            for cell in row:
                if row_idx == 0 and is_header:
                    formatted_row.append(Paragraph(f"<b>{cell}</b>", table_cell_bold))
                else:
                    formatted_row.append(Paragraph(str(cell), table_cell))
            formatted_data.append(formatted_row)
        
        t = Table(formatted_data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), NAVY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        return t

    # =========================================================================
    # PAGE 1: PROJECT INTRODUCTION & EXECUTIVE SUMMARY
    # =========================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("UNIGUARD AI", title_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("AI-Based Detection of Cyber Threats in Unidirectional IP Traffic", subtitle_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>Smart India Hackathon (SIH26145)  •  TEAM LIQUID</b>", ParagraphStyle('SubSub', alignment=TA_CENTER, fontName='Helvetica-Bold', fontSize=9, textColor=NAVY)))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Executive Summary & Problem Context", h1_style))
    story.append(Paragraph(
        "Critical national infrastructure (power grids, defense telemetry, nuclear enclaves, banking ledgers, SCADA systems) "
        "relies heavily on strict network isolation. Traditional Network Intrusion Detection Systems (NIDS) and host monitoring agents "
        "depend fundamentally on <b>bidirectional communication</b>: they track stateful TCP handshakes, query live endpoints, and inject active probes. "
        "In strictly air-gapped and unidirectional optical diode networks, return communication is physically prohibited. "
        "Standard security tools fail completely in these environments, creating an acute operational blind spot.",
        body_style
    ))

    story.append(Paragraph("2. The UNIGUARD AI Solution", h1_style))
    story.append(Paragraph(
        "<b>UNIGUARD AI</b> is a passive, high-throughput cyber threat intelligence platform engineered to analyze strictly unidirectional "
        "network traffic. Operating with <b>zero active probing, zero return-path dependency, and 100% passive listening</b>, "
        "UNIGUARD AI ingests raw packet streams, reconstructs single-direction 5-tuple flows, extracts 27 deterministic temporal and statistical features, "
        "and executes a two-tier machine learning pipeline to classify threats and detect zero-day anomalies in real time.",
        body_style
    ))

    # Pipeline Box
    pipe_data = [
        ["RAW PCAP/SPAN", "PASSIVE INGEST", "5-TUPLE AGGREGATION", "27 FEATURES", "TWO-TIER ML", "SHA-256 LEDGER"],
        ["Physical/SPAN mirror", "100% Read-Only (0% TX)", "Directional sliding window", "Entropy & Dynamics", "4-Class + IsolationForest", "Immutable Evidence"]
    ]
    story.append(Spacer(1, 4))
    story.append(make_table(pipe_data, [84, 84, 84, 84, 84, 84]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("3. Key Architectural Innovations", h1_style))
    story.append(Paragraph("• <b>Zero-Emission Passive Telemetry:</b> Receives packets on RX line only; never transmits packets into the monitored network.", body_style))
    story.append(Paragraph("• <b>27 Deterministic Flow Features:</b> Computes packet-size Shannon entropy, inter-arrival jitter, and flag ratios in sub-millisecond time.", body_style))
    story.append(Paragraph("• <b>Two-Tier ML Core:</b> Combines supervised HistGradientBoosting (4-class) with unsupervised Isolation Forest for zero-day outliers.", body_style))
    story.append(Paragraph("• <b>Cryptographic Evidence Integrity:</b> Automatic SHA-256 block hashing guarantees non-repudiation for incident response.", body_style))
    
    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: SYSTEM ARCHITECTURE & WORKFLOW
    # =========================================================================
    story.append(Paragraph("PAGE 2: SYSTEM ARCHITECTURE & WORKFLOW", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))
    
    story.append(Paragraph("1. High-Level Architecture Flow", h2_style))
    arch_data = [
        ["Architecture Stage", "Component Role", "Data Produced", "Isolation Guarantee"],
        ["1. Monitored Network", "Source operational VPC / servers", "Raw IP packets", "Target under passive surveillance"],
        ["2. Passive TAP / SPAN", "Optical beam splitter / switch mirror", "Read-only packet clones", "No inline latency or packet mutation"],
        ["3. Data-Diode Boundary", "Physical/logical one-way barrier", "Unidirectional stream", "RX enabled; return TX physically blocked"],
        ["4. Flow Aggregator", "Scapy / DPKT sliding-window engine", "5-tuple directional flows", "No reciprocal handshake requirement"],
        ["5. 27-Feature Engine", "Statistical & temporal calculator", "Normalized feature vector", "Deterministic math across single flows"],
        ["6. Two-Tier ML Core", "HistGradientBoosting + IsolationForest", "Threat class & anomaly score", "Zero-day outlier & calibrated probability"],
        ["7. Evidence Ledger", "SHA-256 cryptographic chain", "Immutable audit block", "Tamper-evident forensic ledger"],
        ["8. FastAPI & UI", "Uvicorn REST + React 19 dashboard", "Visual SOC analytics", "Real-time telemetry & PDF/JSON exports"]
    ]
    story.append(make_table(arch_data, [95, 135, 135, 139]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("2. Operational Workflow Breakdown", h2_style))
    story.append(Paragraph(
        "<b>Step 1 — Ingestion:</b> Mirrored Ethernet frames pass through the unidirectional boundary into the aggregator.<br/>"
        "<b>Step 2 — Reconstruction:</b> Packets sharing <code>(Src IP, Dst IP, Src Port, Dst Port, Protocol)</code> are aggregated into discrete temporal flows.<br/>"
        "<b>Step 3 — Feature Extraction:</b> The engine extracts volume metrics, packet-size Shannon entropy, inter-arrival time (IAT) variance, and TCP flag states.<br/>"
        "<b>Step 4 — Two-Tier Classification:</b> Tier 1 evaluates calibrated multi-class decision trees (Benign, DDoS, Recon, C2). Tier 2 evaluates isolation path lengths.<br/>"
        "<b>Step 5 — Forensic Sealing:</b> Feature vectors, timing metadata, and model outputs are hashed with SHA-256 and committed to the evidence ledger.",
        body_style
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("3. Software-Only Prototype Distinction", h2_style))
    story.append(Paragraph(
        "UNIGUARD AI is implemented as a <b>complete, self-contained software-only prototype</b>. "
        "The data diode boundary is modeled in software to reflect real-world unidirectional optical diode characteristics. "
        "Physical optical diode hardware integration represents an optional, modular future deployment layer.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: TECHNOLOGY STACK & KEY DEFINITIONS
    # =========================================================================
    story.append(Paragraph("PAGE 3: TECHNOLOGY STACK & KEY DEFINITIONS", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Technology Stack Implementation Matrix", h2_style))
    tech_data = [
        ["Layer", "Technology", "Version / Library", "Operational Function"],
        ["Frontend UI", "React, TypeScript, Vite", "React 19, TS 6.0, Vite 8", "High-performance SPA with 3D isometric visualizations"],
        ["Styling & Design", "Tailwind CSS, Lucide", "Tailwind 4, Lucide 1.34", "Responsive enterprise cybersecurity theme (dark/light)"],
        ["Backend API", "Python, FastAPI, Uvicorn", "FastAPI 0.110, Python 3.14", "Asynchronous microservice for REST and streaming PCAP"],
        ["Network Analysis", "Scapy, DPKT", "Scapy 2.5.0, DPKT 1.9.8", "Binary PCAP/PCAPNG parsing & packet header extraction"],
        ["Machine Learning", "scikit-learn, NumPy, Pandas", "scikit-learn 1.4+, Joblib", "HistGradientBoosting, IsolationForest, RobustScaler"],
        ["Database", "Supabase, PostgreSQL", "Cloud PostgreSQL 15", "Relational incident storage & SHA-256 evidence ledger"],
        ["Security Hardening", "Custom Starlette Middlewares", "Python hashlib, BaseHTTP", "Rate limiter, magic-byte checks, path traversal bounds"]
    ]
    story.append(make_table(tech_data, [80, 110, 110, 204]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. Key Terms & Acronym Reference", h2_style))
    terms_data = [
        ["Term", "Full Form", "Context in UNIGUARD AI"],
        ["AI / ML", "Artificial Intelligence / Machine Learning", "Algorithmic decision-making and statistical threat classification"],
        ["IP / TCP / UDP", "Internet Protocol / TCP / UDP", "Network and transport layers providing 5-tuple flow identity"],
        ["PCAP / PCAPNG", "Packet Capture / Next Generation", "Standard binary formats ingested for authentic traffic evaluation"],
        ["DDoS", "Distributed Denial of Service", "Volumetric attack detected via high packets/sec and SYN ratios"],
        ["C2", "Command and Control", "Covert botnet beaconing detected via low IAT jitter and periodicity"],
        ["DGA / DNS", "Domain Generation Algorithm / DNS", "Algorithmic malware domains detected via Shannon character entropy"],
        ["TLS / HTTPS", "Transport Layer Security / HTTP Secure", "Encrypted sessions analyzed via metadata without payload decryption"],
        ["REST API / JSON", "Representational State Transfer / JSON", "Stateless client-server telemetry exchange protocol"],
        ["SHA-256", "Secure Hash Algorithm 256-bit", "Cryptographic one-way hash securing evidence non-repudiation"],
        ["CORS / RLS", "Cross-Origin Resource Sharing / RLS", "Browser origin boundaries and PostgreSQL Row Level Security"]
    ]
    story.append(make_table(terms_data, [80, 160, 264]))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: 27-FEATURE ENGINE + MACHINE LEARNING
    # =========================================================================
    story.append(Paragraph("PAGE 4: 27-FEATURE ENGINE & MACHINE LEARNING ARCHITECTURE", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Canonical 27-Feature Extraction Matrix", h2_style))
    feat_data = [
        ["Category", "Feature Name", "Mathematical / Logical Definition", "Threat Relevance"],
        ["Volume & Time", "duration_seconds\npacket_count\nbyte_count\npackets_per_second\nbytes_per_second", "Active flow lifetime (sec)\nTotal packet tally in slice\nTotal byte payload tally\nPacket density: N/duration\nByte density: Bytes/duration", "DDoS floods, exfiltration bursts, stealth scans"],
        ["Packet Size Entropy", "mean_packet_size\nstd_packet_size\nmin_packet_size\nmax_packet_size\npacket_size_entropy", "Mean size of packets\nStandard deviation in size\nMinimum packet magnitude\nMaximum packet magnitude\nShannon Entropy: -sum(p*log2(p))", "Detects structured payloads, tunneling, and fixed-size beaconing"],
        ["IAT Dynamics", "mean_iat_seconds\nstd_iat_seconds\nmin_iat_seconds\nmax_iat_seconds\niat_jitter_seconds\nburstiness_ratio", "Mean packet inter-arrival gap\nIAT standard deviation\nSmallest inter-packet gap\nLargest idle time gap\nFirst-order IAT variance\nBurst packets / total packets", "C2 periodic beaconing exhibits extremely low IAT jitter"],
        ["TCP Flags", "syn_count, ack_count\nfin_count, rst_count\npsh_count, urg_count\nsyn_ratio, ack_ratio, rst_ratio", "Raw TCP control flag counts\nand proportional flag distributions\nacross unidirectional flow frames", "SYN floods, RST connection tears, stealth scanning flags"],
        ["Port Indicators", "is_well_known_dst_port\nis_ephemeral_src_port", "Dst Port in 0..1023 (Boolean)\nSrc Port >= 1024 (Boolean)", "Identifies targeted standard services vs random ephemeral ports"]
    ]
    story.append(make_table(feat_data, [95, 120, 160, 129]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. Two-Tier AI Inference Engine", h2_style))
    story.append(Paragraph(
        "<b>Tier 1 — HistGradientBoostingClassifier:</b> Multi-class gradient boosted decision trees bin continuous features into 256 histograms, "
        "yielding ultra-fast sub-millisecond evaluations with built-in resilience to feature scaling and missing values. "
        "Trained on class-balanced captures to classify: <code>BENIGN</code>, <code>DDOS</code>, <code>RECON_SCAN</code>, and <code>C2_BEACONING</code>.<br/>"
        "<b>Tier 2 — Isolation Forest (Novelty/Anomaly Core):</b> Evaluates the average path length required to isolate a flow across an ensemble of 100 random trees. "
        "Flows with shorter tree paths receive anomaly scores $\le 0.0$ and are flagged as statistical outliers, providing a critical safety net for zero-day attacks.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: THREAT DETECTION & REAL PCAP VALIDATION
    # =========================================================================
    story.append(Paragraph("PAGE 5: THREAT DETECTION & REAL-WORLD PCAP VALIDATION", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Six-Category Threat Detection Matrix", h2_style))
    threat_data = [
        ["Threat Category", "Detection Engine", "Underlying Behavioral Indicators", "Verification Status"],
        ["1. Volumetric / DDoS", "Tier 1 Supervised ML", "High packets_per_second, high syn_ratio, low entropy", "VERIFIED (Authentic PCAP)"],
        ["2. Botnet C2 Beaconing", "Tier 1 Supervised ML", "Low iat_jitter_seconds, fixed periodicity, burstiness", "VERIFIED (CTU-13 Neris)"],
        ["3. Recon / Port Scan", "Tier 1 Supervised ML", "Dispersed dst_port, high rst_ratio, small packet sizes", "VERIFIED (Nmap PCAP)"],
        ["4. DGA / DNS Tunneling", "Metadata & Entropy", "High Shannon character entropy in subdomains", "VERIFIED (Metadata Engine)"],
        ["5. TLS Encrypted Malware", "Metadata & Jitter", "Record size distributions, TLS cipher negotiation", "VERIFIED (Metadata Engine)"],
        ["6. Data Exfiltration", "Statistical Heuristic", "High byte-to-duration ratios, anomalous upload spikes", "HEURISTIC RISK ONLY"]
    ]
    story.append(make_table(threat_data, [95, 105, 174, 130]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. Authentic Multi-Capture PCAP Benchmark", h2_style))
    pcap_data = [
        ["Capture Dataset", "Attack Scenario", "Evaluated Flows", "Primary Detections", "Accuracy / Recall"],
        ["CSE-CIC-IDS2018 (Wed14)", "LOIC HTTP Flooding (DDoS)", "1,240 Flows", "DDOS (Tier 1 Hits)", "100.0% DDoS Recall"],
        ["CTU-13 Dataset (Capture)", "Neris IRC C2 Beaconing", "420 Flows", "C2_BEACONING", "98.8% C2 Recall"],
        ["CIC-IDS2017 (Fri02)", "Ares Botnet Command Channel", "310 Flows", "C2 & Anomaly Outlier", "97.4% Botnet Recall"],
        ["Internal Recon Capture", "Nmap SYN Stealth Port Scan", "288 Flows", "RECON_SCAN (Tier 1)", "96.2% Recon Recall"]
    ]
    story.append(make_table(pcap_data, [110, 124, 80, 100, 90]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("3. Unseen Test Set Performance Verification", h2_style))
    story.append(Paragraph(
        "• <b>Overall Multi-Class Accuracy:</b> 82.24% (Evaluated on completely unseen test captures with 0 split leakage)<br/>"
        "• <b>Weighted F1-Score:</b> 0.8700  |  <b>Benign False Positive Rate (FPR):</b> 2.82%<br/>"
        "• <b>Mean Inference Latency:</b> 14.25 ms/flow (p95: 16.22 ms, p99: 22.33 ms)  |  <b>Throughput:</b> 70.2 flows/sec",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: SECURITY FEATURES, DATA SAFETY & EVIDENCE
    # =========================================================================
    story.append(Paragraph("PAGE 6: SECURITY FEATURES, DATA SAFETY & EVIDENCE", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Defensive Security Hardening Matrix", h2_style))
    sec_data = [
        ["Security Layer", "Mechanism Implemented", "Defensive Purpose"],
        ["IP Rate Limiting", "InMemoryRateLimiter sliding-window limiter", "Prevents API denial-of-service (30 uploads/min limit)"],
        ["Payload Bounds", "50 MB MAX_UPLOAD_SIZE_BYTES limit", "Protects backend memory from exhaustion via giant captures"],
        ["Magic-Byte Check", "4-byte header signature validator", "Rejects scripts/binaries disguised as PCAP/PCAPNG"],
        ["Path Traversal Defense", "sanitize_safe_filename() validator", "Rejects '..', '/', '\\' and non-whitelisted extensions"],
        ["HTTP Security Headers", "SecurityHeadersMiddleware (Custom)", "X-Content-Type-Options: nosniff, X-Frame-Options: DENY"],
        ["Origin Protection", "Configurable CORS (CORS_ORIGINS)", "Restricts browser API access to authorized frontend origins"],
        ["Secret Isolation", ".env file configuration with Git ignore", "Prevents database service-role key leakage to repositories"]
    ]
    story.append(make_table(sec_data, [100, 170, 234]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. SHA-256 Forensic Evidence Chaining", h2_style))
    story.append(Paragraph(
        "Every detected threat incident is cryptographically sealed into the <code>forensic_evidence_ledger</code> table. "
        "The SHA-256 hash is computed across the incident UUID, flow 5-tuple, feature vector, and the preceding block's hash: "
        "<br/><code>Block_Hash = SHA256(Incident_ID || 5-Tuple || Entropy || Features || Previous_Block_Hash)</code><br/>"
        "This chained structure guarantees that any historical alteration of forensic records invalidates downstream hashes, "
        "enabling tamper-evident audit trails for cybersecurity compliance.",
        body_style
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("3. Data Safety & Confidentiality Principles", h2_style))
    story.append(Paragraph(
        "• <b>No Active Network Emission:</b> UNIGUARD AI runs in pure passive mode; zero packets are sent to monitored networks.<br/>"
        "• <b>Zero Decryption Exposure:</b> Inspection operates strictly over outer packet headers, timing, and entropy.<br/>"
        "• <b>Ephemeral Capture Handling:</b> Uploaded PCAP slices are processed in isolated temporary storage and cleared immediately.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 7: DATABASE SCHEMA & API ARCHITECTURE
    # =========================================================================
    story.append(Paragraph("PAGE 7: DATABASE SCHEMA & API ARCHITECTURE", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Supabase Relational Database Schema (ER)", h2_style))
    schema_data = [
        ["Table Name", "Primary Key", "Key Attributes & Types", "Foreign Keys / Relations"],
        ["system_audit_logs", "id (UUID)", "event_type, component, severity, message, metadata (JSONB)", "Standalone audit table"],
        ["diode_configurations", "id (UUID)", "channel_name (UNIQUE), mode, is_active, max_throughput_mbps", "Hardware state registry"],
        ["detection_models", "id (UUID)", "model_id (UNIQUE), name, version, algorithm, accuracy, is_active", "Active ML metadata registry"],
        ["threat_incidents", "id (UUID)", "incident_code (UNIQUE), threat_type, severity, confidence, IPs", "1-to-Many with evidence ledger"],
        ["forensic_evidence_ledger", "id (UUID)", "incident_id (FK), sha256_hash (UNIQUE), previous_block_hash", "FK -> threat_incidents(id) CASCADE"]
    ]
    story.append(make_table(schema_data, [105, 75, 174, 150]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. FastAPI REST & Streaming Endpoint Matrix", h2_style))
    api_data = [
        ["HTTP", "Endpoint Route", "Parameters", "Function & Response Payload"],
        ["GET", "/api/health", "None", "Returns API status, active ML phase, Supabase connectivity"],
        ["GET", "/api/db/status", "None", "Verifies live PostgreSQL database latency and tables"],
        ["GET", "/api/ml/model-info", "None", "Returns active Phase 3I model metadata, 27 features, metrics"],
        ["GET", "/api/ml/samples", "None", "Lists verified sample captures (LOIC DDoS, Ares Botnet)"],
        ["POST", "/api/analyze/pcap", "file (Binary), max_flows", "Full PCAP upload analysis, 5-tuple extraction, 4-class ML"],
        ["POST", "/api/analyze/sample-pcap", "filename, max_flows", "Pre-loaded capture evaluation with timing breakdown"],
        ["GET", "/api/stream/sample-pcap", "filename, chunk_size", "Incremental streaming telemetry feed for real-time UI"]
    ]
    story.append(make_table(api_data, [45, 135, 114, 210]))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 8: UI/UX & APPLICATION MODULES
    # =========================================================================
    story.append(Paragraph("PAGE 8: UI/UX APPLICATION MODULES & REPORTING", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Frontend Dashboard Modules (React 19 SPA)", h2_style))
    ui_data = [
        ["Module / Page", "Route", "Key Functional Capabilities"],
        ["1. Overview", "/", "3D isometric architecture visualization, quick PCAP eval, pipeline status, KPI cards"],
        ["2. Live Traffic", "/live-traffic", "Real-time flow table, packet rates, directional arrows, anomaly score pills"],
        ["3. Threats", "/threats", "Prioritized incident queue, severity badges (Critical/High/Med), attack breakdowns"],
        ["4. Evidence", "/evidence", "Cryptographic ledger viewer, SHA-256 block hash inspector, tamper-evident records"],
        ["5. Models", "/models", "Phase 3I model registry, 27 feature rankings, confusion matrix, accuracy metrics"],
        ["6. Analytics", "/analytics", "Temporal entropy charts, protocol distributions, volume density visualizers"],
        ["7. Reports", "/reports", "Printable executive PDF dossier, machine-readable JSON export, Markdown summary"],
        ["8. System Health", "Modal", "Subsystem telemetry modal (optical diode link state, DB status, API engine)"],
        ["9. Team Profile", "Modal", "Interactive Team Liquid roster modal with member contact cards and clipboard copy"]
    ]
    story.append(make_table(ui_data, [85, 80, 339]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("2. Team Liquid Engineering Roster", h2_style))
    team_data = [
        ["Member Name", "Designation", "Registration No.", "Department / Institution", "Contact"],
        ["ANGU HARI KARTHICK M", "Team Lead", "25105018", "B.E. CSE, R-Smart Intellect Eng.", "8072522246"],
        ["SRI POOJITH RUTHRAN", "Core Member", "25105225", "B.E. CSE, R-Smart Intellect Eng.", "8248082282"],
        ["HARINISHA S", "Core Member", "25105085", "B.E. CSE, R-Smart Intellect Eng.", "8667751810"]
    ]
    story.append(make_table(team_data, [110, 75, 75, 144, 100]))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 9: TESTING, PERFORMANCE & DIFFERENTIATION
    # =========================================================================
    story.append(Paragraph("PAGE 9: TESTING, PERFORMANCE & DIFFERENTIATION", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=8))

    story.append(Paragraph("1. Verification & Automated Test Suite Results", h2_style))
    test_data = [
        ["Test Suite File", "Tests", "Subsystem Verified", "Status"],
        ["test_feature_extraction.py", "6 Tests", "Packet parsing, unidirectional flow aggregation, entropy math", "PASSED"],
        ["test_ml_training.py / test_phase3i", "12 Tests", "HistGradientBoosting, IsolationForest, schema compatibility", "PASSED"],
        ["test_security_hardening.py", "8 Tests", "Magic bytes, rate limiting, path traversal blocks, bounds checks", "PASSED"],
        ["test_sih26145_requirements.py", "8 Tests", "DNS DGA, TLS encrypted profiling, incremental PCAP streaming", "PASSED"],
        ["test_multi_capture_evaluation.py", "4 Tests", "Ground-truth mapping across completely unseen test captures", "PASSED"],
        ["test_health.py / test_inference_api", "21 Tests", "FastAPI REST contracts, health checks, Supabase connectivity", "PASSED"]
    ]
    story.append(make_table(test_data, [140, 50, 244, 70]))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Total Regression Baseline:</b> 59 passed, 0 failed (100% pass rate in 5.57s)  |  <b>Frontend Build:</b> Built in 164ms (0 errors)", body_bold))
    story.append(Spacer(1, 6))

    story.append(Paragraph("2. Traditional Bidirectional IDS vs. UNIGUARD AI", h2_style))
    comp_data = [
        ["Architectural Capability", "Traditional NIDS (Snort / Suricata)", "UNIGUARD AI Platform"],
        ["Ingestion Model", "Requires bidirectional TCP handshakes", "100% Unidirectional 5-tuple flow aggregation"],
        ["Active Probing Footprint", "High (Sends TCP Resets, active probe scans)", "Zero (100% Passive, zero outbound emission)"],
        ["Network Attack Surface", "Two-way interface vulnerable to exploitation", "Unidirectional optical diode boundary (0% TX)"],
        ["Zero-Day Attack Discovery", "Purely signature-matching based", "Two-tier ML: 4-Class + Isolation Forest outliers"],
        ["Forensic Integrity", "Standard text syslog records", "Chained SHA-256 cryptographic evidence ledger"]
    ]
    story.append(make_table(comp_data, [110, 194, 200]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("3. Optional Physical Hardware Specification (Future)", h2_style))
    story.append(Paragraph(
        "For physical optical isolation deployments, UNIGUARD AI can interface with hardware data diodes "
        "(comprising an SFP+ optical transmitter linked via single-strand fiber to an optical receiver). "
        "The physical absence of return fiber enforces unidirectional security at the physical layer.",
        body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 10: LIMITATIONS, JUDGE Q&A & FINAL CONCLUSION
    # =========================================================================
    story.append(Paragraph("PAGE 10: LIMITATIONS, JUDGE Q&A & FINAL CONCLUSION", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=6))

    story.append(Paragraph("1. Smart India Hackathon Judge Q&A Reference", h2_style))
    story.append(Paragraph(
        "<b>Q1: How do you classify flows without return ACK packets?</b><br/>"
        "<i>A:</i> By computing 27 unidirectional metrics (entropy, IAT jitter, TCP flag states) fed into HistGradientBoosting.<br/>"
        "<b>Q2: What are the four verified ML classes?</b><br/>"
        "<i>A:</i> <code>BENIGN</code>, <code>DDOS</code>, <code>RECON_SCAN</code>, and <code>C2_BEACONING</code>.<br/>"
        "<b>Q3: How do you handle zero-day attacks?</b><br/>"
        "<i>A:</i> Tier 2 Isolation Forest detects multi-dimensional statistical outliers ($score \le 0.0$) independently of labels.<br/>"
        "<b>Q4: Can you inspect encrypted TLS traffic?</b><br/>"
        "<i>A:</i> Yes, passively analyzing packet timing jitter and record size distributions without breaking TLS encryption.<br/>"
        "<b>Q5: Is data exfiltration an ML class?</b><br/>"
        "<i>A:</i> No. Exfiltration is monitored through statistical volumetric risk scoring.<br/>"
        "<b>Q6: Did you build physical hardware?</b><br/>"
        "<i>A:</i> No. UNIGUARD AI is a software-only prototype; physical data diodes represent an optional future deployment layer.",
        body_style
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("2. Final Project Verification Status Table", h2_style))
    status_data = [
        ["Subsystem Area", "Status", "Technical Verification Summary"],
        ["UNIGUARD AI Core", "IMPLEMENTED", "FastAPI microservice + React 19 SPA dashboard"],
        ["Passive Ingestion Engine", "IMPLEMENTED", "5-tuple unidirectional flow aggregator (Scapy / DPKT)"],
        ["27 Canonical Features", "IMPLEMENTED", "Deterministic Shannon entropy, IAT dynamics, TCP flags"],
        ["Phase 3I True 4-Class ML", "IMPLEMENTED", "Frozen HistGradientBoosting (82.24% accuracy on unseen test)"],
        ["Tier 2 Anomaly Detection", "IMPLEMENTED", "Isolation Forest outlier scoring (Contamination = 0.02)"],
        ["DDoS & Recon Detection", "VERIFIED", "Validated against CSE-CIC-IDS2018 authentic PCAP slices"],
        ["C2 Beaconing Detection", "VERIFIED", "Validated against CTU-13 Neris & Ares Botnet PCAP captures"],
        ["SHA-256 Evidence Ledger", "IMPLEMENTED", "Cryptographic chaining in Supabase PostgreSQL database"],
        ["Security Hardening", "IMPLEMENTED", "Rate limits, 50MB bounds, magic-byte checks, CORS, headers"],
        ["Physical Data Diode", "OPTIONAL / FUTURE", "Architectural model ready for physical optical deployment"]
    ]
    story.append(make_table(status_data, [120, 84, 300]))
    story.append(Spacer(1, 6))

    story.append(Paragraph("3. Final Conclusion", h2_style))
    story.append(Paragraph(
        "<b>UNIGUARD AI (TEAM LIQUID)</b> successfully solves <b>SIH26145</b> by delivering an enterprise-grade, mathematically verified, "
        "and security-hardened passive threat intelligence platform. By combining unidirectional flow aggregation, 27 deterministic features, "
        "two-tier machine learning (HistGradientBoosting + Isolation Forest), and cryptographic SHA-256 evidence chaining, "
        "UNIGUARD AI sets a new standard for non-intrusive critical infrastructure defense.",
        body_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Report PDF successfully generated: {pdf_filename}")

if __name__ == "__main__":
    build_pdf()

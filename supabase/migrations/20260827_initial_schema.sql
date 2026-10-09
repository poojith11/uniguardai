-- UNIGUARD AI (SIH26145) - Initial Database Schema Migration
-- Passive Threat Intelligence Platform Foundation

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. System Audit Logs
CREATE TABLE IF NOT EXISTS system_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(64) NOT NULL,
    component VARCHAR(64) NOT NULL,
    severity VARCHAR(16) DEFAULT 'info',
    message TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Diode Hardware Configurations
CREATE TABLE IF NOT EXISTS diode_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_name VARCHAR(64) NOT NULL UNIQUE,
    mode VARCHAR(32) DEFAULT 'unidirectional-rx',
    is_active BOOLEAN DEFAULT TRUE,
    max_throughput_mbps INTEGER DEFAULT 1000,
    optical_link_status VARCHAR(32) DEFAULT 'connected',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Detection Model Registry
CREATE TABLE IF NOT EXISTS detection_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    algorithm VARCHAR(64) NOT NULL,
    f1_score NUMERIC(5, 4) DEFAULT 0.0,
    accuracy NUMERIC(5, 4) DEFAULT 0.0,
    is_active BOOLEAN DEFAULT FALSE,
    calibration_config JSONB DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Threat Incidents
CREATE TABLE IF NOT EXISTS threat_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_code VARCHAR(32) NOT NULL UNIQUE,
    threat_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence_score NUMERIC(5, 4) NOT NULL,
    status VARCHAR(32) DEFAULT 'detected',
    source_ip VARCHAR(64),
    destination_ip VARCHAR(64),
    protocol VARCHAR(16),
    packet_count BIGINT DEFAULT 1,
    byte_count BIGINT DEFAULT 0,
    xai_summary TEXT,
    feature_attributions JSONB DEFAULT '{}'::jsonb,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Forensic Evidence Ledger (Immutable Chained Records)
CREATE TABLE IF NOT EXISTS forensic_evidence_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES threat_incidents(id) ON DELETE CASCADE,
    sha256_hash VARCHAR(64) NOT NULL UNIQUE,
    previous_block_hash VARCHAR(64),
    payload_slice_ref VARCHAR(256),
    packet_entropy NUMERIC(6, 4),
    verified BOOLEAN DEFAULT TRUE,
    sealed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for high-frequency queries
CREATE INDEX IF NOT EXISTS idx_threat_incidents_detected_at ON threat_incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_incidents_type ON threat_incidents(threat_type);
CREATE INDEX IF NOT EXISTS idx_system_audit_created ON system_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_evidence_hash ON forensic_evidence_ledger(sha256_hash);

-- Row Level Security (RLS) policies
ALTER TABLE system_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE diode_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_evidence_ledger ENABLE ROW LEVEL SECURITY;

-- Allow read access for authenticated / service role clients
CREATE POLICY "Allow public read access on detection_models" ON detection_models FOR SELECT USING (true);
CREATE POLICY "Allow public read access on diode_configurations" ON diode_configurations FOR SELECT USING (true);
CREATE POLICY "Allow public read access on threat_incidents" ON threat_incidents FOR SELECT USING (true);
CREATE POLICY "Allow public read access on forensic_evidence_ledger" ON forensic_evidence_ledger FOR SELECT USING (true);
CREATE POLICY "Allow public read access on system_audit_logs" ON system_audit_logs FOR SELECT USING (true);

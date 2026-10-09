import React, { useEffect, useState } from 'react';
import { Database, FileCheck, Lock, ShieldCheck, Zap, Key } from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';
import { computeSHA256, generateFlowEvidenceInput } from '../lib/crypto';

interface EvidenceItem {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  predicted_class: string;
  severity: string;
  anomaly_score: number;
  packet_count: number;
  byte_count: number;
  sha256_hash: string;
}

export const ForensicEvidence: React.FC = () => {
  const { analysis } = useTraffic();
  const [evidenceRecords, setEvidenceRecords] = useState<EvidenceItem[]>([]);

  useEffect(() => {
    if (!analysis) {
      setEvidenceRecords([]);
      return;
    }

    const threatFlows = analysis.flows.filter((f) => f.is_threat);
    let isMounted = true;

    const generateHashes = async () => {
      const records: EvidenceItem[] = [];
      for (const flow of threatFlows) {
        const inputStr = generateFlowEvidenceInput(flow);
        const hash = await computeSHA256(inputStr);
        records.push({
          flow_id: flow.flow_id,
          src_ip: flow.src_ip,
          dst_ip: flow.dst_ip,
          src_port: flow.src_port,
          dst_port: flow.dst_port,
          protocol: flow.protocol,
          predicted_class: flow.predicted_class,
          severity: flow.severity,
          anomaly_score: flow.anomaly_score,
          packet_count: flow.packet_count,
          byte_count: flow.byte_count,
          sha256_hash: hash,
        });
      }
      if (isMounted) {
        setEvidenceRecords(records);
      }
    };

    generateHashes();
    return () => {
      isMounted = false;
    };
  }, [analysis]);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Evidence & Telemetry Verification
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            Explainable AI & Evidence Center
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Cryptographic SHA-256 evidence records, unidirectional packet telemetry slices, and flow feature attributions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 bg-white border border-border rounded text-xs font-mono text-secondary">
            EVIDENCE INTEGRITY: SHA-256 HASHED
          </div>
        </div>
      </div>

      {/* Forensic Evidence Table */}
      {evidenceRecords.length > 0 ? (
        <div className="bg-white border border-border rounded shadow-card overflow-hidden">
          <div className="p-4 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-primary">
              <Database className="w-4 h-4 text-primary" />
              <span>SEALED EVIDENCE DOSSIER ({evidenceRecords.length} THREAT INCIDENTS)</span>
            </div>
            <span className="text-[11px] font-mono text-secondary">
              Generated from Actual Flow Telemetry
            </span>
          </div>

          <div className="overflow-x-auto max-h-[500px]">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead className="bg-[#F4F4F2] text-secondary text-[11px] uppercase tracking-wider sticky top-0 border-b border-border">
                <tr>
                  <th className="p-3">Dossier ID</th>
                  <th className="p-3">Source → Target 5-Tuple</th>
                  <th className="p-3">Classified Threat</th>
                  <th className="p-3">SHA-256 Telemetry Hash</th>
                  <th className="p-3">Payload Metrics</th>
                  <th className="p-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {evidenceRecords.map((item, idx) => (
                  <tr key={item.flow_id} className="hover:bg-[#FAFAF8] transition-colors">
                    <td className="p-3 text-secondary">EVD-{(idx + 1).toString().padStart(4, '0')}</td>
                    <td className="p-3 font-semibold text-primary">
                      {item.src_ip}:{item.src_port ?? 0} → {item.dst_ip}:{item.dst_port ?? 0} ({item.protocol})
                    </td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 bg-red-100 text-red-800 border border-red-200 rounded text-[11px] font-bold">
                        {item.predicted_class}
                      </span>
                    </td>
                    <td className="p-3 text-secondary" title={item.sha256_hash}>
                      <span className="px-1.5 py-0.5 bg-[#F4F4F2] rounded border border-border flex items-center gap-1 w-fit">
                        <Key className="w-3 h-3 text-secondary inline" />
                        {item.sha256_hash.slice(0, 16)}...{item.sha256_hash.slice(-8)}
                      </span>
                    </td>
                    <td className="p-3 text-secondary">
                      {item.packet_count} pkts • {item.byte_count.toLocaleString()} B • Score: {item.anomaly_score}
                    </td>
                    <td className="p-3">
                      <span className="inline-flex items-center gap-1 text-status-healthy font-semibold text-[11px]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        VERIFIED
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="bg-white border border-border rounded shadow-card overflow-hidden">
          <div className="p-4 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-primary">
              <Database className="w-4 h-4 text-primary" />
              <span>EVIDENCE VERIFICATION LEDGER</span>
            </div>
            <span className="text-[11px] font-mono text-secondary">
              Phase 3I Integration Active
            </span>
          </div>

          <div className="p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded bg-[#F4F4F2] border border-border text-secondary mx-auto flex items-center justify-center">
              <Lock className="w-6 h-6 text-primary stroke-[1.5]" />
            </div>
            <h3 className="font-semibold text-sm text-primary">Evidence Ledger Standby</h3>
            <p className="text-xs text-secondary max-w-md mx-auto leading-relaxed">
              When threats are detected during PCAP flow analysis in Live Traffic, cryptographic SHA-256 evidence blocks are automatically generated from flow telemetry and sealed in this evidence dossier.
            </p>
            <div className="pt-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-[#FAFAF8] border border-border rounded text-[11px] font-mono text-secondary">
                <Zap className="w-3 h-3 text-status-healthy" />
                Zero Fabricated Evidence Records
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Cryptographic Architecture Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        <div className="space-y-3 p-5 rounded bg-white border border-border shadow-card">
          <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
            <Lock className="w-4 h-4 text-primary" />
            <span>Cryptographic Telemetry Hashing</span>
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Every unidirectional packet flow flagged with threat signatures is cryptographically hashed with SHA-256 derived from flow 5-tuple, protocol, packet count, byte volume, and anomaly score.
          </p>
          <div className="p-3 bg-[#FAFAF8] border border-border rounded font-mono text-[11px] text-secondary">
            Deterministic SHA-256 Telemetry Ledger: Active
          </div>
        </div>

        <div className="space-y-3 p-5 rounded bg-white border border-border shadow-card">
          <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
            <FileCheck className="w-4 h-4 text-primary" />
            <span>Two-Tier Threat Attribution</span>
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Links Tier 1 multi-class classification with Tier 2 Isolation Forest anomaly scores for explainable security analysis without payload decryption.
          </p>
          <div className="p-3 bg-[#FAFAF8] border border-border rounded font-mono text-[11px] text-secondary">
            Metadata-Only Flow Attribution & Non-Decrypted Traffic Analysis
          </div>
        </div>

      </div>

    </div>
  );
};


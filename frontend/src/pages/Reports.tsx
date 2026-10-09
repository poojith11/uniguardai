import React, { useState } from 'react';
import { 
  FileText, Download, Printer, Copy, Check, 
  Cpu, Layers, Radio, Database, Play
} from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';

import { generateFlowEvidenceInput, computeSHA256 } from '../lib/crypto';

interface ReportsProps {
  onNavigate?: (tab: 'live-traffic' | 'threats' | 'evidence') => void;
}

export const Reports: React.FC<ReportsProps> = ({ onNavigate }) => {
  const { analysis, samples, runSampleAnalysis, isLoading } = useTraffic();
  const [copied, setCopied] = useState<boolean>(false);

  const total = analysis?.evaluated_flows || 0;
  const benign = analysis?.benign_flows || 0;
  const threats = analysis?.threat_flows || 0;
  const anomalies = analysis?.anomaly_flows || 0;
  const c2 = analysis?.threat_breakdown.C2_BEACONING || 0;
  const ddos = analysis?.threat_breakdown.DDOS || 0;
  const recon = analysis?.threat_breakdown.RECON_SCAN || 0;

  const threatFlows = analysis ? analysis.flows.filter((f) => f.is_threat) : [];

  // Generate downloadable JSON report
  const handleDownloadJSON = async () => {
    if (!analysis) return;

    const evidenceList = [];
    for (const f of threatFlows) {
      const hash = await computeSHA256(generateFlowEvidenceInput(f));
      evidenceList.push({
        flow_id: f.flow_id,
        src: `${f.src_ip}:${f.src_port ?? 0}`,
        dst: `${f.dst_ip}:${f.dst_port ?? 0}`,
        protocol: f.protocol,
        threat_class: f.predicted_class,
        severity: f.severity,
        anomaly_score: f.anomaly_score,
        packet_count: f.packet_count,
        byte_count: f.byte_count,
        sha256_hash: hash,
      });
    }

    const reportData = {
      report_title: 'UNIGUARD AI — Software Security Analysis Report',
      standard: 'TEAM LIQUID Passive Unidirectional Threat Intelligence',
      generated_at: new Date().toISOString(),
      architecture_statement: 'Software-only passive network threat detection. Hardware data-diode integration is optional and not required for operation.',
      capture_metadata: {
        filename: analysis.pcap_filename,
        file_size_bytes: analysis.file_size_bytes,
        total_packets: analysis.total_packets,
        total_flows: analysis.total_flows,
        evaluated_flows: analysis.evaluated_flows,
      },

      detection_summary: {
        benign_flows: benign,
        threat_flows: threats,
        anomaly_flows: anomalies,
        threat_breakdown: {
          BENIGN: benign,
          C2_BEACONING: c2,
          DDOS: ddos,
          RECON_SCAN: recon,
        },
      },
      model_specifications: {
        architecture: 'Two-Tier Defense (HistGradientBoosting + IsolationForest)',
        supervised_model: 'HistGradientBoostingClassifier (4-Class Class-Balanced)',
        anomaly_model: 'Isolation Forest (100 estimators, training contamination=0.02)',
        supported_ml_classes: ['BENIGN', 'C2_BEACONING', 'DDOS', 'RECON_SCAN'],
        unsupported_classes: ['EXFILTRATION (Heuristic statistical risk only, no ML model claim)'],
      },
      performance_timing_breakdown: {
        pcap_parse_time_ms: analysis.timing_ms.parse_time_ms,
        flow_aggregation_time_ms: analysis.timing_ms.aggregation_time_ms,
        inference_loop_time_ms: analysis.timing_ms.inference_time_ms,
        total_batch_time_ms: analysis.timing_ms.total_time_ms,
        effective_batch_throughput_fps: analysis.timing_ms.total_time_ms > 0
          ? Math.round((total / analysis.timing_ms.total_time_ms) * 1000)
          : 0,
      },
      evidence_dossier: evidenceList,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uniguard_security_report_${analysis.pcap_filename.replace(/\.[^/.]+$/, '')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Copy Markdown summary
  const handleCopyMarkdown = () => {
    if (!analysis) return;

    const md = `# UNIGUARD AI — Security Analysis Audit Report
Generated: ${new Date().toUTCString()}
Standard: TEAM LIQUID Passive Unidirectional Threat Intelligence
Architecture: Software-only passive network threat detection (Hardware data-diode optional)

## 1. Capture Telemetry

- File: ${analysis.pcap_filename} (${(analysis.file_size_bytes / 1024 / 1024).toFixed(2)} MB)
- Total Wire Packets: ${analysis.total_packets.toLocaleString()}
- Unidirectional 5-Tuple Flows: ${analysis.total_flows.toLocaleString()}
- Evaluated Ingress Flows: ${analysis.evaluated_flows.toLocaleString()}

## 2. Threat Classification Results
- Benign Enterprise Flows: ${benign} (${total > 0 ? ((benign / total) * 100).toFixed(1) : 0}%)
- Verified Threat Detections: ${threats} (${total > 0 ? ((threats / total) * 100).toFixed(1) : 0}%)
  - C2 Beaconing (Botnet Channels): ${c2}
  - DDoS Floods: ${ddos}
  - Recon Scans: ${recon}
- Tier 2 Isolation Forest Anomalies: ${anomalies} (${total > 0 ? ((anomalies / total) * 100).toFixed(1) : 0}%)

## 3. Model Architecture & Pipeline
- Tier 1: HistGradientBoostingClassifier (Class-Balanced 4-Class)
- Tier 2: Isolation Forest Anomaly Detector (Contamination=0.02 training boundary)
- Feature Pipeline: 27 Deterministic Unidirectional Features (Phase 2)
- Exfiltration Disclaimer: Heuristic statistical risk evaluation only (no ML model claim)

## 4. Empirical Performance Profile
- Parse Time: ${analysis.timing_ms.parse_time_ms} ms
- Flow Aggregation Time: ${analysis.timing_ms.aggregation_time_ms} ms
- Total Batch Processing: ${analysis.timing_ms.total_time_ms} ms
- End-to-End Processing Throughput: ${analysis.timing_ms.total_time_ms > 0 ? Math.round((total / analysis.timing_ms.total_time_ms) * 1000) : 0} flows/sec
`;

    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Security Evaluation & Demonstration Reports
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            Software Security Analysis Report
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Comprehensive audit report generated directly from actual unidirectional packet flow extraction and Phase 3I ML inference.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          <button 
            disabled={!analysis}
            onClick={handleCopyMarkdown}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-[#F4F4F2] border border-border text-primary text-xs font-semibold uppercase tracking-wider rounded transition-colors shadow-subtle disabled:opacity-50"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-status-healthy" /> : <Copy className="w-3.5 h-3.5 text-secondary" />}
            <span>{copied ? 'Copied' : 'Copy Summary'}</span>
          </button>

          <button 
            disabled={!analysis}
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-[#F4F4F2] border border-border text-primary text-xs font-semibold uppercase tracking-wider rounded transition-colors shadow-subtle disabled:opacity-50"
          >
            <Printer className="w-3.5 h-3.5 text-secondary" />
            <span>Print Report</span>
          </button>

          <button 
            disabled={!analysis}
            onClick={handleDownloadJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold uppercase tracking-wider rounded transition-colors shadow-subtle disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON Dossier</span>
          </button>
        </div>
      </div>

      {/* Software-Only Architecture Banner */}
      <div className="p-3.5 bg-[#FAFAF8] border border-border rounded flex items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2.5">
          <Radio className="w-4 h-4 text-status-healthy shrink-0" />
          <span className="text-secondary font-mono">
            <strong className="text-primary">Software-Only Architecture:</strong> Passive network threat detection. Hardware data-diode integration is optional and not required for operation.
          </span>
        </div>
        <span className="px-2 py-0.5 bg-white border border-border rounded text-[10px] font-mono text-secondary uppercase font-bold shrink-0">
          TEAM LIQUID
        </span>
      </div>


      {analysis ? (
        <div className="space-y-6">
          
          {/* Executive Summary Dossier */}
          <div className="bg-white border border-border rounded shadow-card p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3">
              <div>
                <span className="text-[11px] font-mono uppercase text-secondary font-semibold">Audit Target</span>
                <h3 className="text-base font-bold text-primary font-mono mt-0.5">{analysis.pcap_filename}</h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-1 bg-[#FAFAF8] border border-border rounded text-[11px] font-mono text-secondary">
                  DEMO SOURCE: REAL PCAP
                </span>
                <span className="px-2 py-1 bg-green-50 border border-green-200 text-green-800 rounded text-[11px] font-mono font-bold">
                  EVALUATED ({analysis.evaluated_flows} FLOWS)
                </span>
              </div>
            </div>

            {/* Metric Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-3.5 bg-[#FAFAF8] border border-border rounded">
                <div className="text-[10px] font-mono uppercase text-secondary">Total Packets</div>
                <div className="text-xl font-bold text-primary mt-0.5">{analysis.total_packets.toLocaleString()}</div>
                <div className="text-[10px] text-secondary font-mono">Wire Level Capture</div>
              </div>

              <div className="p-3.5 bg-[#FAFAF8] border border-border rounded">
                <div className="text-[10px] font-mono uppercase text-secondary">Evaluated Flows</div>
                <div className="text-xl font-bold text-primary mt-0.5">{analysis.evaluated_flows.toLocaleString()}</div>
                <div className="text-[10px] text-secondary font-mono">Unidirectional 5-Tuples</div>
              </div>

              <div className="p-3.5 bg-[#FAFAF8] border border-border rounded">
                <div className="text-[10px] font-mono uppercase text-secondary">Benign Flows</div>
                <div className="text-xl font-bold text-status-healthy mt-0.5">{benign.toLocaleString()}</div>
                <div className="text-[10px] text-secondary font-mono">{total > 0 ? ((benign / total) * 100).toFixed(1) : 0}% of Total</div>
              </div>

              <div className="p-3.5 bg-[#FAFAF8] border border-border rounded">
                <div className="text-[10px] font-mono uppercase text-secondary">Verified Threats</div>
                <div className={`text-xl font-bold mt-0.5 ${threats > 0 ? 'text-red-600' : 'text-primary'}`}>
                  {threats.toLocaleString()}
                </div>
                <div className="text-[10px] text-secondary font-mono">Tier 1 Supervised Flags</div>
              </div>
            </div>

            {/* Threat Category Breakdown Table */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-primary uppercase font-mono tracking-wider">
                Threat Classification Breakdown
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 font-mono text-xs">
                <div className="p-3 border border-border rounded bg-white flex justify-between items-center">
                  <span className="text-secondary">BENIGN:</span>
                  <span className="font-bold text-status-healthy">{benign} flows</span>
                </div>
                <div className="p-3 border border-border rounded bg-white flex justify-between items-center">
                  <span className="text-secondary">C2_BEACONING:</span>
                  <span className="font-bold text-red-600">{c2} flows</span>
                </div>
                <div className="p-3 border border-border rounded bg-white flex justify-between items-center">
                  <span className="text-secondary">DDOS:</span>
                  <span className="font-bold text-amber-600">{ddos} flows</span>
                </div>
                <div className="p-3 border border-border rounded bg-white flex justify-between items-center">
                  <span className="text-secondary">RECON_SCAN:</span>
                  <span className="font-bold text-blue-600">{recon} flows</span>
                </div>
              </div>
            </div>

          </div>

          {/* Two-Tier Model Architecture & Anomaly Explanation */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Model Specifications */}
            <div className="bg-white border border-border rounded shadow-card p-5 space-y-3.5">
              <div className="flex items-center justify-between border-b border-border pb-2.5">
                <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
                  <Cpu className="w-4 h-4 text-primary" />
                  <span>Model Specifications</span>
                </div>
                <span className="text-[11px] font-mono text-secondary">Phase 3I Active</span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Tier 1 Classifier:</span>
                  <span className="font-bold text-primary">HistGradientBoostingClassifier</span>
                </div>
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Tier 2 Anomaly Detector:</span>
                  <span className="font-bold text-primary">Isolation Forest (100 Trees)</span>
                </div>
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Predictive Features:</span>
                  <span className="text-primary">27 Deterministic Flow Metrics</span>
                </div>
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Class Balancing:</span>
                  <span className="text-status-healthy font-semibold">Strict Stratified Sampling</span>
                </div>
              </div>

              <div className="p-2.5 bg-amber-50/70 border border-amber-200 rounded text-[11px] text-amber-900 leading-relaxed">
                <strong>EXFILTRATION Disclaimer:</strong> EXFILTRATION is evaluated via statistical volume/port heuristic analysis only. It is not an ML-supported classification in Phase 3I.
              </div>
            </div>

            {/* Anomaly & Timing Metrics */}
            <div className="bg-white border border-border rounded shadow-card p-5 space-y-3.5">
              <div className="flex items-center justify-between border-b border-border pb-2.5">
                <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
                  <Layers className="w-4 h-4 text-primary" />
                  <span>Multi-Stage Performance Profile</span>
                </div>
                <span className="text-[11px] font-mono text-secondary">Empirical Telemetry</span>
              </div>

              <div className="space-y-2 font-mono text-xs">
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">PCAP Parse Latency:</span>
                  <span className="font-bold text-primary">{analysis.timing_ms.parse_time_ms} ms</span>
                </div>
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Flow Aggregation Latency:</span>
                  <span className="font-bold text-primary">{analysis.timing_ms.aggregation_time_ms} ms</span>
                </div>
                <div className="flex justify-between p-2 bg-[#FAFAF8] rounded border border-border">
                  <span className="text-secondary">Batch Inference Latency:</span>
                  <span className="font-bold text-primary">{analysis.timing_ms.inference_time_ms} ms</span>
                </div>
                <div className="flex justify-between p-2 bg-primary/5 rounded border border-primary/20">
                  <span className="text-primary font-semibold">End-to-End Batch Throughput:</span>
                  <span className="font-bold text-primary">
                    {analysis.timing_ms.total_time_ms > 0
                      ? `${Math.round((total / analysis.timing_ms.total_time_ms) * 1000)} flows/sec`
                      : 'N/A'}
                  </span>
                </div>
              </div>

              <div className="p-2.5 bg-[#FAFAF8] border border-border rounded text-[11px] text-secondary leading-relaxed font-mono">
                <strong>Isolation Forest Boundary:</strong> Contamination=0.02 sets the training-time decision boundary on benign flows. Detected anomalies ({anomalies} flows, {total > 0 ? ((anomalies / total) * 100).toFixed(1) : 0}%) reflect genuine network distribution shift.
              </div>
            </div>

          </div>

          {/* Evidence Dossier Section */}
          {threatFlows.length > 0 && (
            <div className="bg-white border border-border rounded shadow-card p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
                  <Database className="w-4 h-4 text-primary" />
                  <span>Threat Evidence Dossier ({threatFlows.length} Incidents)</span>
                </div>
                <span className="text-[11px] font-mono text-secondary">
                  Cryptographic SHA-256 Telemetry Records
                </span>
              </div>

              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead className="bg-[#F4F4F2] text-secondary text-[11px] uppercase sticky top-0 border-b border-border">
                    <tr>
                      <th className="p-2.5">Flow ID</th>
                      <th className="p-2.5">Source → Destination</th>
                      <th className="p-2.5">Threat Class</th>
                      <th className="p-2.5">Severity</th>
                      <th className="p-2.5">Packets / Bytes</th>
                      <th className="p-2.5">Anomaly Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {threatFlows.slice(0, 10).map((f) => (
                      <tr key={f.flow_id} className="hover:bg-[#FAFAF8]">
                        <td className="p-2.5 text-secondary">{f.flow_id.slice(0, 10)}</td>
                        <td className="p-2.5 font-semibold text-primary">
                          {f.src_ip}:{f.src_port ?? 0} → {f.dst_ip}:{f.dst_port ?? 0}
                        </td>
                        <td className="p-2.5">
                          <span className="px-1.5 py-0.5 bg-red-100 text-red-800 rounded font-bold text-[10px]">
                            {f.predicted_class}
                          </span>
                        </td>
                        <td className="p-2.5 font-bold text-red-700">{f.severity}</td>
                        <td className="p-2.5 text-secondary">{f.packet_count} pkts • {f.byte_count.toLocaleString()} B</td>
                        <td className="p-2.5 text-amber-700">{f.anomaly_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>
      ) : (
        /* Standby Empty State */
        <div className="bg-white border border-border rounded shadow-card p-12 text-center space-y-4">
          <div className="w-12 h-12 rounded bg-[#F4F4F2] border border-border text-secondary mx-auto flex items-center justify-center">
            <FileText className="w-6 h-6 text-primary stroke-[1.5]" />
          </div>
          <div className="max-w-md mx-auto space-y-1.5">
            <h3 className="font-semibold text-sm text-primary">No Analysis Loaded</h3>
            <p className="text-xs text-secondary leading-relaxed">
              Select an authentic network capture from below or navigate to Live Traffic to execute the Phase 3I pipeline and generate a comprehensive security report.
            </p>
          </div>

          <div className="pt-3 flex items-center justify-center gap-3 flex-wrap">
            {samples.slice(0, 2).map((s) => (
              <button
                key={s.filename}
                disabled={isLoading}
                onClick={async () => {
                  await runSampleAnalysis(s.filename);
                }}
                className="px-3.5 py-2 bg-[#FAFAF8] hover:bg-[#F4F4F2] border border-border rounded text-xs font-mono font-semibold text-primary flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-subtle"
              >
                <Play className="w-3.5 h-3.5 text-primary" />
                <span>Analyze {s.filename.includes('95') ? 'Ares Botnet' : 'LOIC DDoS'}</span>
              </button>
            ))}
            {onNavigate && (
              <button
                onClick={() => onNavigate('live-traffic')}
                className="px-3.5 py-2 bg-primary hover:bg-primary-hover text-white rounded text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 transition-colors shadow-subtle"
              >
                <span>Go to Live Traffic →</span>
              </button>
            )}
          </div>
        </div>
      )}

    </div>
  );
};

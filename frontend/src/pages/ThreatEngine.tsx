import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, Zap } from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';

export const ThreatEngine: React.FC = () => {
  const { analysis } = useTraffic();

  const threatFlows = analysis ? analysis.flows.filter((f) => f.is_threat) : [];
  const anomalyFlows = analysis ? analysis.flows.filter((f) => f.is_anomaly && !f.is_threat) : [];

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Passive Threat Detection Engine
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            AI Threat Classification Queue
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Two-Tier Machine Learning Threat Detection (HistGradientBoosting 4-Class Classifier + Isolation Forest Outlier Detection).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 bg-white border border-border rounded text-xs font-mono text-secondary">
            ACTIVE MODEL: PHASE 3I TRUE 4-CLASS
          </div>
        </div>
      </div>

      {/* Threat Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        <div className="bg-white border border-border p-4 rounded shadow-card">
          <div className="flex items-center justify-between text-secondary mb-1">
            <span className="text-xs font-semibold uppercase">Total Verified Threats</span>
            <ShieldAlert className="w-4 h-4 text-red-600" />
          </div>
          <div className="text-2xl font-bold text-red-600">{threatFlows.length}</div>
          <div className="text-[11px] font-mono text-secondary mt-0.5">Tier 1 Attack Detections</div>
        </div>

        <div className="bg-white border border-border p-4 rounded shadow-card">
          <div className="flex items-center justify-between text-secondary mb-1">
            <span className="text-xs font-semibold uppercase">C2 Beaconing</span>
            <span className="px-1.5 py-0.5 bg-red-100 text-red-800 text-[10px] font-bold rounded">CRITICAL</span>
          </div>
          <div className="text-2xl font-bold text-primary">
            {analysis?.threat_breakdown.C2_BEACONING ?? 0}
          </div>
          <div className="text-[11px] font-mono text-secondary mt-0.5">Botnet Rhythmic Channels</div>
        </div>

        <div className="bg-white border border-border p-4 rounded shadow-card">
          <div className="flex items-center justify-between text-secondary mb-1">
            <span className="text-xs font-semibold uppercase">DDoS / DoS Floods</span>
            <span className="px-1.5 py-0.5 bg-amber-100 text-amber-800 text-[10px] font-bold rounded">HIGH</span>
          </div>
          <div className="text-2xl font-bold text-primary">
            {analysis?.threat_breakdown.DDOS ?? 0}
          </div>
          <div className="text-[11px] font-mono text-secondary mt-0.5">Volumetric Floods</div>
        </div>

        <div className="bg-white border border-border p-4 rounded shadow-card">
          <div className="flex items-center justify-between text-secondary mb-1">
            <span className="text-xs font-semibold uppercase">Recon Scans</span>
            <span className="px-1.5 py-0.5 bg-blue-100 text-blue-800 text-[10px] font-bold rounded">MEDIUM</span>
          </div>
          <div className="text-2xl font-bold text-primary">
            {analysis?.threat_breakdown.RECON_SCAN ?? 0}
          </div>
          <div className="text-[11px] font-mono text-secondary mt-0.5">Port / Host Sweeps</div>
        </div>

      </div>

      {/* Threat Incident Queue Table */}
      {threatFlows.length > 0 ? (
        <div className="bg-white border border-border rounded shadow-card overflow-hidden">
          <div className="p-4 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-primary">
              <AlertTriangle className="w-4 h-4 text-red-600" />
              <span>ACTIVE THREAT INCIDENT QUEUE ({threatFlows.length} INCIDENTS)</span>
            </div>
            <span className="text-[11px] font-mono text-secondary">
              Class-Balanced Real ML Model Output
            </span>
          </div>

          <div className="overflow-x-auto max-h-[500px]">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead className="bg-[#F4F4F2] text-secondary text-[11px] uppercase tracking-wider sticky top-0 border-b border-border">
                <tr>
                  <th className="p-3">Incident Flow</th>
                  <th className="p-3">Threat Category</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Source IP:Port</th>
                  <th className="p-3">Target IP:Port</th>
                  <th className="p-3">Proto</th>
                  <th className="p-3">Pkts</th>
                  <th className="p-3">Bytes</th>
                  <th className="p-3">Anomaly Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {threatFlows.map((flow) => (
                  <tr key={flow.flow_id} className="hover:bg-red-50/40 transition-colors bg-red-50/20">
                    <td className="p-3 font-semibold text-primary">{flow.flow_id.slice(0, 12)}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 bg-red-100 text-red-800 border border-red-200 rounded text-[11px] font-bold">
                        {flow.predicted_class}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        flow.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                        flow.severity === 'HIGH' ? 'bg-amber-600 text-white' :
                        'bg-blue-600 text-white'
                      }`}>
                        {flow.severity}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-red-700">{flow.src_ip}:{flow.src_port ?? 0}</td>
                    <td className="p-3 text-secondary">{flow.dst_ip}:{flow.dst_port ?? 0}</td>
                    <td className="p-3">{flow.protocol}</td>
                    <td className="p-3">{flow.packet_count}</td>
                    <td className="p-3">{flow.byte_count.toLocaleString()} B</td>
                    <td className="p-3 text-amber-700 font-bold">{flow.anomaly_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="bg-white border border-border rounded shadow-card p-12 text-center space-y-3">
          <div className="w-12 h-12 rounded bg-[#F4F4F2] border border-border text-secondary mx-auto flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-status-healthy stroke-[1.5]" />
          </div>
          <h3 className="font-semibold text-sm text-primary">No Verified Threats Detected</h3>
          <p className="text-xs text-secondary max-w-md mx-auto leading-relaxed">
            {analysis 
              ? `The evaluated capture (${analysis.pcap_filename}) contains ${analysis.benign_flows} benign flows and zero classified threat patterns.`
              : 'Analyze an authentic network capture in Live Traffic to evaluate live threat detections through the Phase 3I pipeline.'}
          </p>
          <div className="pt-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-[#FAFAF8] border border-border rounded text-[11px] font-mono text-secondary">
              <Zap className="w-3 h-3 text-status-healthy" />
              Zero Hardcoded Fake Detections
            </span>
          </div>
        </div>
      )}

      {/* Tier 2 Isolation Forest Anomalies (if any) */}
      {anomalyFlows.length > 0 && (
        <div className="bg-white border border-border rounded shadow-card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <h4 className="font-semibold text-xs text-primary uppercase">
              Tier 2 Isolation Forest Unsupervised Outliers ({anomalyFlows.length})
            </h4>
            <span className="text-[11px] font-mono text-secondary">Zero-Day Outlier Surveillance</span>
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            These flows were classified as normal traffic in Tier 1 supervised models but flagged as unusual statistical outliers by Tier 2 Isolation Forest.
          </p>
        </div>
      )}

    </div>
  );
};

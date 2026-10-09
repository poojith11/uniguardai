import React from 'react';
import { BarChart3, Cpu, Activity } from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';

export const Analytics: React.FC = () => {
  const { analysis } = useTraffic();

  const total = analysis?.evaluated_flows || 0;
  const benign = analysis?.benign_flows || 0;
  const threats = analysis?.threat_flows || 0;
  const anomalies = analysis?.anomaly_flows || 0;

  const c2 = analysis?.threat_breakdown.C2_BEACONING || 0;
  const ddos = analysis?.threat_breakdown.DDOS || 0;
  const recon = analysis?.threat_breakdown.RECON_SCAN || 0;

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Telemetry Analytics & Empirical Trends
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            Traffic Analytics Dashboard
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Aggregated unidirectional flow telemetry, threat distribution ratios, and processing latency profiles.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 bg-white border border-border rounded text-xs font-mono text-secondary">
            DATA SOURCE: {analysis ? analysis.pcap_filename : 'STANDBY'}
          </div>
        </div>
      </div>

      {analysis ? (
        <div className="space-y-6">
          
          {/* Top Analytics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white border border-border p-5 rounded shadow-card">
              <div className="text-xs font-mono text-secondary uppercase">Evaluated Flows</div>
              <div className="text-2xl font-bold text-primary mt-1">{total.toLocaleString()}</div>
              <div className="text-[11px] text-secondary mt-0.5">100% Deterministic Extraction</div>
            </div>

            <div className="bg-white border border-border p-5 rounded shadow-card">
              <div className="text-xs font-mono text-secondary uppercase">Benign Ratio</div>
              <div className="text-2xl font-bold text-status-healthy mt-1">
                {total > 0 ? `${((benign / total) * 100).toFixed(1)}%` : '0%'}
              </div>
              <div className="text-[11px] text-secondary mt-0.5">{benign} Normal Flows</div>
            </div>

            <div className="bg-white border border-border p-5 rounded shadow-card">
              <div className="text-xs font-mono text-secondary uppercase">Threat Ratio</div>
              <div className={`text-2xl font-bold mt-1 ${threats > 0 ? 'text-red-600' : 'text-primary'}`}>
                {total > 0 ? `${((threats / total) * 100).toFixed(1)}%` : '0%'}
              </div>
              <div className="text-[11px] text-secondary mt-0.5">{threats} Classified Threats</div>
            </div>

            <div className="bg-white border border-border p-5 rounded shadow-card">
              <div className="text-xs font-mono text-secondary uppercase">Anomaly Outliers</div>
              <div className="text-2xl font-bold text-amber-600 mt-1">
                {total > 0 ? `${((anomalies / total) * 100).toFixed(1)}%` : '0%'}
              </div>
              <div className="text-[11px] text-secondary mt-0.5">{anomalies} Isolation Forest Flags</div>
            </div>
          </div>

          {/* Graphical Distributions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Threat Breakdown */}
            <div className="bg-white border border-border p-6 rounded shadow-card space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
                  <BarChart3 className="w-4 h-4 text-primary" />
                  <span>Threat Category Breakdown</span>
                </div>
                <span className="text-[11px] font-mono text-secondary">Tier 1 Multi-Class Classifier</span>
              </div>

              <div className="space-y-3 pt-2">
                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-primary">C2_BEACONING (Botnet Channels)</span>
                    <span className="font-bold text-red-600">{c2} flows</span>
                  </div>
                  <div className="w-full bg-[#F4F4F2] h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-red-600 h-full rounded-full"
                      style={{ width: `${total > 0 ? (c2 / total) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-primary">DDOS (Volumetric Floods)</span>
                    <span className="font-bold text-amber-600">{ddos} flows</span>
                  </div>
                  <div className="w-full bg-[#F4F4F2] h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-amber-600 h-full rounded-full"
                      style={{ width: `${total > 0 ? (ddos / total) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-primary">RECON_SCAN (Port Sweeps)</span>
                    <span className="font-bold text-blue-600">{recon} flows</span>
                  </div>
                  <div className="w-full bg-[#F4F4F2] h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-blue-600 h-full rounded-full"
                      style={{ width: `${total > 0 ? (recon / total) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-primary">BENIGN (Safe Traffic)</span>
                    <span className="font-bold text-status-healthy">{benign} flows</span>
                  </div>
                  <div className="w-full bg-[#F4F4F2] h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-status-healthy h-full rounded-full"
                      style={{ width: `${total > 0 ? (benign / total) * 100 : 0}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            </div>

            {/* Execution Latency Profile */}
            <div className="bg-white border border-border p-6 rounded shadow-card space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div className="flex items-center gap-2 font-semibold text-xs text-primary uppercase">
                  <Cpu className="w-4 h-4 text-primary" />
                  <span>Pipeline Latency Breakdown</span>
                </div>
                <span className="text-[11px] font-mono text-secondary">
                  Total: {analysis.timing_ms.total_time_ms} ms
                </span>
              </div>

              <div className="space-y-3 pt-2 text-xs font-mono">
                <div className="p-3 bg-[#FAFAF8] border border-border rounded flex items-center justify-between">
                  <span className="text-secondary">Raw Packet Parser:</span>
                  <span className="font-bold text-primary">{analysis.timing_ms.parse_time_ms} ms</span>
                </div>

                <div className="p-3 bg-[#FAFAF8] border border-border rounded flex items-center justify-between">
                  <span className="text-secondary">Unidirectional Flow Aggregation:</span>
                  <span className="font-bold text-primary">{analysis.timing_ms.aggregation_time_ms} ms</span>
                </div>

                <div className="p-3 bg-[#FAFAF8] border border-border rounded flex items-center justify-between">
                  <span className="text-secondary">Phase 3I 4-Class ML Inference:</span>
                  <span className="font-bold text-status-healthy">{analysis.timing_ms.inference_time_ms} ms</span>
                </div>

                <div className="p-3 bg-primary/5 border border-primary/20 rounded flex items-center justify-between">
                  <span className="text-primary font-semibold">End-to-End Analysis Throughput:</span>
                  <span className="font-bold text-primary">
                    {analysis.timing_ms.total_time_ms > 0
                      ? `${Math.round((total / analysis.timing_ms.total_time_ms) * 1000)} flows/sec`
                      : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

          </div>

        </div>
      ) : (
        <div className="bg-white border border-border rounded shadow-card p-12 text-center space-y-3">
          <div className="w-12 h-12 rounded bg-[#F4F4F2] border border-border text-secondary mx-auto flex items-center justify-center">
            <Activity className="w-6 h-6 text-primary stroke-[1.5]" />
          </div>
          <h3 className="font-semibold text-sm text-primary">Analytics Engine Ready</h3>
          <p className="text-xs text-secondary max-w-md mx-auto leading-relaxed">
            Telemetry analytics and distribution graphs will populate when network captures are evaluated through Live Traffic.
          </p>
        </div>
      )}

    </div>
  );
};

import React, { useRef, useState } from 'react';
import { Activity, Radio, Upload, Play, RefreshCw, AlertTriangle, ShieldCheck, Zap } from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';

export const LiveTraffic: React.FC = () => {
  const { analysis, samples, isLoading, error, runSampleAnalysis, runUploadAnalysis, clearAnalysis } = useTraffic();
  const [selectedSample, setSelectedSample] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      runUploadAnalysis(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Live Ingress Telemetry & ML Inference
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            Unidirectional Traffic Monitor
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Real-time passive packet flow stream evaluated through 27-feature extraction and Phase 3I ML inference engine.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-border rounded text-xs text-secondary font-mono">
            <Radio className="w-3.5 h-3.5 text-status-healthy" />
            <span>DIODE: PASSIVE RX ONLY</span>
          </div>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept=".pcap,.pcapng,.cap"
            className="hidden"
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary hover:bg-primary-hover text-white rounded text-xs font-semibold uppercase tracking-wider transition-colors disabled:opacity-50"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload PCAP</span>
          </button>
        </div>
      </div>

      {/* Control Bar: Sample PCAP Selector */}
      <div className="bg-white border border-border p-4 rounded shadow-card flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3 w-full md:w-auto">
          <span className="text-xs font-semibold text-primary uppercase whitespace-nowrap">Sample Capture:</span>
          <select
            value={selectedSample}
            onChange={(e) => setSelectedSample(e.target.value)}
            className="text-xs font-mono bg-[#FAFAF8] border border-border rounded px-3 py-1.5 text-primary flex-1 md:w-80 outline-none focus:border-primary"
          >
            <option value="">-- Select Authentic PCAP Capture --</option>
            {samples.map((s) => (
              <option key={s.filename} value={s.filename}>
                {s.filename} ({s.size_mb} MB)
              </option>
            ))}
          </select>
          <button
            disabled={!selectedSample || isLoading}
            onClick={() => selectedSample && runSampleAnalysis(selectedSample)}
            className="px-3.5 py-1.5 bg-[#FAFAF8] hover:bg-[#F4F4F2] border border-border rounded text-xs font-semibold text-primary flex items-center gap-1.5 transition-colors disabled:opacity-40"
          >
            <Play className="w-3.5 h-3.5 text-primary" />
            <span>Analyze</span>
          </button>
        </div>

        {analysis && (
          <div className="flex items-center gap-3 text-xs font-mono text-secondary">
            <span>File: <strong className="text-primary">{analysis.pcap_filename}</strong></span>
            <span>•</span>
            <span>Timing: <strong className="text-primary">{analysis.timing_ms.total_time_ms} ms</strong></span>
            <button
              onClick={clearAnalysis}
              className="text-xs text-red-600 hover:underline font-sans ml-2"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 bg-red-50 border border-red-200 text-red-700 text-xs rounded flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading Spinner */}
      {isLoading && (
        <div className="bg-white border border-border rounded p-12 text-center space-y-3 shadow-card">
          <RefreshCw className="w-8 h-8 animate-spin text-primary mx-auto" />
          <div className="text-sm font-semibold text-primary">Executing Phase 2 Feature Extraction & Phase 3I ML Inference...</div>
          <div className="text-xs text-secondary font-mono">Parsing raw packets → Aggregating 5-tuple flows → 27 features → 4-Class Classifier + Isolation Forest</div>
        </div>
      )}

      {/* Real Ingress Telemetry Results */}
      {!isLoading && analysis && (
        <div className="space-y-6">
          
          {/* Telemetry Metric Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-white border border-border p-4 rounded shadow-card">
              <div className="text-[11px] font-mono uppercase text-secondary">Total Packets</div>
              <div className="text-2xl font-bold text-primary mt-1">{analysis.total_packets.toLocaleString()}</div>
              <div className="text-[10px] text-secondary font-mono mt-0.5">Wire Capture Count</div>
            </div>

            <div className="bg-white border border-border p-4 rounded shadow-card">
              <div className="text-[11px] font-mono uppercase text-secondary">Evaluated Flows</div>
              <div className="text-2xl font-bold text-primary mt-1">{analysis.evaluated_flows.toLocaleString()}</div>
              <div className="text-[10px] text-secondary font-mono mt-0.5">Unidirectional 5-Tuples</div>
            </div>

            <div className="bg-white border border-border p-4 rounded shadow-card">
              <div className="text-[11px] font-mono uppercase text-secondary">Benign Traffic</div>
              <div className="text-2xl font-bold text-status-healthy mt-1">{analysis.benign_flows.toLocaleString()}</div>
              <div className="text-[10px] text-secondary font-mono mt-0.5">Safe Enterprise Flows</div>
            </div>

            <div className="bg-white border border-border p-4 rounded shadow-card">
              <div className="text-[11px] font-mono uppercase text-secondary">Threat Detections</div>
              <div className={`text-2xl font-bold mt-1 ${analysis.threat_flows > 0 ? 'text-red-600' : 'text-primary'}`}>
                {analysis.threat_flows.toLocaleString()}
              </div>
              <div className="text-[10px] text-secondary font-mono mt-0.5">Tier 1 Supervised Flags</div>
            </div>

            <div className="bg-white border border-border p-4 rounded shadow-card">
              <div className="text-[11px] font-mono uppercase text-secondary">Anomaly Outliers</div>
              <div className="text-2xl font-bold text-amber-600 mt-1">{analysis.anomaly_flows.toLocaleString()}</div>
              <div className="text-[10px] text-secondary font-mono mt-0.5">Tier 2 Isolation Forest</div>
            </div>
          </div>

          {/* Real Flow Table */}
          <div className="bg-white border border-border rounded shadow-card overflow-hidden">
            <div className="p-4 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold text-primary">
                <Activity className="w-4 h-4 text-primary" />
                <span>EVALUATED UNIDIRECTIONAL IP FLOWS ({analysis.evaluated_flows})</span>
              </div>
              <span className="text-[11px] font-mono text-secondary">
                Batch Inference: {analysis.timing_ms.inference_time_ms} ms ({analysis.evaluated_flows > 0 ? (analysis.timing_ms.inference_time_ms / analysis.evaluated_flows).toFixed(1) : 0} ms/flow) • Parse: {analysis.timing_ms.parse_time_ms} ms
              </span>
            </div>

            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead className="bg-[#F4F4F2] text-secondary text-[11px] uppercase tracking-wider sticky top-0 border-b border-border">
                  <tr>
                    <th className="p-3">Flow ID</th>
                    <th className="p-3">Source IP:Port</th>
                    <th className="p-3">Destination IP:Port</th>
                    <th className="p-3">Proto</th>
                    <th className="p-3">Pkts</th>
                    <th className="p-3">Bytes</th>
                    <th className="p-3">Duration</th>
                    <th className="p-3">ML Classification</th>
                    <th className="p-3">Anomaly Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {analysis.flows.map((flow) => {
                    const isThreat = flow.is_threat;
                    return (
                      <tr
                        key={flow.flow_id}
                        className={`hover:bg-[#FAFAF8] transition-colors ${
                          isThreat ? 'bg-red-50/40' : flow.is_anomaly ? 'bg-amber-50/30' : ''
                        }`}
                      >
                        <td className="p-3 text-secondary">{flow.flow_id.slice(0, 12)}</td>
                        <td className="p-3 font-semibold text-primary">
                          {flow.src_ip}:{flow.src_port ?? 0}
                        </td>
                        <td className="p-3 text-secondary">
                          {flow.dst_ip}:{flow.dst_port ?? 0}
                        </td>
                        <td className="p-3">
                          <span className="px-1.5 py-0.5 bg-[#F4F4F2] border border-border rounded text-[10px]">
                            {flow.protocol}
                          </span>
                        </td>
                        <td className="p-3">{flow.packet_count}</td>
                        <td className="p-3">{flow.byte_count.toLocaleString()} B</td>
                        <td className="p-3">{flow.duration_seconds}s</td>
                        <td className="p-3">
                          {isThreat ? (
                            <span className="px-2 py-0.5 bg-red-100 text-red-800 border border-red-200 rounded text-[11px] font-semibold">
                              {flow.predicted_class}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 bg-green-100 text-green-800 border border-green-200 rounded text-[11px] font-semibold">
                              BENIGN
                            </span>
                          )}
                        </td>
                        <td className="p-3">
                          <span className={`text-[11px] ${flow.anomaly_score < 0 ? 'text-amber-700 font-bold' : 'text-secondary'}`}>
                            {flow.anomaly_score} {flow.is_anomaly ? '(Anomaly)' : ''}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* Honest Standby Empty State */}
      {!isLoading && !analysis && (
        <div className="bg-white border border-border rounded shadow-card overflow-hidden">
          <div className="p-4 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-primary">
              <Activity className="w-4 h-4 text-primary" />
              <span>PASSIVE INGRESS PACKET BUFFER</span>
            </div>
            <span className="text-[11px] font-mono text-secondary">
              Phase 3I Engine Ready • Zero Synthetic Mocks
            </span>
          </div>

          <div className="p-12 text-center space-y-4">
            <div className="w-12 h-12 rounded bg-[#F4F4F2] border border-border text-secondary mx-auto flex items-center justify-center">
              <ShieldCheck className="w-6 h-6 text-status-healthy stroke-[1.5]" />
            </div>
            <div className="max-w-md mx-auto space-y-1">
              <h3 className="font-semibold text-sm text-primary">Passive Ingestion Ready</h3>
              <p className="text-xs text-secondary leading-relaxed">
                Select one of the authentic sample PCAPs above or upload a raw network capture (.pcap / .pcapng) to extract 27 canonical features and execute Phase 3I multi-class ML inference.
              </p>
            </div>
            <div className="pt-2 flex items-center justify-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-[#FAFAF8] border border-border rounded text-[11px] font-mono text-secondary">
                <Zap className="w-3 h-3 text-status-healthy" />
                Zero Synthetic Mocks Enabled
              </span>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

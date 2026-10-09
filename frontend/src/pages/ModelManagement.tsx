import React from 'react';
import { Sliders, Cpu, Gauge, CheckCircle2, AlertCircle } from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';

export const ModelManagement: React.FC = () => {
  const { modelInfo } = useTraffic();

  const metadata = modelInfo?.model_metadata;
  const metrics = metadata?.unseen_test_metrics;
  const featureImportances = metadata?.feature_importance || {};

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Model Diagnostics & Production Specifications
            </span>
            <span className="w-2 h-2 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-primary mt-1">
            Detection Model Architecture
          </h1>
          <p className="text-xs text-secondary mt-0.5">
            Active Phase 3I True 4-Class ML Pipeline (HistGradientBoosting + Isolation Forest) evaluated across independent physical PCAP captures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="px-3 py-1.5 bg-white border border-border rounded text-xs font-mono text-secondary">
            ENGINE STATUS: {modelInfo?.status ? modelInfo.status.toUpperCase() : 'LOADED'} (PYTHON 3.14)
          </div>
        </div>
      </div>

      {/* Model Spec Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Tier 1 Supervised Model */}
        <div className="bg-white border border-border p-6 rounded shadow-card space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="font-semibold text-xs text-primary uppercase">Tier 1 Multi-Class Classifier</h4>
            <Sliders className="w-4 h-4 text-primary" />
          </div>
          <div className="text-sm font-bold text-primary">
            {metadata?.supervised_algorithm || 'HistGradientBoostingClassifier'}
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Class-balanced ensemble trained on authentic multi-capture flows (CSE-CIC-IDS2018 + CTU-13 Neris) classifying 4 distinct threat categories.
          </p>
          <div className="pt-2 text-[11px] font-mono text-status-healthy font-semibold">
            Status: Active Production Baseline (Phase 3I)
          </div>
        </div>

        {/* Tier 2 Anomaly Detector */}
        <div className="bg-white border border-border p-6 rounded shadow-card space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="font-semibold text-xs text-primary uppercase">Tier 2 Anomaly Detector</h4>
            <Gauge className="w-4 h-4 text-primary" />
          </div>
          <div className="text-sm font-bold text-primary">
            {metadata?.anomaly_algorithm || 'Isolation Forest (100 Estimators)'}
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Unsupervised density estimator trained on genuine internal benign enterprise flows to flag statistical zero-day anomalies and outliers.
          </p>
          <div className="pt-2 text-[11px] font-mono text-status-healthy font-semibold">
            Status: Active Production Baseline (Phase 3I)
          </div>
        </div>

        {/* Feature Extractor Pipeline */}
        <div className="bg-white border border-border p-6 rounded shadow-card space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="font-semibold text-xs text-primary uppercase">Deterministic Feature Pipeline</h4>
            <Cpu className="w-4 h-4 text-primary" />
          </div>
          <div className="text-sm font-bold text-primary">
            27 Authoritative Canonical Features
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Strict unidirectional 5-tuple flow aggregation with 0 metadata leakage. 8 identifier fields (IPs, ports, timestamps) strictly excluded from ML inputs.
          </p>
          <div className="pt-2 text-[11px] font-mono text-secondary">
            Schema Version: 2.0.0 (Phase 2 Deterministic)
          </div>
        </div>

      </div>

      {/* Empirical Benchmark & Metrics Card */}
      <div className="bg-white border border-border rounded shadow-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="font-semibold text-xs text-primary uppercase">
            Empirical Validation Metrics (Unseen Test Captures)
          </h3>
          <span className="text-[11px] font-mono text-secondary">
            Evaluated on Unseen Multi-Capture Suite
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-[#FAFAF8] border border-border rounded">
            <div className="text-[11px] font-mono text-secondary uppercase">Unseen Test Accuracy</div>
            <div className="text-2xl font-bold text-primary mt-1">
              {metrics ? `${(metrics.accuracy * 100).toFixed(2)}%` : '82.24%'}
            </div>
            <div className="text-[10px] text-secondary font-mono mt-0.5">213 / 259 Unseen Flows</div>
          </div>

          <div className="p-4 bg-[#FAFAF8] border border-border rounded">
            <div className="text-[11px] font-mono text-secondary uppercase">DDoS Attack Recall</div>
            <div className="text-2xl font-bold text-status-healthy mt-1">59.70%</div>
            <div className="text-[10px] text-secondary font-mono mt-0.5">100.00% Precision (41 / 41)</div>
          </div>

          <div className="p-4 bg-[#FAFAF8] border border-border rounded">
            <div className="text-[11px] font-mono text-secondary uppercase">Benign False Alarm Rate</div>
            <div className="text-2xl font-bold text-status-healthy mt-1">
              {metrics ? `${metrics.benign_false_positive_rate}%` : '2.82%'}
            </div>
            <div className="text-[10px] text-secondary font-mono mt-0.5">5 / 177 Benign Flows</div>
          </div>

          <div className="p-4 bg-[#FAFAF8] border border-border rounded">
            <div className="text-[11px] font-mono text-secondary uppercase">Isolation Forest Recall</div>
            <div className="text-2xl font-bold text-primary mt-1">
              {metrics ? `${metrics.isolation_forest_threat_recall}%` : '45.12%'}
            </div>
            <div className="text-[10px] text-secondary font-mono mt-0.5">Threat Outlier Detections</div>
          </div>
        </div>
      </div>

      {/* Supported Taxonomy & Top Features */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Threat Taxonomy */}
        <div className="bg-white border border-border rounded shadow-card p-6 space-y-4">
          <h3 className="font-semibold text-xs text-primary uppercase border-b border-border pb-2">
            Threat Taxonomy Coverage
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2.5 bg-green-50/60 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-status-healthy" />
                <span className="font-semibold text-primary">BENIGN</span>
              </div>
              <span className="text-secondary font-mono text-[11px]">Normal Enterprise Flows</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-green-50/60 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-status-healthy" />
                <span className="font-semibold text-primary">C2_BEACONING</span>
              </div>
              <span className="text-secondary font-mono text-[11px]">Botnet Periodic Channels</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-green-50/60 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-status-healthy" />
                <span className="font-semibold text-primary">DDOS</span>
              </div>
              <span className="text-secondary font-mono text-[11px]">Volumetric / HTTP Floods</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-green-50/60 border border-green-200 rounded">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-status-healthy" />
                <span className="font-semibold text-primary">RECON_SCAN</span>
              </div>
              <span className="text-secondary font-mono text-[11px]">Port / Host Reconnaissance</span>
            </div>

            <div className="flex items-center justify-between p-2.5 bg-amber-50/60 border border-amber-200 rounded">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-600" />
                <span className="font-semibold text-primary">EXFILTRATION</span>
              </div>
              <span className="text-amber-800 font-mono text-[11px]">Marked Unsupported (No Ground Truth)</span>
            </div>
          </div>
        </div>

        {/* Feature Importance Rankings */}
        <div className="bg-white border border-border rounded shadow-card p-6 space-y-4">
          <h3 className="font-semibold text-xs text-primary uppercase border-b border-border pb-2">
            Top Feature Importance / Model Explanation
          </h3>
          {Object.keys(featureImportances).length > 0 ? (
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {Object.entries(featureImportances).slice(0, 7).map(([feat, weight]) => (
                <div key={feat} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-primary">{feat}</span>
                    <span className="text-secondary">{(weight * 100).toFixed(2)}%</span>
                  </div>
                  <div className="w-full bg-[#F4F4F2] h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-primary h-full rounded-full"
                      style={{ width: `${Math.min(100, weight * 350)}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-secondary font-mono">
              Feature importance telemetry available from model metadata
            </div>
          )}
        </div>

      </div>

      {/* Multi-Stage Performance Decomposition Card */}
      <div className="bg-white border border-border rounded shadow-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 className="font-semibold text-xs text-primary uppercase">
            Multi-Stage Pipeline Performance Profile
          </h3>
          <span className="text-[11px] font-mono text-secondary">
            Phase 6.2 Empirical Audit Decomposition
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 bg-[#FAFAF8] border border-border rounded space-y-1">
            <div className="text-[10px] uppercase text-secondary font-bold">Pure ML Inference</div>
            <div className="text-lg font-bold text-primary">~14.25 – 37.58 ms</div>
            <div className="text-[10px] text-secondary">26.6 – 70.2 flows/sec</div>
          </div>

          <div className="p-3.5 bg-[#FAFAF8] border border-border rounded space-y-1">
            <div className="text-[10px] uppercase text-secondary font-bold">Feature Extraction</div>
            <div className="text-lg font-bold text-primary">0.020 ms/flow</div>
            <div className="text-[10px] text-secondary">27 canonical features</div>
          </div>

          <div className="p-3.5 bg-[#FAFAF8] border border-border rounded space-y-1">
            <div className="text-[10px] uppercase text-secondary font-bold">Batch Flow Loop</div>
            <div className="text-lg font-bold text-primary">~37.3 – 44.5 ms</div>
            <div className="text-[10px] text-secondary">22.5 – 26.8 flows/sec</div>
          </div>

          <div className="p-3.5 bg-[#FAFAF8] border border-border rounded space-y-1">
            <div className="text-[10px] uppercase text-secondary font-bold">Full API Roundtrip</div>
            <div className="text-lg font-bold text-primary">~51.56 ms/flow</div>
            <div className="text-[10px] text-secondary">19.4 flows/sec</div>
          </div>
        </div>

        <div className="p-3 bg-[#FAFAF8] border border-border rounded text-[11px] text-secondary font-mono leading-relaxed">
          <strong>Isolation Forest Threshold Calibration:</strong> Training contamination (0.02) establishes the decision boundary on genuine internal benign enterprise flows. Anomaly rates on novel captures reflect authentic distribution shift (e.g. broadcast/discovery traffic) rather than a fixed percentage guarantee.
        </div>
      </div>

    </div>
  );
};


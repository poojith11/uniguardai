import React, { useEffect, useState } from 'react';
import { UnidirectionalDiodeFlow } from '../components/UnidirectionalDiodeFlow';
import { 
  ShieldCheck, Cpu, Database, Network, Play, Upload,
  Radio, Activity, Brain,
  EyeOff, ArrowRightCircle, Radar, Hash
} from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';
import { getApiUrl } from '../lib/api';

interface OverviewProps {
  onNavigate: (tab: 'live-traffic' | 'threats' | 'evidence') => void;
}

export const Overview: React.FC<OverviewProps> = ({ onNavigate }) => {
  const { analysis, samples, runSampleAnalysis, isLoading } = useTraffic();
  const [apiOnline, setApiOnline] = useState<boolean>(true);

  useEffect(() => {
    fetch(getApiUrl('/api/health'))
      .then((r) => setApiOnline(r.ok))
      .catch(() => setApiOnline(false));
  }, []);


  return (
    <div className="space-y-10 max-w-[1600px] mx-auto px-6 py-8">
      
      {/* Hero Section */}
      <section className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-2 border-b border-border">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[11px] font-mono uppercase tracking-widest text-secondary font-semibold">
              Passive Threat Intelligence Hub
            </span>
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-status-healthy"></span>
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-primary">
            Unidirectional Cyber Threat Telemetry
          </h1>
          <p className="text-sm text-secondary max-w-2xl mt-1 leading-relaxed">
            Continuous passive packet flow inspection at line rate. Unidirectional data-diode ingestion guarantees zero active probing footprint and impenetrable isolation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button 
            onClick={() => onNavigate('live-traffic')}
            className="px-4 py-2 bg-primary hover:bg-primary-hover text-white text-xs font-semibold uppercase tracking-wider rounded transition-colors flex items-center gap-1.5"
          >
            <Network className="w-3.5 h-3.5" />
            <span>Inspect Live Flow</span>
          </button>
          <button 
            onClick={() => onNavigate('threats')}
            className="px-4 py-2 bg-white hover:bg-[#F4F4F2] border border-border text-primary text-xs font-semibold uppercase tracking-wider rounded transition-colors"
          >
            Threat Queue {analysis && analysis.threat_flows > 0 ? `(${analysis.threat_flows})` : ''}
          </button>
        </div>
      </section>

      {/* Unidirectional Hardware Data Diode Architecture Visualization */}
      <section className="space-y-2">
        <div className="flex items-center justify-between text-xs text-secondary px-1">
          <span className="font-mono uppercase font-semibold text-[11px]">Unidirectional Physical Optical Diode Link</span>
          <span className="font-mono text-[11px]">Packet RX: 100% | TX: 0% (Hardware Constrained)</span>
        </div>
        <UnidirectionalDiodeFlow />
      </section>

      {/* Quick PCAP Evaluation Action Bar */}
      <section className="bg-white border border-border p-4 rounded shadow-card flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-[#F4F4F2] flex items-center justify-center text-primary font-mono text-xs font-bold">
            ML
          </div>
          <div>
            <div className="text-xs font-bold text-primary">Evaluate Authentic PCAP Traffic</div>
            <div className="text-[11px] text-secondary">
              Stream authentic network captures through Phase 2 feature extraction and Phase 3I ML inference
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {samples.slice(0, 2).map((s) => (
            <button
              key={s.filename}
              disabled={isLoading}
              onClick={async () => {
                await runSampleAnalysis(s.filename);
                onNavigate('live-traffic');
              }}
              className="px-3 py-1.5 bg-[#FAFAF8] hover:bg-[#F4F4F2] border border-border text-primary text-xs font-mono rounded flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Play className="w-3 h-3 text-primary" />
              <span>{s.filename.includes('95') ? 'Ares Botnet' : 'LOIC DDoS'} ({s.size_mb} MB)</span>
            </button>
          ))}
          <button
            onClick={() => onNavigate('live-traffic')}
            className="px-3 py-1.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold uppercase tracking-wider rounded flex items-center gap-1.5 transition-colors"
          >
            <Upload className="w-3 h-3" />
            <span>Upload Custom PCAP</span>
          </button>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 1 — HOW UNIGUARD AI WORKS                                         */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase tracking-widest text-secondary font-bold">
              PROCESSING PIPELINE
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-primary">
            HOW UNIGUARD AI WORKS
          </h2>
          <p className="text-xs text-secondary mt-0.5 max-w-2xl">
            From passive network traffic to explainable threat intelligence — without active probing.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          
          {/* STEP 01 */}
          <div className="bg-white border border-border rounded-lg p-4 shadow-card flex flex-col justify-between space-y-3 hover:border-neutral-400 transition-colors">
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-secondary bg-[#FAFAF8] px-2 py-0.5 rounded border border-border">
                  STEP 01
                </span>
                <div className="w-7 h-7 rounded bg-black text-white flex items-center justify-center">
                  <Radio className="w-3.5 h-3.5" />
                </div>
              </div>
              <h3 className="text-xs font-bold text-primary font-mono uppercase">
                PASSIVE CAPTURE
              </h3>
              <p className="text-[11px] text-secondary leading-relaxed">
                Authentic network traffic is received through a passive, read-only ingestion path.
              </p>
            </div>
            <div className="pt-2 border-t border-border">
              <span className="inline-block px-2 py-0.5 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded text-[9px] font-mono font-bold uppercase">
                ZERO ACTIVE PROBING
              </span>
            </div>
          </div>

          {/* STEP 02 */}
          <div className="bg-white border border-border rounded-lg p-4 shadow-card flex flex-col justify-between space-y-3 hover:border-neutral-400 transition-colors">
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-secondary bg-[#FAFAF8] px-2 py-0.5 rounded border border-border">
                  STEP 02
                </span>
                <div className="w-7 h-7 rounded bg-black text-white flex items-center justify-center">
                  <Activity className="w-3.5 h-3.5" />
                </div>
              </div>
              <h3 className="text-xs font-bold text-primary font-mono uppercase">
                27-FEATURE EXTRACTION
              </h3>
              <p className="text-[11px] text-secondary leading-relaxed">
                Each unidirectional flow is converted into 27 deterministic statistical and temporal features.
              </p>
            </div>
            <div className="pt-2 border-t border-border">
              <span className="inline-block px-2 py-0.5 bg-blue-50 border border-blue-200 text-blue-800 rounded text-[9px] font-mono font-bold uppercase">
                DETERMINISTIC FEATURES
              </span>
            </div>
          </div>

          {/* STEP 03 */}
          <div className="bg-white border border-border rounded-lg p-4 shadow-card flex flex-col justify-between space-y-3 hover:border-neutral-400 transition-colors">
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-secondary bg-[#FAFAF8] px-2 py-0.5 rounded border border-border">
                  STEP 03
                </span>
                <div className="w-7 h-7 rounded bg-black text-white flex items-center justify-center">
                  <Brain className="w-3.5 h-3.5" />
                </div>
              </div>
              <h3 className="text-xs font-bold text-primary font-mono uppercase">
                TWO-TIER AI ANALYSIS
              </h3>
              <p className="text-[11px] text-secondary leading-relaxed">
                Tier 1 performs 4-class supervised classification while Tier 2 identifies statistical anomalies using Isolation Forest.
              </p>
            </div>
            <div className="pt-2 border-t border-border">
              <span className="inline-block px-2 py-0.5 bg-purple-50 border border-purple-200 text-purple-800 rounded text-[9px] font-mono font-bold uppercase">
                4-CLASS + ANOMALY DETECTION
              </span>
            </div>
          </div>

          {/* STEP 04 */}
          <div className="bg-white border border-border rounded-lg p-4 shadow-card flex flex-col justify-between space-y-3 hover:border-neutral-400 transition-colors">
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-secondary bg-[#FAFAF8] px-2 py-0.5 rounded border border-border">
                  STEP 04
                </span>
                <div className="w-7 h-7 rounded bg-black text-white flex items-center justify-center">
                  <ShieldCheck className="w-3.5 h-3.5" />
                </div>
              </div>
              <h3 className="text-xs font-bold text-primary font-mono uppercase">
                EVIDENCE & RESPONSE
              </h3>
              <p className="text-[11px] text-secondary leading-relaxed">
                Detected activity is visualized, integrity records are generated, and a structured security report can be exported.
              </p>
            </div>
            <div className="pt-2 border-t border-border">
              <span className="inline-block px-2 py-0.5 bg-amber-50 border border-amber-200 text-amber-800 rounded text-[9px] font-mono font-bold uppercase">
                SHA-256 EVIDENCE
              </span>
            </div>
          </div>

        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 2 — WHY UNIGUARD AI?                                              */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase tracking-widest text-secondary font-bold">
              CORE ADVANTAGES
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-primary">
            WHY UNIGUARD AI?
          </h2>
          <p className="text-xs text-secondary mt-0.5 max-w-2xl">
            Designed for security environments where observation must not become interference.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          
          <div className="bg-white border border-border rounded-lg p-5 shadow-card space-y-2 hover:border-neutral-400 transition-colors">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#FAFAF8] border border-border flex items-center justify-center text-primary">
                <EyeOff className="w-3.5 h-3.5" />
              </div>
              <span className="text-[10px] font-mono font-bold text-secondary uppercase">
                01 — PASSIVE BY DESIGN
              </span>
            </div>
            <p className="text-xs text-primary/90 leading-relaxed font-medium pt-1">
              "Analyzes traffic without actively probing or interacting with the monitored network."
            </p>
          </div>

          <div className="bg-white border border-border rounded-lg p-5 shadow-card space-y-2 hover:border-neutral-400 transition-colors">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#FAFAF8] border border-border flex items-center justify-center text-primary">
                <ArrowRightCircle className="w-3.5 h-3.5" />
              </div>
              <span className="text-[10px] font-mono font-bold text-secondary uppercase">
                02 — UNIDIRECTIONAL ARCHITECTURE
              </span>
            </div>
            <p className="text-xs text-primary/90 leading-relaxed font-medium pt-1">
              "Designed around a one-way traffic model with no return-path dependency."
            </p>
          </div>

          <div className="bg-white border border-border rounded-lg p-5 shadow-card space-y-2 hover:border-neutral-400 transition-colors">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#FAFAF8] border border-border flex items-center justify-center text-primary">
                <Radar className="w-3.5 h-3.5" />
              </div>
              <span className="text-[10px] font-mono font-bold text-secondary uppercase">
                03 — KNOWN + UNKNOWN THREATS
              </span>
            </div>
            <p className="text-xs text-primary/90 leading-relaxed font-medium pt-1">
              "Combines supervised threat classification with unsupervised anomaly detection."
            </p>
          </div>

          <div className="bg-white border border-border rounded-lg p-5 shadow-card space-y-2 hover:border-neutral-400 transition-colors">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-[#FAFAF8] border border-border flex items-center justify-center text-primary">
                <Hash className="w-3.5 h-3.5" />
              </div>
              <span className="text-[10px] font-mono font-bold text-secondary uppercase">
                04 — VERIFIABLE EVIDENCE
              </span>
            </div>
            <p className="text-xs text-primary/90 leading-relaxed font-medium pt-1">
              "Generates SHA-256 integrity information from analyzed telemetry for traceable security records."
            </p>
          </div>

        </div>
      </section>

      {/* ========================================================================= */}
      {/* SECTION 3 — SYSTEM STATUS                                                 */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono uppercase tracking-widest text-secondary font-bold">
              OPERATIONAL TELEMETRY
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-primary">
            SYSTEM STATUS
          </h2>
          <p className="text-xs text-secondary mt-0.5 max-w-2xl">
            Current UNIGUARD AI intelligence pipeline.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          
          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-status-healthy" />
              <span>PASSIVE INGESTION</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className="text-[11px] font-bold text-emerald-700 font-mono">ACTIVE</span>
            </div>
          </div>

          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-status-healthy" />
              <span>27-FEATURE ENGINE</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className="text-[11px] font-bold text-emerald-700 font-mono">ACTIVE</span>
            </div>
          </div>

          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-status-healthy" />
              <span>PHASE 3I ML ENGINE</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className="text-[11px] font-bold text-emerald-700 font-mono">ACTIVE</span>
            </div>
          </div>

          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-status-healthy" />
              <span>ISOLATION FOREST</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className="text-[11px] font-bold text-emerald-700 font-mono">ACTIVE</span>
            </div>
          </div>

          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-status-healthy" />
              <span>EVIDENCE LEDGER</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className="text-[11px] font-bold text-emerald-700 font-mono">ACTIVE</span>
            </div>
          </div>

          <div className="bg-white border border-border p-3.5 rounded-lg shadow-card flex flex-col justify-between space-y-1.5">
            <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-secondary font-bold">
              <span className={`w-1.5 h-1.5 rounded-full ${apiOnline ? 'bg-status-healthy' : 'bg-status-warning'}`} />
              <span>API ENGINE</span>
            </div>
            <div className="flex items-baseline justify-between pt-1 border-t border-border">
              <span className="text-[10px] text-secondary font-mono">Status:</span>
              <span className={`text-[11px] font-bold font-mono ${apiOnline ? 'text-emerald-700' : 'text-amber-600'}`}>
                {apiOnline ? 'ONLINE' : 'STANDBY'}
              </span>
            </div>
          </div>

        </div>
      </section>

      {/* KPI Cards */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        
        <div className="bg-white border border-border p-5 rounded shadow-card hover:border-border-strong transition-colors">
          <div className="flex items-center justify-between text-secondary mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider">Architecture State</span>
            <ShieldCheck className="w-4 h-4 text-status-healthy" />
          </div>
          <div className="text-2xl font-bold text-primary">Phase 3I Active</div>
          <div className="text-[11px] font-mono text-secondary mt-1">4-Class Real ML Integrated</div>
        </div>

        <div className="bg-white border border-border p-5 rounded shadow-card hover:border-border-strong transition-colors">
          <div className="flex items-center justify-between text-secondary mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider">Passive Diode</span>
            <Network className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-primary">Zero-Emission</div>
          <div className="text-[11px] font-mono text-secondary mt-1">100% Passive Ingress Only</div>
        </div>

        <div className="bg-white border border-border p-5 rounded shadow-card hover:border-border-strong transition-colors">
          <div className="flex items-center justify-between text-secondary mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider">AI Accuracy</span>
            <Cpu className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-primary">82.24% Real</div>
          <div className="text-[11px] font-mono text-secondary mt-1">4-Class Multi-Capture • 2.8% FPR</div>
        </div>

        <div className="bg-white border border-border p-5 rounded shadow-card hover:border-border-strong transition-colors">
          <div className="flex items-center justify-between text-secondary mb-2">
            <span className="text-xs uppercase font-semibold tracking-wider">Evidence Pipeline</span>
            <Database className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-primary">SHA-256 Chain</div>
          <div className="text-[11px] font-mono text-secondary mt-1">Cryptographic Evidence Ledger</div>
        </div>

      </section>

      {/* Modular Status Cards */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        <div className="bg-white border border-border p-6 rounded shadow-card space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <h3 className="font-semibold text-xs text-primary uppercase">Deterministic 27-Feature Pipeline</h3>
            <span className="text-[11px] font-mono text-secondary">Phase 2 Engine</span>
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Extracts volume, packet-size entropy, inter-arrival time jitter, burstiness, TCP flag distributions, and port indicators without requiring bidirectional TCP handshakes.
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono text-secondary pt-1">
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">5 Volume/Time Features</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">5 Packet Size Features</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">6 IAT Dynamics Features</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">9 TCP Flag State Features</div>
          </div>
        </div>

        <div className="bg-white border border-border p-6 rounded shadow-card space-y-4">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <h3 className="font-semibold text-xs text-primary uppercase">Two-Tier Threat Intelligence</h3>
            <span className="text-[11px] font-mono text-secondary">Phase 3I Defense</span>
          </div>
          <p className="text-xs text-secondary leading-relaxed">
            Tier 1 applies class-balanced multi-class detection (BENIGN, DDOS, RECON_SCAN, C2_BEACONING), backed by Tier 2 Isolation Forest zero-day anomaly surveillance.
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono text-secondary pt-1">
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">Tier 1: Supervised Classifier</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">Tier 2: Isolation Forest</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">4 Supported Threat Classes</div>
            <div className="p-2 bg-[#FAFAF8] rounded border border-border">0 Overlap Capture Splits</div>
          </div>
        </div>

      </section>

    </div>
  );
};


import React from 'react';
import { 
  Lock, XCircle, Brain, Bell, Database,
  ArrowRight, ShieldCheck, Radio, Cpu, CheckCircle2
} from 'lucide-react';


export const UnidirectionalDiodeFlow: React.FC = () => {
  return (
    <div className="relative w-full bg-white border border-border rounded-xl shadow-card p-5 sm:p-6 overflow-hidden">
      
      {/* Top Telemetry Status Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3 mb-5 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-status-healthy animate-pulse" />
          <span className="font-bold text-primary uppercase text-[11px] tracking-wider">
            UNIDIRECTIONAL PASSIVE INGESTION ARCHITECTURE
          </span>
          <span className="hidden md:inline px-2 py-0.5 bg-[#FAFAF8] border border-border rounded text-[10px] text-secondary font-semibold">
            3D ISOMETRIC VIEW
          </span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-secondary">
          <span className="flex items-center gap-1">
            <span className="text-status-healthy font-semibold">INGRESS RX:</span> 100% PASSIVE
          </span>
          <span>•</span>
          <span className="flex items-center gap-1">
            <span className="text-red-600 font-semibold">EGRESS TX:</span> 0% INHIBITED
          </span>
          <span className="hidden lg:inline">•</span>
          <span className="hidden lg:inline text-secondary/70">ZERO RETURN PATH</span>
        </div>
      </div>

      {/* Main 3D Architecture Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 lg:gap-2 xl:gap-3 items-center relative py-1">
        
        {/* ========================================================================= */}
        {/* MODULE 1: PROTECTED NETWORK (Cols 1-2)                                    */}
        {/* ========================================================================= */}
        <div className="lg:col-span-2 group">
          <div className="bg-[#FAFAF8] hover:bg-white border border-border hover:border-neutral-400 rounded-xl p-3.5 flex flex-col justify-between shadow-xs transition-all duration-300 relative overflow-hidden h-full min-h-[290px]">
            
            {/* Top Badge & 3D Isometric Server Illustration */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="px-2 py-0.5 bg-neutral-200/80 border border-neutral-300 rounded text-[9px] font-mono font-bold text-neutral-700 uppercase">
                  SOURCE
                </span>
                <div className="flex items-center gap-1 text-[9px] font-mono text-emerald-700 font-semibold">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  <span>LIVE</span>
                </div>
              </div>

              {/* 3D Isometric Server Rack Graphic */}
              <div className="w-full h-16 flex items-center justify-center my-1">
                <svg viewBox="0 0 120 70" className="w-28 h-16 drop-shadow-sm">
                  {/* Platform Base */}
                  <polygon points="60,65 110,40 60,15 10,40" fill="#E5E7EB" stroke="#D1D5DB" strokeWidth="1.5" />
                  <polygon points="60,68 110,43 110,40 60,65" fill="#9CA3AF" />
                  <polygon points="10,40 60,65 60,68 10,43" fill="#D1D5DB" />
                  
                  {/* Server Stack Level 1 */}
                  <polygon points="60,42 95,25 60,8 25,25" fill="#1F2937" stroke="#111827" strokeWidth="1" />
                  <polygon points="95,25 95,35 60,52 60,42" fill="#111827" />
                  <polygon points="25,25 60,42 60,52 25,35" fill="#374151" />
                  {/* LED Blinks on Server Face */}
                  <circle cx="36" cy="33" r="1.5" fill="#10B981" />
                  <circle cx="43" cy="36" r="1.5" fill="#10B981" />
                  <circle cx="50" cy="40" r="1.5" fill="#3B82F6" />
                  <line x1="33" y1="43" x2="55" y2="33" stroke="#4B5563" strokeWidth="0.75" />

                  {/* Server Stack Level 2 */}
                  <polygon points="60,28 95,11 60,-6 25,11" fill="#1F2937" stroke="#111827" strokeWidth="1" />
                  <polygon points="95,11 95,21 60,38 60,28" fill="#111827" />
                  <polygon points="25,11 60,28 60,38 25,21" fill="#374151" />
                  <circle cx="36" cy="19" r="1.5" fill="#10B981" />
                  <circle cx="43" cy="22" r="1.5" fill="#10B981" />
                  <circle cx="50" cy="26" r="1.5" fill="#10B981" />
                </svg>
              </div>

              <div>
                <h3 className="text-xs font-bold text-primary font-mono uppercase tracking-tight">
                  PROTECTED NETWORK
                </h3>
                <p className="text-[9.5px] text-secondary font-mono mt-0.5">
                  MONITORED ENVIRONMENT
                </p>
              </div>

              <p className="text-[10.5px] text-secondary leading-snug mt-1.5">
                Internal VPC, enterprise servers, and critical infrastructure generating live operational traffic.
              </p>
            </div>

            <div className="mt-2.5 pt-2 border-t border-border flex items-center justify-between text-[9.5px] font-mono text-secondary">
              <span>Isolation: Strict</span>
              <span className="text-emerald-700 font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span>Live Traffic</span>
              </span>
            </div>
          </div>
        </div>

        {/* CONNECTOR 1: Flow Arrow (Col 3 on LG) */}
        <div className="lg:col-span-1 flex flex-col items-center justify-center py-2 lg:py-0">
          <div className="text-[8.5px] font-mono font-bold text-secondary uppercase tracking-wider text-center mb-1">
            NETWORK TRAFFIC
          </div>
          <div className="relative flex items-center justify-center w-full">
            <div className="hidden lg:block w-full h-1 bg-neutral-200 rounded-full relative overflow-hidden">
              <div className="absolute inset-0 bg-emerald-500 w-1/2 animate-[packetFlow_1.6s_linear_infinite]" />
            </div>
            <div className="lg:hidden flex items-center gap-1 text-emerald-600 font-mono text-xs">
              <span>↓</span>
              <span className="text-[10px]">Unidirectional Mirroring</span>
            </div>
            <ArrowRight className="hidden lg:block w-3.5 h-3.5 text-neutral-400 shrink-0 ml-[-3px]" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* MODULE 2: PASSIVE TAP (Cols 4-5)                                          */}
        {/* ========================================================================= */}
        <div className="lg:col-span-2 group">
          <div className="bg-[#FAFAF8] hover:bg-white border border-border hover:border-neutral-400 rounded-xl p-3.5 flex flex-col justify-between shadow-xs transition-all duration-300 relative overflow-hidden h-full min-h-[290px]">
            
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="px-2 py-0.5 bg-emerald-100 border border-emerald-200 rounded text-[9px] font-mono font-bold text-emerald-800 uppercase">
                  MIRROR
                </span>
                <Radio className="w-3.5 h-3.5 text-emerald-600" />
              </div>

              {/* 3D Isometric Passive TAP Appliance */}
              <div className="w-full h-16 flex items-center justify-center my-1">
                <svg viewBox="0 0 120 70" className="w-28 h-16 drop-shadow-sm">
                  {/* Platform Base */}
                  <polygon points="60,62 105,39 60,16 15,39" fill="#E5E7EB" stroke="#D1D5DB" strokeWidth="1.5" />
                  
                  {/* Network TAP Box */}
                  <polygon points="60,40 92,24 60,8 28,24" fill="#065F46" stroke="#047857" strokeWidth="1" />
                  <polygon points="92,24 92,34 60,50 60,40" fill="#064E3B" />
                  <polygon points="28,24 60,40 60,50 28,34" fill="#047857" />
                  
                  {/* Optical Splitter Prism Reflection */}
                  <polygon points="60,35 80,25 60,15 40,25" fill="#34D399" opacity="0.8" />
                  <circle cx="48" cy="38" r="2" fill="#6EE7B7" />
                  <circle cx="56" cy="42" r="2" fill="#6EE7B7" />
                  <line x1="60" y1="15" x2="60" y2="35" stroke="#A7F3D0" strokeWidth="1.5" strokeDasharray="2,2" />
                </svg>
              </div>

              <div>
                <h3 className="text-xs font-bold text-primary font-mono uppercase tracking-tight">
                  PASSIVE TAP
                </h3>
                <p className="text-[9.5px] text-secondary font-mono mt-0.5">
                  TRAFFIC MIRROR • SPAN
                </p>
              </div>

              <p className="text-[10.5px] text-secondary leading-snug mt-1.5">
                Read-only packet mirroring without introducing inline latency or packet manipulation.
              </p>
            </div>

            <div className="mt-2.5 pt-2 border-t border-border flex items-center justify-between text-[9.5px] font-mono">
              <span className="text-secondary">Tap Mode:</span>
              <span className="font-bold text-emerald-800 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                READ-ONLY INGEST
              </span>
            </div>
          </div>
        </div>

        {/* CONNECTOR 2: Flow Arrow (Col 6 on LG) */}
        <div className="lg:col-span-1 flex flex-col items-center justify-center py-2 lg:py-0">
          <div className="text-[8.5px] font-mono font-bold text-secondary uppercase tracking-wider text-center mb-1">
            ONE-WAY LINK
          </div>
          <div className="relative flex items-center justify-center w-full">
            <div className="hidden lg:block w-full h-1 bg-neutral-200 rounded-full relative overflow-hidden">
              <div className="absolute inset-0 bg-cyan-500 w-1/2 animate-[packetFlow_1.6s_linear_infinite_0.4s]" />
            </div>
            <div className="lg:hidden flex items-center gap-1 text-cyan-600 font-mono text-xs">
              <span>↓</span>
              <span className="text-[10px]">Physical Diode Boundary</span>
            </div>
            <ArrowRight className="hidden lg:block w-3.5 h-3.5 text-neutral-400 shrink-0 ml-[-3px]" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* MODULE 3 (CENTER): DATA-DIODE BOUNDARY — 3D ISOMETRIC PHYSICAL GATEWAY    */}
        {/* ========================================================================= */}
        <div className="lg:col-span-3">
          <div className="bg-[#0F1319] text-white border border-cyan-700/50 rounded-xl p-3.5 flex flex-col justify-between shadow-md shadow-cyan-950/20 relative overflow-hidden h-full min-h-[305px]">
            
            {/* Subtle Top Lighting Gradient */}
            <div className="absolute top-0 inset-x-0 h-24 bg-gradient-to-b from-cyan-500/10 to-transparent pointer-events-none" />

            <div className="relative z-10 space-y-2">
              {/* Header Badges */}
              <div className="flex items-center justify-between gap-1 border-b border-white/10 pb-1.5">
                <div className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-600/40 text-cyan-300 font-mono text-[8.5px] font-bold uppercase tracking-wider">
                  <Lock className="w-2.5 h-2.5 text-cyan-400" />
                  <span>DATA-DIODE BOUNDARY</span>
                </div>
                <span className="text-[7.5px] font-mono uppercase font-semibold text-neutral-300 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded">
                  OPTIONAL HARDWARE
                </span>
              </div>

              {/* 3D Isometric Physical Isolator Graphic */}
              <div className="w-full h-14 flex items-center justify-center my-0.5">
                <svg viewBox="0 0 130 65" className="w-32 h-14 drop-shadow-md">
                  {/* Beveled Metal Platform */}
                  <polygon points="65,60 115,35 65,10 15,35" fill="#1E293B" stroke="#0EA5E9" strokeWidth="1" />
                  <polygon points="65,63 115,38 115,35 65,60" fill="#0F172A" />
                  <polygon points="15,35 65,60 65,63 15,38" fill="#334155" />

                  {/* Dark Optical Diode Core Chassis */}
                  <polygon points="65,38 95,23 65,8 35,23" fill="#090D14" stroke="#00E5FF" strokeWidth="1.5" />
                  <polygon points="95,23 95,33 65,48 65,38" fill="#04070B" />
                  <polygon points="35,23 65,38 65,48 35,33" fill="#131B26" />

                  {/* Unidirectional Laser/Optical Beam (Strict Forward Pulse) */}
                  <line x1="42" y1="28" x2="88" y2="28" stroke="#00E5FF" strokeWidth="2" strokeLinecap="round" />
                  <polygon points="86,25 93,28 86,31" fill="#00E5FF" />
                  
                  {/* Blocked Return Barrier X Symbol */}
                  <circle cx="65" cy="43" r="3.5" fill="#EF4444" fillOpacity="0.2" stroke="#EF4444" strokeWidth="1" />
                  <line x1="63" y1="41" x2="67" y2="45" stroke="#EF4444" strokeWidth="1.2" />
                  <line x1="67" y1="41" x2="63" y2="45" stroke="#EF4444" strokeWidth="1.2" />
                </svg>
              </div>

              {/* Title & Direction Specs */}
              <div>
                <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider leading-tight">
                  ONE-WAY ARCHITECTURE
                </h3>
              </div>

              {/* Direction Graphic */}
              <div className="p-1.5 bg-black/60 border border-cyan-500/20 rounded font-mono space-y-0.5">
                <div className="flex items-center justify-between text-[8.5px] text-neutral-300 font-semibold">
                  <span className="text-cyan-300 font-bold">RX (IN)</span>
                  <div className="flex-1 mx-1.5 flex items-center justify-center relative overflow-hidden h-3">
                    <div className="w-full h-[1px] bg-cyan-900" />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className="text-[9.5px] text-cyan-400 font-mono tracking-tighter">─────────→ TX</span>
                    </div>
                  </div>
                  <span className="text-neutral-200 font-bold text-[8px]">MONITORING</span>
                </div>
                <div className="text-[7.5px] text-cyan-400 font-semibold tracking-wider uppercase text-center">
                  ONE-WAY ONLY • FORWARD RX
                </div>
              </div>

              {/* Blocked Return Indicator */}
              <div className="p-1 bg-red-950/30 border border-red-900/40 rounded flex items-center justify-between gap-1 text-[8.5px] font-mono">
                <div className="flex items-center gap-1 text-neutral-200">
                  <XCircle className="w-3 h-3 text-red-500 shrink-0" />
                  <span className="font-bold text-[8px]">RETURN PATH BLOCKED</span>
                </div>
                <span className="text-red-400 font-mono text-[8px] font-semibold">← ─ ─ X</span>
              </div>

              {/* Honesty Disclosure */}
              <div className="text-[7.5px] font-mono text-neutral-400 bg-white/5 px-1.5 py-0.5 rounded border border-white/5 text-center leading-tight">
                CURRENT PROTOTYPE: SOFTWARE-SIMULATED BOUNDARY
              </div>
            </div>

            {/* Bottom Status */}
            <div className="mt-2 pt-1.5 border-t border-white/10 flex items-center justify-between text-[8.5px] font-mono text-neutral-400">
              <span>Feedback Loop:</span>
              <span className="text-red-400 font-bold tracking-wide">IMPOSSIBLE</span>
            </div>
          </div>
        </div>

        {/* CONNECTOR 3: Flow Arrow (Col 10 on LG) */}
        <div className="lg:col-span-1 flex flex-col items-center justify-center py-2 lg:py-0">
          <div className="text-[8.5px] font-mono font-bold text-secondary uppercase tracking-wider text-center mb-1">
            PASSIVE INGEST
          </div>
          <div className="relative flex items-center justify-center w-full">
            <div className="hidden lg:block w-full h-1 bg-neutral-200 rounded-full relative overflow-hidden">
              <div className="absolute inset-0 bg-emerald-500 w-1/2 animate-[packetFlow_1.6s_linear_infinite_0.8s]" />
            </div>
            <div className="lg:hidden flex items-center gap-1 text-emerald-600 font-mono text-xs">
              <span>↓</span>
              <span className="text-[10px]">Real-Time Threat Processing</span>
            </div>
            <ArrowRight className="hidden lg:block w-3.5 h-3.5 text-neutral-400 shrink-0 ml-[-3px]" />
          </div>
        </div>

        {/* ========================================================================= */}
        {/* MODULE 4: UNIGUARD AI DESTINATION SINK (Cols 11-12)                       */}
        {/* ========================================================================= */}
        <div className="lg:col-span-2 group">
          <div className="bg-[#FAFAF8] hover:bg-white border border-border hover:border-neutral-400 rounded-xl p-3.5 flex flex-col justify-between shadow-xs transition-all duration-300 relative overflow-hidden h-full min-h-[290px]">
            
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="px-2 py-0.5 bg-emerald-100 border border-emerald-200 rounded text-[9px] font-mono font-bold text-emerald-800 uppercase">
                  SINK
                </span>
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
              </div>

              {/* 3D Isometric AI Security Node */}
              <div className="w-full h-16 flex items-center justify-center my-1">
                <svg viewBox="0 0 120 70" className="w-28 h-16 drop-shadow-sm">
                  {/* Platform Base */}
                  <polygon points="60,62 105,39 60,16 15,39" fill="#E5E7EB" stroke="#D1D5DB" strokeWidth="1.5" />
                  
                  {/* 3D Shield Crystal Structure */}
                  <polygon points="60,42 88,27 60,12 32,27" fill="#111827" stroke="#10B981" strokeWidth="1.2" />
                  <polygon points="88,27 88,38 60,53 60,42" fill="#064E3B" />
                  <polygon points="32,27 60,42 60,53 32,38" fill="#1F2937" />
                  
                  {/* Core Neural Node Facet */}
                  <circle cx="60" cy="27" r="3" fill="#10B981" />
                  <circle cx="60" cy="27" r="6" fill="none" stroke="#34D399" strokeWidth="0.75" strokeDasharray="2,2" />
                </svg>
              </div>

              <div>
                <h3 className="text-xs font-bold text-primary font-mono uppercase tracking-tight">
                  UNIGUARD AI
                </h3>
                <p className="text-[9.5px] text-secondary font-mono mt-0.5">
                  PASSIVE THREAT INTELLIGENCE
                </p>
              </div>

              {/* 3 Compact Capability Rows */}
              <div className="space-y-1 font-mono text-[9px] mt-2">
                <div className="px-1.5 py-0.5 bg-white border border-border rounded flex items-center justify-between">
                  <span className="text-secondary font-semibold">27 Canonical Features</span>
                  <Cpu className="w-2.5 h-2.5 text-primary" />
                </div>
                <div className="px-1.5 py-0.5 bg-white border border-border rounded flex items-center justify-between">
                  <span className="text-secondary font-semibold">Phase 3I True 4-Class ML</span>
                  <CheckCircle2 className="w-2.5 h-2.5 text-status-healthy" />
                </div>
                <div className="px-1.5 py-0.5 bg-white border border-border rounded flex items-center justify-between">
                  <span className="text-secondary font-semibold">Isolation Forest Anomaly</span>
                  <span className="text-[7.5px] text-secondary">Contam 0.02</span>
                </div>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-border flex items-center justify-between text-[9.5px] font-mono text-secondary">
              <span>Passive Ingestion:</span>
              <span className="text-primary font-bold">RX ONLY</span>
            </div>
          </div>
        </div>

      </div>

      {/* Downstream Intelligence Floating Output Ribbon */}
      <div className="mt-4 pt-3 border-t border-border bg-[#FAFAF8] -mx-5 sm:-mx-6 -mb-5 sm:-mb-6 px-5 sm:px-6 py-2.5 flex flex-col md:flex-row items-center justify-between gap-2.5 text-[10.5px] font-mono text-secondary">
        <div className="flex items-center gap-2">
          <span className="font-bold text-primary uppercase text-[9.5px]">DOWNSTREAM INTELLIGENCE EMISSIONS:</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-border rounded shadow-2xs font-semibold text-primary">
            <Brain className="w-3.5 h-3.5 text-primary" />
            <span>🧠 ML CLASSIFICATION • 4-Class Detection</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-border rounded shadow-2xs font-semibold text-primary">
            <Bell className="w-3.5 h-3.5 text-status-warning" />
            <span>🔔 SECURITY ALERTS • Real-Time Insights</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-white border border-border rounded shadow-2xs font-semibold text-primary">
            <Database className="w-3.5 h-3.5 text-primary" />
            <span>▣ CRYPTOGRAPHIC EVIDENCE • SHA-256 Chain</span>
          </div>
        </div>
      </div>

      {/* Custom CSS Animation Keyframe for Forward-Only Linear Packet Stream */}
      <style>{`
        @keyframes packetFlow {
          0% {
            transform: translateX(-100%);
          }
          100% {
            transform: translateX(200%);
          }
        }
      `}</style>
    </div>
  );
};

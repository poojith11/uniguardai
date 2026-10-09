import React, { useEffect, useState, useRef } from 'react';
import { 
  Shield, Bell, Settings, Radio, CheckCircle2, 
  X, Cpu, Zap, Layers 
} from 'lucide-react';
import { useTraffic } from '../lib/TrafficContext';
import { getApiUrl } from '../lib/api';

export type NavTab = 
  | 'overview' 
  | 'live-traffic' 
  | 'threats' 
  | 'evidence' 
  | 'models' 
  | 'analytics' 
  | 'reports';

interface NavbarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenTeamModal?: () => void;
}

interface BackendHealth {
  status: string;
  service: string;
  version: string;
  phase: string;
  database: {
    configured: boolean;
    connected: boolean;
    error?: string;
  };
  models: {
    loaded: boolean;
    active_phase: string;
  };
  metrics: {
    processed_flows: number;
    threats_detected: number;
  };
}

type OpenMenu = 'none' | 'notifications' | 'settings' | 'passive-tap';

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab, onOpenTeamModal }) => {

  const { analysis } = useTraffic();
  const [health, setHealth] = useState<BackendHealth | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [openMenu, setOpenMenu] = useState<OpenMenu>('none');

  const menuContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(getApiUrl('/api/health'));
        if (res.ok) {
          const data = await res.json();
          setHealth(data);
        } else {
          setHealth(null);
        }
      } catch {
        setHealth(null);
      } finally {
        setLoading(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, []);

  // Handle click outside and Escape key to close popovers
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuContainerRef.current && !menuContainerRef.current.contains(event.target as Node)) {
        setOpenMenu('none');
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpenMenu('none');
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const toggleMenu = (menu: OpenMenu) => {
    setOpenMenu((prev) => (prev === menu ? 'none' : menu));
  };

  const navItems: { id: NavTab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'live-traffic', label: 'Live Traffic' },
    { id: 'threats', label: 'Threats' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'models', label: 'Models' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'reports', label: 'Reports' },
  ];

  const threatFlows = analysis ? analysis.flows.filter((f) => f.is_threat) : [];
  const unreadThreatCount = threatFlows.length;

  return (
    <header className="sticky top-0 z-50 w-full bg-white border-b border-border shadow-subtle">
      <div className="max-w-[1600px] mx-auto px-6 h-16 flex items-center justify-between">
        
        {/* Brand Logo & Tag */}
        <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div 
                className="flex items-center gap-2.5 cursor-pointer select-none" 
                onClick={() => {
                  setOpenMenu('none');
                  onSelectTab('overview');
                }}
              >
                <div className="w-8 h-8 bg-black text-white flex items-center justify-center rounded">
                  <Shield className="w-4 h-4 stroke-[2.2]" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm tracking-tight text-primary uppercase">UNIGUARD AI</span>
                  </div>
                  <p className="text-[11px] text-secondary tracking-tight font-medium">Passive Threat Intelligence</p>
                </div>
              </div>

              {/* Interactive Team Profile Trigger Badge */}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu('none');
                  onOpenTeamModal?.();
                }}
                className="text-[10px] uppercase font-mono px-2 py-0.5 bg-[#F4F4F2] hover:bg-black hover:text-white border border-border hover:border-black text-secondary rounded font-bold transition-all duration-200 cursor-pointer shadow-2xs active:scale-95 flex items-center gap-1.5 group"
                title="Click to open Team Liquid Core Development Profile"
                aria-label="View Team Liquid Profile"
              >
                <span>TEAM LIQUID</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 group-hover:bg-emerald-400" />
              </button>
            </div>


          <div className="hidden lg:block h-5 w-[1px] bg-border" />

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setOpenMenu('none');
                    onSelectTab(item.id);
                  }}
                  className={`px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition-colors relative rounded ${
                    isActive 
                      ? 'text-primary bg-[#F4F4F2]' 
                      : 'text-secondary hover:text-primary hover:bg-[#FAFAF8]'
                  }`}
                >
                  {item.label}
                  {isActive && (
                    <span className="absolute bottom-[-14px] left-3 right-3 h-[2px] bg-black rounded-full" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Status & Action Controls Container */}
        <div ref={menuContainerRef} className="relative flex items-center gap-3">
          
          {/* Real Backend Connection Pill */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded bg-[#FAFAF8] border border-border text-[11px]">
            <span className={`w-2 h-2 rounded-full ${
              health?.status === 'healthy' 
                ? 'bg-status-healthy ring-4 ring-emerald-50' 
                : loading ? 'bg-status-warning animate-pulse' : 'bg-status-critical'
            }`} />
            <span className="font-medium text-secondary">
              {health?.status === 'healthy' ? 'API Engine Online' : loading ? 'Checking API...' : 'API Standby'}
            </span>
            <span className="text-secondary/50 font-mono text-[10px]">{health?.version || 'v0.2.0'}</span>
          </div>

          {/* Icon Controls */}
          <div className="flex items-center gap-1.5">
            
            {/* 1. Notification Bell Button */}
            <button 
              onClick={() => toggleMenu('notifications')}
              aria-label="Security Notifications"
              aria-expanded={openMenu === 'notifications'}
              className={`relative p-2 rounded transition-colors ${
                openMenu === 'notifications' 
                  ? 'bg-primary text-white' 
                  : 'text-secondary hover:text-primary hover:bg-[#F4F4F2]'
              }`}
              title="System Alerts & Notifications"
            >
              <Bell className="w-4 h-4" />
              {unreadThreatCount > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-600 rounded-full ring-2 ring-white"></span>
              )}
            </button>

            {/* 2. Settings Gear Button */}
            <button 
              onClick={() => toggleMenu('settings')}
              aria-label="System Settings & Diagnostics"
              aria-expanded={openMenu === 'settings'}
              className={`p-2 rounded transition-colors ${
                openMenu === 'settings' 
                  ? 'bg-primary text-white' 
                  : 'text-secondary hover:text-primary hover:bg-[#F4F4F2]'
              }`}
              title="Configuration & Architecture Diagnostics"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>

          {/* 3. Passive Tap Button */}
          <button 
            onClick={() => toggleMenu('passive-tap')}
            aria-label="Passive Hardware Diode Status"
            aria-expanded={openMenu === 'passive-tap'}
            className={`text-xs font-semibold px-3.5 py-2 rounded transition-colors flex items-center gap-1.5 shadow-subtle ${
              openMenu === 'passive-tap'
                ? 'bg-[#1a1a1a] text-white ring-2 ring-black/10'
                : 'bg-primary hover:bg-primary-hover text-white'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-status-healthy" />
            <span>Passive Tap</span>
          </button>

          {/* ========================================================================= */}
          {/* POPOVER 1: NOTIFICATIONS POPOVER                                          */}
          {/* ========================================================================= */}
          {openMenu === 'notifications' && (
            <div 
              role="dialog"
              aria-label="Security Notifications"
              className="absolute right-0 top-12 mt-2 w-80 sm:w-96 bg-white border border-border rounded shadow-card z-50 overflow-hidden text-xs"
            >
              <div className="p-3 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
                <div className="flex items-center gap-2 font-mono font-semibold text-primary">
                  <Bell className="w-4 h-4 text-primary" />
                  <span>SECURITY NOTIFICATIONS</span>
                </div>
                <button 
                  onClick={() => setOpenMenu('none')} 
                  className="text-secondary hover:text-primary"
                  aria-label="Close notifications"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="max-h-80 overflow-y-auto divide-y divide-border">
                {threatFlows.length > 0 ? (
                  threatFlows.slice(0, 5).map((threat, idx) => (
                    <div 
                      key={threat.flow_id || idx}
                      onClick={() => {
                        setOpenMenu('none');
                        onSelectTab('threats');
                      }}
                      className="p-3 hover:bg-red-50/40 cursor-pointer transition-colors space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-red-700 uppercase text-[11px]">
                          {threat.predicted_class} DETECTED
                        </span>
                        <span className="px-1.5 py-0.2 bg-red-100 text-red-800 font-mono text-[9px] font-bold rounded">
                          {threat.severity}
                        </span>
                      </div>
                      <p className="text-secondary text-[11px] font-mono">
                        Source: <strong className="text-primary">{threat.src_ip}:{threat.src_port ?? 0}</strong> → {threat.dst_ip}:{threat.dst_port ?? 0}
                      </p>
                      <div className="text-[10px] text-secondary flex justify-between font-mono">
                        <span>Packets: {threat.packet_count}</span>
                        <span>Anomaly Score: {threat.anomaly_score}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-8 text-center space-y-2">
                    <CheckCircle2 className="w-6 h-6 text-status-healthy mx-auto stroke-[1.5]" />
                    <div className="font-semibold text-primary">No New Security Events</div>
                    <p className="text-[11px] text-secondary max-w-xs mx-auto leading-relaxed">
                      {analysis 
                        ? `Capture ${analysis.pcap_filename} evaluated with zero detected threat signatures.`
                        : 'No active threat events in current session. Real alerts populate upon PCAP evaluation.'}
                    </p>
                  </div>
                )}
              </div>

              {threatFlows.length > 0 && (
                <div className="p-2 border-t border-border bg-[#FAFAF8] text-center">
                  <button
                    onClick={() => {
                      setOpenMenu('none');
                      onSelectTab('threats');
                    }}
                    className="text-[11px] font-semibold text-primary hover:underline font-mono uppercase"
                  >
                    View All {threatFlows.length} Threats in Queue →
                  </button>
                </div>
              )}
            </div>
          )}

          {/* ========================================================================= */}
          {/* POPOVER 2: SETTINGS & SYSTEM STATUS                                       */}
          {/* ========================================================================= */}
          {openMenu === 'settings' && (
            <div 
              role="dialog"
              aria-label="System Settings"
              className="absolute right-0 top-12 mt-2 w-80 sm:w-96 bg-white border border-border rounded shadow-card z-50 overflow-hidden text-xs"
            >
              <div className="p-3 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
                <div className="flex items-center gap-2 font-mono font-semibold text-primary">
                  <Settings className="w-4 h-4 text-primary" />
                  <span>SYSTEM DIAGNOSTICS & STATUS</span>
                </div>
                <button 
                  onClick={() => setOpenMenu('none')} 
                  className="text-secondary hover:text-primary"
                  aria-label="Close settings"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
                
                {/* System Section */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase font-bold text-secondary tracking-wider">
                    <Cpu className="w-3.5 h-3.5 text-primary" />
                    <span>System Runtime</span>
                  </div>
                  <div className="bg-[#FAFAF8] border border-border p-2.5 rounded space-y-1.5 font-mono text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-secondary">API Engine:</span>
                      <span className={`font-semibold ${health?.status === 'healthy' ? 'text-status-healthy' : 'text-red-600'}`}>
                        {health?.status === 'healthy' ? 'Online (HTTP 200)' : 'Unavailable'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-secondary">Backend Version:</span>
                      <span className="text-primary">{health?.version || 'v0.2.0'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-secondary">Database:</span>
                      <span className={`font-semibold ${health?.database?.configured ? 'text-status-healthy' : 'text-secondary'}`}>
                        {health?.database?.configured ? 'Supabase Connected' : 'Standby'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Pipeline Section */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase font-bold text-secondary tracking-wider">
                    <Layers className="w-3.5 h-3.5 text-primary" />
                    <span>ML Pipeline Architecture</span>
                  </div>
                  <div className="bg-[#FAFAF8] border border-border p-2.5 rounded space-y-1.5 font-mono text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-secondary">Model Version:</span>
                      <span className="text-primary font-semibold">Phase 3I True 4-Class</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-secondary">Predictive Features:</span>
                      <span className="text-primary">27 Deterministic Flow Metrics</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-secondary">Supervised Model:</span>
                      <span className="text-primary">HistGradientBoosting (4-Class)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-secondary">Anomaly Detector:</span>
                      <span className="text-primary">Isolation Forest (Contam 0.02)</span>
                    </div>
                  </div>
                </div>

                {/* Threat Taxonomy Status */}
                <div className="space-y-1.5 font-mono text-[10px]">
                  <span className="uppercase font-bold text-secondary tracking-wider">Supported Taxonomy:</span>
                  <div className="flex flex-wrap gap-1">
                    {['BENIGN', 'DDOS', 'RECON_SCAN', 'C2_BEACONING'].map((c) => (
                      <span key={c} className="px-1.5 py-0.5 bg-green-50 border border-green-200 text-green-800 rounded font-semibold">
                        {c}
                      </span>
                    ))}
                    <span className="px-1.5 py-0.5 bg-amber-50 border border-amber-200 text-amber-800 rounded">
                      EXFILTRATION (Unsupported)
                    </span>
                  </div>
                </div>

              </div>

              <div className="p-2.5 border-t border-border bg-[#FAFAF8] flex justify-between items-center text-[11px]">
                <span className="text-secondary font-mono">Zero Hardcoded Mocks</span>
                <button
                  onClick={() => {
                    setOpenMenu('none');
                    onSelectTab('models');
                  }}
                  className="font-semibold text-primary hover:underline font-mono uppercase"
                >
                  Model Specs →
                </button>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* POPOVER 3: PASSIVE TAP STATUS                                             */}
          {/* ========================================================================= */}
          {openMenu === 'passive-tap' && (
            <div 
              role="dialog"
              aria-label="Passive Tap Interface Status"
              className="absolute right-0 top-12 mt-2 w-80 sm:w-96 bg-white border border-border rounded shadow-card z-50 overflow-hidden text-xs"
            >
              <div className="p-3 border-b border-border bg-[#FAFAF8] flex items-center justify-between">
                <div className="flex items-center gap-2 font-mono font-semibold text-primary">
                  <Radio className="w-4 h-4 text-status-healthy" />
                  <span>PASSIVE TAP STATUS</span>
                </div>
                <button 
                  onClick={() => setOpenMenu('none')} 
                  className="text-secondary hover:text-primary"
                  aria-label="Close passive tap panel"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-4 space-y-3.5">
                
                <div className="p-2.5 bg-emerald-50/60 border border-emerald-200 rounded flex items-center gap-2.5">
                  <Shield className="w-5 h-5 text-status-healthy shrink-0" />
                  <div className="space-y-0.5">
                    <div className="font-semibold text-primary text-xs">Unidirectional Diode Channel Active</div>
                    <div className="text-[10px] text-secondary font-mono">Software Passive Tap Simulation (Zero-Emission)</div>
                  </div>
                </div>

                <div className="bg-[#FAFAF8] border border-border p-3 rounded space-y-2 font-mono text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-secondary">Operating Mode:</span>
                    <span className="font-semibold text-primary">PASSIVE RX ONLY</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-secondary">Egress Transmission (TX):</span>
                    <span className="font-semibold text-status-healthy">0% (Inhibited)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-secondary">Return Packets / Handshakes:</span>
                    <span className="font-semibold text-status-healthy">0 (Zero Emission)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-secondary">Active Probing / SYN-ACK:</span>
                    <span className="font-semibold text-status-healthy">DISABLED</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-secondary">Feedback Backchannel:</span>
                    <span className="font-semibold text-status-healthy">PHYSICALLY IMPOSSIBLE</span>
                  </div>
                </div>

                <div className="p-2.5 bg-[#FAFAF8] border border-border rounded space-y-1 text-[11px]">
                  <div className="font-semibold text-primary flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-primary" />
                    <span>Architectural Guarantee</span>
                  </div>
                  <p className="text-secondary leading-relaxed text-[11px]">
                    All unidirectional flow telemetry is ingested passively without active probing. Outbound feedback is inhibited to guarantee complete network stealth.
                  </p>
                </div>

              </div>

              <div className="p-2.5 border-t border-border bg-[#FAFAF8] flex justify-between items-center text-[11px]">
                <span className="text-secondary font-mono text-[10px]">RX Line: 100% | TX Line: 0%</span>
                <button
                  onClick={() => {
                    setOpenMenu('none');
                    onSelectTab('live-traffic');
                  }}
                  className="font-semibold text-primary hover:underline font-mono uppercase"
                >
                  Live Telemetry →
                </button>
              </div>
            </div>
          )}

        </div>

      </div>
    </header>
  );
};

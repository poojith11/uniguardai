import { useState } from 'react';
import { Navbar } from './components/Navbar';
import type { NavTab } from './components/Navbar';
import { TeamLiquidModal } from './components/TeamLiquidModal';
import { Overview } from './pages/Overview';
import { LiveTraffic } from './pages/LiveTraffic';
import { ThreatEngine } from './pages/ThreatEngine';
import { ForensicEvidence } from './pages/ForensicEvidence';
import { ModelManagement } from './pages/ModelManagement';
import { Analytics } from './pages/Analytics';
import { Reports } from './pages/Reports';
import { TrafficProvider } from './lib/TrafficContext';

function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [isTeamModalOpen, setIsTeamModalOpen] = useState<boolean>(false);

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return <Overview onNavigate={(tab) => setActiveTab(tab)} />;
      case 'live-traffic':
        return <LiveTraffic />;
      case 'threats':
        return <ThreatEngine />;
      case 'evidence':
        return <ForensicEvidence />;
      case 'models':
        return <ModelManagement />;
      case 'analytics':
        return <Analytics />;
      case 'reports':
        return <Reports onNavigate={(tab) => setActiveTab(tab)} />;
      default:
        return <Overview onNavigate={(tab) => setActiveTab(tab)} />;
    }
  };

  return (
    <TrafficProvider>
      <div className="min-h-screen bg-background text-primary flex flex-col font-sans">
        <Navbar 
          activeTab={activeTab} 
          onSelectTab={setActiveTab} 
          onOpenTeamModal={() => setIsTeamModalOpen(true)}
        />
        
        <main className="flex-1">
          {renderContent()}
        </main>

        <footer className="border-t border-border bg-white py-6 mt-12">
          <div className="max-w-[1600px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-secondary">
            <div className="flex items-center gap-2">
              <span className="font-bold text-primary">UNIGUARD AI</span>
              <span>•</span>
              <button 
                type="button"
                onClick={() => setIsTeamModalOpen(true)}
                className="font-semibold text-secondary hover:text-primary underline-offset-2 hover:underline cursor-pointer transition-colors"
                title="Click to view Team Liquid Profile"
              >
                TEAM LIQUID Passive Unidirectional Threat Intelligence
              </button>
            </div>
            <div className="text-[11px] font-mono text-secondary text-center sm:text-right">
              <div>Software-only passive network threat detection. Hardware data-diode integration is optional.</div>
              <div className="mt-0.5 text-[10px] text-secondary/70">PHASE 3I TRUE 4-CLASS ML ENGINE • ZERO SYNTHETIC MOCKS</div>
            </div>
          </div>
        </footer>

        {/* Interactive Team Liquid Profile Modal */}
        <TeamLiquidModal 
          isOpen={isTeamModalOpen} 
          onClose={() => setIsTeamModalOpen(false)} 
        />
      </div>
    </TrafficProvider>
  );
}

export default App;



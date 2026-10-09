import React, { useEffect, useState } from 'react';
import { 
  Crown, User, Mail, Phone, GraduationCap, 
  Fingerprint, X, Radio, Sparkles, Copy, Check 
} from 'lucide-react';


export interface TeamMember {
  role: string;
  isLead: boolean;
  name: string;
  regNo: string;
  dept: string;
  email: string;
  phone: string;
}

const TEAM_MEMBERS: TeamMember[] = [
  {
    role: 'TEAM LEAD',
    isLead: true,
    name: 'ANGU HARI KARTHICK M',
    regNo: '25105018',
    dept: 'R-SMART INTELLECT ENGINEERING — B.E. CSE',
    email: 'anguharikarthickm.ecs25@rathinam.in',
    phone: '8072522246',
  },
  {
    role: 'MEMBER 01',
    isLead: false,
    name: 'SRI POOJITH RUTHRAN',
    regNo: '25105225',
    dept: 'R-SMART INTELLECT ENGINEERING — B.E. CSE',
    email: 'sripoojithruthran.ecs25@rathinam.in',
    phone: '8248082282',
  },
  {
    role: 'MEMBER 02',
    isLead: false,
    name: 'HARINISHA S',
    regNo: '25105085',
    dept: 'R-SMART INTELLECT ENGINEERING — B.E. CSE',
    email: 'harinisha.s.ecs25@rathinam.in',
    phone: '8667751810',
  },
];

interface TeamLiquidModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TeamLiquidModal: React.FC<TeamLiquidModalProps> = ({ isOpen, onClose }) => {
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  // Close on ESC key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(label);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  return (
    <div 
      className="fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6 bg-black/75 backdrop-blur-md transition-all duration-300 animate-in fade-in"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="team-modal-title"
    >
      <div 
        className="relative w-full max-w-5xl bg-[#0F1115] text-[#FAFAFA] border border-white/10 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh] transition-all transform animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Subtle Decorative Cyber Grid Glow Header */}
        <div className="absolute top-0 inset-x-0 h-40 bg-gradient-to-b from-cyan-500/10 via-blue-500/5 to-transparent pointer-events-none" />
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Modal Header */}
        <div className="relative z-10 px-6 sm:px-8 pt-6 pb-5 border-b border-white/10 flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 text-[10px] font-mono font-bold tracking-wider uppercase">
                <Sparkles className="w-3 h-3" />
                <span>CORE DEVELOPMENT TEAM</span>
              </div>
              <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>ACTIVE DEVELOPMENT TEAM</span>
              </div>
            </div>

            <div className="flex items-baseline gap-3 pt-1">
              <h2 id="team-modal-title" className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white font-mono">
                TEAM LIQUID
              </h2>
              <span className="text-sm font-semibold text-cyan-400 font-mono hidden sm:inline">
                • UNIGUARD AI
              </span>
            </div>

            <p className="text-xs sm:text-sm text-neutral-300">
              "UNIGUARD AI — AI-Based Passive Cyber Threat Intelligence"
            </p>
            <p className="text-[11px] text-neutral-400 italic">
              Building intelligent, passive and explainable cyber threat detection.
            </p>
          </div>

          <button 
            onClick={onClose}
            aria-label="Close Team Profile Modal"
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-neutral-400 hover:text-white transition-colors border border-white/5 shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body / Member Cards Container */}
        <div className="relative z-10 p-6 sm:p-8 overflow-y-auto space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {TEAM_MEMBERS.map((member) => {
              const isLead = member.isLead;
              return (
                <div
                  key={member.regNo}
                  className={`relative rounded-xl transition-all duration-300 flex flex-col justify-between overflow-hidden p-5 sm:p-6 ${
                    isLead
                      ? 'bg-gradient-to-b from-[#161B22] to-[#0E1217] border-2 border-cyan-500/40 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-400/20'
                      : 'bg-[#14181F]/90 hover:bg-[#181D26] border border-white/10 hover:border-white/20'
                  }`}
                >
                  {/* Subtle Card Accent */}
                  {isLead && (
                    <div className="absolute top-0 right-0 px-3 py-1 bg-cyan-500/20 border-b border-l border-cyan-500/30 rounded-bl-lg text-[9px] font-mono text-cyan-300 font-bold uppercase tracking-wider flex items-center gap-1">
                      <Crown className="w-3 h-3 text-cyan-400" />
                      <span>LEADERSHIP</span>
                    </div>
                  )}

                  <div className="space-y-4">
                    {/* Role Badge & Avatar Icon */}
                    <div className="flex items-center justify-between">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border ${
                        isLead 
                          ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30' 
                          : 'bg-white/5 text-neutral-300 border-white/10'
                      }`}>
                        {member.role}
                      </span>
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center border ${
                        isLead 
                          ? 'bg-cyan-950/80 border-cyan-500/40 text-cyan-300' 
                          : 'bg-neutral-800 border-white/10 text-neutral-300'
                      }`}>
                        {isLead ? <Crown className="w-4 h-4" /> : <User className="w-4 h-4" />}
                      </div>
                    </div>

                    {/* Member Name */}
                    <div>
                      <h3 className="text-base sm:text-lg font-bold text-white font-mono tracking-tight leading-snug">
                        {member.name}
                      </h3>
                      <div className="mt-1 flex items-center gap-1.5 text-xs text-cyan-400/90 font-mono">
                        <Fingerprint className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
                        <span className="text-neutral-400 text-[11px]">Reg:</span>
                        <span className="font-semibold">{member.regNo}</span>
                      </div>
                    </div>

                    {/* Department */}
                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/5 space-y-1">
                      <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-neutral-400 font-semibold">
                        <GraduationCap className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Department</span>
                      </div>
                      <p className="text-[11px] font-medium text-neutral-200 leading-tight">
                        {member.dept}
                      </p>
                    </div>

                    {/* Contact Information */}
                    <div className="space-y-2 pt-1 border-t border-white/5 text-xs font-mono">
                      {/* Email */}
                      <div className="flex items-center justify-between gap-2 group">
                        <a 
                          href={`mailto:${member.email}`}
                          className="flex items-center gap-2 text-neutral-300 hover:text-cyan-300 transition-colors truncate text-[11px]"
                          title={`Email ${member.name}`}
                        >
                          <Mail className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <span className="truncate">{member.email}</span>
                        </a>
                        <button
                          onClick={() => handleCopy(member.email, `${member.regNo}-email`)}
                          className="p-1 rounded text-neutral-400 hover:text-white hover:bg-white/10 transition-colors shrink-0"
                          title="Copy Email"
                          aria-label="Copy Email"
                        >
                          {copiedItem === `${member.regNo}-email` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>

                      {/* Phone */}
                      <div className="flex items-center justify-between gap-2 group">
                        <a 
                          href={`tel:${member.phone}`}
                          className="flex items-center gap-2 text-neutral-300 hover:text-cyan-300 transition-colors text-[11px]"
                          title={`Call ${member.name}`}
                        >
                          <Phone className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <span>+91 {member.phone}</span>
                        </a>
                        <button
                          onClick={() => handleCopy(member.phone, `${member.regNo}-phone`)}
                          className="p-1 rounded text-neutral-400 hover:text-white hover:bg-white/10 transition-colors shrink-0"
                          title="Copy Phone"
                          aria-label="Copy Phone"
                        >
                          {copiedItem === `${member.regNo}-phone` ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Card Bottom Micro-Indicator */}
                  <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-neutral-400">
                    <span className="flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                      <span>Verified Contributor</span>
                    </span>
                    <span className="text-neutral-400">{isLead ? 'Core Lead' : 'Engineer'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="relative z-10 px-6 sm:px-8 py-4 bg-black/60 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-neutral-400">
          <div className="flex items-center gap-2 text-center sm:text-left">
            <Radio className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              <strong className="text-white">UNIGUARD AI</strong> • Passive Unidirectional Cyber Threat Intelligence
            </span>
          </div>
          <div className="text-[11px] text-cyan-400/80 font-bold tracking-wider">
            TEAM LIQUID • 2026
          </div>
        </div>
      </div>
    </div>
  );
};

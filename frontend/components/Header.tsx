
import React from 'react';
import { Network, Home } from 'lucide-react';
import { AppModule } from '../types';

interface HeaderProps {
  activeModule: AppModule;
  isScanning?: boolean;
  scanError?: string | null;
  onScan?: () => void;
  onSave?: () => void;
  onLoad?: () => void;
  onSelectModule: (module: AppModule) => void;
}

const MODULES: Array<{ id: AppModule; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'network', label: 'Terminal' },
  { id: 'desktop_safety', label: 'Desktop Safety' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'alerts', label: 'Alerts' },
];

export const Header: React.FC<HeaderProps> = ({ activeModule, isScanning, scanError, onScan, onSave, onLoad, onSelectModule }) => {
  return (
    <header className="z-30 border-b border-white/10 bg-black/80 px-6 py-3 backdrop-blur-md">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <button
            onClick={() => onSelectModule('hub')}
            className="flex h-8 w-8 items-center justify-center rounded bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
            title="Back to Hub"
          >
            {activeModule === 'hub' ? <Network size={20} /> : <Home size={20} />}
          </button>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white uppercase">
              <button onClick={() => onSelectModule('hub')} className="hover:text-cyan-300 transition-colors">
                Panopticon
              </button>
            </h1>
            <div className="flex items-center gap-2 text-[10px] text-slate-500 font-bold uppercase tracking-widest">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
              System Primed
            </div>
          </div>
        </div>

        {activeModule !== 'hub' && activeModule !== 'network' ? (
          <div className="flex flex-wrap items-center gap-3">
            <div className="rounded border border-white/10 bg-white/5 px-4 py-2 text-[10px] font-black uppercase tracking-[0.25em] text-slate-400">
              Shared backend &bull; module workspace
            </div>
          </div>
        ) : null}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {MODULES.map((module) => (
          <button
            key={module.id}
            onClick={() => onSelectModule(module.id)}
            className={`rounded-full border px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.25em] transition-colors ${
              activeModule === module.id
                ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-200'
                : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10 hover:text-white'
            }`}
          >
            {module.label}
          </button>
        ))}
      </div>
    </header>
  );
};

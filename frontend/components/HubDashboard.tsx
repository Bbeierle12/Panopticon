import React, { useEffect, useState } from 'react';
import {
  Activity,
  Database,
  Download,
  FileText,
  Monitor,
  ScrollText,
  Settings,
  LayoutGrid,
} from 'lucide-react';
import { AppModule, HubStatus } from '../types';
import { NetWatchApi } from '../services/api';

interface HubDashboardProps {
  onSelectModule: (module: AppModule) => void;
}

interface HubCard {
  id: AppModule | 'api_docs';
  title: string;
  description: string;
  accent: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  external?: boolean;
}

const HUB_CARDS: HubCard[] = [
  {
    id: 'overview',
    title: 'Web UI Modules',
    description: 'Network canvas, sentinel, alerts, vulnerabilities, and overview dashboards.',
    accent: 'from-cyan-500/20 to-cyan-950/20 border-cyan-500/20 text-cyan-300',
    icon: LayoutGrid,
  },
  {
    id: 'api_docs',
    title: 'Orchestrator API',
    description: 'Swagger documentation and interactive API explorer.',
    accent: 'from-violet-500/20 to-violet-950/20 border-violet-500/20 text-violet-300',
    icon: FileText,
    external: true,
  },
  {
    id: 'system_status',
    title: 'System Status',
    description: 'Tool health, adapter status, and scheduled job monitoring.',
    accent: 'from-emerald-500/20 to-emerald-950/20 border-emerald-500/20 text-emerald-300',
    icon: Activity,
  },
  {
    id: 'data_explorer',
    title: 'Data Explorer',
    description: 'Browse and query alerts, devices, scans, and vulnerability records.',
    accent: 'from-blue-500/20 to-blue-950/20 border-blue-500/20 text-blue-300',
    icon: Database,
  },
  {
    id: 'logs',
    title: 'Logs & Events',
    description: 'Real-time event stream and historical server log viewer.',
    accent: 'from-amber-500/20 to-amber-950/20 border-amber-500/20 text-amber-300',
    icon: ScrollText,
  },
  {
    id: 'configuration',
    title: 'Configuration',
    description: 'View and edit platform settings, sentinel feeds, and scheduler config.',
    accent: 'from-slate-400/20 to-slate-950/20 border-slate-400/20 text-slate-300',
    icon: Settings,
  },
  {
    id: 'export',
    title: 'Reports & Export',
    description: 'Export scan results, alert history, and vulnerability reports as CSV or JSON.',
    accent: 'from-pink-500/20 to-pink-950/20 border-pink-500/20 text-pink-300',
    icon: Download,
  },
];

function StatBadge({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex items-center gap-1.5 rounded bg-white/5 px-2 py-0.5 text-[10px]">
      <span className="text-slate-500 uppercase">{label}</span>
      <span className="font-bold text-white">{value}</span>
    </div>
  );
}

export const HubDashboard: React.FC<HubDashboardProps> = ({ onSelectModule }) => {
  const [status, setStatus] = useState<HubStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const data = await NetWatchApi.getHubStatus();
        if (mounted) setStatus(data);
      } catch (e: any) {
        if (mounted) setError(e.message);
      }
    };
    load();
    const interval = setInterval(load, 15000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const handleCardClick = (card: HubCard) => {
    if (card.id === 'api_docs') {
      window.open('/docs', '_blank');
    } else {
      onSelectModule(card.id as AppModule);
    }
  };

  const toolsOnline = status?.tools.filter(t => t.status === 'available').length ?? 0;
  const toolsTotal = status?.tools.length ?? 0;
  const totalRecords = status
    ? status.counts.alerts + status.counts.devices + status.counts.scans + status.counts.vulnerabilities
    : 0;

  function getCardStats(cardId: string): React.ReactNode {
    if (!status) return null;
    switch (cardId) {
      case 'overview':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="Modules" value={5} />
          </div>
        );
      case 'api_docs':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="Version" value={status.health.version} />
            <StatBadge label="Status" value={status.health.status} />
          </div>
        );
      case 'system_status':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="Tools" value={`${toolsOnline}/${toolsTotal}`} />
            <StatBadge label="Jobs" value={status.scheduler_jobs.length} />
          </div>
        );
      case 'data_explorer':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="Records" value={totalRecords} />
            <StatBadge label="Alerts" value={status.counts.alerts} />
            <StatBadge label="Devices" value={status.counts.devices} />
          </div>
        );
      case 'logs':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="WS Clients" value={status.ws_clients} />
          </div>
        );
      case 'configuration':
        return null;
      case 'export':
        return (
          <div className="flex flex-wrap gap-1.5">
            <StatBadge label="Tables" value={4} />
          </div>
        );
      default:
        return null;
    }
  }

  return (
    <div className="flex h-full flex-col overflow-auto bg-black/50 p-8">
      {/* Header */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight text-white">Panopticon Hub</h2>
        <p className="mt-1 text-sm text-slate-500">Navigation dashboard — all modules, data, and operations.</p>
        {error && (
          <p className="mt-2 text-xs text-red-400">Backend unreachable: {error}</p>
        )}
        {status && (
          <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              {status.health.status.toUpperCase()}
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">v{status.health.version}</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">{toolsOnline} tools online</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">{totalRecords} records</span>
          </div>
        )}
      </div>

      {/* Desktop App Banner */}
      <div className="mb-6 rounded-lg border border-indigo-500/20 bg-gradient-to-r from-indigo-500/10 to-indigo-950/10 p-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-indigo-500/15 p-2 text-indigo-300">
            <Monitor size={20} />
          </div>
          <div>
            <h3 className="text-sm font-bold text-indigo-200">NetWatch Desktop</h3>
            <p className="text-xs text-slate-500">Native Iced/Rust application with embedded webview. Launch separately via the desktop shortcut.</p>
          </div>
        </div>
      </div>

      {/* Card Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {HUB_CARDS.map((card) => (
          <button
            key={card.id}
            onClick={() => handleCardClick(card)}
            className={`group flex flex-col items-start rounded-lg border bg-gradient-to-b p-5 text-left transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-black/50 ${card.accent}`}
          >
            <div className="mb-3 rounded-lg bg-white/5 p-2.5 transition-colors group-hover:bg-white/10">
              <card.icon size={20} />
            </div>
            <h3 className="text-sm font-bold text-white">{card.title}</h3>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">{card.description}</p>
            <div className="mt-3">
              {getCardStats(card.id)}
            </div>
            {card.external && (
              <span className="mt-2 text-[9px] font-bold uppercase tracking-widest text-slate-600">Opens in new tab</span>
            )}
          </button>
        ))}
      </div>
    </div>
  );
};

import React, { useEffect, useState } from 'react';
import { Activity, RefreshCw, Wrench, Clock, Radio } from 'lucide-react';
import { HubStatus } from '../types';
import { NetWatchApi } from '../services/api';

function statusColor(status: string): string {
  switch (status) {
    case 'available': return 'text-emerald-400';
    case 'not_found': case 'unavailable': return 'text-red-400';
    case 'degraded': return 'text-amber-400';
    default: return 'text-slate-500';
  }
}

function statusDot(status: string): string {
  switch (status) {
    case 'available': return 'bg-emerald-500';
    case 'not_found': case 'unavailable': return 'bg-red-500';
    case 'degraded': return 'bg-amber-500';
    default: return 'bg-slate-600';
  }
}

export const SystemStatus: React.FC = () => {
  const [status, setStatus] = useState<HubStatus | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setStatus(await NetWatchApi.getHubStatus());
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-full flex-col overflow-auto bg-black/50 p-6">
      <div className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity size={18} className="text-emerald-400" />
          <h2 className="text-lg font-bold text-white">System Status</h2>
        </div>
        <button onClick={load} className="flex items-center gap-1.5 rounded bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10 hover:text-white">
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {!status ? (
        <p className="text-sm text-slate-600">Loading...</p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Tools Health */}
          <div className="rounded-lg border border-white/10 bg-black/40 p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-white">
              <Wrench size={14} /> Tool Health
            </div>
            <div className="space-y-2">
              {status.tools.map(tool => (
                <div key={tool.name} className="flex items-center justify-between rounded bg-white/5 px-3 py-2">
                  <span className="text-xs text-slate-300">{tool.name}</span>
                  <span className={`flex items-center gap-1.5 text-[10px] font-bold uppercase ${statusColor(tool.status)}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${statusDot(tool.status)}`} />
                    {tool.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Adapters */}
          <div className="rounded-lg border border-white/10 bg-black/40 p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-white">
              <Radio size={14} /> Adapters
            </div>
            <div className="space-y-2">
              {status.adapters.map(adapter => (
                <div key={adapter.name} className="flex items-center justify-between rounded bg-white/5 px-3 py-2">
                  <div>
                    <span className="text-xs text-slate-300">{adapter.display_name}</span>
                    <span className="ml-2 text-[10px] text-slate-600">({adapter.name})</span>
                  </div>
                  <span className={`text-[10px] font-bold uppercase ${statusColor(String(adapter.status))}`}>
                    {String(adapter.status)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Scheduler Jobs */}
          <div className="rounded-lg border border-white/10 bg-black/40 p-5 lg:col-span-2">
            <div className="mb-4 flex items-center gap-2 text-sm font-bold text-white">
              <Clock size={14} /> Scheduled Jobs
            </div>
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/10">
                    <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Name</th>
                    <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Trigger</th>
                    <th className="px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">Next Run</th>
                  </tr>
                </thead>
                <tbody>
                  {status.scheduler_jobs.map((job, i) => (
                    <tr key={i} className="border-b border-white/5">
                      <td className="px-3 py-2 text-slate-300">{job.name}</td>
                      <td className="px-3 py-2 text-slate-500">{job.trigger_type}</td>
                      <td className="px-3 py-2 text-slate-500">{job.next_run || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Summary Stats */}
          <div className="rounded-lg border border-white/10 bg-black/40 p-5 lg:col-span-2">
            <div className="mb-4 text-sm font-bold text-white">Platform Counts</div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {Object.entries(status.counts).map(([key, val]) => (
                <div key={key} className="rounded bg-white/5 p-3 text-center">
                  <div className="text-2xl font-bold text-white">{val}</div>
                  <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">{key}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

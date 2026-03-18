import React, { useState } from 'react';
import { Download, CheckCircle } from 'lucide-react';
import { NetWatchApi } from '../services/api';

type Resource = 'alerts' | 'devices' | 'scans' | 'vulnerabilities';
type Format = 'csv' | 'json';

const RESOURCES: Array<{ id: Resource; label: string; description: string }> = [
  { id: 'alerts', label: 'Alerts', description: 'All security alerts with severity, status, and correlation data.' },
  { id: 'devices', label: 'Devices', description: 'Discovered network devices with ports, OS, and status.' },
  { id: 'scans', label: 'Scans', description: 'Scan history with results, timing, and parameters.' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', description: 'CVE records with CVSS scores and remediation.' },
];

export const ExportView: React.FC = () => {
  const [selectedResource, setSelectedResource] = useState<Resource>('alerts');
  const [format, setFormat] = useState<Format>('csv');
  const [limit, setLimit] = useState(10000);
  const [exporting, setExporting] = useState(false);
  const [lastExport, setLastExport] = useState<string | null>(null);

  const handleExport = async () => {
    setExporting(true);
    setLastExport(null);
    try {
      await NetWatchApi.exportResource(selectedResource, format, limit);
      setLastExport(`Exported ${selectedResource} as ${format.toUpperCase()}`);
    } catch (e: any) {
      setLastExport(`Error: ${e.message}`);
    }
    setExporting(false);
  };

  return (
    <div className="flex h-full flex-col overflow-auto bg-black/50 p-6">
      <div className="mb-6 flex items-center gap-3">
        <Download size={18} className="text-pink-400" />
        <h2 className="text-lg font-bold text-white">Reports & Export</h2>
      </div>

      <div className="max-w-2xl space-y-6">
        {/* Resource selector */}
        <div>
          <label className="mb-2 block text-xs font-bold uppercase tracking-widest text-slate-500">Resource</label>
          <div className="grid grid-cols-2 gap-3">
            {RESOURCES.map(r => (
              <button
                key={r.id}
                onClick={() => setSelectedResource(r.id)}
                className={`rounded-lg border p-4 text-left transition-all ${
                  selectedResource === r.id
                    ? 'border-pink-500/40 bg-pink-500/10'
                    : 'border-white/10 bg-white/5 hover:bg-white/10'
                }`}
              >
                <div className={`text-sm font-bold ${selectedResource === r.id ? 'text-pink-200' : 'text-white'}`}>{r.label}</div>
                <div className="mt-1 text-[10px] text-slate-500">{r.description}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Format */}
        <div>
          <label className="mb-2 block text-xs font-bold uppercase tracking-widest text-slate-500">Format</label>
          <div className="flex gap-3">
            {(['csv', 'json'] as Format[]).map(f => (
              <button
                key={f}
                onClick={() => setFormat(f)}
                className={`rounded-full border px-4 py-1.5 text-xs font-bold uppercase transition-colors ${
                  format === f
                    ? 'border-pink-500/40 bg-pink-500/15 text-pink-200'
                    : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Limit */}
        <div>
          <label className="mb-2 block text-xs font-bold uppercase tracking-widest text-slate-500">Max rows</label>
          <select
            value={limit}
            onChange={e => setLimit(Number(e.target.value))}
            className="rounded bg-white/5 border border-white/10 px-3 py-2 text-xs text-slate-300"
          >
            <option value={100}>100</option>
            <option value={1000}>1,000</option>
            <option value={10000}>10,000</option>
            <option value={50000}>50,000</option>
            <option value={100000}>100,000</option>
          </select>
        </div>

        {/* Export button */}
        <button
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center gap-2 rounded bg-pink-600 px-6 py-2.5 text-sm font-bold text-white hover:bg-pink-500 disabled:opacity-50 shadow-[0_0_15px_rgba(236,72,153,0.3)]"
        >
          <Download size={16} />
          {exporting ? 'Exporting...' : `Export ${selectedResource} as ${format.toUpperCase()}`}
        </button>

        {lastExport && (
          <div className={`flex items-center gap-2 rounded border px-3 py-2 text-xs ${
            lastExport.startsWith('Error')
              ? 'border-red-500/30 bg-red-500/10 text-red-300'
              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
          }`}>
            {!lastExport.startsWith('Error') && <CheckCircle size={14} />}
            {lastExport}
          </div>
        )}
      </div>
    </div>
  );
};

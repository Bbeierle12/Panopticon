import React, { useEffect, useState } from 'react';
import { Database, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { NetWatchApi } from '../services/api';

type Resource = 'alerts' | 'devices' | 'scans' | 'vulnerabilities';

const RESOURCES: Array<{ id: Resource; label: string }> = [
  { id: 'alerts', label: 'Alerts' },
  { id: 'devices', label: 'Devices' },
  { id: 'scans', label: 'Scans' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
];

const PAGE_SIZE = 25;

export const DataExplorer: React.FC = () => {
  const [resource, setResource] = useState<Resource>('alerts');
  const [data, setData] = useState<Record<string, unknown>[]>([]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const fetchers: Record<Resource, () => Promise<any[]>> = {
        alerts: () => NetWatchApi.getAlerts({ offset, limit: PAGE_SIZE }),
        devices: () => NetWatchApi.getDevices({ offset, limit: PAGE_SIZE }),
        scans: () => NetWatchApi.getScans({ offset, limit: PAGE_SIZE }),
        vulnerabilities: () => NetWatchApi.getVulnerabilities({ offset, limit: PAGE_SIZE }),
      };
      const rows = await fetchers[resource]();
      setData(rows as Record<string, unknown>[]);
    } catch (e: any) {
      setError(e.message);
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, [resource, offset]);

  const columns = data.length > 0
    ? Object.keys(data[0]).filter(k => !['raw_data', 'results', 'parameters', 'ports', 'references'].includes(k))
    : [];

  return (
    <div className="flex h-full flex-col overflow-hidden bg-black/50 p-6">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Database size={18} className="text-blue-400" />
          <h2 className="text-lg font-bold text-white">Data Explorer</h2>
        </div>
        <button onClick={load} className="flex items-center gap-1.5 rounded bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10 hover:text-white">
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Resource tabs */}
      <div className="mb-4 flex gap-2">
        {RESOURCES.map(r => (
          <button
            key={r.id}
            onClick={() => { setResource(r.id); setOffset(0); setExpandedRow(null); }}
            className={`rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-widest transition-colors ${
              resource === r.id
                ? 'border-blue-500/40 bg-blue-500/15 text-blue-200'
                : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
            }`}
          >
            {r.label}
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-xs text-red-400">{error}</p>}

      {/* Table */}
      <div className="flex-1 overflow-auto rounded border border-white/10">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-black/90">
            <tr>
              {columns.map(col => (
                <th key={col} className="whitespace-nowrap border-b border-white/10 px-3 py-2 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((row, i) => {
              const rowId = String(row.id || i);
              const isExpanded = expandedRow === rowId;
              return (
                <React.Fragment key={rowId}>
                  <tr
                    onClick={() => setExpandedRow(isExpanded ? null : rowId)}
                    className="cursor-pointer border-b border-white/5 hover:bg-white/5 transition-colors"
                  >
                    {columns.map(col => (
                      <td key={col} className="max-w-[200px] truncate px-3 py-2 text-slate-300">
                        {String(row[col] ?? '')}
                      </td>
                    ))}
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={columns.length} className="bg-white/5 px-4 py-3">
                        <pre className="max-h-60 overflow-auto text-[10px] text-slate-400 whitespace-pre-wrap">
                          {JSON.stringify(row, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {data.length === 0 && !loading && (
              <tr><td colSpan={columns.length} className="px-4 py-8 text-center text-slate-600">No records found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
        <span>Showing {offset + 1}-{offset + data.length} (page {Math.floor(offset / PAGE_SIZE) + 1})</span>
        <div className="flex gap-2">
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            className="flex items-center gap-1 rounded bg-white/5 px-2 py-1 hover:bg-white/10 disabled:opacity-30"
          >
            <ChevronLeft size={12} /> Prev
          </button>
          <button
            disabled={data.length < PAGE_SIZE}
            onClick={() => setOffset(offset + PAGE_SIZE)}
            className="flex items-center gap-1 rounded bg-white/5 px-2 py-1 hover:bg-white/10 disabled:opacity-30"
          >
            Next <ChevronRight size={12} />
          </button>
        </div>
      </div>
    </div>
  );
};

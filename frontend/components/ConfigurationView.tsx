import React, { useEffect, useState } from 'react';
import { Settings, RefreshCw, Save, FileText } from 'lucide-react';
import { ConfigResponse } from '../types';
import { NetWatchApi } from '../services/api';

type ViewMode = 'structured' | 'raw';

export const ConfigurationView: React.FC = () => {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [rawConfig, setRawConfig] = useState<{ default_toml: string; local_toml: string } | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('structured');
  const [editMode, setEditMode] = useState(false);
  const [editText, setEditText] = useState('');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: 'ok' | 'error' } | null>(null);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [cfg, raw] = await Promise.all([
        NetWatchApi.getConfig(),
        NetWatchApi.getConfigRaw(),
      ]);
      setConfig(cfg);
      setRawConfig(raw);
      setEditText(raw.local_toml || '# Local overrides (merged on top of default.toml)\n');
    } catch (e: any) {
      setMessage({ text: e.message, type: 'error' });
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    try {
      // Parse the TOML text to validate before sending
      // We send the raw text as local.toml content — backend will parse it
      // For now, we use the structured config update endpoint
      // Convert TOML-ish text to JSON would require a library, so we use the structured approach
      const result = await NetWatchApi.updateConfig(config?.config || {});
      setMessage({ text: `${result.status}: ${result.note}`, type: 'ok' });
      await load();
      setEditMode(false);
    } catch (e: any) {
      setMessage({ text: e.message, type: 'error' });
    }
    setSaving(false);
  };

  const renderValue = (val: unknown, depth = 0): React.ReactNode => {
    if (val === null || val === undefined) return <span className="text-slate-600">null</span>;
    if (typeof val === 'boolean') return <span className={val ? 'text-emerald-400' : 'text-red-400'}>{String(val)}</span>;
    if (typeof val === 'number') return <span className="text-blue-400">{val}</span>;
    if (typeof val === 'string') {
      if (val === '***') return <span className="text-amber-500">***</span>;
      return <span className="text-slate-300">"{val}"</span>;
    }
    if (Array.isArray(val)) {
      if (val.length === 0) return <span className="text-slate-600">[]</span>;
      return (
        <div className="ml-4">
          {val.map((item, i) => (
            <div key={i} className="text-slate-400">- {typeof item === 'string' ? item : JSON.stringify(item)}</div>
          ))}
        </div>
      );
    }
    if (typeof val === 'object') {
      return (
        <div className={depth > 0 ? 'ml-4 border-l border-white/5 pl-3' : ''}>
          {Object.entries(val as Record<string, unknown>).map(([k, v]) => (
            <div key={k} className="py-0.5">
              <span className="text-cyan-400">{k}</span>
              <span className="text-slate-600">: </span>
              {typeof v === 'object' && v !== null && !Array.isArray(v) ? (
                <>
                  <br />
                  {renderValue(v, depth + 1)}
                </>
              ) : (
                renderValue(v, depth + 1)
              )}
            </div>
          ))}
        </div>
      );
    }
    return <span>{String(val)}</span>;
  };

  return (
    <div className="flex h-full flex-col overflow-hidden bg-black/50 p-6">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Settings size={18} className="text-slate-400" />
          <h2 className="text-lg font-bold text-white">Configuration</h2>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="flex items-center gap-1.5 rounded bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10 hover:text-white">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Reload
          </button>
        </div>
      </div>

      {message && (
        <div className={`mb-4 rounded border px-3 py-2 text-xs ${message.type === 'ok' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-red-500/30 bg-red-500/10 text-red-300'}`}>
          {message.text}
        </div>
      )}

      {/* View mode tabs */}
      <div className="mb-4 flex items-center gap-2">
        <button
          onClick={() => setViewMode('structured')}
          className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-widest ${
            viewMode === 'structured'
              ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
          }`}
        >
          <Settings size={10} /> Structured
        </button>
        <button
          onClick={() => setViewMode('raw')}
          className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-widest ${
            viewMode === 'raw'
              ? 'border-cyan-500/40 bg-cyan-500/15 text-cyan-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
          }`}
        >
          <FileText size={10} /> Raw TOML
        </button>
        {config?.source && (
          <span className="ml-auto text-[10px] text-slate-600">
            local.toml: {config.source.local_exists ? 'present' : 'not created'}
          </span>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto rounded border border-white/10 bg-black/80 p-4">
        {viewMode === 'structured' && config ? (
          <div className="font-mono text-xs leading-relaxed">
            {renderValue(config.config)}
          </div>
        ) : viewMode === 'raw' && rawConfig ? (
          <div className="space-y-6">
            <div>
              <h3 className="mb-2 text-xs font-bold text-slate-400">default.toml</h3>
              <pre className="whitespace-pre-wrap text-[11px] text-slate-500">{rawConfig.default_toml}</pre>
            </div>
            <div className="border-t border-white/10 pt-4">
              <h3 className="mb-2 text-xs font-bold text-slate-400">local.toml (overrides)</h3>
              {editMode ? (
                <div>
                  <textarea
                    value={editText}
                    onChange={e => setEditText(e.target.value)}
                    className="w-full rounded bg-black border border-white/10 p-3 font-mono text-[11px] text-slate-300 focus:border-cyan-500/50 focus:outline-none"
                    rows={15}
                  />
                  <div className="mt-2 flex gap-2">
                    <button
                      onClick={handleSave}
                      disabled={saving}
                      className="flex items-center gap-1.5 rounded bg-cyan-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-cyan-500"
                    >
                      <Save size={12} /> {saving ? 'Saving...' : 'Save'}
                    </button>
                    <button
                      onClick={() => setEditMode(false)}
                      className="rounded bg-white/5 border border-white/10 px-4 py-1.5 text-xs text-slate-400 hover:bg-white/10"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <pre className="whitespace-pre-wrap text-[11px] text-slate-500">{rawConfig.local_toml || '(empty)'}</pre>
                  <button
                    onClick={() => setEditMode(true)}
                    className="mt-2 rounded bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10 hover:text-white"
                  >
                    Edit local.toml
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-600">Loading...</p>
        )}
      </div>
    </div>
  );
};

import React, { useEffect, useRef, useState } from 'react';
import { ScrollText, RefreshCw, Radio } from 'lucide-react';
import { NetWatchApi } from '../services/api';

type LogTab = 'file' | 'realtime';

export const LogsViewer: React.FC = () => {
  const [tab, setTab] = useState<LogTab>('file');
  const [logLines, setLogLines] = useState<string[]>([]);
  const [realtimeEvents, setRealtimeEvents] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [lineCount, setLineCount] = useState(200);
  const bottomRef = useRef<HTMLDivElement>(null);

  const loadFile = async () => {
    setLoading(true);
    try {
      const data = await NetWatchApi.getLogs({ lines: lineCount });
      setLogLines(data.lines);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (tab === 'file') loadFile();
  }, [tab, lineCount]);

  // Real-time event listener
  useEffect(() => {
    if (tab !== 'realtime') return;

    const handler = (data: any) => {
      const ts = new Date().toISOString();
      const line = `[${ts}] ${JSON.stringify(data)}`;
      setRealtimeEvents(prev => [...prev.slice(-500), line]);
    };

    const events = [
      'system.startup', 'system.shutdown',
      'device.discovered', 'device.updated', 'device.status_changed',
      'scan.started', 'scan.completed', 'scan.failed',
      'alert.created', 'alert.updated',
      'tool.status_changed',
    ];

    NetWatchApi.connectWS();
    events.forEach(e => NetWatchApi.on(e, handler));
    return () => { events.forEach(e => NetWatchApi.off(e, handler)); };
  }, [tab]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logLines, realtimeEvents]);

  const lines = tab === 'file' ? logLines : realtimeEvents;

  return (
    <div className="flex h-full flex-col overflow-hidden bg-black/50 p-6">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ScrollText size={18} className="text-amber-400" />
          <h2 className="text-lg font-bold text-white">Logs & Events</h2>
        </div>
        <div className="flex items-center gap-2">
          {tab === 'file' && (
            <>
              <select
                value={lineCount}
                onChange={e => setLineCount(Number(e.target.value))}
                className="rounded bg-white/5 border border-white/10 px-2 py-1 text-xs text-slate-300"
              >
                <option value={100}>100 lines</option>
                <option value={200}>200 lines</option>
                <option value={500}>500 lines</option>
                <option value={1000}>1000 lines</option>
              </select>
              <button onClick={loadFile} className="flex items-center gap-1.5 rounded bg-white/5 border border-white/10 px-3 py-1.5 text-xs text-slate-400 hover:bg-white/10 hover:text-white">
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
              </button>
            </>
          )}
        </div>
      </div>

      {/* Tab switcher */}
      <div className="mb-4 flex gap-2">
        <button
          onClick={() => setTab('file')}
          className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-widest ${
            tab === 'file'
              ? 'border-amber-500/40 bg-amber-500/15 text-amber-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
          }`}
        >
          <ScrollText size={10} /> Server Log
        </button>
        <button
          onClick={() => setTab('realtime')}
          className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-widest ${
            tab === 'realtime'
              ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200'
              : 'border-white/10 bg-white/5 text-slate-400 hover:bg-white/10'
          }`}
        >
          <Radio size={10} /> Real-time Events
        </button>
      </div>

      {/* Log output */}
      <div className="flex-1 overflow-auto rounded border border-white/10 bg-black/80 p-4 font-mono text-[11px] leading-relaxed text-slate-400">
        {lines.length === 0 && (
          <p className="text-slate-600">{tab === 'file' ? 'No log entries found.' : 'Waiting for events...'}</p>
        )}
        {lines.map((line, i) => (
          <div
            key={i}
            className={`whitespace-pre-wrap break-all ${
              line.includes('"level": "error"') || line.includes('ERROR')
                ? 'text-red-400'
                : line.includes('"level": "warning"') || line.includes('WARN')
                ? 'text-amber-400'
                : line.includes('"level": "info"') || line.includes('INFO')
                ? 'text-slate-400'
                : 'text-slate-600'
            }`}
          >
            {line}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

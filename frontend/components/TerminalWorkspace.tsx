import React, { useEffect, useState, useCallback } from 'react';
import { Terminal as TermIcon } from 'lucide-react';
import { XTerminal } from './XTerminal';
import { TerminalTabs } from './TerminalTabs';
import { useAvailableShells } from '../hooks/useTerminalSession';
import { ShellInfo, TerminalTab, TerminalSessionState } from '../types';

let wsTabIdCounter = 100;
const generateTabId = () => `ws-tab-${++wsTabIdCounter}`;

export const TerminalWorkspace: React.FC = () => {
  const [tabs, setTabs] = useState<TerminalTab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<Map<string, string | null>>(new Map());

  const { shells, loading: shellsLoading } = useAvailableShells();

  // Auto-create first tab
  useEffect(() => {
    if (shells.length > 0 && tabs.length === 0) {
      const defaultShell = shells[0];
      const newTabId = generateTabId();
      const newTab: TerminalTab = {
        id: newTabId,
        sessionId: null,
        shell: defaultShell,
        state: 'idle',
        title: defaultShell.name,
      };
      setTabs([newTab]);
      setActiveTabId(newTabId);
    }
  }, [shells, tabs.length]);

  const handleNewTab = useCallback((shell: ShellInfo) => {
    const newTabId = generateTabId();
    const newTab: TerminalTab = {
      id: newTabId,
      sessionId: null,
      shell,
      state: 'idle',
      title: shell.name,
    };
    setTabs(prev => [...prev, newTab]);
    setActiveTabId(newTabId);
  }, []);

  const handleTabClose = useCallback((tabId: string) => {
    setTabs(prev => {
      const newTabs = prev.filter(t => t.id !== tabId);
      if (activeTabId === tabId && newTabs.length > 0) {
        const closedIndex = prev.findIndex(t => t.id === tabId);
        const newActiveIndex = Math.min(closedIndex, newTabs.length - 1);
        setActiveTabId(newTabs[newActiveIndex].id);
      } else if (newTabs.length === 0) {
        setActiveTabId(null);
      }
      return newTabs;
    });
    setSessions(prev => {
      const newSessions = new Map(prev);
      newSessions.delete(tabId);
      return newSessions;
    });
  }, [activeTabId]);

  const handleTabSelect = useCallback((tabId: string) => {
    setActiveTabId(tabId);
  }, []);

  const handleSessionCreated = useCallback((tabId: string, sessionId: string) => {
    setSessions(prev => new Map(prev).set(tabId, sessionId));
    setTabs(prev => prev.map(t =>
      t.id === tabId ? { ...t, sessionId, state: 'connected' as TerminalSessionState } : t
    ));
  }, []);

  const handleSessionStateChange = useCallback((tabId: string, state: TerminalSessionState) => {
    setTabs(prev => prev.map(t =>
      t.id === tabId ? { ...t, state } : t
    ));
  }, []);

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[#07090d]">
      {/* Tab bar */}
      <TerminalTabs
        tabs={tabs}
        activeTabId={activeTabId}
        shells={shells}
        onTabSelect={handleTabSelect}
        onTabClose={handleTabClose}
        onNewTab={handleNewTab}
      />

      {/* Full-height terminal area */}
      <div className="flex-1 overflow-hidden relative">
        {tabs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-slate-500">
            <TermIcon size={40} className="text-slate-700" />
            {shellsLoading ? (
              <span className="text-sm">Detecting available shells...</span>
            ) : (
              <>
                <span className="text-sm">No active sessions</span>
                <div className="flex flex-wrap gap-2">
                  {shells.map(shell => (
                    <button
                      key={shell.id}
                      onClick={() => handleNewTab(shell)}
                      className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-slate-300 hover:bg-white/10 hover:text-white transition-colors"
                    >
                      <TermIcon size={14} />
                      {shell.name}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        ) : (
          tabs.map((tab) => (
            <div
              key={tab.id}
              className={`absolute inset-0 ${tab.id === activeTabId ? 'visible' : 'invisible'}`}
            >
              <XTerminal
                tabId={tab.id}
                shell={tab.shell}
                sessionId={sessions.get(tab.id) || null}
                onSessionCreated={(sessionId) => handleSessionCreated(tab.id, sessionId)}
                onStateChange={(state) => handleSessionStateChange(tab.id, state)}
              />
            </div>
          ))
        )}
      </div>
    </div>
  );
};

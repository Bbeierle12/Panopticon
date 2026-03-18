
import React, { useRef, useState } from 'react';
import { Layers, FolderPlus } from 'lucide-react';
import { Scanlines } from './components/Scanlines';
import { Header } from './components/Header';
import { Toolbar } from './components/Toolbar';
import { ScanningOverlay } from './components/ScanningOverlay';
import { NetworkCanvas } from './components/NetworkCanvas';
import { InspectorPanel } from './components/InspectorPanel';
import { ConsolePanel } from './components/ConsolePanel';
import { SentinelDashboard } from './components/SentinelDashboard';
import { OverviewDashboard } from './components/OverviewDashboard';
import { AlertsDashboard } from './components/AlertsDashboard';
import { VulnerabilitiesWorkspace } from './components/VulnerabilitiesWorkspace';
import { HubDashboard } from './components/HubDashboard';
import { DataExplorer } from './components/DataExplorer';
import { LogsViewer } from './components/LogsViewer';
import { SystemStatus } from './components/SystemStatus';
import { ConfigurationView } from './components/ConfigurationView';
import { ExportView } from './components/ExportView';

import { useNetwork } from './hooks/useNetwork';
import { useScanner } from './hooks/useScanner';
import { useInteraction } from './hooks/useInteraction';
import { usePentest } from './hooks/usePentest';
import { AppModule } from './types';

export default function NetworkMapper() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredConnection, setHoveredConnection] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [activeModule, setActiveModule] = useState<AppModule>('hub');

  // Custom Hooks for Logic Separation
  const { 
    nodes, setNodes, connections, setConnections, 
    addNode, createGroup, deleteSelection, 
    saveTopology, loadTopology 
  } = useNetwork();
  
  const { isScanning, scanProgress, scanError, scanNetwork } = useScanner(nodes, setSelectedIds);
  const { executeCommand } = usePentest(nodes);
  
  const {
    mode, setMode, pan, isPanning, selectionBox,
    handleMouseDown, handleMouseMove, handleMouseUp, handleNodeDown
  } = useInteraction({
    svgRef, nodes, setNodes, connections, setConnections, selectedIds, setSelectedIds
  });

  const selectedNode = selectedIds.length === 1 ? nodes.find(n => n.id === selectedIds[0]) : null;

  const handleAddNode = (type: any) => {
    const id = addNode(type, pan);
    setSelectedIds([id]);
  };

  const handleCreateGroup = () => {
    const groupId = createGroup(selectedIds);
    if (groupId) setSelectedIds([groupId]);
  };

  const handleDelete = () => {
    deleteSelection(selectedIds);
    setSelectedIds([]);
  };

  return (
    <div className="relative flex h-screen w-full flex-col overflow-hidden bg-black font-mono text-slate-200 selection:bg-cyan-500/30">
      <Scanlines />
      <style>
        {`
          @keyframes scanline { 0% { background-position: 0% 0%; } 100% { background-position: 0% 100%; } }
          @keyframes dash { to { stroke-dashoffset: -20; } }
          @keyframes pulse-ring { 0% { transform: scale(0.8); opacity: 0.5; } 100% { transform: scale(1.5); opacity: 0; } }
          .animate-scanline { animation: scanline 8s linear infinite; }
          .animate-dash { animation: dash 1s linear infinite; }
          .animate-pulse-ring { animation: pulse-ring 2s cubic-bezier(0.24, 0, 0.38, 1) infinite; }
          @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
          .animate-spin-slow { animation: spin 15s linear infinite; }
        `}
      </style>

      {/* HEADER */}
      <Header 
        activeModule={activeModule}
        isScanning={isScanning}
        scanError={scanError}
        onScan={scanNetwork}
        onSave={saveTopology}
        onLoad={() => { if(loadTopology()) setSelectedIds([]); }}
        onSelectModule={setActiveModule}
      />

      {/* MAIN WORKSPACE + TERMINAL */}
      <div className="relative flex min-h-0 flex-1 flex-col overflow-hidden">
        {/* WORKSPACE ROW */}
        <div className="relative flex min-h-0 flex-1 overflow-hidden">
          {activeModule === 'network' ? (
            <>
              <ScanningOverlay isScanning={isScanning} scanProgress={scanProgress} />

              <Toolbar
                mode={mode}
                setMode={setMode}
                onAddNode={handleAddNode}
                onGroup={handleCreateGroup}
                onDelete={handleDelete}
                onPentest={(tool) => executeCommand(tool, selectedIds)}
              />

              <div className="relative flex-1 bg-[#050505] overflow-hidden">
                <div
                  className="absolute inset-0 opacity-10 pointer-events-none"
                  style={{
                    backgroundImage: `linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)`,
                    backgroundSize: '40px 40px',
                    backgroundPosition: `${pan.x}px ${pan.y}px`
                  }}
                />

                <NetworkCanvas
                  ref={svgRef}
                  nodes={nodes}
                  connections={connections}
                  pan={pan}
                  isPanning={isPanning}
                  selectedIds={selectedIds}
                  selectionBox={selectionBox}
                  hoveredConnection={hoveredConnection}
                  setHoveredConnection={setHoveredConnection}
                  onMouseDown={handleMouseDown}
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  onNodeDown={handleNodeDown}
                />
              </div>

              {selectedNode && (
                <InspectorPanel
                  selectedNode={selectedNode}
                  nodes={nodes}
                  connections={connections}
                  hoveredConnection={hoveredConnection}
                  setHoveredConnection={setHoveredConnection}
                  onClose={() => setSelectedIds([])}
                />
              )}

              {selectedIds.length > 1 && (
                <div className="z-30 w-80 border-l border-white/10 bg-black/90 p-6 flex flex-col items-center justify-center text-center">
                  <div className="mb-4 p-4 rounded-full bg-cyan-500/10 text-cyan-400">
                    <Layers size={32} />
                  </div>
                  <h2 className="text-lg font-bold text-white mb-2">Multiple Selection</h2>
                  <p className="text-xs text-slate-400 mb-6">{selectedIds.length} nodes selected. Group them to organize your topology.</p>

                  <button
                    onClick={handleCreateGroup}
                    className="flex items-center gap-2 rounded bg-cyan-600 px-6 py-2 text-xs font-bold text-white hover:bg-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.4)]"
                  >
                    <FolderPlus size={14} /> CREATE GROUP
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="flex-1 overflow-hidden">
              {activeModule === 'hub' ? <HubDashboard onSelectModule={setActiveModule} /> : null}
              {activeModule === 'overview' ? <OverviewDashboard onSelectModule={setActiveModule} /> : null}
              {activeModule === 'desktop_safety' ? (
                <SentinelDashboard
                  embedded
                  onShowVulnReport={() => setActiveModule('vulnerabilities')}
                />
              ) : null}
              {activeModule === 'vulnerabilities' ? <VulnerabilitiesWorkspace /> : null}
              {activeModule === 'alerts' ? <AlertsDashboard /> : null}
              {activeModule === 'data_explorer' ? <DataExplorer /> : null}
              {activeModule === 'logs' ? <LogsViewer /> : null}
              {activeModule === 'system_status' ? <SystemStatus /> : null}
              {activeModule === 'configuration' ? <ConfigurationView /> : null}
              {activeModule === 'export' ? <ExportView /> : null}
            </div>
          )}
        </div>

        {/* CONSOLE PANEL - below the workspace row, never overlaps sidebar */}
        <ConsolePanel />
      </div>
    </div>
  );
}

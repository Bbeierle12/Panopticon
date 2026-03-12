/**
 * React Widget Entry Point for Embedded NetworkCanvas
 *
 * This standalone widget is designed to be embedded in a Wry webview
 * within the Rust Iced desktop application. It renders the NetworkCanvas
 * component and handles bidirectional communication with the Rust host.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { NetworkCanvas } from '../components/NetworkCanvas';
import { Node, Connection } from '../types';

// Diagnostic: mark that the bundle loaded successfully
(window as any).__widgetBundleLoaded = true;
console.log("[bundle boot]");

// Types matching the Rust IPC protocol
interface NetworkStateJson {
  seq: number;
  nodes: NodeJson[];
  connections: ConnectionJson[];
  selected_ids: string[];
  hovered_connection: string | null;
  pan: [number, number];
  zoom: number;
  connecting_from: string | null;
  is_scanning: boolean;
  scan_progress: number;
}

interface NodeJson {
  id: string;
  type: string;
  x: number;
  y: number;
  label: string;
  status: string;
  ip: string;
  mac?: string;
  vendor?: string;
  oui?: string;
  hostname?: string;
  os_family?: string;
  signal_strength?: number;
  ssids?: string[];
  ports?: PortJson[];
  vulnerabilities?: VulnerabilityJson[];
  parent_id?: string;
  width?: number;
  height?: number;
}

interface PortJson {
  number: number;
  protocol: string;
  state: string;
  service_name?: string;
  service_version?: string;
}

interface VulnerabilityJson {
  cve: string;
  cvss: number;
  severity: string;
  description: string;
  references?: string[];
}

interface ConnectionJson {
  id: string;
  from: string;
  to: string;
  type: string;
  traffic: number;
  ssid?: string;
  speed?: string;
}

// IPC types for sending events to Rust
type IpcEvent =
  | { type: 'Ready' }
  | { type: 'NodeSelected'; id: string; add_to_selection: boolean }
  | { type: 'NodeDeselected' }
  | { type: 'NodeMoved'; id: string; x: number; y: number }
  | { type: 'CanvasPan'; dx: number; dy: number }
  | { type: 'CanvasZoom'; zoom: number }
  | { type: 'StartConnection'; from_id: string }
  | { type: 'CompleteConnection'; to_id: string }
  | { type: 'CancelConnection' }
  | { type: 'ConnectionHovered'; id: string | null };

// Convert JSON node to internal Node type
function jsonToNode(json: NodeJson): Node {
  return {
    id: json.id,
    type: json.type as Node['type'],
    x: json.x,
    y: json.y,
    label: json.label,
    status: json.status as Node['status'],
    ip: json.ip,
    vendor: json.vendor,
    oui: json.oui,
    parentId: json.parent_id,
    signalStrength: json.signal_strength,
    ssids: json.ssids,
    width: json.width,
    height: json.height,
    ports: json.ports?.map(p => p.number),
    vulnerabilities: json.vulnerabilities?.map(v => v.cve),
    detailedVulnerabilities: json.vulnerabilities?.map(v => ({
      cve: v.cve,
      cvss: v.cvss,
      severity: v.severity as 'low' | 'medium' | 'high' | 'critical',
      description: v.description,
      references: v.references || [],
    })),
  };
}

// Convert JSON connection to internal Connection type
function jsonToConnection(json: ConnectionJson): Connection {
  return {
    id: json.id,
    from: json.from,
    to: json.to,
    traffic: json.traffic,
    type: json.type as 'wired' | 'wireless',
    ssid: json.ssid,
    speed: json.speed,
  };
}

// Send event to Rust via Wry IPC
function postToRust(event: IpcEvent): void {
  try {
    // Wry's IPC uses window.ipc.postMessage
    if ((window as any).ipc?.postMessage) {
      (window as any).ipc.postMessage(JSON.stringify(event));
    } else {
      // Fallback for development/testing
      console.log('[IPC]', event);
    }
  } catch (e) {
    console.error('Failed to send IPC message:', e);
  }
}

// Main widget component
function NetworkCanvasWidget() {
  const svgRef = useRef<SVGSVGElement>(null);

  // State from Rust
  const [nodes, setNodes] = useState<Node[]>([]);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [hoveredConnection, setHoveredConnection] = useState<string | null>(null);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  // Local interaction state
  const [isPanning, setIsPanning] = useState(false);
  const [selectionBox, setSelectionBox] = useState<{ start: { x: number; y: number }; current: { x: number; y: number } } | null>(null);
  const [dragState, setDragState] = useState<{ nodeId: string; startX: number; startY: number } | null>(null);

  // Apply a network state update to React state
  const applyState = useCallback((state: NetworkStateJson, source: string) => {
    try {
      const mapped = state.nodes.map(jsonToNode);
      const mappedConns = state.connections.map(jsonToConnection);
      const badCoords = mapped.filter(n => !Number.isFinite(n.x) || !Number.isFinite(n.y));

      console.log(`[react bridge recv] source=${source} seq=${(state as any).seq} nodes=${mapped.length} conns=${mappedConns.length} badCoords=${badCoords.length}`);
      if (badCoords.length > 0) {
        console.warn("[react bridge] bad coords sample:", badCoords[0]);
      }

      setNodes(mapped);
      setConnections(mappedConns);
      setSelectedIds(state.selected_ids);
      setHoveredConnection(state.hovered_connection);
      setPan({ x: state.pan[0], y: state.pan[1] });
      setZoom(state.zoom);
      setIsScanning(state.is_scanning);
      setScanProgress(state.scan_progress);
      (window as any).__lastSeq = (state as any).seq;
    } catch (e) {
      console.error(`[react bridge] FAILED source=${source}`, e, state);
    }
  }, []);

  // Handle state updates from Rust
  useEffect(() => {
    console.log("[react bridge installed]");
    (window as any).__bridgeVariant = "react";

    // Register the update function on window for Rust to call
    (window as any).updateNetworkState = (state: NetworkStateJson) => {
      applyState(state, "live");
    };

    // Consume any state buffered by the placeholder bridge (bridge race fix)
    const buffered = (window as any).__bufferedNetworkState;
    if (buffered) {
      console.log("[react bridge] consuming buffered state, seq=" + buffered.seq +
                  " nodes=" + (buffered.nodes?.length ?? 0));
      applyState(buffered, "buffered");
      delete (window as any).__bufferedNetworkState;
    }

    // Notify Rust that we're ready
    postToRust({ type: 'Ready' });

    return () => {
      console.log("[react bridge removed]");
      (window as any).__bridgeVariant = "none";
      delete (window as any).updateNetworkState;
    };
  }, [applyState]);

  // Mouse handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0) { // Left click
      if (e.shiftKey || e.ctrlKey) {
        // Start selection box
        setSelectionBox({
          start: { x: e.clientX, y: e.clientY },
          current: { x: e.clientX, y: e.clientY },
        });
      } else {
        // Start panning
        setIsPanning(true);
      }
    }
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isPanning) {
      const dx = e.movementX / zoom;
      const dy = e.movementY / zoom;
      setPan(p => ({ x: p.x + dx, y: p.y + dy }));
      postToRust({ type: 'CanvasPan', dx, dy });
    } else if (selectionBox) {
      setSelectionBox(sb => sb ? { ...sb, current: { x: e.clientX, y: e.clientY } } : null);
    } else if (dragState) {
      const node = nodes.find(n => n.id === dragState.nodeId);
      if (node) {
        const dx = (e.clientX - dragState.startX) / zoom;
        const dy = (e.clientY - dragState.startY) / zoom;
        const newX = node.x + dx;
        const newY = node.y + dy;

        // Update local state immediately for responsiveness
        setNodes(ns => ns.map(n =>
          n.id === dragState.nodeId ? { ...n, x: newX, y: newY } : n
        ));

        // Notify Rust
        postToRust({ type: 'NodeMoved', id: dragState.nodeId, x: newX, y: newY });

        // Update drag start position
        setDragState({ ...dragState, startX: e.clientX, startY: e.clientY });
      }
    }
  }, [isPanning, selectionBox, dragState, zoom, nodes]);

  const handleMouseUp = useCallback((e: React.MouseEvent) => {
    if (isPanning) {
      setIsPanning(false);
    } else if (selectionBox) {
      // Calculate selected nodes within box
      // TODO: implement selection box node detection
      setSelectionBox(null);
    } else if (dragState) {
      setDragState(null);
    } else if (!dragState && e.target === svgRef.current) {
      // Clicked on background - deselect
      setSelectedIds([]);
      postToRust({ type: 'NodeDeselected' });
    }
  }, [isPanning, selectionBox, dragState]);

  const handleNodeDown = useCallback((e: React.MouseEvent, id: string) => {
    e.stopPropagation();

    const addToSelection = e.shiftKey || e.ctrlKey;

    // Select the node
    if (addToSelection) {
      setSelectedIds(ids => ids.includes(id) ? ids : [...ids, id]);
    } else {
      setSelectedIds([id]);
    }
    postToRust({ type: 'NodeSelected', id, add_to_selection: addToSelection });

    // Start dragging
    setDragState({ nodeId: id, startX: e.clientX, startY: e.clientY });
  }, []);

  const handleConnectionHover = useCallback((id: string | null) => {
    setHoveredConnection(id);
    postToRust({ type: 'ConnectionHovered', id });
  }, []);

  // Wheel handler for zoom
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      const newZoom = Math.max(0.25, Math.min(4, zoom * delta));
      setZoom(newZoom);
      postToRust({ type: 'CanvasZoom', zoom: newZoom });
    };

    svg.addEventListener('wheel', handleWheel, { passive: false });
    return () => svg.removeEventListener('wheel', handleWheel);
  }, [zoom]);

  return (
    <div className="relative h-full w-full bg-black overflow-hidden">
      {/* Debug overlay */}
      <div style={{ position: 'absolute', top: 4, left: 4, zIndex: 50, color: '#22d3ee', fontSize: 10, fontFamily: 'monospace', background: 'rgba(0,0,0,0.8)', padding: '2px 6px', borderRadius: 4 }}>
        {nodes.length} nodes | {connections.length} conns | seq {(window as any).__lastSeq ?? "none"} | pan=({pan.x.toFixed(0)},{pan.y.toFixed(0)}) | zoom={zoom.toFixed(2)}
        {nodes.length > 0 && ` | first=(${nodes[0].x.toFixed(0)},${nodes[0].y.toFixed(0)})`}
        {' | bridge='}{(window as any).__bridgeVariant ?? '?'}
      </div>

      {/* Scanning overlay */}
      {isScanning && (
        <div className="absolute top-2 right-2 z-10 bg-black/80 border border-cyan-500/30 rounded px-3 py-1">
          <span className="text-cyan-400 text-xs font-mono">
            SCANNING... {scanProgress}%
          </span>
        </div>
      )}

      <NetworkCanvas
        ref={svgRef}
        nodes={nodes}
        connections={connections}
        pan={pan}
        isPanning={isPanning}
        selectedIds={selectedIds}
        selectionBox={selectionBox}
        hoveredConnection={hoveredConnection}
        setHoveredConnection={handleConnectionHover}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onNodeDown={handleNodeDown}
      />
    </div>
  );
}

// Mount the widget
const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(
    <React.StrictMode>
      <NetworkCanvasWidget />
    </React.StrictMode>
  );
}

// Export for module use
export { NetworkCanvasWidget };

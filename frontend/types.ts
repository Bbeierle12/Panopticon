
export type NodeType = 'server' | 'firewall' | 'router' | 'database' | 'workstation' | 'mobile' | 'cloud' | 'iot' | 'extender' | 'group';

// ============ API Models (aligned with backend schemas) ============

export interface ApiPort {
  id: string;
  port_number: number;
  protocol: string;
  state: string;
  service_name?: string;
  service_version?: string;
  banner?: string;
}

export interface ApiDevice {
  id: string;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  vendor?: string;
  os_family?: string;
  os_version?: string;
  device_type?: string;
  status: 'online' | 'offline' | 'warning' | 'compromised';
  first_seen: string;
  last_seen: string;
  notes?: string;
  ports: ApiPort[];
  created_at: string;
  updated_at: string;
}

export interface ApiAlert {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info';
  status: string;
  source_tool: string;
  source_event_id?: string;
  category?: string;
  device_ip?: string;
  fingerprint?: string;
  count: number;
  first_seen: string;
  last_seen: string;
  raw_data?: Record<string, unknown>;
  correlation_id?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SentinelFeedMetadataEntry {
  name: string;
  status: string;
  updated_at: string;
  counts: Record<string, number>;
  file: string;
  message?: string;
}

export interface SentinelFeedsStatus {
  metadata: Record<string, SentinelFeedMetadataEntry>;
  ioc_counts: Record<string, number>;
}

export interface SentinelVulnerabilityMatch {
  id: string;
  timestamp: string;
  package: string;
  version: string;
  cve_id: string;
  severity: string;
  source: string;
  exploited: number;
  detail: string;
}

export interface SentinelSnapshotStatus {
  process?: string | null;
  network?: string | null;
  file_hashes?: string | null;
  auth?: string | null;
  persistence?: string | null;
  metrics?: string | null;
}

export interface SentinelStatus {
  enabled: boolean;
  db_path: string;
  snapshots: SentinelSnapshotStatus;
  feeds: SentinelFeedsStatus;
  recent_vulns: SentinelVulnerabilityMatch[];
}

export interface SentinelCollectResult {
  timestamp: string;
  counts: Record<string, number>;
  warnings: string[];
  pruned: Record<string, number>;
}

export interface SentinelCorrelationResult {
  count: number;
  warnings: string[];
  alerts: Record<string, unknown>[];
  ingestion?: {
    submitted: number;
    created: number;
    deduped: number;
    alert_ids: string[];
  };
}

export interface SentinelVulnReport {
  rows: SentinelVulnerabilityMatch[];
}

export interface ApiVulnerability {
  id: string;
  title: string;
  description?: string;
  cve_id?: string;
  cvss_score?: number;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info';
  status: string;
  device_id?: string;
  device_ip?: string;
  port?: number;
  service?: string;
  source_tool: string;
  solution?: string;
  references?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ApiScan {
  id: string;
  scan_type: string;
  tool: string;
  target: string;
  status: string;
  progress: number;
  started_at?: string;
  completed_at?: string;
  result_summary?: string;
  error_message?: string;
  parameters?: Record<string, unknown>;
  results?: Record<string, unknown>;
  devices_found: number;
  alerts_generated: number;
  created_at: string;
  updated_at: string;
}

export interface ApiToolInfo {
  name: string;
  display_name: string;
  category: string;
  description: string;
  version?: string;
  status: string;
  supported_tasks: string[];
}

export interface AlertStats {
  total: number;
  open_by_severity: Record<string, number>;
  open_by_tool: Record<string, number>;
}

// ============ Request/Response types ============

export interface ScanCreateParams {
  scan_type: 'network' | 'vulnerability' | 'traffic' | 'malware';
  tool: string;
  target: string;
  parameters?: Record<string, unknown>;
}

export interface ToolExecuteParams {
  tool: string;
  task: string;
  result: unknown;
}

// ============ WebSocket Event types ============

export interface WsDeviceEvent {
  device_id: string;
  ip: string;
  hostname?: string;
}

export interface WsScanEvent {
  scan_id: string;
  status?: string;
  progress?: number;
}

export interface WsAlertEvent {
  alert_id: string;
}

export interface Vulnerability {
  cve: string;
  cvss: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  references: string[];
}

export interface Node {
  id: string;
  type: NodeType;
  x: number;
  y: number;
  label: string;
  status: 'online' | 'offline' | 'warning' | 'compromised';
  ip: string;
  vendor?: string; // Brand/Manufacturer
  oui?: string; // Organizationally Unique Identifier
  parentId?: string;
  signalStrength?: number;
  ssids?: string[]; // Broadcasted networks
  width?: number; // For groups
  height?: number; // For groups
  ports?: number[]; // Open ports numbers for quick visual
  apiData?: ApiDevice; // Full API data reference
  vulnerabilities?: string[]; // Vulnerabilities found (simple list)
  detailedVulnerabilities?: Vulnerability[]; // Structured list
}

export interface Connection {
  id: string;
  from: string;
  to: string;
  traffic: number;
  type: 'wired' | 'wireless';
  ssid?: string;
  speed?: string;
}

// ============ Terminal types ============

export interface ShellInfo {
  id: string;
  name: string;
  path: string;
}

export type TerminalSessionState = 'idle' | 'creating' | 'connected' | 'error' | 'disconnected';

export interface TerminalTab {
  id: string;
  sessionId: string | null;
  shell: ShellInfo | null;
  state: TerminalSessionState;
  title: string;
}

export type AppModule = 'hub' | 'overview' | 'network' | 'desktop_safety' | 'vulnerabilities' | 'alerts' | 'data_explorer' | 'logs' | 'system_status' | 'configuration' | 'export';

// ============ Hub types ============

export interface HubStatus {
  timestamp: string;
  health: { status: string; version: string };
  counts: {
    alerts: number;
    devices: number;
    scans: number;
    vulnerabilities: number;
  };
  tools: Array<{ name: string; status: string }>;
  adapters: Array<{ name: string; display_name: string; status: string }>;
  scheduler_jobs: Array<{ name: string; trigger_type: string; next_run?: string }>;
  ws_clients: number;
}

export interface ConfigResponse {
  config: Record<string, unknown>;
  source: {
    default: string;
    local: string;
    local_exists: boolean;
  };
}

export interface LogFileResponse {
  file: string;
  exists: boolean;
  total_lines: number;
  lines: string[];
}

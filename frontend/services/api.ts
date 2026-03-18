
import {
  ApiAlert,
  ApiDevice,
  ApiScan,
  ApiToolInfo,
  ApiVulnerability,
  AlertStats,
  ConfigResponse,
  HubStatus,
  LogFileResponse,
  ScanCreateParams,
  SentinelCollectResult,
  SentinelCorrelationResult,
  SentinelStatus,
  SentinelVulnReport,
  ToolExecuteParams,
} from '../types';

const API_ORIGIN = (import.meta.env.VITE_NETSEC_API_ORIGIN as string | undefined)?.replace(/\/$/, '') || 'http://127.0.0.1:8420';
const API_BASE = `${API_ORIGIN}/api`;
const WS_URL = (import.meta.env.VITE_NETSEC_WS_URL as string | undefined) || `${API_ORIGIN.replace(/^http/, 'ws')}/ws`;

export class NetWatchApi {
  private static ws: WebSocket | null = null;
  private static handlers: Record<string, ((data: any) => void)[]> = {};
  private static apiKey: string | null = null;

  /** Set API key for authenticated requests */
  static setApiKey(key: string | null) {
    this.apiKey = key;
  }

  private static getHeaders(): HeadersInit {
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    return headers;
  }

  // ============ Devices ============

  static async getDevices(params?: { offset?: number; limit?: number; status?: string }): Promise<ApiDevice[]> {
    try {
      const query = new URLSearchParams();
      if (params?.offset) query.set('offset', String(params.offset));
      if (params?.limit) query.set('limit', String(params.limit));
      if (params?.status) query.set('status', params.status);

      const url = `${API_BASE}/devices${query.toString() ? '?' + query : ''}`;
      const res = await fetch(url, { headers: this.getHeaders() });
      if (!res.ok) throw new Error('Failed to fetch devices');
      return await res.json();
    } catch (e) {
      console.warn("API Unavailable, using mock data fallback internally in hooks.");
      throw e;
    }
  }

  static async getDevice(deviceId: string): Promise<ApiDevice> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch device ${deviceId}`);
    return res.json();
  }

  static async updateDevice(deviceId: string, updates: Partial<Pick<ApiDevice, 'hostname' | 'device_type' | 'notes' | 'status'>>): Promise<ApiDevice> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error(`Failed to update device ${deviceId}`);
    return res.json();
  }

  static async deleteDevice(deviceId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
      method: 'DELETE',
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to delete device ${deviceId}`);
  }

  // ============ Scans ============

  static async launchScan(params: ScanCreateParams): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        scan_type: params.scan_type,
        tool: params.tool,
        target: params.target,
        parameters: params.parameters
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Scan launch failed' }));
      throw new Error(err.detail || 'Scan launch failed');
    }
    return res.json();
  }

  static async getScans(params?: { offset?: number; limit?: number; status?: string }): Promise<ApiScan[]> {
    const query = new URLSearchParams();
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.status) query.set('status', params.status);

    const url = `${API_BASE}/scans${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
  }

  static async getScan(scanId: string): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch scan ${scanId}`);
    return res.json();
  }

  static async cancelScan(scanId: string): Promise<ApiScan> {
    const res = await fetch(`${API_BASE}/scans/${scanId}/cancel`, {
      method: 'POST',
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Failed to cancel scan ${scanId}`);
    return res.json();
  }

  // ============ Tools ============

  static async getTools(): Promise<ApiToolInfo[]> {
    const res = await fetch(`${API_BASE}/tools`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch tools');
    return res.json();
  }

  static async getTool(toolName: string): Promise<ApiToolInfo> {
    const res = await fetch(`${API_BASE}/tools/${toolName}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch tool ${toolName}`);
    return res.json();
  }

  static async getToolsHealth(): Promise<Array<{ name: string; status: string }>> {
    const res = await fetch(`${API_BASE}/tools/health`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch tools health');
    return res.json();
  }

  static async executeTool(toolName: string, task: string, params: Record<string, unknown> = {}): Promise<ToolExecuteParams> {
    const res = await fetch(`${API_BASE}/tools/${toolName}/execute`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ task, params })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Tool execution failed' }));
      throw new Error(err.detail || 'Tool execution failed');
    }
    return res.json();
  }

  // ============ Alerts ============

  static async getAlerts(params?: { severity?: string; status?: string; source_tool?: string; offset?: number; limit?: number }): Promise<ApiAlert[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    if (params?.source_tool) query.set('source_tool', params.source_tool);
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.limit) query.set('limit', String(params.limit));

    const url = `${API_BASE}/alerts${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  }

  static async getAlert(alertId: string): Promise<ApiAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error(`Failed to fetch alert ${alertId}`);
    return res.json();
  }

  static async getAlertStats(): Promise<AlertStats> {
    const res = await fetch(`${API_BASE}/alerts/stats`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch alert stats');
    return res.json();
  }

  static async updateAlert(alertId: string, updates: { status?: string; severity?: string; notes?: string }): Promise<ApiAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(updates)
    });
    if (!res.ok) throw new Error(`Failed to update alert ${alertId}`);
    return res.json();
  }

  // ============ Vulnerabilities ============

  static async getVulnerabilities(params?: { severity?: string; status?: string; offset?: number; limit?: number }): Promise<ApiVulnerability[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    if (params?.offset) query.set('offset', String(params.offset));
    if (params?.limit) query.set('limit', String(params.limit));

    const url = `${API_BASE}/vulnerabilities${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
    return res.json();
  }

  // ============ Sentinel ============

  static async getSentinelStatus(): Promise<SentinelStatus> {
    const res = await fetch(`${API_BASE}/sentinel/status`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch Sentinel status');
    return res.json();
  }

  static async collectSentinel(): Promise<SentinelCollectResult> {
    const res = await fetch(`${API_BASE}/sentinel/collect`, {
      method: 'POST',
      headers: this.getHeaders(),
    });
    if (!res.ok) throw new Error('Failed to collect Sentinel snapshots');
    return res.json();
  }

  static async refreshSentinelFeeds(force = true): Promise<Record<string, unknown>> {
    const res = await fetch(`${API_BASE}/sentinel/osint/feeds`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ force }),
    });
    if (!res.ok) throw new Error('Failed to refresh Sentinel feeds');
    return res.json();
  }

  static async getSentinelVulns(limit = 25): Promise<SentinelVulnReport> {
    const res = await fetch(`${API_BASE}/sentinel/vulns?limit=${limit}`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch Sentinel vulnerabilities');
    return res.json();
  }

  static async scanSentinelVulns(params?: { force?: boolean; refresh_feeds?: boolean }): Promise<Record<string, unknown>> {
    const res = await fetch(`${API_BASE}/sentinel/vulns/scan`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        force: params?.force ?? false,
        refresh_feeds: params?.refresh_feeds ?? true,
      }),
    });
    if (!res.ok) throw new Error('Failed to run Sentinel vulnerability scan');
    return res.json();
  }

  static async correlateSentinel(params?: { refresh_feeds?: boolean; scan_vulns?: boolean; ingest_alerts?: boolean }): Promise<SentinelCorrelationResult> {
    const res = await fetch(`${API_BASE}/sentinel/correlate`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        refresh_feeds: params?.refresh_feeds ?? true,
        scan_vulns: params?.scan_vulns ?? true,
        ingest_alerts: params?.ingest_alerts ?? true,
      }),
    });
    if (!res.ok) throw new Error('Failed to run Sentinel correlation');
    return res.json();
  }

  // ============ Overview ============

  static async getOverview(): Promise<{
    health: { status: string; version: string };
    alerts: ApiAlert[];
    alert_stats: AlertStats;
    scans: ApiScan[];
    sentinel: SentinelStatus;
    tools_health: Array<{ name: string; status: string }>;
  }> {
    const res = await fetch(`${API_BASE}/overview`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch overview');
    return res.json();
  }

  // ============ System ============

  static async getSystemHealth(): Promise<{ status: string; version: string }> {
    const res = await fetch(`${API_BASE}/system/health`);  // No auth needed
    if (!res.ok) throw new Error('Failed to fetch system health');
    return res.json();
  }

  static async getSystemInfo(): Promise<Record<string, unknown>> {
    const res = await fetch(`${API_BASE}/system/info`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch system info');
    return res.json();
  }

  // ============ Hub ============

  static async getHubStatus(): Promise<HubStatus> {
    const res = await fetch(`${API_BASE}/hub/status`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch hub status');
    return res.json();
  }

  // ============ Config ============

  static async getConfig(): Promise<ConfigResponse> {
    const res = await fetch(`${API_BASE}/config`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch config');
    return res.json();
  }

  static async getConfigRaw(): Promise<{ default_toml: string; local_toml: string }> {
    const res = await fetch(`${API_BASE}/config/raw`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch raw config');
    return res.json();
  }

  static async updateConfig(overrides: Record<string, unknown>): Promise<{ status: string; note: string }> {
    const res = await fetch(`${API_BASE}/config`, {
      method: 'PUT',
      headers: this.getHeaders(),
      body: JSON.stringify(overrides),
    });
    if (!res.ok) throw new Error('Failed to update config');
    return res.json();
  }

  // ============ Logs ============

  static async getLogs(params?: { lines?: number; offset?: number }): Promise<LogFileResponse> {
    const query = new URLSearchParams();
    if (params?.lines) query.set('lines', String(params.lines));
    if (params?.offset) query.set('offset', String(params.offset));
    const url = `${API_BASE}/logs/file${query.toString() ? '?' + query : ''}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch logs');
    return res.json();
  }

  // ============ Export ============

  static async exportResource(resource: string, format: 'csv' | 'json' = 'csv', limit = 10000): Promise<void> {
    const url = `${API_BASE}/export/${resource}?fmt=${format}&limit=${limit}`;
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to export');
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = res.headers.get('content-disposition')?.split('filename="')[1]?.replace('"', '') || `${resource}.${format}`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ============ Scheduler ============

  static async getSchedulerJobs(): Promise<Array<{ name: string; trigger_type: string; next_run?: string }>> {
    const res = await fetch(`${API_BASE}/scheduler/jobs`, { headers: this.getHeaders() });
    if (!res.ok) throw new Error('Failed to fetch scheduler jobs');
    return res.json();
  }

  static connectWS() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;

    this.ws = new WebSocket(WS_URL);

    this.ws.onopen = () => {
      console.log('NetSec Agent Connected');
      this.emit('system.startup', null);
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        // Assuming msg structure: { type: 'event.name', data: ... }
        if (msg.type) {
          this.emit(msg.type, msg.data);
        }
      } catch (e) {
        console.error('WS Parse Error', e);
      }
    };

    this.ws.onclose = () => {
      console.log('NetSec Agent Disconnected');
      this.emit('system.shutdown', null);
      setTimeout(() => this.connectWS(), 5000); // Reconnect
    };
  }

  static on(event: string, handler: (data: any) => void) {
    if (!this.handlers[event]) this.handlers[event] = [];
    this.handlers[event].push(handler);
  }

  static off(event: string, handler: (data: any) => void) {
    if (!this.handlers[event]) return;
    this.handlers[event] = this.handlers[event].filter(h => h !== handler);
  }

  private static emit(event: string, data: any) {
    if (this.handlers[event]) {
      this.handlers[event].forEach(h => h(data));
    }
  }
}

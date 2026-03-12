//! Main application state and logic.

use iced::widget::{column, container, row, horizontal_rule, Stack};
use iced::{Element, Length, Subscription, Task, Theme};

use crate::api::{
    self, ApiClient, ApiConfig, WsConfig, WsState,
    websocket::{self, WsMessage2},
};
use crate::desktop::{notifications, persistence};
use crate::message::{InspectorTab, Message, Severity, ToastLevel, ToolMode};
use crate::webview::{CanvasWebview, NetworkStateJson, WebviewEvent, parse_node_id, parse_connection_id};
use crate::views::settings::Settings;
use crate::views::ui_components::{ConfirmDialog, Toast};
use crate::state::network::NetworkState;
use crate::state::terminal::TerminalState;
use crate::theme;
use crate::views;

use reqwest::Url;
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// API connection state.
#[derive(Debug, Clone, Default)]
pub struct ApiState {
    /// Whether the WebSocket is connected
    pub ws_connected: bool,
    /// WebSocket connection state
    pub ws_state: Option<WsState>,
    /// Last error message
    pub last_error: Option<String>,
    /// Cached devices from API
    pub devices: Vec<api::Device>,
    /// Cached scans from API
    pub scans: Vec<api::Scan>,
    /// Cached alerts from API
    pub alerts: Vec<api::Alert>,
    /// Cached alert stats
    pub alert_stats: Option<api::AlertStats>,
    /// Cached vulnerabilities
    pub vulnerabilities: Vec<api::Vulnerability>,
    /// Cached traffic flows
    pub traffic: Vec<api::TrafficFlow>,
    /// Cached tools
    pub tools: Vec<api::Tool>,
    /// Cached tools health
    pub tools_health: Vec<api::ToolHealth>,
    /// Cached scheduled jobs
    pub jobs: Vec<api::ScheduledJob>,
    /// Whether we're loading devices
    pub loading_devices: bool,
    /// Whether we're loading scans
    pub loading_scans: bool,
    /// Whether we're loading alerts
    pub loading_alerts: bool,
}

/// Main application state.
pub struct NetWatch {
    /// Terminal panel state
    terminal: TerminalState,
    /// Network canvas state
    network: NetworkState,
    /// Current tool mode
    tool_mode: ToolMode,
    /// Active inspector tab
    inspector_tab: InspectorTab,
    /// Whether the terminal panel is visible
    terminal_visible: bool,
    /// Whether the inspector panel is visible
    inspector_visible: bool,
    /// Whether the toolbar is visible
    toolbar_visible: bool,
    /// Whether the vulnerability dashboard modal is visible
    show_vuln_dashboard: bool,
    /// Vulnerability filter by severity
    vuln_filter_severity: Option<Severity>,
    /// Vulnerability search query
    vuln_search_query: String,
    /// Whether the alerts dashboard modal is visible
    show_alerts_dashboard: bool,
    /// Selected alert ID in the alerts dashboard
    selected_alert_id: Option<String>,
    /// Alert filter by severity
    alert_filter_severity: Option<String>,
    /// Alert filter by status
    alert_filter_status: Option<String>,
    /// Alert search query
    alert_search_query: String,
    /// Whether the scans dashboard modal is visible
    show_scans_dashboard: bool,
    /// Selected scan ID in the scans dashboard
    selected_scan_id: Option<String>,
    /// Scan filter by status
    scan_filter_status: Option<String>,
    /// Whether the traffic dashboard modal is visible
    show_traffic_dashboard: bool,
    /// Selected traffic flow ID
    selected_traffic_id: Option<String>,
    /// Traffic filter by protocol
    traffic_filter_protocol: Option<String>,
    /// Whether the tools dashboard modal is visible
    show_tools_dashboard: bool,
    /// Selected tool name
    selected_tool: Option<String>,
    /// Whether the scheduler dashboard modal is visible
    show_scheduler_dashboard: bool,
    /// Selected job ID
    selected_job_id: Option<String>,
    /// Whether the settings panel is visible
    show_settings: bool,
    /// Application settings
    settings: Settings,
    /// Toast notifications
    toasts: Vec<Toast>,
    /// Next toast ID
    next_toast_id: usize,
    /// Confirmation dialog
    confirm_dialog: Option<ConfirmDialog>,
    /// API client for backend communication
    api_client: Option<ApiClient>,
    /// API connection state
    api_state: ApiState,
    /// WebSocket configuration
    ws_config: WsConfig,
    /// Whether WebSocket subscription is enabled
    ws_enabled: bool,
    /// Last auto-refresh time
    last_refresh: Instant,
    /// Active scan ID for status polling when WS updates are unavailable
    active_scan_id: Option<String>,
    /// Wry webview for React NetworkCanvas
    webview: Option<CanvasWebview>,
    /// Receiver for webview IPC events
    webview_event_rx: Option<std::sync::mpsc::Receiver<WebviewEvent>>,
    /// Whether webview has been successfully created
    webview_initialized: bool,
    /// Monotonic sequence number for webview state syncs (diagnostic)
    sync_seq: u64,
    /// Current window width in logical pixels
    window_width: f64,
    /// Current window height in logical pixels
    window_height: f64,
}

impl NetWatch {
    /// Create a new application instance.
    pub fn new() -> (Self, Task<Message>) {
        let mut terminal = TerminalState::new();
        let mut network = NetworkState::new();
        let mut startup_tasks = Vec::new();

        // Create initial terminal tab with default shell
        let terminal_cmd = terminal.create_default_tab();

        // Optional sample network for demo/testing only
        if Self::sample_data_enabled() {
            network.create_sample_network();
            tracing::warn!("Sample network is enabled (NETWATCH_ENABLE_SAMPLE_DATA)");
        }

        // Load persisted settings or use defaults
        let settings = persistence::load_settings().unwrap_or_default();
        tracing::info!("Settings loaded: API URL = {}", settings.api_url);

        if let Some((message, level, backend_started)) =
            Self::ensure_local_backend_running(&settings.api_url)
        {
            startup_tasks.push(Task::done(Message::ShowToast(message, level)));
            if backend_started {
                startup_tasks.push(Task::perform(
                    async move {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    },
                    |_| Message::RefreshAll,
                ));
            }
        }

        // Initialize API client with settings
        let api_config = ApiConfig {
            base_url: settings.api_url.clone(),
            api_key: None,
            timeout_secs: 30,
        };
        let (api_client, api_client_error) = match ApiClient::new(api_config) {
            Ok(client) => (Some(client), None),
            Err(e) => {
                let message = format!("Failed to create API client: {}", e);
                tracing::error!("{}", message);
                (None, Some(message))
            }
        };
        if let Some(message) = api_client_error {
            startup_tasks.push(Task::done(Message::ShowToast(message, ToastLevel::Error)));
        }

        // WebSocket config from settings
        let ws_config = WsConfig {
            url: settings.ws_url.clone(),
            reconnect_delay_ms: 5000,
            max_reconnect_attempts: 10,
        };

        // Task to obtain the window handle for webview creation
        let webview_task = Self::create_webview_init_task();

        // Initial commands: terminal + fetch initial data + webview init
        let mut init_tasks = vec![
            terminal_cmd,
            Task::done(Message::FetchDevices),
            Task::done(Message::FetchScans),
            Task::done(Message::FetchAlerts),
            Task::done(Message::FetchAlertStats),
            webview_task,
        ];
        init_tasks.extend(startup_tasks);
        let init_cmd = Task::batch(init_tasks);

        (
            Self {
                terminal,
                network,
                tool_mode: ToolMode::Select,
                inspector_tab: InspectorTab::Details,
                terminal_visible: true,
                inspector_visible: true,
                toolbar_visible: true,
                show_vuln_dashboard: false,
                vuln_filter_severity: None,
                vuln_search_query: String::new(),
                show_alerts_dashboard: false,
                selected_alert_id: None,
                alert_filter_severity: None,
                alert_filter_status: None,
                alert_search_query: String::new(),
                show_scans_dashboard: false,
                selected_scan_id: None,
                scan_filter_status: None,
                show_traffic_dashboard: false,
                selected_traffic_id: None,
                traffic_filter_protocol: None,
                show_tools_dashboard: false,
                selected_tool: None,
                show_scheduler_dashboard: false,
                selected_job_id: None,
                show_settings: false,
                settings,
                toasts: Vec::new(),
                next_toast_id: 0,
                confirm_dialog: None,
                api_client,
                api_state: ApiState::default(),
                ws_config,
                ws_enabled: true,
                last_refresh: Instant::now(),
                active_scan_id: None,
                webview: None,
                webview_event_rx: None,
                webview_initialized: false,
                sync_seq: 0,
                window_width: 1400.0,
                window_height: 900.0,
            },
            init_cmd,
        )
    }

    /// Create a Task that obtains the window handle for webview creation.
    #[cfg(target_os = "windows")]
    fn create_webview_init_task() -> Task<Message> {
        iced::window::get_oldest().then(|opt_id| {
            match opt_id {
                Some(id) => iced::window::run_with_handle(id, |handle| {
                    use raw_window_handle::HasWindowHandle;
                    handle.window_handle().ok().and_then(|wh| {
                        match wh.as_raw() {
                            raw_window_handle::RawWindowHandle::Win32(h) => {
                                Some(h.hwnd.get() as isize)
                            }
                            _ => None,
                        }
                    })
                }).map(|opt_hwnd| {
                    match opt_hwnd {
                        Some(hwnd) => Message::WebviewHandleReady(hwnd),
                        None => Message::Tick,
                    }
                }),
                None => {
                    tracing::debug!("Window not ready yet, will retry webview init");
                    Task::done(Message::Tick)
                }
            }
        })
    }

    #[cfg(target_os = "linux")]
    fn create_webview_init_task() -> Task<Message> {
        iced::window::get_oldest().then(|opt_id| {
            match opt_id {
                Some(id) => iced::window::run_with_handle(id, |handle| {
                    use raw_window_handle::HasWindowHandle;
                    handle.window_handle().ok().and_then(|wh| {
                        match wh.as_raw() {
                            raw_window_handle::RawWindowHandle::Xlib(h) => {
                                Some(h.window as isize)
                            }
                            raw_window_handle::RawWindowHandle::Xcb(h) => {
                                Some(h.window.get() as isize)
                            }
                            other => {
                                tracing::warn!("Unsupported window handle type: {:?}", other);
                                None
                            }
                        }
                    })
                }).map(|opt_handle| {
                    match opt_handle {
                        Some(handle) => Message::WebviewHandleReady(handle),
                        None => Message::Tick,
                    }
                }),
                None => {
                    tracing::debug!("Window not ready yet, will retry webview init");
                    Task::done(Message::Tick)
                }
            }
        })
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn create_webview_init_task() -> Task<Message> {
        Task::none()
    }

    fn sample_data_enabled() -> bool {
        std::env::var("NETWATCH_ENABLE_SAMPLE_DATA")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    }

    fn infer_local_subnet_target(&self) -> String {
        if let Some(node) = self.network.nodes.iter().find(|n| matches!(n.node_type, crate::message::NodeType::Router)) {
            if let Some(cidr) = Self::ipv4_to_cidr24(&node.ip) {
                return cidr;
            }
        }

        if let Some(cidr) = self.network.nodes.iter().find_map(|n| Self::ipv4_to_cidr24(&n.ip)) {
            return cidr;
        }

        "192.168.1.0/24".to_string()
    }

    fn ipv4_to_cidr24(ip: &str) -> Option<String> {
        let host = ip.split('/').next()?.trim();
        let parsed = host.parse::<Ipv4Addr>().ok()?;
        let [a, b, c, _] = parsed.octets();
        Some(format!("{a}.{b}.{c}.0/24"))
    }

    fn ensure_local_backend_running(api_url: &str) -> Option<(String, ToastLevel, bool)> {
        let parsed = match Url::parse(api_url) {
            Ok(url) => url,
            Err(e) => {
                return Some((
                    format!("Invalid API URL '{}': {}", api_url, e),
                    ToastLevel::Error,
                    false,
                ));
            }
        };

        let host = parsed.host_str()?.to_ascii_lowercase();
        if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
            return None;
        }

        if Self::is_api_reachable(&parsed) {
            return None;
        }

        match Self::start_local_backend_process() {
            Ok(()) => Some((
                "Backend not reachable; attempted auto-start with `python -m netsec`".to_string(),
                ToastLevel::Warning,
                true,
            )),
            Err(e) => Some((
                format!(
                    "Backend not reachable at {}. Start it with `PYTHONPATH=python python -m netsec` ({})",
                    api_url, e
                ),
                ToastLevel::Error,
                false,
            )),
        }
    }

    fn is_api_reachable(url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let Some(port) = url.port_or_known_default() else {
            return false;
        };

        let Ok(mut addrs) = format!("{host}:{port}").to_socket_addrs() else {
            return false;
        };
        let Some(addr) = addrs.next() else {
            return false;
        };

        TcpStream::connect_timeout(&addr, Duration::from_millis(350)).is_ok()
    }

    fn start_local_backend_process() -> Result<(), String> {
        let backend_cwd = Self::resolve_backend_cwd();
        let mut launchers: Vec<(&str, &[&str])> = vec![("python", &["-m", "netsec"])];
        #[cfg(target_os = "windows")]
        {
            launchers.push(("py", &["-m", "netsec"]));
        }

        let mut last_error = String::new();
        for (bin, args) in launchers {
            let mut cmd = Command::new(bin);
            cmd.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());

            if let Some(cwd) = backend_cwd.as_ref() {
                cmd.current_dir(cwd).env("PYTHONPATH", "python");
            }

            match cmd.spawn() {
                Ok(_) => return Ok(()),
                Err(e) => last_error = format!("{}: {}", bin, e),
            }
        }

        if last_error.is_empty() {
            Err("No Python launcher available".to_string())
        } else {
            Err(last_error)
        }
    }

    fn resolve_backend_cwd() -> Option<PathBuf> {
        let cwd = std::env::current_dir().ok()?;
        if cwd.join("python").join("netsec").exists() {
            return Some(cwd);
        }

        let exe = std::env::current_exe().ok()?;
        for ancestor in exe.ancestors() {
            if ancestor.join("python").join("netsec").exists() {
                return Some(ancestor.to_path_buf());
            }
        }

        None
    }

    fn upsert_scan_cache(&mut self, scan: api::Scan) {
        if let Some(pos) = self.api_state.scans.iter().position(|s| s.id == scan.id) {
            self.api_state.scans[pos] = scan;
        } else {
            self.api_state.scans.insert(0, scan);
        }
    }

    fn apply_scan_status(&mut self, scan: &api::Scan) -> Option<Task<Message>> {
        match scan.status.as_str() {
            "pending" | "running" => {
                self.network.is_scanning = true;
                self.network.scan_progress = scan.progress;
                self.active_scan_id = Some(scan.id.clone());
                None
            }
            "completed" => {
                self.network.is_scanning = false;
                self.network.scan_progress = 100;
                self.active_scan_id = None;
                Some(Task::batch([
                    Task::done(Message::FetchDevices),
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchScans),
                ]))
            }
            "failed" => {
                self.network.is_scanning = false;
                self.active_scan_id = None;
                if let Some(error) = scan.error_message.clone() {
                    self.api_state.last_error = Some(error.clone());
                    Some(Task::done(Message::ShowToast(
                        format!("Scan failed: {}", error),
                        ToastLevel::Error,
                    )))
                } else {
                    None
                }
            }
            "cancelled" => {
                self.network.is_scanning = false;
                self.active_scan_id = None;
                None
            }
            _ => None,
        }
    }

    /// Get the window title.
    pub fn title(&self) -> String {
        String::from("NetWatch - Network Security Monitor")
    }

    /// Handle messages.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // === Terminal messages ===
            Message::TerminalInput(tab_id, input) => {
                self.terminal.write_input(tab_id, &input)
            }
            Message::TerminalOutput(tab_id, data) => {
                self.terminal.handle_output(tab_id, &data);
                Task::none()
            }
            Message::TerminalNewTab(shell) => {
                self.terminal.create_tab(shell)
            }
            Message::TerminalCloseTab(tab_id) => {
                self.terminal.close_tab(tab_id);
                Task::none()
            }
            Message::TerminalSelectTab(tab_id) => {
                self.terminal.select_tab(tab_id);
                Task::none()
            }
            Message::TerminalResized(tab_id, cols, rows) => {
                self.terminal.resize_tab(tab_id, cols, rows);
                Task::none()
            }
            Message::TerminalClosed(tab_id) => {
                self.terminal.handle_closed(tab_id);
                Task::none()
            }

            // === Network Canvas messages ===
            Message::NodeSelected(id) | Message::DeviceSelected(id) => {
                self.network.select_node(id);
                Task::none()
            }
            Message::NodeDeselected | Message::DeviceDeselected => {
                self.network.clear_selection();
                Task::none()
            }
            Message::NodesAddToSelection(ids) => {
                self.network.add_to_selection(&ids);
                Task::none()
            }
            Message::CanvasPan(dx, dy) => {
                self.network.pan(dx, dy);
                Task::none()
            }
            Message::CanvasZoom(zoom) => {
                self.network.set_zoom(zoom);
                Task::none()
            }
            Message::AddNode(node_type) => {
                use crate::state::network::Node;
                // Add a new node at a default position
                let label = node_type.label().to_string();
                let ip = format!("192.168.1.{}", self.network.nodes.len() + 100);
                let node = Node::new(node_type, 300.0, 200.0, label, ip);
                self.network.add_node(node);
                Task::none()
            }
            Message::DeleteSelected => {
                self.network.delete_selected();
                Task::none()
            }
            Message::GroupSelected => {
                // TODO: Implement grouping
                Task::none()
            }
            Message::NodeMoved(id, x, y) => {
                self.network.move_node(id, x, y);
                Task::none()
            }
            Message::StartConnection(from_id) => {
                self.network.connecting_from = Some(from_id);
                Task::none()
            }
            Message::CompleteConnection(to_id) => {
                if let Some(from_id) = self.network.connecting_from.take() {
                    use crate::message::ConnectionType;
                    self.network.add_connection(from_id, to_id, ConnectionType::Wired);
                }
                Task::none()
            }
            Message::CancelConnection => {
                self.network.connecting_from = None;
                Task::none()
            }
            Message::ConnectionHovered(id) => {
                self.network.hovered_connection = id;
                Task::none()
            }

            // === Tool Mode ===
            Message::SetToolMode(mode) => {
                self.tool_mode = mode;
                Task::none()
            }

            // === Scanning ===
            Message::ScanNetwork => {
                // Create a network discovery scan targeting the local subnet
                let scan = api::ScanCreate {
                    scan_type: "network".to_string(),
                    tool: "nmap".to_string(),
                    target: self.infer_local_subnet_target(),
                    parameters: Some({
                        let mut params = std::collections::HashMap::new();
                        params.insert("scan_type".to_string(), serde_json::json!("quick"));
                        params
                    }),
                };
                Task::done(Message::CreateScan(scan))
            }
            Message::RunNmapScan(scan_type) => {
                use crate::message::NmapScanType;

                // Get target from selected node or default to subnet
                let target = if let Some(node) = self.network.selected_node() {
                    node.ip.clone()
                } else {
                    self.infer_local_subnet_target()
                };

                // Map scan type to nmap parameters
                let (nmap_args, scan_type_str) = match scan_type {
                    NmapScanType::Quick => ("-T4 -F", "quick"),
                    NmapScanType::Ports => ("-p-", "ports"),
                    NmapScanType::Service => ("-sV", "service"),
                    NmapScanType::OS => ("-O", "os"),
                    NmapScanType::Vuln => ("--script vuln", "vulnerability"),
                    NmapScanType::Full => ("-A -T4", "full"),
                };

                let scan = api::ScanCreate {
                    scan_type: scan_type_str.to_string(),
                    tool: "nmap".to_string(),
                    target,
                    parameters: Some({
                        let mut params = std::collections::HashMap::new();
                        params.insert("args".to_string(), serde_json::json!(nmap_args));
                        params.insert("scan_type".to_string(), serde_json::json!(scan_type_str));
                        params
                    }),
                };

                tracing::info!("Running Nmap {} scan", scan_type_str);
                Task::done(Message::CreateScan(scan))
            }
            Message::RunAttackTool(tool) => {
                use crate::message::AttackTool;

                // Get target from selected node
                let target = if let Some(node) = self.network.selected_node() {
                    node.ip.clone()
                } else {
                    tracing::warn!("No device selected for attack tool");
                    self.api_state.last_error = Some("Select a target device first".to_string());
                    return Task::none();
                };

                let (tool_name, task_type) = match tool {
                    AttackTool::Hydra => ("hydra", "bruteforce"),
                    AttackTool::Metasploit => ("metasploit", "exploit"),
                };

                // For attack tools, we'd typically want user input for credentials/options
                // For now, just log and create a basic scan entry
                tracing::info!("Launching {} against {}", tool_name, target);

                let scan = api::ScanCreate {
                    scan_type: task_type.to_string(),
                    tool: tool_name.to_string(),
                    target,
                    parameters: None, // Would need UI for credentials
                };

                Task::done(Message::CreateScan(scan))
            }
            Message::ScanCompleted => {
                self.network.is_scanning = false;
                self.network.scan_progress = 100;
                self.active_scan_id = None;
                // Refresh data after scan completes
                Task::batch([
                    Task::done(Message::FetchDevices),
                    Task::done(Message::FetchAlerts),
                ])
            }
            Message::ScanProgress(progress) => {
                self.network.scan_progress = progress;
                Task::none()
            }
            Message::ScanDevice(id) => {
                // Find the device IP and run a targeted scan
                if let Some(node) = self.network.get_node(id) {
                    let target = node.ip.clone();
                    tracing::info!("Scanning device: {} ({})", node.label, target);

                    let scan = api::ScanCreate {
                        scan_type: "service".to_string(),
                        tool: "nmap".to_string(),
                        target,
                        parameters: Some({
                            let mut params = std::collections::HashMap::new();
                            params.insert("args".to_string(), serde_json::json!("-sV -O"));
                            params
                        }),
                    };

                    Task::done(Message::CreateScan(scan))
                } else {
                    tracing::warn!("Device not found: {:?}", id);
                    Task::none()
                }
            }

            // === File Operations ===
            Message::SaveProject => {
                // TODO: Implement save dialog
                tracing::info!("Save project requested");
                Task::none()
            }
            Message::LoadProject => {
                // TODO: Implement load dialog
                tracing::info!("Load project requested");
                Task::none()
            }

            // === UI Panels ===
            Message::ToggleTerminalPanel => {
                self.terminal_visible = !self.terminal_visible;
                self.update_webview_bounds();
                Task::none()
            }
            Message::ToggleInspectorPanel => {
                self.inspector_visible = !self.inspector_visible;
                self.update_webview_bounds();
                Task::none()
            }
            Message::ToggleToolbar => {
                self.toolbar_visible = !self.toolbar_visible;
                self.update_webview_bounds();
                Task::none()
            }
            Message::ShowVulnDashboard => {
                self.show_vuln_dashboard = true;
                // Fetch latest vulnerabilities from API
                Task::done(Message::FetchVulnerabilities)
            }
            Message::HideVulnDashboard => {
                self.show_vuln_dashboard = false;
                Task::none()
            }
            Message::SetInspectorTab(tab) => {
                self.inspector_tab = tab;
                Task::none()
            }

            // === Vulnerability Dashboard ===
            Message::VulnFilterSeverity(severity) => {
                self.vuln_filter_severity = severity;
                Task::none()
            }
            Message::VulnSortBy(_field) => {
                // TODO: Implement sorting
                Task::none()
            }
            Message::VulnSearch(query) => {
                self.vuln_search_query = query;
                Task::none()
            }

            // === Alerts Dashboard ===
            Message::ShowAlertsDashboard => {
                self.show_alerts_dashboard = true;
                // Fetch latest alerts
                Task::batch([
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchAlertStats),
                ])
            }
            Message::HideAlertsDashboard => {
                self.show_alerts_dashboard = false;
                self.selected_alert_id = None;
                Task::none()
            }
            Message::AlertSelected(id) => {
                self.selected_alert_id = Some(id);
                Task::none()
            }
            Message::AlertFilterSeverity(severity) => {
                self.alert_filter_severity = severity;
                Task::none()
            }
            Message::AlertFilterStatus(status) => {
                self.alert_filter_status = status;
                Task::none()
            }
            Message::AlertSearch(query) => {
                self.alert_search_query = query;
                Task::none()
            }
            Message::AcknowledgeAlert(id) => {
                let update = api::AlertUpdate {
                    status: Some("acknowledged".to_string()),
                    severity: None,
                    notes: None,
                };
                Task::done(Message::UpdateAlert(id, update))
            }
            Message::ResolveAlert(id) => {
                let update = api::AlertUpdate {
                    status: Some("resolved".to_string()),
                    severity: None,
                    notes: None,
                };
                Task::done(Message::UpdateAlert(id, update))
            }
            Message::DismissAlert(id) => {
                let update = api::AlertUpdate {
                    status: Some("dismissed".to_string()),
                    severity: None,
                    notes: None,
                };
                Task::done(Message::UpdateAlert(id, update))
            }

            // === Scans Dashboard ===
            Message::ShowScansDashboard => {
                self.show_scans_dashboard = true;
                // Fetch latest scans
                Task::done(Message::FetchScans)
            }
            Message::HideScansDashboard => {
                self.show_scans_dashboard = false;
                self.selected_scan_id = None;
                Task::none()
            }
            Message::ScanSelected(id) => {
                self.selected_scan_id = Some(id);
                Task::none()
            }
            Message::ScanFilterStatus(status) => {
                self.scan_filter_status = status;
                Task::none()
            }
            Message::RescanTarget(target, scan_type, tool) => {
                let scan = api::ScanCreate {
                    scan_type,
                    tool,
                    target,
                    parameters: None,
                };
                Task::done(Message::CreateScan(scan))
            }

            // === Traffic Dashboard ===
            Message::ShowTrafficDashboard => {
                self.show_traffic_dashboard = true;
                Task::done(Message::FetchTraffic)
            }
            Message::HideTrafficDashboard => {
                self.show_traffic_dashboard = false;
                self.selected_traffic_id = None;
                Task::none()
            }
            Message::TrafficFlowSelected(id) => {
                self.selected_traffic_id = Some(id);
                Task::none()
            }
            Message::TrafficFilterProtocol(protocol) => {
                self.traffic_filter_protocol = protocol;
                Task::none()
            }
            Message::TrafficFilterDirection(_direction) => {
                // TODO: Implement direction filtering
                Task::none()
            }

            // === Tools Dashboard ===
            Message::ShowToolsDashboard => {
                self.show_tools_dashboard = true;
                Task::batch([
                    Task::done(Message::FetchTools),
                    Task::done(Message::FetchToolsHealth),
                ])
            }
            Message::HideToolsDashboard => {
                self.show_tools_dashboard = false;
                self.selected_tool = None;
                Task::none()
            }
            Message::ToolSelected(name) => {
                self.selected_tool = Some(name);
                Task::none()
            }
            Message::RunToolHealthCheck(name) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.all_tools_health().await },
                        |result| Message::ToolsHealthFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }

            // === Scheduler Dashboard ===
            Message::ShowSchedulerDashboard => {
                self.show_scheduler_dashboard = true;
                Task::done(Message::FetchJobs)
            }
            Message::HideSchedulerDashboard => {
                self.show_scheduler_dashboard = false;
                self.selected_job_id = None;
                Task::none()
            }
            Message::JobSelected(id) => {
                self.selected_job_id = Some(id);
                Task::none()
            }
            Message::ToggleJobEnabled(id) => {
                // Find job and toggle
                if let Some(job) = self.api_state.jobs.iter().find(|j| j.id == id) {
                    if job.enabled {
                        Task::done(Message::PauseJob(id))
                    } else {
                        Task::done(Message::ResumeJob(id))
                    }
                } else {
                    Task::none()
                }
            }

            // === Settings ===
            Message::ShowSettings => {
                self.show_settings = true;
                Task::none()
            }
            Message::HideSettings => {
                self.show_settings = false;
                Task::none()
            }
            Message::SettingsUpdateApiUrl(url) => {
                self.settings.api_url = url;
                Task::none()
            }
            Message::SettingsUpdateWsUrl(url) => {
                self.settings.ws_url = url;
                Task::none()
            }
            Message::SettingsToggleDarkMode => {
                self.settings.dark_mode = !self.settings.dark_mode;
                Task::none()
            }
            Message::SettingsToggleNotifications => {
                self.settings.notifications_enabled = !self.settings.notifications_enabled;
                Task::none()
            }
            Message::SettingsToggleAutoRefresh => {
                self.settings.auto_refresh = !self.settings.auto_refresh;
                Task::none()
            }
            Message::SettingsUpdateRefreshInterval(secs) => {
                self.settings.refresh_interval_secs = secs;
                Task::none()
            }
            Message::SettingsSave => {
                // Persist settings to file
                if let Err(e) = persistence::save_settings(&self.settings) {
                    tracing::error!("Failed to save settings: {}", e);
                    return Task::done(Message::ShowToast(
                        format!("Failed to save settings: {}", e),
                        ToastLevel::Error,
                    ));
                }
                tracing::info!("Settings saved to disk");

                // Update API client with new URL if changed
                let config = ApiConfig {
                    base_url: self.settings.api_url.clone(),
                    api_key: None,
                    timeout_secs: 30,
                };
                let client = match ApiClient::new(config) {
                    Ok(client) => client,
                    Err(e) => {
                        let message = format!("Failed to apply API settings: {}", e);
                        tracing::error!("{}", message);
                        self.api_client = None;
                        self.api_state.last_error = Some(message.clone());
                        return Task::done(Message::ShowToast(message, ToastLevel::Error));
                    }
                };
                self.api_client = Some(client);
                // Update WebSocket config
                self.ws_config.url = self.settings.ws_url.clone();
                self.show_settings = false;

                let mut tasks = vec![Task::done(Message::ShowToast(
                    "Settings saved".to_string(),
                    ToastLevel::Success,
                ))];
                if let Some((message, level, backend_started)) =
                    Self::ensure_local_backend_running(&self.settings.api_url)
                {
                    tasks.push(Task::done(Message::ShowToast(message, level)));
                    if backend_started {
                        tasks.push(Task::perform(
                            async move {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            },
                            |_| Message::RefreshAll,
                        ));
                    }
                }
                Task::batch(tasks)
            }

            // === Notifications ===
            Message::ShowToast(message, level) => {
                let toast = Toast::new(self.next_toast_id, message, level);
                self.toasts.push(toast);
                self.next_toast_id += 1;
                Task::none()
            }
            Message::DismissToast(id) => {
                self.toasts.retain(|t| t.id != id);
                Task::none()
            }
            Message::ShowConfirmDialog(message, action) => {
                self.confirm_dialog = Some(ConfirmDialog::new(message, *action));
                Task::none()
            }
            Message::ConfirmDialogAccept => {
                if let Some(dialog) = self.confirm_dialog.take() {
                    return self.update(*dialog.confirm_action);
                }
                Task::none()
            }
            Message::ConfirmDialogCancel => {
                self.confirm_dialog = None;
                Task::none()
            }

            // === System ===
            Message::Tick => {
                let mut tasks = Vec::new();

                // Auto-dismiss old toasts (5 second lifetime)
                let now = Instant::now();
                let old_count = self.toasts.len();
                self.toasts.retain(|toast| {
                    now.duration_since(toast.created_at) < Duration::from_secs(5)
                });
                if self.toasts.len() != old_count {
                    tracing::debug!("Auto-dismissed {} toasts", old_count - self.toasts.len());
                }

                // Auto-refresh if enabled
                if self.settings.auto_refresh {
                    let refresh_interval = Duration::from_secs(self.settings.refresh_interval_secs as u64);
                    if now.duration_since(self.last_refresh) >= refresh_interval {
                        self.last_refresh = now;
                        tracing::debug!("Auto-refresh triggered");
                        tasks.push(Task::done(Message::RefreshAll));
                    }
                }

                if let Some(scan_id) = self.active_scan_id.clone() {
                    tasks.push(Task::done(Message::FetchScan(scan_id)));
                }

                // Retry webview creation if not yet initialized
                if !self.webview_initialized {
                    tasks.push(Self::create_webview_init_task());
                }

                if tasks.is_empty() {
                    Task::none()
                } else {
                    Task::batch(tasks)
                }
            }
            Message::WindowResized(w, h) => {
                tracing::debug!("WindowResized: {}x{}", w, h);
                self.window_width = w as f64;
                self.window_height = h as f64;
                self.update_webview_bounds();
                Task::none()
            }

            // =================================================================
            // API Messages
            // =================================================================

            Message::ApiConnect => {
                self.ws_enabled = true;
                Task::none()
            }
            Message::ApiDisconnect => {
                self.ws_enabled = false;
                Task::none()
            }
            Message::ApiHealthCheck(result) => {
                match result {
                    Ok(healthy) => {
                        tracing::info!("API health check: {}", if healthy { "OK" } else { "FAILED" });
                    }
                    Err(e) => {
                        tracing::error!("API health check error: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::RefreshAll => {
                tracing::info!("Refreshing all data from API");
                Task::batch([
                    Task::done(Message::FetchDevices),
                    Task::done(Message::FetchScans),
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchAlertStats),
                    Task::done(Message::FetchVulnerabilities),
                    Task::done(Message::FetchTools),
                ])
            }

            // === Devices ===
            Message::FetchDevices => {
                if let Some(client) = self.api_client.clone() {
                    self.api_state.loading_devices = true;
                    Task::perform(
                        async move { client.list_devices(None, None, None).await },
                        |result| Message::DevicesFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::DevicesFetched(result) => {
                self.api_state.loading_devices = false;
                match result {
                    Ok(devices) => {
                        tracing::info!("Fetched {} devices", devices.len());
                        self.api_state.devices = devices;
                        // Sync to canvas and push to webview
                        self.sync_devices_to_canvas();
                        self.sync_state_to_webview();
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch devices: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::FetchDevice(id) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.get_device(&id).await },
                        |result| Message::DeviceFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::DeviceFetched(result) => {
                match result {
                    Ok(device) => {
                        tracing::debug!("Fetched device: {}", device.id);
                        // Update device in cache
                        if let Some(pos) = self.api_state.devices.iter().position(|d| d.id == device.id) {
                            self.api_state.devices[pos] = device;
                        } else {
                            self.api_state.devices.push(device);
                        }
                        // Sync updated device data to canvas and webview
                        self.sync_devices_to_canvas();
                        self.sync_state_to_webview();
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch device: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::UpdateDevice(id, update) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.update_device(&id, update).await },
                        |result| Message::DeviceUpdated(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::DeviceUpdated(result) => {
                match result {
                    Ok(device) => {
                        tracing::info!("Device updated: {}", device.id);
                        // Update in cache
                        if let Some(pos) = self.api_state.devices.iter().position(|d| d.id == device.id) {
                            self.api_state.devices[pos] = device;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to update device: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::DeleteDevice(id) => {
                if let Some(client) = self.api_client.clone() {
                    let id_clone = id.clone();
                    Task::perform(
                        async move {
                            client.delete_device(&id_clone).await?;
                            Ok::<_, api::ApiError>(id_clone)
                        },
                        |result| Message::DeviceDeleted(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::DeviceDeleted(result) => {
                match result {
                    Ok(id) => {
                        tracing::info!("Device deleted: {}", id);
                        self.api_state.devices.retain(|d| d.id != id);
                    }
                    Err(e) => {
                        tracing::error!("Failed to delete device: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Scans ===
            Message::CreateScan(scan_create) => {
                if let Some(client) = self.api_client.clone() {
                    self.network.is_scanning = true;
                    self.network.scan_progress = 0;
                    Task::perform(
                        async move { client.create_scan(scan_create).await },
                        |result| Message::ScanCreated(result.map_err(|e| e.to_string())),
                    )
                } else {
                    let message = "Cannot start scan: backend API client is unavailable. Check API URL and backend process.".to_string();
                    tracing::error!("{}", message);
                    self.network.is_scanning = false;
                    self.active_scan_id = None;
                    self.api_state.last_error = Some(message.clone());
                    Task::done(Message::ShowToast(message, ToastLevel::Error))
                }
            }
            Message::ScanCreated(result) => {
                match result {
                    Ok(scan) => {
                        tracing::info!("Scan created: {} ({})", scan.id, scan.status);
                        self.upsert_scan_cache(scan.clone());
                        if let Some(task) = self.apply_scan_status(&scan) {
                            return task;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to create scan: {}", e);
                        self.network.is_scanning = false;
                        self.active_scan_id = None;
                        self.api_state.last_error = Some(e.clone());

                        let mut tasks = vec![Task::done(Message::ShowToast(
                            format!("Failed to create scan: {}", e),
                            ToastLevel::Error,
                        ))];
                        if let Some((message, level, backend_started)) =
                            Self::ensure_local_backend_running(&self.settings.api_url)
                        {
                            tasks.push(Task::done(Message::ShowToast(message, level)));
                            if backend_started {
                                tasks.push(Task::perform(
                                    async move {
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    },
                                    |_| Message::RefreshAll,
                                ));
                            }
                        }
                        return Task::batch(tasks);
                    }
                }
                Task::none()
            }
            Message::FetchScans => {
                if let Some(client) = self.api_client.clone() {
                    self.api_state.loading_scans = true;
                    Task::perform(
                        async move { client.list_scans(None, Some(50), None).await },
                        |result| Message::ScansFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::ScansFetched(result) => {
                self.api_state.loading_scans = false;
                match result {
                    Ok(scans) => {
                        tracing::info!("Fetched {} scans", scans.len());
                        self.api_state.scans = scans;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch scans: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::FetchScan(id) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.get_scan(&id).await },
                        |result| Message::ScanFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::ScanFetched(result) => {
                match result {
                    Ok(scan) => {
                        self.upsert_scan_cache(scan.clone());
                        if let Some(task) = self.apply_scan_status(&scan) {
                            return task;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch scan: {}", e);
                        self.network.is_scanning = false;
                        self.active_scan_id = None;
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::CancelScan(id) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.cancel_scan(&id).await },
                        |result| Message::ScanCancelled(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::ScanCancelled(result) => {
                match result {
                    Ok(scan) => {
                        tracing::info!("Scan cancelled: {}", scan.id);
                        self.network.is_scanning = false;
                        self.active_scan_id = None;
                        self.upsert_scan_cache(scan);
                    }
                    Err(e) => {
                        tracing::error!("Failed to cancel scan: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Alerts ===
            Message::FetchAlerts => {
                if let Some(client) = self.api_client.clone() {
                    self.api_state.loading_alerts = true;
                    Task::perform(
                        async move { client.list_alerts(None, Some(100), None, None, None).await },
                        |result| Message::AlertsFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::AlertsFetched(result) => {
                self.api_state.loading_alerts = false;
                match result {
                    Ok(alerts) => {
                        tracing::info!("Fetched {} alerts", alerts.len());
                        self.api_state.alerts = alerts;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch alerts: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::FetchAlertStats => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.alert_stats().await },
                        |result| Message::AlertStatsFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::AlertStatsFetched(result) => {
                match result {
                    Ok(stats) => {
                        tracing::debug!("Alert stats: {} total", stats.total);
                        self.api_state.alert_stats = Some(stats);
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch alert stats: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::UpdateAlert(id, update) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.update_alert(&id, update).await },
                        |result| Message::AlertUpdated(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::AlertUpdated(result) => {
                match result {
                    Ok(alert) => {
                        tracing::info!("Alert updated: {}", alert.id);
                        // Update in cache
                        if let Some(pos) = self.api_state.alerts.iter().position(|a| a.id == alert.id) {
                            self.api_state.alerts[pos] = alert;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to update alert: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Vulnerabilities ===
            Message::FetchVulnerabilities => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.list_vulnerabilities(None, None, None, None).await },
                        |result| Message::VulnerabilitiesFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::VulnerabilitiesFetched(result) => {
                match result {
                    Ok(vulns) => {
                        tracing::info!("Fetched {} vulnerabilities", vulns.len());
                        self.api_state.vulnerabilities = vulns;
                        // Sync to canvas nodes
                        self.sync_vulnerabilities_to_canvas();
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch vulnerabilities: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::UpdateVulnerability(id, update) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.update_vulnerability(&id, update).await },
                        |result| Message::VulnerabilityUpdated(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::VulnerabilityUpdated(result) => {
                match result {
                    Ok(vuln) => {
                        tracing::info!("Vulnerability updated: {}", vuln.id);
                        if let Some(pos) = self.api_state.vulnerabilities.iter().position(|v| v.id == vuln.id) {
                            self.api_state.vulnerabilities[pos] = vuln;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to update vulnerability: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Traffic ===
            Message::FetchTraffic => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.list_traffic(None, Some(100), None, None, None).await },
                        |result| Message::TrafficFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::TrafficFetched(result) => {
                match result {
                    Ok(traffic) => {
                        tracing::info!("Fetched {} traffic flows", traffic.len());
                        self.api_state.traffic = traffic;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch traffic: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Tools ===
            Message::FetchTools => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.list_tools().await },
                        |result| Message::ToolsFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::ToolsFetched(result) => {
                match result {
                    Ok(tools) => {
                        tracing::info!("Fetched {} tools", tools.len());
                        self.api_state.tools = tools;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch tools: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::FetchToolsHealth => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.all_tools_health().await },
                        |result| Message::ToolsHealthFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::ToolsHealthFetched(result) => {
                match result {
                    Ok(health) => {
                        tracing::debug!("Fetched health for {} tools", health.len());
                        self.api_state.tools_health = health;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch tools health: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // === Confirmation wrappers ===
            Message::ConfirmDeleteDevice(id) => {
                let device_label = self.api_state.devices
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| d.hostname.clone().unwrap_or_else(|| d.ip_address.clone()))
                    .unwrap_or_else(|| id.clone());

                Task::done(Message::ShowConfirmDialog(
                    format!("Delete device '{}'? This action cannot be undone.", device_label),
                    Box::new(Message::DeleteDevice(id)),
                ))
            }
            Message::ConfirmDeleteJob(id) => {
                let job_name = self.api_state.jobs
                    .iter()
                    .find(|j| j.id == id)
                    .map(|j| j.name.clone())
                    .unwrap_or_else(|| id.clone());

                Task::done(Message::ShowConfirmDialog(
                    format!("Delete scheduled job '{}'? This action cannot be undone.", job_name),
                    Box::new(Message::DeleteJob(id)),
                ))
            }

            // === Scheduler ===
            Message::FetchJobs => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.list_jobs().await },
                        |result| Message::JobsFetched(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::JobsFetched(result) => {
                match result {
                    Ok(jobs) => {
                        tracing::info!("Fetched {} jobs", jobs.len());
                        self.api_state.jobs = jobs;
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch jobs: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::CreateJob(job_create) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.create_job(job_create).await },
                        |result| Message::JobCreated(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::JobCreated(result) => {
                match result {
                    Ok(job) => {
                        tracing::info!("Job created: {}", job.id);
                        self.api_state.jobs.push(job);
                    }
                    Err(e) => {
                        tracing::error!("Failed to create job: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::DeleteJob(id) => {
                if let Some(client) = self.api_client.clone() {
                    let id_clone = id.clone();
                    Task::perform(
                        async move {
                            client.delete_job(&id_clone).await?;
                            Ok::<_, api::ApiError>(id_clone)
                        },
                        |result| Message::JobDeleted(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::JobDeleted(result) => {
                match result {
                    Ok(id) => {
                        tracing::info!("Job deleted: {}", id);
                        self.api_state.jobs.retain(|j| j.id != id);
                    }
                    Err(e) => {
                        tracing::error!("Failed to delete job: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::PauseJob(id) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.pause_job(&id).await },
                        |result| Message::JobPaused(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::JobPaused(result) => {
                match result {
                    Ok(job) => {
                        tracing::info!("Job paused: {}", job.id);
                        if let Some(pos) = self.api_state.jobs.iter().position(|j| j.id == job.id) {
                            self.api_state.jobs[pos] = job;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to pause job: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }
            Message::ResumeJob(id) => {
                if let Some(client) = self.api_client.clone() {
                    Task::perform(
                        async move { client.resume_job(&id).await },
                        |result| Message::JobResumed(result.map_err(|e| e.to_string())),
                    )
                } else {
                    Task::none()
                }
            }
            Message::JobResumed(result) => {
                match result {
                    Ok(job) => {
                        tracing::info!("Job resumed: {}", job.id);
                        if let Some(pos) = self.api_state.jobs.iter().position(|j| j.id == job.id) {
                            self.api_state.jobs[pos] = job;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to resume job: {}", e);
                        self.api_state.last_error = Some(e);
                    }
                }
                Task::none()
            }

            // =================================================================
            // WebSocket Messages
            // =================================================================

            Message::WsStateChanged(state) => {
                tracing::info!("WebSocket state: {:?}", state);
                self.api_state.ws_connected = matches!(state, WsState::Connected);
                self.api_state.ws_state = Some(state);
                Task::none()
            }
            Message::WsEventReceived(event) => {
                self.handle_ws_event(event)
            }
            Message::WsParseError(error) => {
                tracing::warn!("WebSocket parse error: {}", error);
                Task::none()
            }

            // =================================================================
            // Webview Messages (React NetworkCanvas)
            // =================================================================

            Message::WebviewHandleReady(hwnd) => {
                if self.webview.is_none() {
                    tracing::info!("Got window handle (HWND={}), creating webview", hwnd);
                    let (tx, rx) = std::sync::mpsc::channel();
                    match CanvasWebview::new(hwnd, tx) {
                        Ok(wv) => {
                            self.webview = Some(wv);
                            self.webview_event_rx = Some(rx);
                            self.webview_initialized = true;
                            tracing::info!("Webview created successfully");
                            self.update_webview_bounds();
                            self.sync_state_to_webview();
                        }
                        Err(e) => {
                            tracing::error!("Failed to create webview: {}", e);
                        }
                    }
                }
                // Query the actual window size to correct initial bounds
                iced::window::get_oldest().then(|opt_id| {
                    match opt_id {
                        Some(id) => iced::window::get_size(id)
                            .map(|size| Message::WindowResized(size.width as u32, size.height as u32)),
                        None => Task::none(),
                    }
                })
            }
            Message::WebviewReady => {
                tracing::info!(
                    "WV_READY nodes_in_state={} conns_in_state={}",
                    self.network.nodes.len(),
                    self.network.connections.len()
                );
                if let Some(ref mut wv) = self.webview {
                    wv.set_ready();
                }
                // Sync current state to webview
                self.sync_state_to_webview();
                Task::none()
            }
            Message::WebviewNodeSelected(id_str, add_to_selection) => {
                if let Some(node_id) = parse_node_id(&id_str) {
                    if add_to_selection {
                        self.network.add_to_selection(&[node_id]);
                    } else {
                        self.network.select_node(node_id);
                    }
                    self.sync_state_to_webview();
                }
                Task::none()
            }
            Message::WebviewNodeDeselected => {
                self.network.clear_selection();
                self.sync_state_to_webview();
                Task::none()
            }
            Message::WebviewNodeMoved(id_str, x, y) => {
                if let Some(node_id) = parse_node_id(&id_str) {
                    self.network.move_node(node_id, x, y);
                    // Don't sync back to webview for moves - the webview is the source of truth here
                }
                Task::none()
            }
            Message::WebviewCanvasPan(dx, dy) => {
                self.network.pan(dx, dy);
                // Don't sync back to webview - it's handling the pan locally
                Task::none()
            }
            Message::WebviewCanvasZoom(zoom) => {
                self.network.set_zoom(zoom);
                // Don't sync back to webview - it's handling the zoom locally
                Task::none()
            }
            Message::WebviewStartConnection(from_id_str) => {
                if let Some(node_id) = parse_node_id(&from_id_str) {
                    self.network.connecting_from = Some(node_id);
                }
                Task::none()
            }
            Message::WebviewCompleteConnection(to_id_str) => {
                if let Some(to_id) = parse_node_id(&to_id_str) {
                    if let Some(from_id) = self.network.connecting_from.take() {
                        use crate::message::ConnectionType;
                        self.network.add_connection(from_id, to_id, ConnectionType::Wired);
                        self.sync_state_to_webview();
                    }
                }
                Task::none()
            }
            Message::WebviewCancelConnection => {
                self.network.connecting_from = None;
                Task::none()
            }
            Message::WebviewConnectionHovered(id_opt) => {
                self.network.hovered_connection = id_opt.and_then(|s| parse_connection_id(&s));
                Task::none()
            }
            Message::WebviewTick => {
                // Pump GTK events on Linux (required for webkit2gtk)
                #[cfg(target_os = "linux")]
                {
                    while gtk::events_pending() {
                        gtk::main_iteration_do(false);
                    }
                }
                // Drain pending webview IPC events
                let mut tasks = Vec::new();
                if let Some(ref rx) = self.webview_event_rx {
                    while let Ok(event) = rx.try_recv() {
                        match event {
                            WebviewEvent::Ready => {
                                tasks.push(Task::done(Message::WebviewReady));
                            }
                            WebviewEvent::NodeSelected { id, add_to_selection } => {
                                tasks.push(Task::done(Message::WebviewNodeSelected(id, add_to_selection)));
                            }
                            WebviewEvent::NodeDeselected => {
                                tasks.push(Task::done(Message::WebviewNodeDeselected));
                            }
                            WebviewEvent::NodeMoved { id, x, y } => {
                                tasks.push(Task::done(Message::WebviewNodeMoved(id, x, y)));
                            }
                            WebviewEvent::CanvasPan { dx, dy } => {
                                tasks.push(Task::done(Message::WebviewCanvasPan(dx, dy)));
                            }
                            WebviewEvent::CanvasZoom { zoom } => {
                                tasks.push(Task::done(Message::WebviewCanvasZoom(zoom)));
                            }
                            WebviewEvent::StartConnection { from_id } => {
                                tasks.push(Task::done(Message::WebviewStartConnection(from_id)));
                            }
                            WebviewEvent::CompleteConnection { to_id } => {
                                tasks.push(Task::done(Message::WebviewCompleteConnection(to_id)));
                            }
                            WebviewEvent::CancelConnection => {
                                tasks.push(Task::done(Message::WebviewCancelConnection));
                            }
                            WebviewEvent::ConnectionHovered { id } => {
                                tasks.push(Task::done(Message::WebviewConnectionHovered(id)));
                            }
                        }
                    }
                }
                if tasks.is_empty() {
                    Task::none()
                } else {
                    Task::batch(tasks)
                }
            }
        }
    }

    /// Sync the current network state to the webview.
    fn sync_state_to_webview(&mut self) {
        if let Some(ref wv) = self.webview {
            self.sync_seq += 1;
            let seq = self.sync_seq;
            let mut json = NetworkStateJson::from(&self.network);
            json.seq = seq;

            tracing::info!(
                "WV_SYNC seq={} ready={} nodes={} conns={} pan=({:.0},{:.0}) zoom={:.2}",
                seq,
                wv.is_ready(),
                json.nodes.len(),
                json.connections.len(),
                json.pan.0,
                json.pan.1,
                json.zoom,
            );

            // Log layout diagnostics on non-empty syncs
            if !self.network.nodes.is_empty() {
                let hub = self.network.find_hub_node();
                let all_origin = self.network.nodes.iter().all(|n| n.x == 0.0 && n.y == 0.0);
                tracing::info!(
                    "WV_SYNC_LAYOUT seq={} hub={:?} all_origin={}",
                    seq, hub, all_origin
                );
                for n in self.network.nodes.iter().take(3) {
                    tracing::debug!(
                        "  NODE {} ip={} pos=({:.1}, {:.1})",
                        n.id.0, n.ip, n.x, n.y
                    );
                }
            }

            if let Err(e) = wv.update_state(&json) {
                tracing::warn!("WV_SYNC_FAIL seq={} err={}", seq, e);
            }
        }
    }

    /// Recompute and apply webview bounds based on current layout state.
    fn update_webview_bounds(&mut self) {
        // Layout constants (must match the view code)
        const HEADER_HEIGHT: f64 = 56.0; // header container height
        const RULE_HEIGHT: f64 = 1.0;    // horizontal_rule(1)
        const TOOLBAR_WIDTH: f64 = 72.0; // toolbar container width
        const INSPECTOR_WIDTH: f64 = 280.0; // inspector panel width
        const ROW_SPACING: f64 = 1.0;    // main_content row spacing

        let top = HEADER_HEIGHT + RULE_HEIGHT;
        let left = if self.toolbar_visible {
            TOOLBAR_WIDTH + ROW_SPACING
        } else {
            0.0
        };
        let right_inset = if self.inspector_visible {
            INSPECTOR_WIDTH + ROW_SPACING
        } else {
            0.0
        };

        // Main content area height depends on terminal visibility.
        // column uses FillPortion(7) for main, FillPortion(3) for terminal.
        let available_height = self.window_height - top;
        let main_height = if self.terminal_visible {
            available_height * 7.0 / 10.0
        } else {
            available_height
        };

        let width = (self.window_width - left - right_inset).max(0.0);
        let height = main_height.max(0.0);

        tracing::debug!(
            "Webview bounds: x={:.0}, y={:.0}, w={:.0}, h={:.0} (window={:.0}x{:.0})",
            left, top, width, height, self.window_width, self.window_height
        );

        if let Some(ref mut wv) = self.webview {
            if let Err(e) = wv.set_bounds(left, top, width, height) {
                tracing::warn!("Failed to update webview bounds: {}", e);
            }
        }
    }

    /// Handle a WebSocket event from the backend.
    fn handle_ws_event(&mut self, event: api::WsEvent) -> Task<Message> {
        use api::WsEventType;

        tracing::debug!("WS event: {:?} from {}", event.event_type, event.source);

        match event.event_type {
            // Scan events
            WsEventType::ScanStarted => {
                self.network.is_scanning = true;
                self.network.scan_progress = 0;
                if let Some(scan_id) = event.get_string("scan_id") {
                    self.active_scan_id = Some(scan_id.clone());
                    Task::done(Message::FetchScan(scan_id))
                } else {
                    Task::none()
                }
            }
            WsEventType::ScanProgress => {
                if let Some(progress) = event.get_i64("progress") {
                    self.network.scan_progress = progress as u8;
                }
                Task::none()
            }
            WsEventType::ScanCompleted => {
                self.network.is_scanning = false;
                self.network.scan_progress = 100;
                self.active_scan_id = None;

                // Show native notification if enabled
                if self.settings.notifications_enabled {
                    let scan_type = event.get_string("scan_type").unwrap_or_else(|| "Network".to_string());
                    let target = event.get_string("target").unwrap_or_else(|| "unknown".to_string());
                    notifications::notify_scan_completed(&scan_type, &target, "completed");
                }

                // Refresh devices and alerts after scan completes
                Task::batch([
                    Task::done(Message::FetchDevices),
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchScans),
                ])
            }
            WsEventType::ScanFailed => {
                self.network.is_scanning = false;
                self.active_scan_id = None;
                if let Some(error) = event.get_string("error") {
                    tracing::error!("Scan failed: {}", error);
                    self.api_state.last_error = Some(error);
                }

                // Show native notification if enabled
                if self.settings.notifications_enabled {
                    let scan_type = event.get_string("scan_type").unwrap_or_else(|| "Network".to_string());
                    let target = event.get_string("target").unwrap_or_else(|| "unknown".to_string());
                    notifications::notify_scan_completed(&scan_type, &target, "failed");
                }

                Task::done(Message::FetchScans)
            }

            // Device events
            WsEventType::DeviceDiscovered => {
                // Show native notification if enabled
                if self.settings.notifications_enabled {
                    let ip = event.get_string("ip_address").unwrap_or_else(|| "unknown".to_string());
                    let hostname = event.get_string("hostname");
                    notifications::notify_device_discovered(&ip, hostname.as_deref());
                }

                Task::done(Message::FetchDevices)
            }
            WsEventType::DeviceUpdated => {
                if let Some(device_id) = event.get_string("device_id") {
                    Task::done(Message::FetchDevice(device_id))
                } else {
                    Task::done(Message::FetchDevices)
                }
            }
            WsEventType::DeviceOffline => {
                if let Some(device_id) = event.get_string("device_id") {
                    // Update device status in cache
                    if let Some(device) = self.api_state.devices.iter_mut().find(|d| d.id == device_id) {
                        device.status = "offline".to_string();
                    }
                    self.sync_devices_to_canvas();
                    self.sync_state_to_webview();
                }
                Task::none()
            }

            // Alert events
            WsEventType::AlertCreated => {
                // Show native notification if enabled
                if self.settings.notifications_enabled {
                    let severity = event.get_string("severity").unwrap_or_else(|| "info".to_string());
                    let title = event.get_string("title").unwrap_or_else(|| "New Alert".to_string());
                    let message = event.get_string("message").unwrap_or_else(|| "A new alert was created".to_string());
                    notifications::notify_alert(&severity, &title, &message);
                }

                // Refresh alerts and stats
                Task::batch([
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchAlertStats),
                ])
            }
            WsEventType::AlertUpdated | WsEventType::AlertResolved => {
                Task::batch([
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchAlertStats),
                ])
            }

            // Tool events
            WsEventType::ToolOnline | WsEventType::ToolOffline => {
                Task::done(Message::FetchToolsHealth)
            }

            // System events
            WsEventType::SystemStartup => {
                tracing::info!("Backend system started");
                // Refresh all data
                Task::batch([
                    Task::done(Message::FetchDevices),
                    Task::done(Message::FetchScans),
                    Task::done(Message::FetchAlerts),
                    Task::done(Message::FetchTools),
                ])
            }
            WsEventType::SystemShutdown => {
                tracing::warn!("Backend system shutting down");
                Task::none()
            }
        }
    }

    /// Sync devices from API to the network canvas.
    /// This creates/updates nodes on the canvas based on API device data.
    pub fn sync_devices_to_canvas(&mut self) {
        use crate::message::{NodeStatus, NodeType};
        use crate::state::network::{Node, Port as CanvasPort, Vulnerability as CanvasVuln};

        for api_device in &self.api_state.devices {
            // Check if device already exists on canvas (by IP)
            let existing = self.network.nodes.iter_mut().find(|n| n.ip == api_device.ip_address);

            if let Some(node) = existing {
                // Update existing node
                node.hostname = api_device.hostname.clone();
                node.vendor = api_device.vendor.clone();
                node.os_family = api_device.os_family.clone();
                node.mac = api_device.mac_address.clone();
                node.status = match api_device.status.as_str() {
                    "online" | "up" => NodeStatus::Online,
                    "offline" | "down" => NodeStatus::Offline,
                    "warning" => NodeStatus::Warning,
                    _ => NodeStatus::Online,
                };
                // Update ports
                node.ports = api_device.ports.iter().map(|p| CanvasPort {
                    number: p.port_number,
                    protocol: p.protocol.clone(),
                    state: p.state.clone(),
                    service_name: p.service_name.clone(),
                    service_version: p.service_version.clone(),
                }).collect();
            } else {
                // Create new node
                let node_type = match api_device.device_type.as_deref() {
                    Some("router") => NodeType::Router,
                    Some("server") => NodeType::Server,
                    Some("firewall") => NodeType::Firewall,
                    Some("database") => NodeType::Database,
                    Some("workstation") | Some("desktop") | Some("laptop") => NodeType::Workstation,
                    Some("mobile") | Some("phone") | Some("tablet") => NodeType::Mobile,
                    Some("iot") | Some("camera") | Some("sensor") => NodeType::IoT,
                    Some("ap") | Some("access_point") | Some("extender") => NodeType::Extender,
                    Some("cloud") => NodeType::Cloud,
                    _ => NodeType::Workstation, // Default
                };

                // Temporary position - radial layout applied after all nodes added
                let x = 0.0;
                let y = 0.0;

                let label = api_device.hostname.clone()
                    .unwrap_or_else(|| api_device.ip_address.clone());

                let mut node = Node::new(node_type, x, y, label, api_device.ip_address.clone());
                node.mac = api_device.mac_address.clone();
                node.vendor = api_device.vendor.clone();
                node.hostname = api_device.hostname.clone();
                node.os_family = api_device.os_family.clone();
                node.status = match api_device.status.as_str() {
                    "online" | "up" => NodeStatus::Online,
                    "offline" | "down" => NodeStatus::Offline,
                    "warning" => NodeStatus::Warning,
                    _ => NodeStatus::Online,
                };
                node.ports = api_device.ports.iter().map(|p| CanvasPort {
                    number: p.port_number,
                    protocol: p.protocol.clone(),
                    state: p.state.clone(),
                    service_name: p.service_name.clone(),
                    service_version: p.service_version.clone(),
                }).collect();

                self.network.add_node(node);
            }
        }

        // Apply radial layout to position all nodes
        self.network.apply_radial_layout();

        // Create hub-to-spoke connections
        self.network.create_hub_connections();

        // Sync vulnerabilities to nodes
        self.sync_vulnerabilities_to_canvas();
    }

    /// Sync vulnerabilities from API to canvas nodes.
    fn sync_vulnerabilities_to_canvas(&mut self) {
        use crate::message::Severity;
        use crate::state::network::Vulnerability as CanvasVuln;

        for api_vuln in &self.api_state.vulnerabilities {
            // Find the device this vulnerability belongs to
            if let Some(ref device_id) = api_vuln.device_id {
                // Find matching device by ID or IP
                if let Some(api_device) = self.api_state.devices.iter().find(|d| &d.id == device_id) {
                    // Find matching node on canvas
                    if let Some(node) = self.network.nodes.iter_mut().find(|n| n.ip == api_device.ip_address) {
                        // Check if vuln already exists
                        let cve = api_vuln.cve_id.clone().unwrap_or_else(|| api_vuln.id.clone());
                        if !node.vulnerabilities.iter().any(|v| v.cve == cve) {
                            node.vulnerabilities.push(CanvasVuln {
                                cve,
                                cvss: api_vuln.cvss_score.unwrap_or(0.0),
                                severity: match api_vuln.severity.as_str() {
                                    "critical" => Severity::Critical,
                                    "high" => Severity::High,
                                    "medium" => Severity::Medium,
                                    _ => Severity::Low,
                                },
                                description: api_vuln.description.clone().unwrap_or_default(),
                                references: api_vuln.references.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Render the view.
    pub fn view(&self) -> Element<Message> {
        // Calculate vuln count for header
        let (critical, high, medium, low) = self.network.vuln_counts();
        let vuln_count = critical + high + medium + low;

        // Header with API state info
        let header = views::header::view(
            self.network.is_scanning,
            vuln_count,
            self.api_state.ws_connected,
            self.api_state.devices.len(),
            self.api_state.alerts.len(),
            self.api_state.scans.len(),
        );

        // Left toolbar
        let toolbar = if self.toolbar_visible {
            views::toolbar::view(self.tool_mode)
        } else {
            container(column![]).width(Length::Shrink).into()
        };

        // Main content area (canvas)
        let canvas = views::canvas::view(&self.network);

        // Inspector panel
        let inspector = if self.inspector_visible {
            views::inspector::view(&self.network, self.inspector_tab)
        } else {
            container(column![]).width(Length::Shrink).into()
        };

        // Main row: toolbar | canvas | inspector
        let main_content = row![
            toolbar,
            container(canvas)
                .width(Length::Fill)
                .height(Length::Fill),
            inspector,
        ]
        .spacing(1);

        // Terminal panel
        let terminal = if self.terminal_visible {
            views::terminal::view(&self.terminal)
        } else {
            container(column![]).height(Length::Shrink).into()
        };

        // Main layout without modal
        let main_layout: Element<Message> = column![
            header,
            horizontal_rule(1),
            container(main_content)
                .width(Length::Fill)
                .height(Length::FillPortion(if self.terminal_visible { 7 } else { 10 }))
                .style(theme::content_style),
            if self.terminal_visible {
                container(terminal)
                    .width(Length::Fill)
                    .height(Length::FillPortion(3))
            } else {
                container(column![])
                    .height(Length::Shrink)
            }
        ]
        .into();

        // Overlay modals if visible
        if self.show_vuln_dashboard {
            let vuln_dashboard = views::vuln_dashboard::view(
                &self.network,
                self.vuln_filter_severity,
                &self.vuln_search_query,
            );

            Stack::new()
                .push(main_layout)
                .push(vuln_dashboard)
                .into()
        } else if self.show_alerts_dashboard {
            let alerts_dashboard = views::alerts::view(
                &self.api_state.alerts,
                self.api_state.alert_stats.as_ref(),
                self.selected_alert_id.as_deref(),
                self.alert_filter_severity.as_deref(),
                self.alert_filter_status.as_deref(),
                &self.alert_search_query,
            );

            Stack::new()
                .push(main_layout)
                .push(alerts_dashboard)
                .into()
        } else if self.show_scans_dashboard {
            let scans_dashboard = views::scans::view(
                &self.api_state.scans,
                self.selected_scan_id.as_deref(),
                self.scan_filter_status.as_deref(),
            );

            Stack::new()
                .push(main_layout)
                .push(scans_dashboard)
                .into()
        } else if self.show_traffic_dashboard {
            let traffic_dashboard = views::traffic::view(
                &self.api_state.traffic,
                &self.selected_traffic_id,
                &self.traffic_filter_protocol,
            );

            Stack::new()
                .push(main_layout)
                .push(traffic_dashboard)
                .into()
        } else if self.show_tools_dashboard {
            let tools_dashboard = views::tools::view(
                &self.api_state.tools,
                &self.api_state.tools_health,
                &self.selected_tool,
            );

            Stack::new()
                .push(main_layout)
                .push(tools_dashboard)
                .into()
        } else if self.show_scheduler_dashboard {
            let scheduler_dashboard = views::scheduler::view(
                &self.api_state.jobs,
                &self.selected_job_id,
            );

            Stack::new()
                .push(main_layout)
                .push(scheduler_dashboard)
                .into()
        } else if self.show_settings {
            let settings_panel = views::settings::view(&self.settings);

            Stack::new()
                .push(main_layout)
                .push(settings_panel)
                .into()
        } else if let Some(ref dialog) = self.confirm_dialog {
            let dialog_view = views::ui_components::confirm_dialog_view(dialog);

            Stack::new()
                .push(main_layout)
                .push(dialog_view)
                .into()
        } else {
            // Add toast container on top
            if !self.toasts.is_empty() {
                let toast_view = views::ui_components::toast_container(&self.toasts);
                Stack::new()
                    .push(main_layout)
                    .push(toast_view)
                    .into()
            } else {
                main_layout
            }
        }
    }

    /// Get subscriptions.
    pub fn subscription(&self) -> Subscription<Message> {
        use iced::time;

        let mut subs = vec![
            // Terminal output subscriptions
            self.terminal.subscription(),
            // Tick every second for toasts and auto-refresh
            time::every(Duration::from_secs(1)).map(|_| Message::Tick),
            // Window size events for webview bounds (Opened + Resized)
            iced::event::listen_with(|event, _status, _id| {
                match event {
                    iced::Event::Window(iced::window::Event::Opened { size, .. }) => {
                        Some(Message::WindowResized(size.width as u32, size.height as u32))
                    }
                    iced::Event::Window(iced::window::Event::Resized(size)) => {
                        Some(Message::WindowResized(size.width as u32, size.height as u32))
                    }
                    _ => None,
                }
            }),
        ];

        // Webview event polling (fast tick for responsive IPC)
        if self.webview_initialized {
            subs.push(time::every(Duration::from_millis(50)).map(|_| Message::WebviewTick));
        }

        // WebSocket subscription (if enabled)
        if self.ws_enabled {
            let ws_sub = websocket::connect(self.ws_config.clone()).map(|msg| {
                match msg {
                    WsMessage2::StateChanged(state) => Message::WsStateChanged(state),
                    WsMessage2::Event(event) => Message::WsEventReceived(event),
                    WsMessage2::ParseError(error) => Message::WsParseError(error),
                }
            });
            subs.push(ws_sub);
        }

        Subscription::batch(subs)
    }

    /// Get the theme.
    pub fn theme(&self) -> Theme {
        theme::get_theme()
    }
}

impl Default for NetWatch {
    fn default() -> Self {
        Self::new().0
    }
}

impl Default for WsState {
    fn default() -> Self {
        WsState::Disconnected
    }
}

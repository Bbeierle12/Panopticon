//! Application messages and types.
//!
//! All user interactions and events are represented as messages
//! following the Elm architecture.

use netsec_pty::ShellInfo;
use uuid::Uuid;

use crate::api::{
    self, Alert, AlertStats, BrowsingData, Device, Scan, ScheduledJob, Tool, ToolHealth,
    TrafficFlow, Vulnerability, WsEvent, WsState,
};

/// Unique identifier for a terminal tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TabId(pub Uuid);

impl TabId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TabId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a device/node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Uuid);

impl ConnectionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

/// Node types for the network canvas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Server,
    Firewall,
    Router,
    Database,
    Workstation,
    Mobile,
    Cloud,
    IoT,
    Extender,
    Group,
}

impl NodeType {
    pub fn label(&self) -> &'static str {
        match self {
            NodeType::Server => "Server",
            NodeType::Firewall => "Firewall",
            NodeType::Router => "Router",
            NodeType::Database => "Database",
            NodeType::Workstation => "Workstation",
            NodeType::Mobile => "Mobile",
            NodeType::Cloud => "Cloud",
            NodeType::IoT => "IoT",
            NodeType::Extender => "AP",
            NodeType::Group => "Group",
        }
    }
}

/// Node status on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeStatus {
    #[default]
    Online,
    Offline,
    Warning,
    Compromised,
}

/// Vulnerability severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Connection type between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Wired,
    Wireless,
}

/// Tool mode for canvas interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolMode {
    #[default]
    Select,
    Connect,
    Pan,
}

/// Nmap scan types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmapScanType {
    Quick,
    Ports,
    Service,
    OS,
    Vuln,
    Full,
}

impl NmapScanType {
    pub fn label(&self) -> &'static str {
        match self {
            NmapScanType::Quick => "Quick Scan",
            NmapScanType::Ports => "Port Scan",
            NmapScanType::Service => "Service Detection",
            NmapScanType::OS => "OS Fingerprint",
            NmapScanType::Vuln => "Vulnerability Scan",
            NmapScanType::Full => "Full Scan",
        }
    }
}

/// Attack tool types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackTool {
    Hydra,
    Metasploit,
}

/// Inspector panel tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InspectorTab {
    #[default]
    Details,
    Connections,
    Traffic,
}

/// Toast notification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// Application messages.
#[derive(Debug, Clone)]
pub enum Message {
    // === Terminal ===
    /// User typed input in a terminal tab
    TerminalInput(TabId, String),
    /// Terminal output received from PTY
    TerminalOutput(TabId, Vec<u8>),
    /// Request to create a new terminal tab with the given shell
    TerminalNewTab(ShellInfo),
    /// Request to close a terminal tab
    TerminalCloseTab(TabId),
    /// User selected a different terminal tab
    TerminalSelectTab(TabId),
    /// Terminal was resized
    TerminalResized(TabId, u16, u16),
    /// Terminal PTY closed/exited
    TerminalClosed(TabId),

    // === Network Canvas ===
    /// User selected a node on the canvas
    NodeSelected(NodeId),
    /// User deselected all nodes
    NodeDeselected,
    /// Add nodes to selection
    NodesAddToSelection(Vec<NodeId>),
    /// Canvas was panned by (dx, dy)
    CanvasPan(f32, f32),
    /// Canvas zoom level changed
    CanvasZoom(f32),
    /// Add a new node to the canvas
    AddNode(NodeType),
    /// Delete selected nodes
    DeleteSelected,
    /// Group selected nodes
    GroupSelected,
    /// Node position changed
    NodeMoved(NodeId, f32, f32),
    /// Start connecting nodes
    StartConnection(NodeId),
    /// Complete a connection to a node
    CompleteConnection(NodeId),
    /// Cancel connection in progress
    CancelConnection,
    /// Hover over a connection
    ConnectionHovered(Option<ConnectionId>),

    // === Tool Mode ===
    /// Change the current tool mode
    SetToolMode(ToolMode),

    // === Scanning ===
    /// Start a network scan
    ScanNetwork,
    /// Run an Nmap scan
    RunNmapScan(NmapScanType),
    /// Run an attack tool
    RunAttackTool(AttackTool),
    /// Scan completed
    ScanCompleted,
    /// Scan progress update
    ScanProgress(u8),

    // === File Operations ===
    /// Save the current project
    SaveProject,
    /// Load a project
    LoadProject,

    // === Keyboard ===
    /// Keyboard input event
    KeyboardInput {
        key: iced::keyboard::Key,
        modifiers: iced::keyboard::Modifiers,
    },

    // === UI Panels ===
    /// Toggle the terminal panel visibility
    ToggleTerminalPanel,
    /// Toggle the inspector panel visibility
    ToggleInspectorPanel,
    /// Toggle the toolbar visibility
    ToggleToolbar,
    /// Show the vulnerability dashboard
    ShowVulnDashboard,
    /// Hide the vulnerability dashboard
    HideVulnDashboard,
    /// Show browsing metrics dashboard
    ShowBrowsingDashboard,
    /// Hide browsing metrics dashboard
    HideBrowsingDashboard,
    /// Browsing data fetched
    BrowsingDataFetched(Result<BrowsingData, String>),
    /// Fetch browsing data
    FetchBrowsingData,
    /// Change inspector tab
    SetInspectorTab(InspectorTab),

    // === Vulnerability Dashboard ===
    /// Filter vulnerabilities by severity
    VulnFilterSeverity(Option<Severity>),
    /// Sort vulnerabilities
    VulnSortBy(String),
    /// Search vulnerabilities
    VulnSearch(String),

    // === Alerts Dashboard ===
    /// Show the alerts dashboard
    ShowAlertsDashboard,
    /// Hide the alerts dashboard
    HideAlertsDashboard,
    /// Select an alert in the list
    AlertSelected(String),
    /// Filter alerts by severity
    AlertFilterSeverity(Option<String>),
    /// Filter alerts by status
    AlertFilterStatus(Option<String>),
    /// Search alerts
    AlertSearch(String),
    /// Acknowledge an alert
    AcknowledgeAlert(String),
    /// Resolve an alert
    ResolveAlert(String),
    /// Dismiss an alert
    DismissAlert(String),

    // === Scans Dashboard ===
    /// Show the scans dashboard
    ShowScansDashboard,
    /// Hide the scans dashboard
    HideScansDashboard,
    /// Select a scan in the list
    ScanSelected(String),
    /// Filter scans by status
    ScanFilterStatus(Option<String>),
    /// Re-run a scan with the same parameters
    RescanTarget(String, String, String), // target, scan_type, tool

    // === Traffic Dashboard ===
    /// Show the traffic dashboard
    ShowTrafficDashboard,
    /// Hide the traffic dashboard
    HideTrafficDashboard,
    /// Select a traffic flow
    TrafficFlowSelected(String),
    /// Filter traffic by protocol
    TrafficFilterProtocol(Option<String>),
    /// Filter traffic by direction
    TrafficFilterDirection(Option<String>),

    // === Tools Dashboard ===
    /// Show the tools dashboard
    ShowToolsDashboard,
    /// Hide the tools dashboard
    HideToolsDashboard,
    /// Select a tool
    ToolSelected(String),
    /// Run a tool health check
    RunToolHealthCheck(String),

    // === Scheduler Dashboard ===
    /// Show the scheduler dashboard
    ShowSchedulerDashboard,
    /// Hide the scheduler dashboard
    HideSchedulerDashboard,
    /// Select a scheduled job
    JobSelected(String),
    /// Toggle job enabled state
    ToggleJobEnabled(String),

    // === Settings ===
    /// Show the settings panel
    ShowSettings,
    /// Hide the settings panel
    HideSettings,
    /// Update API URL setting
    SettingsUpdateApiUrl(String),
    /// Update WebSocket URL setting
    SettingsUpdateWsUrl(String),
    /// Toggle dark mode
    SettingsToggleDarkMode,
    /// Toggle notifications
    SettingsToggleNotifications,
    /// Toggle auto-refresh
    SettingsToggleAutoRefresh,
    /// Update refresh interval
    SettingsUpdateRefreshInterval(u32),
    /// Save settings
    SettingsSave,

    // === Notifications ===
    /// Show a toast notification
    ShowToast(String, ToastLevel),
    /// Dismiss a toast
    DismissToast(usize),
    /// Show confirmation dialog
    ShowConfirmDialog(String, Box<Message>),
    /// Confirm dialog action
    ConfirmDialogAccept,
    /// Cancel dialog
    ConfirmDialogCancel,

    // === System ===
    /// Periodic tick for animations and updates
    Tick,
    /// Window was resized
    WindowResized(u32, u32),

    // === Legacy aliases for compatibility ===
    /// User selected a device (alias for NodeSelected)
    DeviceSelected(NodeId),
    /// Device deselected (alias for NodeDeselected)
    DeviceDeselected,
    /// Scan a specific device
    ScanDevice(NodeId),

    // =========================================================================
    // API Messages
    // =========================================================================

    // === Connection ===
    /// Connect to the backend API
    ApiConnect,
    /// Disconnect from the backend API
    ApiDisconnect,
    /// API health check completed
    ApiHealthCheck(Result<bool, String>),
    /// Refresh all data from the API
    RefreshAll,

    // === Devices ===
    /// Request to fetch all devices
    FetchDevices,
    /// Devices fetched from API
    DevicesFetched(Result<Vec<Device>, String>),
    /// Request to fetch a specific device
    FetchDevice(String),
    /// Single device fetched
    DeviceFetched(Result<Device, String>),
    /// Request to update a device
    UpdateDevice(String, api::DeviceUpdate),
    /// Device updated
    DeviceUpdated(Result<Device, String>),
    /// Request to delete a device
    DeleteDevice(String),
    /// Device deleted
    DeviceDeleted(Result<String, String>),

    // === Scans ===
    /// Request to create a new scan
    CreateScan(api::ScanCreate),
    /// Scan created
    ScanCreated(Result<Scan, String>),
    /// Request to fetch all scans
    FetchScans,
    /// Scans fetched
    ScansFetched(Result<Vec<Scan>, String>),
    /// Request to fetch a specific scan
    FetchScan(String),
    /// Single scan fetched
    ScanFetched(Result<Scan, String>),
    /// Request to cancel a scan
    CancelScan(String),
    /// Scan cancelled
    ScanCancelled(Result<Scan, String>),

    // === Alerts ===
    /// Request to fetch all alerts
    FetchAlerts,
    /// Alerts fetched
    AlertsFetched(Result<Vec<Alert>, String>),
    /// Request to fetch alert stats
    FetchAlertStats,
    /// Alert stats fetched
    AlertStatsFetched(Result<AlertStats, String>),
    /// Request to update an alert
    UpdateAlert(String, api::AlertUpdate),
    /// Alert updated
    AlertUpdated(Result<Alert, String>),

    // === Vulnerabilities ===
    /// Request to fetch vulnerabilities
    FetchVulnerabilities,
    /// Vulnerabilities fetched
    VulnerabilitiesFetched(Result<Vec<Vulnerability>, String>),
    /// Request to update a vulnerability
    UpdateVulnerability(String, api::VulnerabilityUpdate),
    /// Vulnerability updated
    VulnerabilityUpdated(Result<Vulnerability, String>),

    // === Traffic ===
    /// Request to fetch traffic flows
    FetchTraffic,
    /// Traffic flows fetched
    TrafficFetched(Result<Vec<TrafficFlow>, String>),

    // === Tools ===
    /// Request to fetch all tools
    FetchTools,
    /// Tools fetched
    ToolsFetched(Result<Vec<Tool>, String>),
    /// Request to check all tools health
    FetchToolsHealth,
    /// Tools health fetched
    ToolsHealthFetched(Result<Vec<ToolHealth>, String>),

    // === Scheduler ===
    /// Request to fetch scheduled jobs
    FetchJobs,
    /// Request to delete a device with confirmation
    ConfirmDeleteDevice(String),
    /// Request to delete a job with confirmation
    ConfirmDeleteJob(String),
    /// Jobs fetched
    JobsFetched(Result<Vec<ScheduledJob>, String>),
    /// Request to create a job
    CreateJob(api::JobCreate),
    /// Job created
    JobCreated(Result<ScheduledJob, String>),
    /// Request to delete a job
    DeleteJob(String),
    /// Job deleted
    JobDeleted(Result<String, String>),
    /// Request to pause a job
    PauseJob(String),
    /// Job paused
    JobPaused(Result<ScheduledJob, String>),
    /// Request to resume a job
    ResumeJob(String),
    /// Job resumed
    JobResumed(Result<ScheduledJob, String>),

    // =========================================================================
    // WebSocket Messages
    // =========================================================================

    /// WebSocket connection state changed
    WsStateChanged(WsState),
    /// WebSocket event received
    WsEventReceived(WsEvent),
    /// WebSocket parse error
    WsParseError(String),

    // =========================================================================
    // Webview Messages (React NetworkCanvas)
    // =========================================================================

    /// Window handle obtained for webview creation
    WebviewHandleReady(isize),
    /// Webview has finished loading and is ready
    WebviewReady,
    /// User selected a node in the webview
    WebviewNodeSelected(String, bool),
    /// User deselected all nodes in the webview
    WebviewNodeDeselected,
    /// User moved a node in the webview
    WebviewNodeMoved(String, f32, f32),
    /// User panned the canvas in the webview
    WebviewCanvasPan(f32, f32),
    /// User zoomed the canvas in the webview
    WebviewCanvasZoom(f32),
    /// User started a connection in the webview
    WebviewStartConnection(String),
    /// User completed a connection in the webview
    WebviewCompleteConnection(String),
    /// User cancelled a connection in the webview
    WebviewCancelConnection,
    /// User hovered over a connection in the webview
    WebviewConnectionHovered(Option<String>),
    /// Periodic tick for processing webview events
    WebviewTick,
}

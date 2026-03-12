//! IPC types for communication between Rust and the React webview.
//!
//! Defines the JSON structures used for bidirectional communication.

use serde::{Deserialize, Serialize};
use crate::message::{NodeId, NodeStatus, NodeType, Severity};
use crate::state::network::{NetworkState, Node, Connection, Port, Vulnerability};

/// Events sent from the React webview to Rust.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum WebviewEvent {
    /// Webview has finished loading and is ready
    Ready,
    /// User selected a node (with optional ctrl/shift for multi-select)
    NodeSelected {
        id: String,
        #[serde(default)]
        add_to_selection: bool,
    },
    /// User deselected all nodes (clicked on canvas background)
    NodeDeselected,
    /// User moved a node to a new position
    NodeMoved {
        id: String,
        x: f32,
        y: f32,
    },
    /// User panned the canvas
    CanvasPan {
        dx: f32,
        dy: f32,
    },
    /// User zoomed the canvas
    CanvasZoom {
        zoom: f32,
    },
    /// User started a connection from a node
    StartConnection {
        from_id: String,
    },
    /// User completed a connection to a node
    CompleteConnection {
        to_id: String,
    },
    /// User cancelled connection in progress
    CancelConnection,
    /// User hovered over a connection
    ConnectionHovered {
        id: Option<String>,
    },
}

/// Node data serialized for React.
#[derive(Debug, Clone, Serialize)]
pub struct NodeJson {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub x: f32,
    pub y: f32,
    pub label: String,
    pub status: String,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oui: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_strength: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ssids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
}

impl From<&Node> for NodeJson {
    fn from(node: &Node) -> Self {
        Self {
            id: node.id.0.to_string(),
            node_type: node_type_to_string(node.node_type),
            x: node.x,
            y: node.y,
            label: node.label.clone(),
            status: node_status_to_string(node.status),
            ip: node.ip.clone(),
            mac: node.mac.clone(),
            vendor: node.vendor.clone(),
            oui: node.oui.clone(),
            hostname: node.hostname.clone(),
            os_family: node.os_family.clone(),
            signal_strength: node.signal_strength,
            ssids: node.ssids.clone(),
            ports: node.ports.iter().map(PortJson::from).collect(),
            vulnerabilities: node.vulnerabilities.iter().map(VulnerabilityJson::from).collect(),
            parent_id: node.parent_id.map(|id| id.0.to_string()),
            width: node.width,
            height: node.height,
        }
    }
}

/// Port data serialized for React.
#[derive(Debug, Clone, Serialize)]
pub struct PortJson {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
}

impl From<&Port> for PortJson {
    fn from(port: &Port) -> Self {
        Self {
            number: port.number,
            protocol: port.protocol.clone(),
            state: port.state.clone(),
            service_name: port.service_name.clone(),
            service_version: port.service_version.clone(),
        }
    }
}

/// Vulnerability data serialized for React.
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityJson {
    pub cve: String,
    pub cvss: f32,
    pub severity: String,
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl From<&Vulnerability> for VulnerabilityJson {
    fn from(vuln: &Vulnerability) -> Self {
        Self {
            cve: vuln.cve.clone(),
            cvss: vuln.cvss,
            severity: severity_to_string(vuln.severity),
            description: vuln.description.clone(),
            references: vuln.references.clone(),
        }
    }
}

/// Connection data serialized for React.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionJson {
    pub id: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub connection_type: String,
    pub traffic: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<String>,
}

impl From<&Connection> for ConnectionJson {
    fn from(conn: &Connection) -> Self {
        Self {
            id: conn.id.0.to_string(),
            from: conn.from.0.to_string(),
            to: conn.to.0.to_string(),
            connection_type: match conn.connection_type {
                crate::message::ConnectionType::Wired => "wired".to_string(),
                crate::message::ConnectionType::Wireless => "wireless".to_string(),
            },
            traffic: conn.traffic,
            ssid: conn.ssid.clone(),
            speed: conn.speed.clone(),
        }
    }
}

/// Complete network state serialized for React.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkStateJson {
    /// Monotonic sequence number for diagnosing bridge timing issues
    pub seq: u64,
    pub nodes: Vec<NodeJson>,
    pub connections: Vec<ConnectionJson>,
    pub selected_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hovered_connection: Option<String>,
    pub pan: (f32, f32),
    pub zoom: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connecting_from: Option<String>,
    pub is_scanning: bool,
    pub scan_progress: u8,
}

impl From<&NetworkState> for NetworkStateJson {
    fn from(state: &NetworkState) -> Self {
        Self {
            seq: 0, // Will be overwritten by sync_state_to_webview
            nodes: state.nodes.iter().map(NodeJson::from).collect(),
            connections: state.connections.iter().map(ConnectionJson::from).collect(),
            selected_ids: state.selected_ids.iter().map(|id| id.0.to_string()).collect(),
            hovered_connection: state.hovered_connection.map(|id| id.0.to_string()),
            pan: state.pan,
            zoom: state.zoom,
            connecting_from: state.connecting_from.map(|id| id.0.to_string()),
            is_scanning: state.is_scanning,
            scan_progress: state.scan_progress,
        }
    }
}

/// Convert NodeType to string for JSON.
fn node_type_to_string(node_type: NodeType) -> String {
    match node_type {
        NodeType::Server => "server",
        NodeType::Firewall => "firewall",
        NodeType::Router => "router",
        NodeType::Database => "database",
        NodeType::Workstation => "workstation",
        NodeType::Mobile => "mobile",
        NodeType::Cloud => "cloud",
        NodeType::IoT => "iot",
        NodeType::Extender => "extender",
        NodeType::Group => "group",
    }.to_string()
}

/// Convert NodeStatus to string for JSON.
fn node_status_to_string(status: NodeStatus) -> String {
    match status {
        NodeStatus::Online => "online",
        NodeStatus::Offline => "offline",
        NodeStatus::Warning => "warning",
        NodeStatus::Compromised => "compromised",
    }.to_string()
}

/// Convert Severity to string for JSON.
fn severity_to_string(severity: Severity) -> String {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }.to_string()
}

/// Parse a node ID string back to NodeId.
pub fn parse_node_id(s: &str) -> Option<NodeId> {
    uuid::Uuid::parse_str(s).ok().map(NodeId)
}

/// Parse a connection ID string back to ConnectionId.
pub fn parse_connection_id(s: &str) -> Option<crate::message::ConnectionId> {
    uuid::Uuid::parse_str(s).ok().map(crate::message::ConnectionId)
}

//! API response models matching Python backend schemas.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Deserialize a datetime string that may or may not include timezone info.
/// The Python backend returns naive datetimes like "2026-01-31T20:10:37.918776"
/// while chrono's DateTime<Utc> expects a timezone suffix.
fn flexible_datetime<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // Try RFC 3339 / ISO 8601 with timezone first
    if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
        return Ok(dt.with_timezone(&Utc));
    }
    // Try naive datetime (no timezone) and assume UTC
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(naive.and_utc());
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.and_utc());
    }
    Err(serde::de::Error::custom(format!("Cannot parse datetime: {}", s)))
}

/// Same as flexible_datetime but for Option<DateTime<Utc>>.
fn flexible_datetime_opt<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
                return Ok(Some(dt.with_timezone(&Utc)));
            }
            if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f") {
                return Ok(Some(naive.and_utc()));
            }
            if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
                return Ok(Some(naive.and_utc()));
            }
            Err(serde::de::Error::custom(format!("Cannot parse datetime: {}", s)))
        }
    }
}

// ============================================================================
// System
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(deserialize_with = "flexible_datetime")]
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub python_version: String,
    pub platform: String,
    pub uptime_seconds: f64,
    pub database_status: String,
}

// ============================================================================
// Devices
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Port {
    pub id: String,
    pub port_number: u16,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub status: String,
    #[serde(deserialize_with = "flexible_datetime")]
    pub first_seen: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub last_seen: DateTime<Utc>,
    pub notes: Option<String>,
    pub ports: Vec<Port>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

// ============================================================================
// Scans
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct ScanCreate {
    pub scan_type: String,
    pub tool: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scan {
    pub id: String,
    pub scan_type: String,
    pub tool: String,
    pub target: String,
    pub status: String,
    /// Scan progress as an integer percentage 0-100, mapped from the Python API.
    pub progress: u8,
    #[serde(default, deserialize_with = "flexible_datetime_opt")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "flexible_datetime_opt")]
    pub completed_at: Option<DateTime<Utc>>,
    pub result_summary: Option<String>,
    pub error_message: Option<String>,
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    pub results: Option<HashMap<String, serde_json::Value>>,
    pub devices_found: i32,
    pub alerts_generated: i32,
    #[serde(deserialize_with = "flexible_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Alerts
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub source_tool: String,
    pub source_event_id: Option<String>,
    pub category: Option<String>,
    pub device_ip: Option<String>,
    pub device_id: Option<String>,
    pub fingerprint: Option<String>,
    pub count: i32,
    #[serde(deserialize_with = "flexible_datetime")]
    pub first_seen: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub last_seen: DateTime<Utc>,
    pub raw_data: Option<HashMap<String, serde_json::Value>>,
    pub correlation_id: Option<String>,
    pub notes: Option<String>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertStats {
    pub total: i32,
    #[serde(alias = "by_severity")]
    pub open_by_severity: HashMap<String, i32>,
    #[serde(alias = "by_status")]
    pub open_by_tool: HashMap<String, i32>,
}

// ============================================================================
// Vulnerabilities
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub severity: String,
    pub status: String,
    pub device_id: Option<String>,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub source_tool: String,
    pub solution: Option<String>,
    pub references: Vec<String>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solution: Option<String>,
}

// ============================================================================
// Traffic
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct TrafficFlow {
    pub id: String,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub packets_sent: i64,
    pub packets_received: i64,
    #[serde(deserialize_with = "flexible_datetime")]
    pub started_at: DateTime<Utc>,
    #[serde(default, deserialize_with = "flexible_datetime_opt")]
    pub ended_at: Option<DateTime<Utc>>,
    pub application: Option<String>,
    pub country_src: Option<String>,
    pub country_dst: Option<String>,
}

// ============================================================================
// Tools
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct Tool {
    pub name: String,
    pub display_name: String,
    pub category: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub status: String,
    pub supported_tasks: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolHealth {
    pub name: String,
    pub status: String,
    pub message: Option<String>,
}

// ============================================================================
// Scheduler
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    pub name: String,
    pub trigger_type: String,
    pub trigger_args: HashMap<String, String>,
    pub task_type: String,
    pub task_params: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    #[serde(default, deserialize_with = "flexible_datetime_opt")]
    pub next_run: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "flexible_datetime_opt")]
    pub last_run: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "flexible_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobCreate {
    pub name: String,
    pub trigger_type: String,
    pub trigger_args: HashMap<String, String>,
    pub task_type: String,
    pub task_params: HashMap<String, serde_json::Value>,
}

// ============================================================================
// API Error
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("Deserialization error: {0}")]
    Deserialize(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
}

impl ApiError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, ApiError::Api { status: 404, .. })
    }
}

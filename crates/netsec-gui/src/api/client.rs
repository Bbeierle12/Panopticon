//! HTTP client for the NetSec REST API.

use reqwest::Client;

use super::models::*;

/// Configuration for the API client.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout_secs: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8420".to_string(),
            api_key: None,
            timeout_secs: 30,
        }
    }
}

/// HTTP client for the NetSec backend API.
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    config: ApiConfig,
}

impl ApiClient {
    /// Create a new API client with the given configuration.
    pub fn new(config: ApiConfig) -> Result<Self, ApiError> {
        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs));

        if let Some(ref key) = config.api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key))
                    .map_err(|e| ApiError::ConnectionFailed(e.to_string()))?,
            );
            builder = builder.default_headers(headers);
        }

        let client = builder.build()?;
        Ok(Self { client, config })
    }

    /// Create a client with default configuration.
    pub fn with_defaults() -> Result<Self, ApiError> {
        Self::new(ApiConfig::default())
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api{}", self.config.base_url, path)
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ApiError> {
        let status = response.status();
        if status.is_success() {
            response
                .json()
                .await
                .map_err(|e| ApiError::Deserialize(e.to_string()))
        } else {
            let message = response
                .json::<ApiErrorDetail>()
                .await
                .map(|e| e.detail)
                .unwrap_or_else(|_| format!("HTTP {}", status));
            Err(ApiError::Api {
                status: status.as_u16(),
                message,
            })
        }
    }

    // ========================================================================
    // System endpoints
    // ========================================================================

    /// Check API health.
    pub async fn health(&self) -> Result<HealthResponse, ApiError> {
        let resp = self.client.get(self.url("/system/health")).send().await?;
        self.handle_response(resp).await
    }

    /// Get system information.
    pub async fn system_info(&self) -> Result<SystemInfo, ApiError> {
        let resp = self.client.get(self.url("/system/info")).send().await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Device endpoints
    // ========================================================================

    /// List all devices.
    pub async fn list_devices(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
        status: Option<&str>,
    ) -> Result<Vec<Device>, ApiError> {
        let mut req = self.client.get(self.url("/devices"));
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        if let Some(l) = limit {
            req = req.query(&[("limit", l)]);
        }
        if let Some(s) = status {
            req = req.query(&[("status", s)]);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Get a device by ID.
    pub async fn get_device(&self, device_id: &str) -> Result<Device, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/devices/{}", device_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Update a device.
    pub async fn update_device(
        &self,
        device_id: &str,
        update: DeviceUpdate,
    ) -> Result<Device, ApiError> {
        let resp = self
            .client
            .patch(self.url(&format!("/devices/{}", device_id)))
            .json(&update)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Delete a device.
    pub async fn delete_device(&self, device_id: &str) -> Result<(), ApiError> {
        let resp = self
            .client
            .delete(self.url(&format!("/devices/{}", device_id)))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let message = resp
                .json::<ApiErrorDetail>()
                .await
                .map(|e| e.detail)
                .unwrap_or_else(|_| format!("HTTP {}", status));
            Err(ApiError::Api {
                status: status.as_u16(),
                message,
            })
        }
    }

    // ========================================================================
    // Scan endpoints
    // ========================================================================

    /// Create and launch a new scan.
    pub async fn create_scan(&self, scan: ScanCreate) -> Result<Scan, ApiError> {
        let resp = self
            .client
            .post(self.url("/scans"))
            .json(&scan)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// List scans.
    pub async fn list_scans(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
        status: Option<&str>,
    ) -> Result<Vec<Scan>, ApiError> {
        let mut req = self.client.get(self.url("/scans"));
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        if let Some(l) = limit {
            req = req.query(&[("limit", l)]);
        }
        if let Some(s) = status {
            req = req.query(&[("status", s)]);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Get a scan by ID.
    pub async fn get_scan(&self, scan_id: &str) -> Result<Scan, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/scans/{}", scan_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Cancel a running scan.
    pub async fn cancel_scan(&self, scan_id: &str) -> Result<Scan, ApiError> {
        let resp = self
            .client
            .post(self.url(&format!("/scans/{}/cancel", scan_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Alert endpoints
    // ========================================================================

    /// List alerts.
    pub async fn list_alerts(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
        severity: Option<&str>,
        status: Option<&str>,
        source_tool: Option<&str>,
    ) -> Result<Vec<Alert>, ApiError> {
        let mut req = self.client.get(self.url("/alerts"));
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        if let Some(l) = limit {
            req = req.query(&[("limit", l)]);
        }
        if let Some(s) = severity {
            req = req.query(&[("severity", s)]);
        }
        if let Some(s) = status {
            req = req.query(&[("status", s)]);
        }
        if let Some(t) = source_tool {
            req = req.query(&[("source_tool", t)]);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Get alert statistics.
    pub async fn alert_stats(&self) -> Result<AlertStats, ApiError> {
        let resp = self.client.get(self.url("/alerts/stats")).send().await?;
        self.handle_response(resp).await
    }

    /// Get an alert by ID.
    pub async fn get_alert(&self, alert_id: &str) -> Result<Alert, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/alerts/{}", alert_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Update an alert.
    pub async fn update_alert(
        &self,
        alert_id: &str,
        update: AlertUpdate,
    ) -> Result<Alert, ApiError> {
        let resp = self
            .client
            .patch(self.url(&format!("/alerts/{}", alert_id)))
            .json(&update)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Vulnerability endpoints
    // ========================================================================

    /// List vulnerabilities.
    pub async fn list_vulnerabilities(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
        severity: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<Vulnerability>, ApiError> {
        let mut req = self.client.get(self.url("/vulnerabilities"));
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        if let Some(l) = limit {
            req = req.query(&[("limit", l)]);
        }
        if let Some(s) = severity {
            req = req.query(&[("severity", s)]);
        }
        if let Some(s) = status {
            req = req.query(&[("status", s)]);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// Get a vulnerability by ID.
    pub async fn get_vulnerability(&self, vuln_id: &str) -> Result<Vulnerability, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/vulnerabilities/{}", vuln_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Update a vulnerability.
    pub async fn update_vulnerability(
        &self,
        vuln_id: &str,
        update: VulnerabilityUpdate,
    ) -> Result<Vulnerability, ApiError> {
        let resp = self
            .client
            .patch(self.url(&format!("/vulnerabilities/{}", vuln_id)))
            .json(&update)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Traffic endpoints
    // ========================================================================

    /// List traffic flows.
    pub async fn list_traffic(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        protocol: Option<&str>,
    ) -> Result<Vec<TrafficFlow>, ApiError> {
        let mut req = self.client.get(self.url("/traffic"));
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        if let Some(l) = limit {
            req = req.query(&[("limit", l)]);
        }
        if let Some(s) = src_ip {
            req = req.query(&[("src_ip", s)]);
        }
        if let Some(d) = dst_ip {
            req = req.query(&[("dst_ip", d)]);
        }
        if let Some(p) = protocol {
            req = req.query(&[("protocol", p)]);
        }
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Tool endpoints
    // ========================================================================

    /// List all tools.
    pub async fn list_tools(&self) -> Result<Vec<Tool>, ApiError> {
        let resp = self.client.get(self.url("/tools")).send().await?;
        self.handle_response(resp).await
    }

    /// Get a tool by name.
    pub async fn get_tool(&self, tool_name: &str) -> Result<Tool, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/tools/{}", tool_name)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Check tool health.
    pub async fn tool_health(&self, tool_name: &str) -> Result<ToolHealth, ApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/tools/{}/health", tool_name)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Check all tools health.
    pub async fn all_tools_health(&self) -> Result<Vec<ToolHealth>, ApiError> {
        let resp = self.client.get(self.url("/tools/health")).send().await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Scheduler endpoints
    // ========================================================================

    /// List scheduled jobs.
    pub async fn list_jobs(&self) -> Result<Vec<ScheduledJob>, ApiError> {
        let resp = self.client.get(self.url("/scheduler/jobs")).send().await?;
        self.handle_response(resp).await
    }

    /// Create a scheduled job.
    pub async fn create_job(&self, job: JobCreate) -> Result<ScheduledJob, ApiError> {
        let resp = self
            .client
            .post(self.url("/scheduler/jobs"))
            .json(&job)
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Delete a scheduled job.
    pub async fn delete_job(&self, job_id: &str) -> Result<(), ApiError> {
        let resp = self
            .client
            .delete(self.url(&format!("/scheduler/jobs/{}", job_id)))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let message = resp
                .json::<ApiErrorDetail>()
                .await
                .map(|e| e.detail)
                .unwrap_or_else(|_| format!("HTTP {}", status));
            Err(ApiError::Api {
                status: status.as_u16(),
                message,
            })
        }
    }

    /// Pause a scheduled job.
    pub async fn pause_job(&self, job_id: &str) -> Result<ScheduledJob, ApiError> {
        let resp = self
            .client
            .post(self.url(&format!("/scheduler/jobs/{}/pause", job_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    /// Resume a scheduled job.
    pub async fn resume_job(&self, job_id: &str) -> Result<ScheduledJob, ApiError> {
        let resp = self
            .client
            .post(self.url(&format!("/scheduler/jobs/{}/resume", job_id)))
            .send()
            .await?;
        self.handle_response(resp).await
    }

    // ========================================================================
    // Browsing Metrics
    // ========================================================================

    pub async fn browsing_realtime(&self) -> Result<BrowsingRealtime, ApiError> {
        let resp = self.client.get(self.url("/browsing/realtime")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_top_domains(&self, limit: u32) -> Result<Vec<DnsTopDomain>, ApiError> {
        let resp = self.client.get(self.url(&format!("/browsing/dns/top-domains?limit={}", limit))).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_suspicious_domains(&self) -> Result<Vec<SuspiciousDomain>, ApiError> {
        let resp = self.client.get(self.url("/browsing/dns/suspicious")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_query_types(&self) -> Result<Vec<DnsQueryType>, ApiError> {
        let resp = self.client.get(self.url("/browsing/dns/query-types")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_tls_versions(&self) -> Result<Vec<TlsVersionCount>, ApiError> {
        let resp = self.client.get(self.url("/browsing/traffic/tls-versions")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_protocols(&self) -> Result<Vec<ProtocolDist>, ApiError> {
        let resp = self.client.get(self.url("/browsing/traffic/protocols")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_top_destinations(&self, limit: u32) -> Result<Vec<TrafficDestination>, ApiError> {
        let resp = self.client.get(self.url(&format!("/browsing/traffic/top-destinations?limit={}", limit))).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_beacons(&self) -> Result<Vec<BeaconDetection>, ApiError> {
        let resp = self.client.get(self.url("/browsing/security/beacons")).send().await?;
        self.handle_response(resp).await
    }

    pub async fn browsing_recent_events(&self, limit: u32) -> Result<Vec<BrowsingEvent>, ApiError> {
        let resp = self.client.get(self.url(&format!("/browsing/events/recent?limit={}", limit))).send().await?;
        self.handle_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:8420");
        assert!(config.api_key.is_none());
        assert_eq!(config.timeout_secs, 30);
    }
}

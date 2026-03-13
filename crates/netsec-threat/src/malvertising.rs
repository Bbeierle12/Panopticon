//! Malvertising detection.
//!
//! Detects malicious advertising network activity:
//! - Connections to known malvertising domains/IPs
//! - Suspicious HTTP redirect chains (302 chains to exploit kits)
//! - Drive-by download patterns (unexpected binary downloads from ad domains)
//! - Watering hole indicators (ad scripts loading exploit payloads)

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use std::collections::HashMap;
use tracing::warn;

use crate::{ThreatDetector, ThreatResult};

/// Known malicious/suspicious ad-related domain patterns.
/// In production, this would be loaded from a threat intelligence feed.
const SUSPICIOUS_DOMAIN_PATTERNS: &[&str] = &[
    // Common exploit kit landing page patterns
    "click.track",
    "ad.doubleclick.net.suspicious",
    "malware-download",
    "exploit-kit",
    "drive-by",
    // Known malvertising infrastructure patterns
    "adserving-malware",
    "tracking-pixel-redirect",
    "cdn-fake-update",
    "browser-update-required",
    "flash-player-update",
    "codec-pack-download",
    "free-scan-online",
    "your-computer-infected",
    "clean-pc-now",
];

/// Suspicious file extensions that shouldn't come from ad networks.
const SUSPICIOUS_DOWNLOAD_EXTENSIONS: &[&str] = &[
    ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".hta", ".dll", ".cpl", ".jar", ".apk",
];

/// An HTTP request/response record (from Zeek http.log or proxy logs).
#[derive(Debug, Clone)]
pub struct HttpRecord {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub status_code: u16,
    pub referrer: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub response_body_len: u64,
}

/// Configuration for malvertising detection.
#[derive(Debug, Clone)]
pub struct MalvertisingConfig {
    /// Maximum redirect chain length before alerting.
    pub max_redirect_chain: usize,
    /// Custom blocklist domains (in addition to built-in patterns).
    pub blocklist_domains: Vec<String>,
    /// Path to Zeek http.log.
    pub zeek_http_log: Option<String>,
}

impl Default for MalvertisingConfig {
    fn default() -> Self {
        Self {
            max_redirect_chain: 4,
            blocklist_domains: Vec::new(),
            zeek_http_log: None,
        }
    }
}

/// Detector for malvertising, exploit kits, and drive-by downloads.
pub struct MalvertisingDetector {
    config: MalvertisingConfig,
}

impl MalvertisingDetector {
    pub fn new() -> Self {
        Self {
            config: MalvertisingConfig::default(),
        }
    }

    pub fn with_config(config: MalvertisingConfig) -> Self {
        Self { config }
    }

    /// Check if a domain matches known suspicious patterns.
    pub fn is_suspicious_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS {
            if lower.contains(pattern) {
                return true;
            }
        }
        for blocked in &self.config.blocklist_domains {
            if lower.contains(&blocked.to_lowercase()) {
                return true;
            }
        }
        false
    }

    /// Check if a URI references a suspicious file download.
    pub fn is_suspicious_download(uri: &str) -> bool {
        let lower = uri.to_lowercase();
        SUSPICIOUS_DOWNLOAD_EXTENSIONS
            .iter()
            .any(|ext| lower.ends_with(ext))
    }

    /// Parse Zeek http.log into records.
    pub fn parse_zeek_http(content: &str) -> Vec<HttpRecord> {
        let mut records = Vec::new();
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // Zeek TSV: ts uid orig_h orig_p resp_h resp_p trans_depth method host uri referrer version user_agent ... status_code ... resp_fuids resp_mime_types
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 16 {
                let status_code = fields[15].parse().unwrap_or(0);
                let response_body_len = fields.get(18).and_then(|s| s.parse().ok()).unwrap_or(0);
                let content_type = fields.get(28).map(|s| s.to_string());
                records.push(HttpRecord {
                    timestamp: fields[0].to_string(),
                    src_ip: fields[2].to_string(),
                    dst_ip: fields[4].to_string(),
                    method: fields[7].to_string(),
                    host: fields[8].to_string(),
                    uri: fields[9].to_string(),
                    status_code,
                    referrer: if fields[10] == "-" {
                        None
                    } else {
                        Some(fields[10].to_string())
                    },
                    user_agent: if fields[12] == "-" {
                        None
                    } else {
                        Some(fields[12].to_string())
                    },
                    content_type,
                    response_body_len,
                });
            }
        }
        records
    }

    /// Analyze HTTP records for malvertising indicators.
    pub fn analyze(&self, records: &[HttpRecord]) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();

        // Build redirect chains: src_ip → sequence of hosts via 301/302
        let mut redirect_chains: HashMap<String, Vec<String>> = HashMap::new();

        for record in records {
            // Check 1: Suspicious domain connections
            if self.is_suspicious_domain(&record.host) {
                warn!(host = %record.host, src = %record.src_ip, "Connection to suspicious domain");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::High,
                    category: AlertCategory::Malware,
                    title: format!("Malvertising: {} connected to {}", record.src_ip, record.host),
                    description: format!(
                        "Device {} made an HTTP {} request to suspicious domain '{}{}'. \
                         This domain matches known malvertising/exploit kit patterns.",
                        record.src_ip, record.method, record.host, record.uri
                    ),
                    device_ip: Some(record.src_ip.clone()),
                    fingerprint: format!("malvert-domain-{}-{}", record.src_ip, record.host),
                    raw_data: serde_json::json!({
                        "src_ip": record.src_ip,
                        "host": record.host,
                        "uri": record.uri,
                        "method": record.method,
                        "status_code": record.status_code,
                        "referrer": record.referrer,
                        "user_agent": record.user_agent,
                    }),
                    timestamp: Utc::now(),
                });
            }

            // Check 2: Suspicious file downloads
            if Self::is_suspicious_download(&record.uri) && record.response_body_len > 0 {
                warn!(
                    uri = %record.uri,
                    host = %record.host,
                    src = %record.src_ip,
                    "Suspicious file download detected"
                );
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::Critical,
                    category: AlertCategory::Malware,
                    title: format!(
                        "Drive-by download: {} fetched {} from {}",
                        record.src_ip, record.uri, record.host
                    ),
                    description: format!(
                        "Device {} downloaded a suspicious file '{}' from '{}' ({} bytes). \
                         Executable downloads from web browsing may indicate a drive-by \
                         download attack or social engineering.",
                        record.src_ip, record.uri, record.host, record.response_body_len
                    ),
                    device_ip: Some(record.src_ip.clone()),
                    fingerprint: format!("driveby-{}-{}", record.src_ip, record.uri),
                    raw_data: serde_json::json!({
                        "src_ip": record.src_ip,
                        "host": record.host,
                        "uri": record.uri,
                        "response_body_len": record.response_body_len,
                        "content_type": record.content_type,
                        "referrer": record.referrer,
                    }),
                    timestamp: Utc::now(),
                });
            }

            // Track redirect chains
            if record.status_code == 301 || record.status_code == 302 {
                redirect_chains
                    .entry(record.src_ip.clone())
                    .or_default()
                    .push(record.host.clone());
            }
        }

        // Check 3: Long redirect chains (exploit kit delivery)
        for (src_ip, chain) in &redirect_chains {
            if chain.len() > self.config.max_redirect_chain {
                let unique_hosts: Vec<&String> = {
                    let mut seen = std::collections::HashSet::new();
                    chain.iter().filter(|h| seen.insert(*h)).collect()
                };
                warn!(
                    src = %src_ip,
                    chain_len = chain.len(),
                    "Long redirect chain — possible exploit kit"
                );
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::High,
                    category: AlertCategory::Malware,
                    title: format!(
                        "Redirect chain: {} followed {} redirects",
                        src_ip,
                        chain.len()
                    ),
                    description: format!(
                        "Device {} was redirected through {} hops across {} unique hosts. \
                         Exploit kits use long redirect chains to evade detection: {}",
                        src_ip,
                        chain.len(),
                        unique_hosts.len(),
                        unique_hosts
                            .iter()
                            .map(|h| h.as_str())
                            .collect::<Vec<_>>()
                            .join(" → ")
                    ),
                    device_ip: Some(src_ip.clone()),
                    fingerprint: format!("redirect-chain-{}", src_ip),
                    raw_data: serde_json::json!({
                        "src_ip": src_ip,
                        "chain_length": chain.len(),
                        "hosts": unique_hosts,
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        alerts
    }

    /// Read and analyze Zeek HTTP logs if available.
    fn analyze_logs(&self) -> Vec<NormalizedAlert> {
        let path = match &self.config.zeek_http_log {
            Some(p) => p.clone(),
            None => {
                let defaults = [
                    "/opt/zeek/logs/current/http.log",
                    "/usr/local/zeek/logs/current/http.log",
                    "/var/log/zeek/current/http.log",
                ];
                match defaults.iter().find(|p| std::path::Path::new(p).exists()) {
                    Some(p) => p.to_string(),
                    None => return Vec::new(),
                }
            }
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let records = Self::parse_zeek_http(&content);
                self.analyze(&records)
            }
            Err(_) => Vec::new(),
        }
    }
}

impl Default for MalvertisingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for MalvertisingDetector {
    fn name(&self) -> &str {
        "malvertising"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        Ok(self.analyze_logs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(host: &str, uri: &str, status: u16, body_len: u64) -> HttpRecord {
        HttpRecord {
            timestamp: "1234567890".into(),
            src_ip: "192.168.1.100".into(),
            dst_ip: "1.2.3.4".into(),
            method: "GET".into(),
            host: host.into(),
            uri: uri.into(),
            status_code: status,
            referrer: None,
            user_agent: Some("Mozilla/5.0".into()),
            content_type: None,
            response_body_len: body_len,
        }
    }

    #[test]
    fn test_suspicious_domain_builtin() {
        let d = MalvertisingDetector::new();
        assert!(d.is_suspicious_domain("free-scan-online.example.com"));
        assert!(d.is_suspicious_domain("cdn-fake-update.evil.com"));
        assert!(!d.is_suspicious_domain("www.google.com"));
        assert!(!d.is_suspicious_domain("cdn.example.com"));
    }

    #[test]
    fn test_suspicious_domain_custom_blocklist() {
        let d = MalvertisingDetector::with_config(MalvertisingConfig {
            blocklist_domains: vec!["evil-ads.net".into()],
            ..Default::default()
        });
        assert!(d.is_suspicious_domain("tracker.evil-ads.net"));
        assert!(!d.is_suspicious_domain("safe.example.com"));
    }

    #[test]
    fn test_suspicious_download() {
        assert!(MalvertisingDetector::is_suspicious_download("/update.exe"));
        assert!(MalvertisingDetector::is_suspicious_download("/path/codec.msi"));
        assert!(MalvertisingDetector::is_suspicious_download("/file.ps1"));
        assert!(!MalvertisingDetector::is_suspicious_download("/page.html"));
        assert!(!MalvertisingDetector::is_suspicious_download("/image.png"));
    }

    #[test]
    fn test_detect_suspicious_domain() {
        let d = MalvertisingDetector::new();
        let records = vec![make_record("your-computer-infected.com", "/scan", 200, 5000)];
        let alerts = d.analyze(&records);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Malvertising"));
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn test_detect_driveby_download() {
        let d = MalvertisingDetector::new();
        let records = vec![make_record("ads.example.com", "/payload.exe", 200, 50000)];
        let alerts = d.analyze(&records);
        assert!(alerts.iter().any(|a| a.title.contains("Drive-by download")));
    }

    #[test]
    fn test_detect_redirect_chain() {
        let d = MalvertisingDetector::with_config(MalvertisingConfig {
            max_redirect_chain: 2,
            ..Default::default()
        });
        let records = vec![
            make_record("ad1.example.com", "/click", 302, 0),
            make_record("ad2.example.com", "/track", 302, 0),
            make_record("ad3.example.com", "/redir", 302, 0),
        ];
        let alerts = d.analyze(&records);
        assert!(alerts.iter().any(|a| a.title.contains("Redirect chain")));
    }

    #[test]
    fn test_no_alert_normal_browsing() {
        let d = MalvertisingDetector::new();
        let records = vec![
            make_record("www.google.com", "/search?q=test", 200, 10000),
            make_record("www.wikipedia.org", "/wiki/Rust", 200, 50000),
        ];
        let alerts = d.analyze(&records);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_name() {
        let d = MalvertisingDetector::new();
        assert_eq!(d.name(), "malvertising");
    }
}

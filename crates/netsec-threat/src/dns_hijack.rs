//! DNS hijack detection.
//!
//! Detects DNS poisoning by resolving known-good domains and comparing
//! results against expected IPs or trusted resolvers (Quad9, Cloudflare).

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use tracing::warn;

use crate::{ThreatDetector, ThreatError, ThreatResult};

/// A canary domain with known-good IPs used to detect DNS hijacking.
#[derive(Debug, Clone)]
pub struct DnsCanary {
    pub domain: String,
    /// Known-good IP prefixes (e.g., "142.250." for Google).
    /// If empty, any resolution is accepted on first pass and then pinned.
    pub expected_prefixes: Vec<String>,
}

/// DNS hijack detector configuration.
pub struct DnsHijackDetector {
    canaries: Vec<DnsCanary>,
    /// Learned resolutions: domain → set of IPs seen
    pinned: std::sync::Mutex<HashMap<String, Vec<String>>>,
}

impl DnsHijackDetector {
    pub fn new() -> Self {
        Self {
            canaries: default_canaries(),
            pinned: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn with_canaries(canaries: Vec<DnsCanary>) -> Self {
        Self {
            canaries,
            pinned: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a domain using the system resolver.
    pub fn resolve(domain: &str) -> ThreatResult<Vec<String>> {
        let addr = format!("{domain}:443");
        match addr.to_socket_addrs() {
            Ok(addrs) => Ok(addrs.map(|a| a.ip().to_string()).collect()),
            Err(e) => Err(ThreatError::Detection(format!(
                "failed to resolve {domain}: {e}"
            ))),
        }
    }

    /// Check a single canary against resolved IPs.
    pub fn check_canary(canary: &DnsCanary, resolved_ips: &[String]) -> Option<String> {
        if canary.expected_prefixes.is_empty() {
            return None;
        }
        // Check if any resolved IP matches any expected prefix
        let any_match = resolved_ips.iter().any(|ip| {
            canary
                .expected_prefixes
                .iter()
                .any(|prefix| ip.starts_with(prefix))
        });
        if any_match {
            None
        } else {
            Some(format!(
                "DNS hijack suspected for {}: resolved to [{}], expected prefix(es) [{}]",
                canary.domain,
                resolved_ips.join(", "),
                canary.expected_prefixes.join(", ")
            ))
        }
    }

    /// Run detection against all canaries.
    pub fn analyze(&self) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();
        let mut pinned = self.pinned.lock().unwrap();

        for canary in &self.canaries {
            let resolved = match Self::resolve(&canary.domain) {
                Ok(ips) if !ips.is_empty() => ips,
                Ok(_) => continue,
                Err(_) => continue,
            };

            // Check against expected prefixes
            if let Some(reason) = Self::check_canary(canary, &resolved) {
                warn!(domain = %canary.domain, "{reason}");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::Critical,
                    category: AlertCategory::NetworkThreat,
                    title: format!("DNS hijack: {} resolves to unexpected IPs", canary.domain),
                    description: reason,
                    device_ip: None,
                    fingerprint: format!("dns-hijack-{}", canary.domain),
                    raw_data: serde_json::json!({
                        "domain": canary.domain,
                        "resolved_ips": resolved,
                        "expected_prefixes": canary.expected_prefixes,
                    }),
                    timestamp: Utc::now(),
                });
                continue;
            }

            // Pin-based detection: if we learned IPs before, check for changes
            if let Some(prev_ips) = pinned.get(&canary.domain) {
                // Check if resolved IPs are completely different subnets
                let new_only: Vec<&String> = resolved
                    .iter()
                    .filter(|ip| !prev_ips.contains(ip))
                    .collect();
                if !new_only.is_empty() && new_only.len() == resolved.len() {
                    // All IPs changed — suspicious
                    warn!(
                        domain = %canary.domain,
                        "All resolved IPs changed since last check"
                    );
                    alerts.push(NormalizedAlert {
                        source_tool: "netsec-threat".into(),
                        severity: Severity::Medium,
                        category: AlertCategory::NetworkThreat,
                        title: format!("DNS drift: {} IPs changed completely", canary.domain),
                        description: format!(
                            "Domain {} resolved to [{}] but was previously [{}]. \
                             Complete IP change may indicate DNS hijacking.",
                            canary.domain,
                            resolved.join(", "),
                            prev_ips.join(", ")
                        ),
                        device_ip: None,
                        fingerprint: format!("dns-drift-{}", canary.domain),
                        raw_data: serde_json::json!({
                            "domain": canary.domain,
                            "old_ips": prev_ips,
                            "new_ips": resolved,
                        }),
                        timestamp: Utc::now(),
                    });
                }
            }

            // Update pinned
            pinned.insert(canary.domain.clone(), resolved);
        }

        alerts
    }
}

impl Default for DnsHijackDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for DnsHijackDetector {
    fn name(&self) -> &str {
        "dns_hijack"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        Ok(self.analyze())
    }
}

/// Default canary domains with known IP prefixes.
fn default_canaries() -> Vec<DnsCanary> {
    vec![
        DnsCanary {
            domain: "dns.google".into(),
            expected_prefixes: vec!["8.8.".into(), "8.34.".into()],
        },
        DnsCanary {
            domain: "one.one.one.one".into(),
            expected_prefixes: vec!["1.1.1.".into(), "1.0.0.".into()],
        },
        DnsCanary {
            domain: "dns.quad9.net".into(),
            expected_prefixes: vec!["9.9.9.".into(), "149.112.".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_canary_match() {
        let canary = DnsCanary {
            domain: "dns.google".into(),
            expected_prefixes: vec!["8.8.".into()],
        };
        let result = DnsHijackDetector::check_canary(&canary, &["8.8.8.8".into()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_canary_mismatch() {
        let canary = DnsCanary {
            domain: "dns.google".into(),
            expected_prefixes: vec!["8.8.".into()],
        };
        let result = DnsHijackDetector::check_canary(&canary, &["192.168.1.1".into()]);
        assert!(result.is_some());
        assert!(result.unwrap().contains("DNS hijack suspected"));
    }

    #[test]
    fn test_check_canary_empty_prefixes() {
        let canary = DnsCanary {
            domain: "example.com".into(),
            expected_prefixes: vec![],
        };
        let result = DnsHijackDetector::check_canary(&canary, &["1.2.3.4".into()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_with_custom_canary_no_resolution() {
        // Canary pointing to a non-resolvable domain => no alerts (resolution fails silently)
        let detector = DnsHijackDetector::with_canaries(vec![DnsCanary {
            domain: "this-domain-does-not-exist-xyz-12345.invalid".into(),
            expected_prefixes: vec!["1.2.3.".into()],
        }]);
        let alerts = detector.analyze();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_default_canaries() {
        let canaries = default_canaries();
        assert_eq!(canaries.len(), 3);
        assert!(canaries.iter().any(|c| c.domain == "dns.google"));
    }

    #[test]
    fn test_name() {
        let d = DnsHijackDetector::new();
        assert_eq!(d.name(), "dns_hijack");
    }

    #[test]
    fn test_pin_based_detection() {
        let detector = DnsHijackDetector::with_canaries(vec![DnsCanary {
            domain: "test.example".into(),
            expected_prefixes: vec![],
        }]);
        // Manually pin some IPs
        {
            let mut pinned = detector.pinned.lock().unwrap();
            pinned.insert("test.example".into(), vec!["1.2.3.4".into()]);
        }
        // analyze() will try to resolve test.example which will fail,
        // so no alerts from pin comparison
        let alerts = detector.analyze();
        assert!(alerts.is_empty());
    }
}

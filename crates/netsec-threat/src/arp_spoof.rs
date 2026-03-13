//! ARP spoofing detection.
//!
//! Reads the system ARP table (`/proc/net/arp` on Linux, `arp -a` elsewhere)
//! and detects:
//! - MAC address changes for a known IP (potential MITM)
//! - Multiple IPs claiming the same MAC (potential gateway spoof)

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::warn;

use crate::{ThreatDetector, ThreatError, ThreatResult};

/// An entry from the system ARP table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub device: String,
}

/// Detector that watches the ARP table for spoofing indicators.
pub struct ArpSpoofDetector {
    /// Previous snapshot: IP → MAC
    known_mappings: Mutex<HashMap<String, String>>,
}

impl ArpSpoofDetector {
    pub fn new() -> Self {
        Self {
            known_mappings: Mutex::new(HashMap::new()),
        }
    }

    /// Parse `/proc/net/arp` content into entries.
    pub fn parse_proc_arp(content: &str) -> Vec<ArpEntry> {
        let mut entries = Vec::new();
        for line in content.lines().skip(1) {
            // Format: IP HW_type Flags MAC Mask Device
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let mac = parts[3].to_lowercase();
                // Skip incomplete entries (00:00:00:00:00:00)
                if mac == "00:00:00:00:00:00" {
                    continue;
                }
                entries.push(ArpEntry {
                    ip: parts[0].to_string(),
                    mac,
                    device: parts[5].to_string(),
                });
            }
        }
        entries
    }

    /// Parse `arp -a` output (macOS/BSD format).
    pub fn parse_arp_a(content: &str) -> Vec<ArpEntry> {
        let mut entries = Vec::new();
        for line in content.lines() {
            // Format: hostname (IP) at MAC on interface [...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 && parts[2] == "at" && parts[4] == "on" {
                let ip = parts[1].trim_matches(|c| c == '(' || c == ')').to_string();
                let mac = parts[3].to_lowercase();
                if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" {
                    continue;
                }
                entries.push(ArpEntry {
                    ip,
                    mac,
                    device: parts[5].to_string(),
                });
            }
        }
        entries
    }

    /// Read the current ARP table from the system.
    fn read_arp_table() -> ThreatResult<Vec<ArpEntry>> {
        // Try /proc/net/arp first (Linux)
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            return Ok(Self::parse_proc_arp(&content));
        }
        // Fall back to arp -a
        let output = std::process::Command::new("arp")
            .arg("-a")
            .output()
            .map_err(|e| ThreatError::Command(format!("arp -a failed: {e}")))?;
        let content = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_arp_a(&content))
    }

    /// Analyze entries against known state and return alerts.
    pub fn analyze(&self, entries: &[ArpEntry]) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();
        let mut known = self.known_mappings.lock().unwrap();

        // Check 1: MAC changed for a known IP
        for entry in entries {
            if let Some(prev_mac) = known.get(&entry.ip) {
                if *prev_mac != entry.mac {
                    warn!(
                        ip = %entry.ip,
                        old_mac = %prev_mac,
                        new_mac = %entry.mac,
                        "ARP spoofing detected: MAC changed"
                    );
                    alerts.push(NormalizedAlert {
                        source_tool: "netsec-threat".into(),
                        severity: Severity::High,
                        category: AlertCategory::NetworkThreat,
                        title: format!(
                            "ARP spoof: {} changed MAC {} → {}",
                            entry.ip, prev_mac, entry.mac
                        ),
                        description: format!(
                            "Device at {} changed its MAC address from {} to {}. \
                             This may indicate an ARP spoofing / MITM attack on interface {}.",
                            entry.ip, prev_mac, entry.mac, entry.device
                        ),
                        device_ip: Some(entry.ip.clone()),
                        fingerprint: format!("arp-spoof-mac-change-{}", entry.ip),
                        raw_data: serde_json::json!({
                            "ip": entry.ip,
                            "old_mac": prev_mac,
                            "new_mac": entry.mac,
                            "interface": entry.device,
                        }),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        // Check 2: Multiple IPs with the same MAC (potential gateway spoof)
        let mut mac_to_ips: HashMap<&str, Vec<&str>> = HashMap::new();
        for entry in entries {
            mac_to_ips
                .entry(&entry.mac)
                .or_default()
                .push(&entry.ip);
        }
        for (mac, ips) in &mac_to_ips {
            if ips.len() > 3 {
                // More than 3 IPs on one MAC is suspicious (routers typically have 1-2)
                warn!(mac = %mac, count = ips.len(), "Suspicious: many IPs sharing one MAC");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::Medium,
                    category: AlertCategory::NetworkThreat,
                    title: format!(
                        "ARP anomaly: MAC {} claimed by {} IPs",
                        mac,
                        ips.len()
                    ),
                    description: format!(
                        "MAC address {} is associated with {} IP addresses: {}. \
                         This may indicate ARP spoofing or a misconfigured gateway.",
                        mac,
                        ips.len(),
                        ips.join(", ")
                    ),
                    device_ip: Some(ips[0].to_string()),
                    fingerprint: format!("arp-anomaly-multi-ip-{}", mac),
                    raw_data: serde_json::json!({
                        "mac": mac,
                        "ips": ips,
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        // Update known mappings
        for entry in entries {
            known.insert(entry.ip.clone(), entry.mac.clone());
        }

        alerts
    }
}

impl Default for ArpSpoofDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for ArpSpoofDetector {
    fn name(&self) -> &str {
        "arp_spoof"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        let entries = Self::read_arp_table()?;
        Ok(self.analyze(&entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_ARP_SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0
192.168.1.100    0x1         0x0         00:00:00:00:00:00     *        eth0";

    const ARP_A_SAMPLE: &str = "\
gateway (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
mypc (192.168.1.50) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
? (192.168.1.200) at (incomplete) on en0 ifscope [ethernet]";

    #[test]
    fn test_parse_proc_arp() {
        let entries = ArpSpoofDetector::parse_proc_arp(PROC_ARP_SAMPLE);
        assert_eq!(entries.len(), 2); // incomplete entry skipped
        assert_eq!(entries[0].ip, "192.168.1.1");
        assert_eq!(entries[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(entries[0].device, "eth0");
    }

    #[test]
    fn test_parse_arp_a() {
        let entries = ArpSpoofDetector::parse_arp_a(ARP_A_SAMPLE);
        assert_eq!(entries.len(), 2); // incomplete skipped
        assert_eq!(entries[0].ip, "192.168.1.1");
        assert_eq!(entries[1].ip, "192.168.1.50");
    }

    #[test]
    fn test_detect_mac_change() {
        let detector = ArpSpoofDetector::new();

        // First pass: learn the table
        let entries = vec![ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "aa:bb:cc:dd:ee:01".into(),
            device: "eth0".into(),
        }];
        let alerts = detector.analyze(&entries);
        assert!(alerts.is_empty(), "first pass should learn, not alert");

        // Second pass: MAC changed
        let entries2 = vec![ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "ff:ff:ff:00:00:01".into(),
            device: "eth0".into(),
        }];
        let alerts2 = detector.analyze(&entries2);
        assert_eq!(alerts2.len(), 1);
        assert!(alerts2[0].title.contains("ARP spoof"));
        assert_eq!(alerts2[0].severity, Severity::High);
    }

    #[test]
    fn test_detect_multi_ip_same_mac() {
        let detector = ArpSpoofDetector::new();
        let entries = vec![
            ArpEntry { ip: "10.0.0.1".into(), mac: "aa:aa:aa:aa:aa:aa".into(), device: "eth0".into() },
            ArpEntry { ip: "10.0.0.2".into(), mac: "aa:aa:aa:aa:aa:aa".into(), device: "eth0".into() },
            ArpEntry { ip: "10.0.0.3".into(), mac: "aa:aa:aa:aa:aa:aa".into(), device: "eth0".into() },
            ArpEntry { ip: "10.0.0.4".into(), mac: "aa:aa:aa:aa:aa:aa".into(), device: "eth0".into() },
        ];
        let alerts = detector.analyze(&entries);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("ARP anomaly"));
        assert_eq!(alerts[0].severity, Severity::Medium);
    }

    #[test]
    fn test_no_alert_on_stable_table() {
        let detector = ArpSpoofDetector::new();
        let entries = vec![ArpEntry {
            ip: "192.168.1.1".into(),
            mac: "aa:bb:cc:dd:ee:01".into(),
            device: "eth0".into(),
        }];
        detector.analyze(&entries);
        let alerts = detector.analyze(&entries);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_name() {
        let d = ArpSpoofDetector::new();
        assert_eq!(d.name(), "arp_spoof");
    }

    #[test]
    fn test_parse_empty() {
        let entries = ArpSpoofDetector::parse_proc_arp("IP address       HW type     Flags       HW address            Mask     Device\n");
        assert!(entries.is_empty());
    }
}

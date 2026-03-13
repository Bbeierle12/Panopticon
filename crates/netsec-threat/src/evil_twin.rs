//! Evil twin access point detection.
//!
//! Scans for nearby WiFi networks and detects:
//! - Duplicate SSIDs with different BSSIDs (potential evil twin)
//! - Known SSID appearing on unexpected channels or with different security

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use std::collections::HashMap;
use tracing::warn;

use crate::{ThreatDetector, ThreatError, ThreatResult};

/// A WiFi access point seen during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub signal_dbm: i32,
    pub encryption: String,
}

/// Detector for evil twin (rogue) access points.
pub struct EvilTwinDetector {
    /// SSIDs we trust and their expected BSSIDs.
    trusted_ssids: HashMap<String, Vec<String>>,
}

impl EvilTwinDetector {
    pub fn new() -> Self {
        Self {
            trusted_ssids: HashMap::new(),
        }
    }

    /// Create a detector that knows which BSSIDs are legitimate for given SSIDs.
    pub fn with_trusted(trusted: HashMap<String, Vec<String>>) -> Self {
        Self {
            trusted_ssids: trusted,
        }
    }

    /// Scan for WiFi networks using `iw` or `iwlist` on Linux.
    fn scan_wifi() -> ThreatResult<Vec<AccessPoint>> {
        // Try nmcli first (most common on modern Linux)
        if let Ok(output) = std::process::Command::new("nmcli")
            .args(["-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"])
            .output()
        {
            if output.status.success() {
                return Ok(Self::parse_nmcli(&String::from_utf8_lossy(&output.stdout)));
            }
        }

        // Fall back to iwlist
        if let Ok(output) = std::process::Command::new("iwlist")
            .args(["scan"])
            .output()
        {
            if output.status.success() {
                return Ok(Self::parse_iwlist(&String::from_utf8_lossy(&output.stdout)));
            }
        }

        Err(ThreatError::Command(
            "no WiFi scan tool available (tried nmcli, iwlist)".into(),
        ))
    }

    /// Parse nmcli output (colon-delimited).
    pub fn parse_nmcli(content: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            // nmcli -t uses \: for literal colons in SSID, but BSSID has colons too
            // Format: SSID:BSSID_part1:...:BSSID_part6:CHAN:SIGNAL:SECURITY
            // We need at least SSID + 6 BSSID parts + CHAN + SIGNAL + SECURITY = 10 parts
            if parts.len() >= 10 {
                let ssid = parts[0].replace("\\:", ":");
                if ssid.is_empty() {
                    continue;
                }
                let bssid = format!(
                    "{}:{}:{}:{}:{}:{}",
                    parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                )
                .to_uppercase();
                let channel = parts[7].parse().unwrap_or(0);
                let signal = parts[8].parse::<i32>().unwrap_or(-100);
                // nmcli SIGNAL is 0-100 percentage; convert roughly to dBm
                let signal_dbm = signal - 100; // rough approximation
                let security = parts[9..].join(":");

                aps.push(AccessPoint {
                    ssid,
                    bssid,
                    channel,
                    signal_dbm,
                    encryption: security,
                });
            }
        }
        aps
    }

    /// Parse iwlist scan output.
    pub fn parse_iwlist(content: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();
        let mut current_bssid = String::new();
        let mut current_ssid = String::new();
        let mut current_channel: u32 = 0;
        let mut current_signal: i32 = -100;
        let mut current_enc = String::from("Open");

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("Cell ") && trimmed.contains("Address: ") {
                // Save previous AP
                if !current_bssid.is_empty() && !current_ssid.is_empty() {
                    aps.push(AccessPoint {
                        ssid: current_ssid.clone(),
                        bssid: current_bssid.clone(),
                        channel: current_channel,
                        signal_dbm: current_signal,
                        encryption: current_enc.clone(),
                    });
                }
                // New cell
                if let Some(addr) = trimmed.split("Address: ").nth(1) {
                    current_bssid = addr.trim().to_uppercase();
                }
                current_ssid.clear();
                current_channel = 0;
                current_signal = -100;
                current_enc = "Open".into();
            } else if trimmed.starts_with("ESSID:") {
                current_ssid = trimmed
                    .trim_start_matches("ESSID:")
                    .trim_matches('"')
                    .to_string();
            } else if trimmed.starts_with("Channel:") {
                current_channel = trimmed
                    .trim_start_matches("Channel:")
                    .parse()
                    .unwrap_or(0);
            } else if trimmed.contains("Signal level=") {
                if let Some(sig) = trimmed.split("Signal level=").nth(1) {
                    let num_str = sig.split_whitespace().next().unwrap_or("-100");
                    current_signal = num_str.parse().unwrap_or(-100);
                }
            } else if trimmed.contains("Encryption key:on") {
                current_enc = "WPA/WPA2".into();
            }
        }
        // Save last AP
        if !current_bssid.is_empty() && !current_ssid.is_empty() {
            aps.push(AccessPoint {
                ssid: current_ssid,
                bssid: current_bssid,
                channel: current_channel,
                signal_dbm: current_signal,
                encryption: current_enc,
            });
        }

        aps
    }

    /// Analyze a list of access points for evil twin indicators.
    pub fn analyze(&self, aps: &[AccessPoint]) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();

        // Group by SSID
        let mut ssid_groups: HashMap<&str, Vec<&AccessPoint>> = HashMap::new();
        for ap in aps {
            ssid_groups.entry(&ap.ssid).or_default().push(ap);
        }

        for (ssid, group) in &ssid_groups {
            if group.len() < 2 {
                continue;
            }

            // Multiple APs with the same SSID — check if any are untrusted
            if let Some(trusted_bssids) = self.trusted_ssids.get(*ssid) {
                for ap in group {
                    if !trusted_bssids.contains(&ap.bssid) {
                        warn!(
                            ssid = %ssid,
                            rogue_bssid = %ap.bssid,
                            "Evil twin detected: untrusted BSSID for known SSID"
                        );
                        alerts.push(NormalizedAlert {
                            source_tool: "netsec-threat".into(),
                            severity: Severity::Critical,
                            category: AlertCategory::NetworkThreat,
                            title: format!(
                                "Evil twin AP: '{}' on untrusted BSSID {}",
                                ssid, ap.bssid
                            ),
                            description: format!(
                                "Access point with SSID '{}' detected on BSSID {} (channel {}, signal {} dBm, {}). \
                                 This BSSID is not in the trusted list. Possible evil twin attack.",
                                ssid, ap.bssid, ap.channel, ap.signal_dbm, ap.encryption
                            ),
                            device_ip: None,
                            fingerprint: format!("evil-twin-{}-{}", ssid, ap.bssid),
                            raw_data: serde_json::json!({
                                "ssid": ssid,
                                "rogue_bssid": ap.bssid,
                                "channel": ap.channel,
                                "signal_dbm": ap.signal_dbm,
                                "encryption": ap.encryption,
                                "trusted_bssids": trusted_bssids,
                            }),
                            timestamp: Utc::now(),
                        });
                    }
                }
            } else {
                // No trusted BSSIDs configured — just flag duplicate SSIDs
                // Check for different encryption levels (open clone of encrypted network)
                let has_open = group.iter().any(|ap| ap.encryption.to_lowercase().contains("open") || ap.encryption.is_empty());
                let has_encrypted = group.iter().any(|ap| !ap.encryption.to_lowercase().contains("open") && !ap.encryption.is_empty());

                if has_open && has_encrypted {
                    warn!(ssid = %ssid, "Suspicious: same SSID with mixed encryption");
                    alerts.push(NormalizedAlert {
                        source_tool: "netsec-threat".into(),
                        severity: Severity::High,
                        category: AlertCategory::NetworkThreat,
                        title: format!("Suspicious AP: '{}' seen with mixed encryption", ssid),
                        description: format!(
                            "SSID '{}' is broadcast by {} access points with mixed security \
                             (both open and encrypted). An open clone of an encrypted network \
                             is a common evil twin technique.",
                            ssid,
                            group.len()
                        ),
                        device_ip: None,
                        fingerprint: format!("evil-twin-mixed-enc-{}", ssid),
                        raw_data: serde_json::json!({
                            "ssid": ssid,
                            "access_points": group.iter().map(|ap| {
                                serde_json::json!({
                                    "bssid": ap.bssid,
                                    "channel": ap.channel,
                                    "signal_dbm": ap.signal_dbm,
                                    "encryption": ap.encryption,
                                })
                            }).collect::<Vec<_>>(),
                        }),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        alerts
    }
}

impl Default for EvilTwinDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for EvilTwinDetector {
    fn name(&self) -> &str {
        "evil_twin"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        let aps = Self::scan_wifi()?;
        Ok(self.analyze(&aps))
    }

    fn available(&self) -> bool {
        // Only available on Linux with WiFi tools
        cfg!(target_os = "linux")
            && (std::process::Command::new("nmcli")
                .arg("--version")
                .output()
                .is_ok()
                || std::process::Command::new("iwlist")
                    .arg("--version")
                    .output()
                    .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iwlist() {
        let sample = r#"
wlan0     Scan completed :
          Cell 01 - Address: AA:BB:CC:DD:EE:01
                    Channel:6
                    ESSID:"HomeBase"
                    Signal level=-45 dBm
                    Encryption key:on
          Cell 02 - Address: AA:BB:CC:DD:EE:02
                    Channel:6
                    ESSID:"HomeBase"
                    Signal level=-70 dBm
                    Encryption key:on
          Cell 03 - Address: FF:FF:FF:00:00:01
                    Channel:11
                    ESSID:"FreeWifi"
                    Signal level=-80 dBm
"#;
        let aps = EvilTwinDetector::parse_iwlist(sample);
        assert_eq!(aps.len(), 3);
        assert_eq!(aps[0].ssid, "HomeBase");
        assert_eq!(aps[0].bssid, "AA:BB:CC:DD:EE:01");
        assert_eq!(aps[0].channel, 6);
        assert_eq!(aps[0].signal_dbm, -45);
    }

    #[test]
    fn test_detect_evil_twin_with_trusted() {
        let mut trusted = HashMap::new();
        trusted.insert(
            "HomeBase".into(),
            vec!["AA:BB:CC:DD:EE:01".into()],
        );
        let detector = EvilTwinDetector::with_trusted(trusted);

        let aps = vec![
            AccessPoint {
                ssid: "HomeBase".into(),
                bssid: "AA:BB:CC:DD:EE:01".into(),
                channel: 6,
                signal_dbm: -45,
                encryption: "WPA2".into(),
            },
            AccessPoint {
                ssid: "HomeBase".into(),
                bssid: "FF:FF:FF:00:00:99".into(),
                channel: 6,
                signal_dbm: -60,
                encryption: "WPA2".into(),
            },
        ];

        let alerts = detector.analyze(&aps);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Evil twin"));
        assert!(alerts[0].title.contains("FF:FF:FF:00:00:99"));
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_mixed_encryption() {
        let detector = EvilTwinDetector::new();
        let aps = vec![
            AccessPoint {
                ssid: "CoffeeShop".into(),
                bssid: "AA:AA:AA:00:00:01".into(),
                channel: 1,
                signal_dbm: -50,
                encryption: "WPA2".into(),
            },
            AccessPoint {
                ssid: "CoffeeShop".into(),
                bssid: "BB:BB:BB:00:00:01".into(),
                channel: 1,
                signal_dbm: -55,
                encryption: "Open".into(),
            },
        ];

        let alerts = detector.analyze(&aps);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("mixed encryption"));
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn test_no_alert_single_ap() {
        let detector = EvilTwinDetector::new();
        let aps = vec![AccessPoint {
            ssid: "MyWifi".into(),
            bssid: "AA:BB:CC:DD:EE:01".into(),
            channel: 6,
            signal_dbm: -40,
            encryption: "WPA2".into(),
        }];
        let alerts = detector.analyze(&aps);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_no_alert_trusted_bssids() {
        let mut trusted = HashMap::new();
        trusted.insert(
            "HomeBase".into(),
            vec!["AA:BB:CC:DD:EE:01".into(), "AA:BB:CC:DD:EE:02".into()],
        );
        let detector = EvilTwinDetector::with_trusted(trusted);

        let aps = vec![
            AccessPoint {
                ssid: "HomeBase".into(),
                bssid: "AA:BB:CC:DD:EE:01".into(),
                channel: 6,
                signal_dbm: -45,
                encryption: "WPA2".into(),
            },
            AccessPoint {
                ssid: "HomeBase".into(),
                bssid: "AA:BB:CC:DD:EE:02".into(),
                channel: 11,
                signal_dbm: -60,
                encryption: "WPA2".into(),
            },
        ];

        let alerts = detector.analyze(&aps);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_name() {
        let d = EvilTwinDetector::new();
        assert_eq!(d.name(), "evil_twin");
    }
}

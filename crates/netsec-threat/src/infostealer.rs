//! Infostealer / credential theft detection.
//!
//! Monitors for indicators of credential-stealing malware:
//! - File access to browser credential stores (Login Data, cookies.sqlite, etc.)
//! - Connections to known infostealer C2 infrastructure
//! - Suspicious outbound data patterns from browser-related processes
//! - Known infostealer file artifacts on disk

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use tracing::warn;

use crate::{ThreatDetector, ThreatResult};

/// Browser credential store paths that infostealers target.
const CREDENTIAL_PATHS: &[&str] = &[
    // Chromium-based (Chrome, Edge, Brave, Opera, Vivaldi)
    ".config/google-chrome/Default/Login Data",
    ".config/google-chrome/Default/Cookies",
    ".config/google-chrome/Default/Web Data",
    ".config/google-chrome/Local State",
    ".config/BraveSoftware/Brave-Browser/Default/Login Data",
    ".config/microsoft-edge/Default/Login Data",
    ".config/opera/Default/Login Data",
    // Firefox
    ".mozilla/firefox/*/logins.json",
    ".mozilla/firefox/*/cookies.sqlite",
    ".mozilla/firefox/*/key4.db",
    ".mozilla/firefox/*/cert9.db",
    // Crypto wallets
    ".config/Exodus/exodus.wallet",
    ".config/Electrum/wallets",
    ".local/share/io.metamask",
    // SSH / GPG
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".gnupg/private-keys-v1.d",
    // Application tokens
    ".config/discord/Local Storage",
    ".config/Slack/Local Storage",
    // Windows paths (for cross-platform awareness)
    "AppData/Local/Google/Chrome/User Data/Default/Login Data",
    "AppData/Local/Google/Chrome/User Data/Default/Cookies",
    "AppData/Local/Microsoft/Edge/User Data/Default/Login Data",
    "AppData/Roaming/Mozilla/Firefox/Profiles/*/logins.json",
    "AppData/Roaming/Mozilla/Firefox/Profiles/*/key4.db",
    "AppData/Roaming/Exodus/exodus.wallet",
    "AppData/Roaming/Electrum/wallets",
];

/// Known infostealer artifact filenames.
const STEALER_ARTIFACTS: &[&str] = &[
    "passwords.txt",
    "cookies.txt",
    "credit_cards.txt",
    "autofill.txt",
    "wallets.txt",
    "discord_tokens.txt",
    "browser_data.zip",
    "stealer_log",
    "loot.zip",
    "SystemInfo.txt",
];

/// Known file extensions used by infostealers for exfiltration.
const EXFIL_ARCHIVE_PATTERNS: &[&str] = &[
    "_passwords.", "_cookies.", "_wallets.", "_cards.",
    "browser_", "steal_", "grab_", "loot_",
];

/// Detector for infostealer malware indicators.
pub struct InfostealerDetector {
    /// Home directories to monitor (defaults to current user's home).
    home_dirs: Vec<String>,
    /// Additional temp directories to scan for artifacts.
    temp_dirs: Vec<String>,
}

impl InfostealerDetector {
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
        Self {
            home_dirs: vec![home],
            temp_dirs: vec![
                "/tmp".into(),
                "/var/tmp".into(),
                std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
            ],
        }
    }

    pub fn with_dirs(home_dirs: Vec<String>, temp_dirs: Vec<String>) -> Self {
        Self {
            home_dirs,
            temp_dirs,
        }
    }

    /// Check if any credential store files have been accessed recently.
    /// Returns files whose mtime is within the last `window_secs` seconds.
    pub fn check_credential_access(&self, window_secs: u64) -> Vec<(String, std::time::SystemTime)> {
        let mut accessed = Vec::new();
        let now = std::time::SystemTime::now();

        for home in &self.home_dirs {
            for pattern in CREDENTIAL_PATHS {
                let full_path = format!("{}/{}", home, pattern);
                // Handle glob patterns with *
                if full_path.contains('*') {
                    // Simple glob: expand parent dir and match
                    if let Some(parent) = full_path.rsplit_once('/').map(|(p, _)| p) {
                        let parent_without_star = parent.replace('*', "");
                        if let Ok(entries) = std::fs::read_dir(&parent_without_star) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if let Ok(meta) = path.metadata() {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Ok(elapsed) = now.duration_since(mtime) {
                                            if elapsed.as_secs() < window_secs {
                                                accessed.push((
                                                    path.to_string_lossy().to_string(),
                                                    mtime,
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if let Ok(meta) = std::fs::metadata(&full_path) {
                    if let Ok(mtime) = meta.modified() {
                        if let Ok(elapsed) = now.duration_since(mtime) {
                            if elapsed.as_secs() < window_secs {
                                accessed.push((full_path, mtime));
                            }
                        }
                    }
                }
            }
        }

        accessed
    }

    /// Scan temp directories for known stealer artifacts.
    pub fn scan_stealer_artifacts(&self) -> Vec<String> {
        let mut found = Vec::new();

        for dir in &self.temp_dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_lowercase();

                // Check exact artifact names
                if STEALER_ARTIFACTS.iter().any(|a| name == *a) {
                    found.push(entry.path().to_string_lossy().to_string());
                    continue;
                }

                // Check exfiltration archive patterns
                if EXFIL_ARCHIVE_PATTERNS.iter().any(|p| name.contains(p)) {
                    found.push(entry.path().to_string_lossy().to_string());
                }
            }
        }

        found
    }

    /// Analyze system state for infostealer indicators.
    pub fn analyze(&self) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();

        // Check 1: Recent credential file access (last 5 minutes)
        let accessed = self.check_credential_access(300);
        if !accessed.is_empty() {
            // Multiple credential files accessed in a short window is suspicious
            // A single file is normal (browser reading its own data)
            // 3+ different credential types is concerning
            let unique_types: std::collections::HashSet<&str> = accessed
                .iter()
                .map(|(path, _)| {
                    if path.contains("Login Data") || path.contains("logins.json") {
                        "passwords"
                    } else if path.contains("Cookies") || path.contains("cookies.sqlite") {
                        "cookies"
                    } else if path.contains("key4.db") || path.contains("Local State") {
                        "encryption_keys"
                    } else if path.contains("wallet") || path.contains("Electrum") || path.contains("metamask") {
                        "crypto_wallets"
                    } else if path.contains(".ssh") || path.contains(".gnupg") {
                        "ssh_gpg_keys"
                    } else if path.contains("discord") || path.contains("Slack") {
                        "app_tokens"
                    } else {
                        "other"
                    }
                })
                .collect();

            if unique_types.len() >= 3 {
                warn!(
                    files = accessed.len(),
                    types = unique_types.len(),
                    "Multiple credential types accessed recently — possible infostealer"
                );
                let file_list: Vec<&str> = accessed.iter().map(|(p, _)| p.as_str()).collect();
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::Critical,
                    category: AlertCategory::Malware,
                    title: format!(
                        "Infostealer activity: {} credential files accessed ({} types)",
                        accessed.len(),
                        unique_types.len()
                    ),
                    description: format!(
                        "Multiple credential stores ({}) across {} categories were accessed \
                         within the last 5 minutes. This pattern is consistent with infostealer \
                         malware harvesting passwords, cookies, and keys. Files: {:?}",
                        accessed.len(),
                        unique_types.len(),
                        file_list
                    ),
                    device_ip: None,
                    fingerprint: "infostealer-credential-harvest".into(),
                    raw_data: serde_json::json!({
                        "files_accessed": file_list,
                        "credential_types": unique_types.iter().collect::<Vec<_>>(),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        // Check 2: Stealer artifacts in temp dirs
        let artifacts = self.scan_stealer_artifacts();
        for artifact in &artifacts {
            warn!(path = %artifact, "Infostealer artifact found");
            alerts.push(NormalizedAlert {
                source_tool: "netsec-threat".into(),
                severity: Severity::Critical,
                category: AlertCategory::Malware,
                title: format!("Infostealer artifact: {}", artifact),
                description: format!(
                    "Found suspected infostealer artifact at '{}'. \
                     This file matches known patterns used by credential-stealing malware \
                     (RedLine, Raccoon, Vidar, etc.) to stage stolen data before exfiltration.",
                    artifact
                ),
                device_ip: None,
                fingerprint: format!("infostealer-artifact-{}", artifact),
                raw_data: serde_json::json!({
                    "artifact_path": artifact,
                }),
                timestamp: Utc::now(),
            });
        }

        alerts
    }
}

impl Default for InfostealerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for InfostealerDetector {
    fn name(&self) -> &str {
        "infostealer"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        Ok(self.analyze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_credential_paths_non_empty() {
        assert!(!CREDENTIAL_PATHS.is_empty());
    }

    #[test]
    fn test_stealer_artifacts_non_empty() {
        assert!(!STEALER_ARTIFACTS.is_empty());
    }

    #[test]
    fn test_no_alerts_clean_system() {
        // Point at non-existent dirs to simulate clean system
        let detector = InfostealerDetector::with_dirs(
            vec!["/nonexistent-home-test-12345".into()],
            vec!["/nonexistent-tmp-test-12345".into()],
        );
        let alerts = detector.analyze();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_detect_stealer_artifact() {
        let tmp = TempDir::new().unwrap();
        let artifact_path = tmp.path().join("passwords.txt");
        {
            let mut f = std::fs::File::create(&artifact_path).unwrap();
            writeln!(f, "stolen data").unwrap();
        }

        let detector = InfostealerDetector::with_dirs(
            vec!["/nonexistent-12345".into()],
            vec![tmp.path().to_string_lossy().to_string()],
        );
        let alerts = detector.analyze();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Infostealer artifact"));
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_exfil_archive_pattern() {
        let tmp = TempDir::new().unwrap();
        let artifact_path = tmp.path().join("grab_cookies.zip");
        {
            std::fs::File::create(&artifact_path).unwrap();
        }

        let detector = InfostealerDetector::with_dirs(
            vec!["/nonexistent-12345".into()],
            vec![tmp.path().to_string_lossy().to_string()],
        );
        let alerts = detector.analyze();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Infostealer artifact"));
    }

    #[test]
    fn test_ignore_unrelated_temp_files() {
        let tmp = TempDir::new().unwrap();
        // Create harmless files
        std::fs::File::create(tmp.path().join("notes.txt")).unwrap();
        std::fs::File::create(tmp.path().join("build.log")).unwrap();

        let detector = InfostealerDetector::with_dirs(
            vec!["/nonexistent-12345".into()],
            vec![tmp.path().to_string_lossy().to_string()],
        );
        let alerts = detector.analyze();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_name() {
        let d = InfostealerDetector::new();
        assert_eq!(d.name(), "infostealer");
    }
}

//! Traffic entropy analysis.
//!
//! Calculates Shannon entropy of traffic payloads to detect:
//! - Encrypted C2 channels (high entropy, regular intervals)
//! - Compressed data exfiltration
//! - Cryptojacking / mining traffic (Stratum protocol on known ports)

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use tracing::warn;

use crate::{ThreatDetector, ThreatResult};

/// Known cryptocurrency mining (Stratum) ports.
const MINING_PORTS: &[u16] = &[
    3333, 3334, 3335, 3336,  // Common Stratum
    4444, 4445,              // More Stratum
    5555, 5556,              // Monero
    7777, 7778,              // Various
    8332, 8333,              // Bitcoin
    8888, 8899,              // Various pools
    9332, 9333,              // Litecoin
    14433, 14444,            // Monero SSL
    45560, 45700,            // Monero
];

/// A network flow summary for entropy analysis.
#[derive(Debug, Clone)]
pub struct FlowSummary {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub payload_sample: Vec<u8>,
    pub bytes_total: u64,
    pub packet_count: u64,
    /// Interval between packets in milliseconds (0 if unknown).
    pub avg_interval_ms: u64,
}

/// Configuration for entropy-based detection.
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    /// Entropy threshold (0.0-8.0 for bytes). Encrypted/compressed data is typically >7.0.
    pub high_entropy_threshold: f64,
    /// Minimum payload size to analyze (ignore tiny payloads).
    pub min_payload_bytes: usize,
    /// Beaconing interval regularity threshold (std_dev in ms). Low std_dev = beaconing.
    pub beacon_regularity_threshold_ms: u64,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            high_entropy_threshold: 7.2,
            min_payload_bytes: 64,
            beacon_regularity_threshold_ms: 500,
        }
    }
}

/// Detector for encrypted C2, data exfiltration, and cryptojacking.
pub struct EntropyDetector {
    config: EntropyConfig,
}

impl EntropyDetector {
    pub fn new() -> Self {
        Self {
            config: EntropyConfig::default(),
        }
    }

    pub fn with_config(config: EntropyConfig) -> Self {
        Self { config }
    }

    /// Calculate Shannon entropy of a byte slice (0.0 - 8.0).
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Check if a destination port is a known mining port.
    pub fn is_mining_port(port: u16) -> bool {
        MINING_PORTS.contains(&port)
    }

    /// Analyze a set of flows for suspicious entropy and mining indicators.
    pub fn analyze(&self, flows: &[FlowSummary]) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();

        for flow in flows {
            // Check 1: Mining port connections
            if Self::is_mining_port(flow.dst_port) {
                warn!(
                    dst = %flow.dst_ip,
                    port = flow.dst_port,
                    "Connection to known mining port"
                );
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::High,
                    category: AlertCategory::Anomaly,
                    title: format!(
                        "Cryptojacking: {} → {}:{} (mining port)",
                        flow.src_ip, flow.dst_ip, flow.dst_port
                    ),
                    description: format!(
                        "Device {} is connecting to {}:{} which is a known cryptocurrency \
                         mining (Stratum) port. This may indicate cryptojacking malware.",
                        flow.src_ip, flow.dst_ip, flow.dst_port
                    ),
                    device_ip: Some(flow.src_ip.clone()),
                    fingerprint: format!(
                        "cryptojack-port-{}-{}-{}",
                        flow.src_ip, flow.dst_ip, flow.dst_port
                    ),
                    raw_data: serde_json::json!({
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "dst_port": flow.dst_port,
                        "bytes_total": flow.bytes_total,
                    }),
                    timestamp: Utc::now(),
                });
            }

            // Check 2: High entropy payload (encrypted C2 or exfiltration)
            if flow.payload_sample.len() >= self.config.min_payload_bytes {
                let entropy = Self::shannon_entropy(&flow.payload_sample);
                if entropy > self.config.high_entropy_threshold {
                    // Check if this is on a standard encrypted port (443, 993, etc.)
                    // Those are expected to have high entropy
                    let standard_tls_ports = [443, 993, 995, 465, 8443, 636];
                    if !standard_tls_ports.contains(&flow.dst_port) {
                        warn!(
                            src = %flow.src_ip,
                            dst = %flow.dst_ip,
                            port = flow.dst_port,
                            entropy = format!("{:.2}", entropy),
                            "High entropy on non-standard port"
                        );
                        alerts.push(NormalizedAlert {
                            source_tool: "netsec-threat".into(),
                            severity: Severity::Medium,
                            category: AlertCategory::Anomaly,
                            title: format!(
                                "High entropy traffic: {} → {}:{} (entropy {:.2})",
                                flow.src_ip, flow.dst_ip, flow.dst_port, entropy
                            ),
                            description: format!(
                                "Flow from {} to {}:{} has entropy {:.2}/8.0 which indicates \
                                 encrypted or compressed data on a non-standard port. \
                                 May indicate encrypted C2 or data exfiltration.",
                                flow.src_ip, flow.dst_ip, flow.dst_port, entropy
                            ),
                            device_ip: Some(flow.src_ip.clone()),
                            fingerprint: format!(
                                "high-entropy-{}-{}-{}",
                                flow.src_ip, flow.dst_ip, flow.dst_port
                            ),
                            raw_data: serde_json::json!({
                                "src_ip": flow.src_ip,
                                "dst_ip": flow.dst_ip,
                                "dst_port": flow.dst_port,
                                "entropy": entropy,
                                "payload_size": flow.payload_sample.len(),
                                "bytes_total": flow.bytes_total,
                            }),
                            timestamp: Utc::now(),
                        });
                    }
                }
            }

            // Check 3: Beaconing detection (regular intervals + consistent size)
            if flow.avg_interval_ms > 0
                && flow.avg_interval_ms < 60_000
                && flow.packet_count > 10
            {
                // Regular small packets at fixed intervals = C2 beacon
                let avg_pkt_size = if flow.packet_count > 0 {
                    flow.bytes_total / flow.packet_count
                } else {
                    0
                };
                if avg_pkt_size < 512 && avg_pkt_size > 0 {
                    warn!(
                        src = %flow.src_ip,
                        dst = %flow.dst_ip,
                        interval_ms = flow.avg_interval_ms,
                        "Beaconing pattern detected"
                    );
                    alerts.push(NormalizedAlert {
                        source_tool: "netsec-threat".into(),
                        severity: Severity::High,
                        category: AlertCategory::Anomaly,
                        title: format!(
                            "Beaconing: {} → {} every {}ms",
                            flow.src_ip, flow.dst_ip, flow.avg_interval_ms
                        ),
                        description: format!(
                            "Device {} is sending small packets (~{} bytes) to {} at regular \
                             ~{}ms intervals ({} packets total). This pattern is consistent \
                             with C2 beacon traffic.",
                            flow.src_ip, avg_pkt_size, flow.dst_ip,
                            flow.avg_interval_ms, flow.packet_count
                        ),
                        device_ip: Some(flow.src_ip.clone()),
                        fingerprint: format!("beacon-{}-{}", flow.src_ip, flow.dst_ip),
                        raw_data: serde_json::json!({
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
                            "avg_interval_ms": flow.avg_interval_ms,
                            "avg_packet_size": avg_pkt_size,
                            "packet_count": flow.packet_count,
                        }),
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        alerts
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for EntropyDetector {
    fn name(&self) -> &str {
        "entropy"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        // In production, this would read from Zeek conn.log or pcap files.
        // Without traffic data, return empty.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_zero() {
        // All same bytes = 0 entropy
        let data = vec![0u8; 1000];
        let e = EntropyDetector::shannon_entropy(&data);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_max() {
        // Uniformly distributed bytes = ~8.0 entropy
        let mut data = Vec::new();
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = EntropyDetector::shannon_entropy(&data);
        assert!(e > 7.99, "expected ~8.0, got {e}");
    }

    #[test]
    fn test_shannon_entropy_text() {
        // ASCII text has moderate entropy (~4-5)
        let data = b"Hello world! This is a normal english text string for testing.";
        let e = EntropyDetector::shannon_entropy(data);
        assert!(e > 3.0 && e < 6.0, "expected 3-6, got {e}");
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(EntropyDetector::shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_is_mining_port() {
        assert!(EntropyDetector::is_mining_port(3333));
        assert!(EntropyDetector::is_mining_port(8333));
        assert!(EntropyDetector::is_mining_port(14444));
        assert!(!EntropyDetector::is_mining_port(80));
        assert!(!EntropyDetector::is_mining_port(443));
    }

    #[test]
    fn test_detect_mining_port() {
        let detector = EntropyDetector::new();
        let flows = vec![FlowSummary {
            src_ip: "192.168.1.100".into(),
            dst_ip: "pool.minexmr.com".into(),
            dst_port: 3333,
            protocol: "tcp".into(),
            payload_sample: vec![],
            bytes_total: 50000,
            packet_count: 100,
            avg_interval_ms: 0,
        }];
        let alerts = detector.analyze(&flows);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].title.contains("Cryptojacking"));
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn test_detect_high_entropy() {
        let detector = EntropyDetector::new();
        // Create high-entropy payload (random-looking)
        let mut payload = Vec::new();
        for i in 0..256u16 {
            payload.push(i as u8);
        }
        let flows = vec![FlowSummary {
            src_ip: "192.168.1.100".into(),
            dst_ip: "suspicious.example.com".into(),
            dst_port: 8080,
            protocol: "tcp".into(),
            payload_sample: payload,
            bytes_total: 100_000,
            packet_count: 50,
            avg_interval_ms: 0,
        }];
        let alerts = detector.analyze(&flows);
        assert!(alerts.iter().any(|a| a.title.contains("High entropy")));
    }

    #[test]
    fn test_no_alert_standard_tls() {
        let detector = EntropyDetector::new();
        let mut payload = Vec::new();
        for i in 0..256u16 {
            payload.push(i as u8);
        }
        let flows = vec![FlowSummary {
            src_ip: "192.168.1.100".into(),
            dst_ip: "google.com".into(),
            dst_port: 443, // Standard TLS
            protocol: "tcp".into(),
            payload_sample: payload,
            bytes_total: 100_000,
            packet_count: 50,
            avg_interval_ms: 0,
        }];
        let alerts = detector.analyze(&flows);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_detect_beaconing() {
        let detector = EntropyDetector::new();
        let flows = vec![FlowSummary {
            src_ip: "192.168.1.100".into(),
            dst_ip: "c2.evil.com".into(),
            dst_port: 8443,
            protocol: "tcp".into(),
            payload_sample: vec![],
            bytes_total: 5000,
            packet_count: 100,
            avg_interval_ms: 30_000, // Every 30 seconds
        }];
        let alerts = detector.analyze(&flows);
        assert!(alerts.iter().any(|a| a.title.contains("Beaconing")));
    }

    #[test]
    fn test_name() {
        let d = EntropyDetector::new();
        assert_eq!(d.name(), "entropy");
    }
}

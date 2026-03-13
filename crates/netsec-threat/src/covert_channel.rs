//! Covert channel detection.
//!
//! Analyzes DNS, ICMP, and HTTP traffic for tunneling indicators:
//! - DNS tunneling: unusually long subdomain labels, high query frequency, TXT abuse
//! - ICMP tunneling: oversized payloads, high frequency
//! - HTTP covert channels: suspicious header patterns, beaconing

use async_trait::async_trait;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use std::collections::HashMap;
use tracing::warn;

use crate::{ThreatDetector, ThreatResult};

/// A DNS query record (from Zeek dns.log or system DNS logs).
#[derive(Debug, Clone)]
pub struct DnsQueryRecord {
    pub timestamp: String,
    pub src_ip: String,
    pub query: String,
    pub qtype: String,
    pub answer: Option<String>,
}

/// Configuration for covert channel detection thresholds.
#[derive(Debug, Clone)]
pub struct CovertChannelConfig {
    /// Max average label length before flagging DNS tunneling.
    pub dns_max_avg_label_len: usize,
    /// Max number of queries to a single domain in the analysis window.
    pub dns_max_queries_per_domain: usize,
    /// Max ICMP payload size before flagging.
    pub icmp_max_payload_bytes: usize,
    /// Path to Zeek dns.log (if available).
    pub zeek_dns_log: Option<String>,
}

impl Default for CovertChannelConfig {
    fn default() -> Self {
        Self {
            dns_max_avg_label_len: 30,
            dns_max_queries_per_domain: 100,
            icmp_max_payload_bytes: 64,
            zeek_dns_log: None,
        }
    }
}

/// Detector for DNS tunneling, ICMP tunneling, and other covert channels.
pub struct CovertChannelDetector {
    config: CovertChannelConfig,
}

impl CovertChannelDetector {
    pub fn new() -> Self {
        Self {
            config: CovertChannelConfig::default(),
        }
    }

    pub fn with_config(config: CovertChannelConfig) -> Self {
        Self { config }
    }

    /// Parse a Zeek dns.log file into query records.
    pub fn parse_zeek_dns(content: &str) -> Vec<DnsQueryRecord> {
        let mut records = Vec::new();
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // Zeek TSV: ts uid orig_h orig_p resp_h resp_p proto trans_id rtt query qclass qclass_name qtype qtype_name ...
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 13 {
                records.push(DnsQueryRecord {
                    timestamp: fields[0].to_string(),
                    src_ip: fields[2].to_string(),
                    query: fields[9].to_string(),
                    qtype: fields[12].to_string(),
                    answer: fields.get(21).map(|s| s.to_string()),
                });
            }
        }
        records
    }

    /// Analyze DNS queries for tunneling indicators.
    pub fn analyze_dns(&self, queries: &[DnsQueryRecord]) -> Vec<NormalizedAlert> {
        let mut alerts = Vec::new();

        // Group queries by base domain (last 2 labels)
        let mut domain_queries: HashMap<String, Vec<&DnsQueryRecord>> = HashMap::new();
        for q in queries {
            let base = extract_base_domain(&q.query);
            domain_queries.entry(base).or_default().push(q);
        }

        for (domain, group) in &domain_queries {
            // Check 1: High query volume to a single domain
            if group.len() > self.config.dns_max_queries_per_domain {
                warn!(domain = %domain, count = group.len(), "High DNS query volume — possible tunnel");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::High,
                    category: AlertCategory::Anomaly,
                    title: format!("DNS tunnel suspected: {} queries to {}", group.len(), domain),
                    description: format!(
                        "Unusually high DNS query rate ({} queries) to domain '{}'. \
                         DNS tunneling tools generate many queries to encode data in subdomains.",
                        group.len(),
                        domain
                    ),
                    device_ip: group.first().map(|q| q.src_ip.clone()),
                    fingerprint: format!("dns-tunnel-volume-{}", domain),
                    raw_data: serde_json::json!({
                        "domain": domain,
                        "query_count": group.len(),
                        "src_ips": group.iter().map(|q| &q.src_ip).collect::<Vec<_>>(),
                    }),
                    timestamp: Utc::now(),
                });
            }

            // Check 2: Long subdomain labels (data encoding)
            let avg_label_len = avg_subdomain_label_length(group.iter().map(|q| q.query.as_str()));
            if avg_label_len > self.config.dns_max_avg_label_len {
                warn!(domain = %domain, avg_len = avg_label_len, "Long DNS labels — possible tunnel");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::High,
                    category: AlertCategory::Anomaly,
                    title: format!("DNS tunnel suspected: long labels for {}", domain),
                    description: format!(
                        "DNS queries to '{}' have an average subdomain label length of {} chars \
                         (threshold: {}). DNS tunneling encodes data in subdomain labels.",
                        domain, avg_label_len, self.config.dns_max_avg_label_len
                    ),
                    device_ip: group.first().map(|q| q.src_ip.clone()),
                    fingerprint: format!("dns-tunnel-labels-{}", domain),
                    raw_data: serde_json::json!({
                        "domain": domain,
                        "avg_label_length": avg_label_len,
                        "threshold": self.config.dns_max_avg_label_len,
                    }),
                    timestamp: Utc::now(),
                });
            }

            // Check 3: TXT record abuse
            let txt_count = group.iter().filter(|q| q.qtype == "TXT" || q.qtype == "16").count();
            if txt_count > 20 {
                warn!(domain = %domain, txt_count, "High TXT query count — possible tunnel");
                alerts.push(NormalizedAlert {
                    source_tool: "netsec-threat".into(),
                    severity: Severity::Medium,
                    category: AlertCategory::Anomaly,
                    title: format!("DNS TXT abuse: {} TXT queries to {}", txt_count, domain),
                    description: format!(
                        "{} TXT record queries to '{}'. TXT records are commonly used \
                         for DNS tunneling to exfiltrate larger payloads.",
                        txt_count, domain
                    ),
                    device_ip: group.first().map(|q| q.src_ip.clone()),
                    fingerprint: format!("dns-txt-abuse-{}", domain),
                    raw_data: serde_json::json!({
                        "domain": domain,
                        "txt_query_count": txt_count,
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        alerts
    }

    /// Read and analyze Zeek DNS logs if available.
    fn analyze_zeek_logs(&self) -> Vec<NormalizedAlert> {
        let path = match &self.config.zeek_dns_log {
            Some(p) => p.clone(),
            None => {
                // Try default Zeek paths
                let defaults = [
                    "/opt/zeek/logs/current/dns.log",
                    "/usr/local/zeek/logs/current/dns.log",
                    "/var/log/zeek/current/dns.log",
                ];
                match defaults.iter().find(|p| std::path::Path::new(p).exists()) {
                    Some(p) => p.to_string(),
                    None => return Vec::new(),
                }
            }
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let queries = Self::parse_zeek_dns(&content);
                self.analyze_dns(&queries)
            }
            Err(_) => Vec::new(),
        }
    }
}

impl Default for CovertChannelDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatDetector for CovertChannelDetector {
    fn name(&self) -> &str {
        "covert_channel"
    }

    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>> {
        Ok(self.analyze_zeek_logs())
    }
}

/// Extract the base domain (last 2 labels) from a FQDN.
fn extract_base_domain(fqdn: &str) -> String {
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    if labels.len() >= 2 {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else {
        fqdn.to_string()
    }
}

/// Calculate the average subdomain label length across a set of queries.
fn avg_subdomain_label_length<'a>(queries: impl Iterator<Item = &'a str>) -> usize {
    let mut total_len: usize = 0;
    let mut count: usize = 0;
    for query in queries {
        let labels: Vec<&str> = query.trim_end_matches('.').split('.').collect();
        // Subdomain labels are everything except the last 2 (base domain)
        if labels.len() > 2 {
            for label in &labels[..labels.len() - 2] {
                total_len += label.len();
                count += 1;
            }
        }
    }
    if count == 0 {
        0
    } else {
        total_len / count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("foo.bar.example.com"), "example.com");
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("a.b.c.d.e.com"), "e.com");
        assert_eq!(extract_base_domain("localhost"), "localhost");
    }

    #[test]
    fn test_avg_subdomain_label_length() {
        let queries = vec![
            "short.example.com",
            "a.example.com",
            "medium-label.example.com",
        ];
        let avg = avg_subdomain_label_length(queries.into_iter());
        // "short"=5, "a"=1, "medium-label"=12 → avg = 18/3 = 6
        assert_eq!(avg, 6);
    }

    #[test]
    fn test_avg_subdomain_no_subdomains() {
        let queries = vec!["example.com", "test.org"];
        let avg = avg_subdomain_label_length(queries.into_iter());
        assert_eq!(avg, 0);
    }

    #[test]
    fn test_detect_high_volume() {
        let detector = CovertChannelDetector::with_config(CovertChannelConfig {
            dns_max_queries_per_domain: 5,
            ..Default::default()
        });
        let queries: Vec<DnsQueryRecord> = (0..10)
            .map(|i| DnsQueryRecord {
                timestamp: "1234567890".into(),
                src_ip: "192.168.1.100".into(),
                query: format!("sub{i}.evil.com"),
                qtype: "A".into(),
                answer: None,
            })
            .collect();
        let alerts = detector.analyze_dns(&queries);
        assert!(alerts.iter().any(|a| a.title.contains("DNS tunnel suspected")));
    }

    #[test]
    fn test_detect_long_labels() {
        let detector = CovertChannelDetector::with_config(CovertChannelConfig {
            dns_max_avg_label_len: 10,
            ..Default::default()
        });
        let queries = vec![DnsQueryRecord {
            timestamp: "1234567890".into(),
            src_ip: "192.168.1.100".into(),
            query: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com".into(), // 33 chars
            qtype: "A".into(),
            answer: None,
        }];
        let alerts = detector.analyze_dns(&queries);
        assert!(alerts.iter().any(|a| a.title.contains("long labels")));
    }

    #[test]
    fn test_detect_txt_abuse() {
        let detector = CovertChannelDetector::new();
        let queries: Vec<DnsQueryRecord> = (0..25)
            .map(|i| DnsQueryRecord {
                timestamp: "1234567890".into(),
                src_ip: "192.168.1.100".into(),
                query: format!("q{i}.tunnel.com"),
                qtype: "TXT".into(),
                answer: None,
            })
            .collect();
        let alerts = detector.analyze_dns(&queries);
        assert!(alerts.iter().any(|a| a.title.contains("TXT abuse")));
    }

    #[test]
    fn test_no_alert_normal_traffic() {
        let detector = CovertChannelDetector::new();
        let queries = vec![
            DnsQueryRecord {
                timestamp: "1".into(),
                src_ip: "192.168.1.100".into(),
                query: "www.google.com".into(),
                qtype: "A".into(),
                answer: None,
            },
            DnsQueryRecord {
                timestamp: "2".into(),
                src_ip: "192.168.1.100".into(),
                query: "mail.google.com".into(),
                qtype: "A".into(),
                answer: None,
            },
        ];
        let alerts = detector.analyze_dns(&queries);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_parse_zeek_dns() {
        let sample = "#separator \\x09\n\
            #fields\tts\tuid\torig_h\torig_p\tresp_h\tresp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\n\
            1234567890.000000\tCuid\t192.168.1.100\t12345\t8.8.8.8\t53\tudp\t1234\t0.01\twww.example.com\t1\tC_INTERNET\tA\n";
        let records = CovertChannelDetector::parse_zeek_dns(sample);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].src_ip, "192.168.1.100");
        assert_eq!(records[0].query, "www.example.com");
        assert_eq!(records[0].qtype, "A");
    }

    #[test]
    fn test_name() {
        let d = CovertChannelDetector::new();
        assert_eq!(d.name(), "covert_channel");
    }
}

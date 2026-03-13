//! Network threat detection modules: evil twin, ARP spoof, DNS hijack,
//! covert channels, entropy analysis, malvertising, and infostealer detection.

pub mod arp_spoof;
pub mod covert_channel;
pub mod dns_hijack;
pub mod entropy;
pub mod evil_twin;
pub mod infostealer;
pub mod malvertising;

use async_trait::async_trait;
use netsec_models::alert::NormalizedAlert;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatError {
    #[error("detection error: {0}")]
    Detection(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("command failed: {0}")]
    Command(String),
}

pub type ThreatResult<T> = Result<T, ThreatError>;

/// Trait implemented by all threat detection modules.
#[async_trait]
pub trait ThreatDetector: Send + Sync {
    /// Human-readable name for this detector.
    fn name(&self) -> &str;

    /// Run a single detection pass and return any alerts found.
    async fn detect(&self) -> ThreatResult<Vec<NormalizedAlert>>;

    /// Check whether this detector can run on the current system.
    fn available(&self) -> bool {
        true
    }
}

/// Engine that runs all registered threat detectors.
pub struct ThreatEngine {
    detectors: Vec<Box<dyn ThreatDetector>>,
}

impl ThreatEngine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Create an engine with all built-in detectors using default configs.
    pub fn with_defaults() -> Self {
        let mut engine = Self::new();
        engine.add(Box::new(arp_spoof::ArpSpoofDetector::new()));
        engine.add(Box::new(dns_hijack::DnsHijackDetector::new()));
        engine.add(Box::new(evil_twin::EvilTwinDetector::new()));
        engine.add(Box::new(covert_channel::CovertChannelDetector::new()));
        engine.add(Box::new(entropy::EntropyDetector::new()));
        engine.add(Box::new(malvertising::MalvertisingDetector::new()));
        engine.add(Box::new(infostealer::InfostealerDetector::new()));
        engine
    }

    pub fn add(&mut self, detector: Box<dyn ThreatDetector>) {
        self.detectors.push(detector);
    }

    /// Run all available detectors and collect alerts.
    pub async fn run_all(&self) -> Vec<(String, ThreatResult<Vec<NormalizedAlert>>)> {
        let mut results = Vec::new();
        for detector in &self.detectors {
            if detector.available() {
                let name = detector.name().to_string();
                let result = detector.detect().await;
                results.push((name, result));
            }
        }
        results
    }

    /// Run all detectors and flatten into a single alert list, skipping errors.
    pub async fn run_all_collect(&self) -> Vec<NormalizedAlert> {
        let results = self.run_all().await;
        results
            .into_iter()
            .filter_map(|(_, r)| r.ok())
            .flatten()
            .collect()
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn available_detectors(&self) -> Vec<&str> {
        self.detectors
            .iter()
            .filter(|d| d.available())
            .map(|d| d.name())
            .collect()
    }
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_new_empty() {
        let engine = ThreatEngine::new();
        assert_eq!(engine.detector_count(), 0);
        assert!(engine.available_detectors().is_empty());
    }

    #[test]
    fn test_engine_with_defaults() {
        let engine = ThreatEngine::with_defaults();
        assert_eq!(engine.detector_count(), 7);
        let names = engine.available_detectors();
        assert!(names.contains(&"arp_spoof"));
        assert!(names.contains(&"dns_hijack"));
        assert!(names.contains(&"evil_twin"));
        assert!(names.contains(&"covert_channel"));
        assert!(names.contains(&"entropy"));
        assert!(names.contains(&"malvertising"));
        assert!(names.contains(&"infostealer"));
    }

    #[tokio::test]
    async fn test_engine_run_all_collect() {
        let engine = ThreatEngine::new();
        let alerts = engine.run_all_collect().await;
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_default_trait() {
        let engine = ThreatEngine::default();
        assert_eq!(engine.detector_count(), 0);
    }
}

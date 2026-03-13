use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub api_url: String,
    pub ws_url: String,
    pub notifications_enabled: bool,
    pub auto_refresh: bool,
    pub refresh_interval_secs: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:8420".into(),
            ws_url: "ws://127.0.0.1:8420/ws".into(),
            notifications_enabled: true,
            auto_refresh: true,
            refresh_interval_secs: 30,
        }
    }
}

fn settings_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "netsec", "NetSec")
        .map(|dirs| dirs.config_dir().join("settings.toml"))
}

pub fn load() -> AppSettings {
    let Some(path) = settings_path() else {
        return AppSettings::default();
    };
    if !path.exists() {
        return AppSettings::default();
    }
    match fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => AppSettings::default(),
    }
}

pub fn save(settings: &AppSettings) -> Result<(), String> {
    let path = settings_path().ok_or("Cannot determine config path")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content = toml::to_string_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())?;
    tracing::info!("Settings saved to {:?}", path);
    Ok(())
}

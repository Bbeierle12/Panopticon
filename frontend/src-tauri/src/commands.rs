use tauri::{App, Emitter};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut};
use tauri_plugin_notification::NotificationExt;

use crate::settings::{self, AppSettings};

// ── Tauri commands (called from the React frontend) ─────────────────

#[tauri::command]
pub fn notify_alert(
    app: tauri::AppHandle,
    severity: String,
    title: String,
    message: String,
) -> Result<(), String> {
    let summary = format!("[{}] {}", severity.to_uppercase(), title);
    app.notification()
        .builder()
        .title(&summary)
        .body(&message)
        .show()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn notify_scan_complete(
    app: tauri::AppHandle,
    scan_type: String,
    target: String,
    status: String,
) -> Result<(), String> {
    let title = if status == "completed" {
        format!("Scan Completed: {}", scan_type)
    } else {
        format!("Scan Failed: {}", scan_type)
    };
    let body = format!("Target: {}\nStatus: {}", target, status);
    app.notification()
        .builder()
        .title(&title)
        .body(&body)
        .show()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_settings() -> AppSettings {
    settings::load()
}

#[tauri::command]
pub fn save_settings(settings: AppSettings) -> Result<(), String> {
    settings::save(&settings)
}

#[tauri::command]
pub async fn backend_health() -> Result<serde_json::Value, String> {
    let s = settings::load();
    let url = format!("{}/api/system/health", s.api_url);
    let resp = reqwest::get(&url).await.map_err(|e| e.to_string())?;
    resp.json().await.map_err(|e| e.to_string())
}

// ── Global shortcuts ────────────────────────────────────────────────

pub fn register_shortcuts(app: &App) -> Result<(), Box<dyn std::error::Error>> {
    let shortcuts: Vec<(Shortcut, &str)> = vec![
        (
            Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyN),
            "toggle-window",
        ),
        (
            Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyR),
            "refresh-data",
        ),
        (
            Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyA),
            "open-alerts",
        ),
    ];

    for (shortcut, action) in shortcuts {
        let action_name = action.to_string();
        let handle = app.handle().clone();

        app.global_shortcut().on_shortcut(shortcut, move |_app, _shortcut, _event| {
            tracing::info!("Global shortcut: {}", action_name);
            let _ = handle.emit("global-shortcut", &action_name);
        })?;

        tracing::info!("Registered shortcut: {:?} -> {}", shortcut, action);
    }

    Ok(())
}

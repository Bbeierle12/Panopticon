// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod settings;

use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting NetSec Desktop Application");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .setup(|app| {
            // Register global shortcuts
            commands::register_shortcuts(app)?;

            tracing::info!("NetSec Desktop ready");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::notify_alert,
            commands::notify_scan_complete,
            commands::get_settings,
            commands::save_settings,
            commands::backend_health,
        ])
        .run(tauri::generate_context!())
        .expect("error running NetSec Desktop");
}

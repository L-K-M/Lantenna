mod commands;
mod models;
mod scanner;
mod storage;
mod system_colors;
mod updates;
mod window_activity;
mod wol;

use commands::{AppState, ScanManager};
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let storage = match storage::Storage::new() {
        Ok(storage) => storage,
        Err(error) => {
            log::error!(
                "Failed to initialize persistent storage ({}). Falling back to in-memory storage.",
                error
            );
            storage::Storage::in_memory()
        }
    };
    let app_state = AppState {
        storage: Arc::new(storage),
        scan_manager: Arc::new(ScanManager::new()),
    };

    tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            match app.get_webview_window("main") {
                Some(window) => window_activity::track(&window)?,
                // Only reachable if the window label in tauri.conf.json stops
                // being "main"; say so rather than leaving the title bar stuck
                // on its startup state with nothing in the log.
                None => log::warn!("no \"main\" window; window activity not tracked"),
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_network_interfaces,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_results,
            commands::scan_host_ports,
            commands::open_external_url,
            commands::get_system_colors,
            updates::check_self_update,
            updates::open_release_url,
            commands::wake_host,
            window_activity::is_window_active,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

mod commands;
mod models;
mod scanner;
mod storage;
mod system_colors;

use commands::{AppState, ScanManager};
use std::sync::Arc;

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
        .invoke_handler(tauri::generate_handler![
            commands::get_network_interfaces,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_results,
            commands::scan_host_ports,
            commands::open_external_url,
            commands::get_system_colors,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

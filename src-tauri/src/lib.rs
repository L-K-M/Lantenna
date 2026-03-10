mod commands;
mod models;
mod scanner;
mod storage;

use commands::{AppState, ScanManager};
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let storage = storage::Storage::new().expect("Failed to initialize storage");
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

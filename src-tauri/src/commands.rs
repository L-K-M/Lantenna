use crate::models::{
    Host, NetworkInterface, PortProfile, ScanErrorPayload, ScanOptions, ScanProgress, ScanResult,
    SystemColors,
};
use crate::scanner;
use crate::storage::Storage;
use crate::system_colors;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

pub struct AppState {
    pub storage: Arc<Storage>,
    pub scan_manager: Arc<ScanManager>,
}

pub struct ScanManager {
    running: AtomicBool,
    cancel_flag: Arc<AtomicBool>,
}

impl ScanManager {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) -> bool {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.cancel_flag.store(false, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    pub fn finish(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        self.cancel_flag.clone()
    }
}

#[tauri::command]
pub async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    scanner::list_network_interfaces().map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn start_scan(
    options: ScanOptions,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if !state.scan_manager.start() {
        return Err("A scan is already running".to_string());
    }

    let storage = state.storage.clone();
    let scan_manager = state.scan_manager.clone();

    tauri::async_runtime::spawn(async move {
        let result = scanner::run_scan(
            options,
            scan_manager.cancel_token(),
            |progress| {
                let _ = app.emit_to("main", "scan-progress", progress);
            },
            |host| {
                let _ = app.emit_to("main", "host-found", host);
            },
        )
        .await;

        match result {
            Ok(scan_result) => {
                let mut scan_result = scan_result;
                scan_result.hosts =
                    scanner::enrich_hosts_with_cache(scan_result.hosts, storage.clone()).await;

                if let Err(error) = storage.save_scan_result(scan_result.clone()) {
                    log::error!("Failed to persist scan result: {}", error);
                }
                let _ = app.emit_to("main", "scan-complete", scan_result);
            }
            Err(error) => {
                let payload = ScanErrorPayload {
                    message: error.to_string(),
                };
                let _ = app.emit_to("main", "scan-error", payload);
            }
        }

        scan_manager.finish();
    });

    Ok(())
}

#[tauri::command]
pub async fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
    if state.scan_manager.is_running() {
        state.scan_manager.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn get_scan_results(state: State<'_, AppState>) -> Result<Option<ScanResult>, String> {
    state
        .storage
        .get_latest_scan()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn scan_host_ports(
    ip: String,
    profile: PortProfile,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Host, String> {
    let timeout_ms = match profile {
        PortProfile::Quick => 220,
        PortProfile::Standard => 280,
        PortProfile::Deep => 320,
    };

    let target_ip = ip.clone();
    let mut last_emitted_scanned = 0usize;
    let mut last_emit_at = Instant::now() - Duration::from_millis(250);

    let host = match scanner::scan_single_host_with_progress(
        ip,
        profile,
        timeout_ms,
        |scanned, total, found| {
            let now = Instant::now();
            let should_emit = scanned == 0
                || scanned >= total
                || scanned.saturating_sub(last_emitted_scanned) >= 12
                || now.duration_since(last_emit_at) >= Duration::from_millis(75);

            if !should_emit {
                return;
            }

            last_emitted_scanned = scanned;
            last_emit_at = now;

            let _ = app.emit_to(
                "main",
                "host-scan-progress",
                ScanProgress {
                    scanned,
                    total,
                    found,
                    running: true,
                    current_ip: Some(target_ip.clone()),
                },
            );
        },
    )
    .await
    {
        Ok(host) => host,
        Err(error) => {
            let _ = app.emit_to(
                "main",
                "host-scan-progress",
                ScanProgress {
                    scanned: 0,
                    total: 1,
                    found: 0,
                    running: false,
                    current_ip: Some(target_ip),
                },
            );
            return Err(error.to_string());
        }
    };

    let host = scanner::enrich_host_with_cache(host, state.storage.clone()).await;

    let _ = app.emit_to(
        "main",
        "host-scan-progress",
        ScanProgress {
            scanned: 1,
            total: 1,
            found: host.open_ports.len(),
            running: false,
            current_ip: Some(host.ip.clone()),
        },
    );

    Ok(host)
}

#[tauri::command]
pub async fn open_external_url(url: String) -> Result<(), String> {
    let normalized = url.to_lowercase();
    let allowed = normalized.starts_with("http://")
        || normalized.starts_with("https://")
        || normalized.starts_with("smb://")
        || normalized.starts_with("ssh://")
        || normalized.starts_with("ftp://")
        || normalized.starts_with("vnc://")
        || normalized.starts_with("telnet://")
        || normalized.starts_with("rtsp://");

    if !allowed {
        return Err("Unsupported URL scheme".to_string());
    }

    open::that(&url)
        .map_err(|error| error.to_string())
        .map(|_| ())
}

#[tauri::command]
pub fn get_system_colors() -> Result<SystemColors, String> {
    Ok(system_colors::get_system_colors())
}

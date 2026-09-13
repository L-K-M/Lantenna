#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Warnings here report lost functionality — an unreadable neighbour table
    // costs every MAC address, and with it vendor lookup, device-type
    // inference and Wake on LAN. env_logger's own default shows errors only,
    // so warnings would never reach anyone. RUST_LOG still overrides this.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    lantenna_lib::run();
}

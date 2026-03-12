use crate::models::{
    DeviceFingerprint, DiscoveryMode, Host, NetworkInterface, PortInfo, PortProfile, ScanOptions,
    ScanProgress, ScanResult,
};
use crate::storage::Storage;
use anyhow::{Context, Result};
use chrono::Utc;
use futures::{stream, StreamExt};
use if_addrs::{get_if_addrs, IfAddr};
use ipnet::Ipv4Net;
use ndb_oui::OuiDb;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command as StdCommand;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout, Duration};

fn available_workers() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
}

fn host_concurrency_for_profile(profile: &PortProfile, workers: usize) -> usize {
    match profile {
        PortProfile::Quick => (workers * 3).clamp(12, 32),
        PortProfile::Standard => (workers * 2).clamp(8, 24),
        PortProfile::Deep => workers.clamp(4, 12),
    }
}

fn port_concurrency_for_profile(profile: &PortProfile, workers: usize) -> usize {
    match profile {
        PortProfile::Quick => 12,
        PortProfile::Standard => (workers * 2).clamp(12, 32),
        PortProfile::Deep => (workers * 4).clamp(24, 64),
    }
}

fn global_connection_limit_for_profile(profile: &PortProfile, workers: usize) -> usize {
    match profile {
        PortProfile::Quick => (workers * 16).clamp(64, 128),
        PortProfile::Standard => (workers * 12).clamp(48, 112),
        PortProfile::Deep => (workers * 8).clamp(32, 96),
    }
}

fn select_interface<'a>(
    interfaces: &'a [NetworkInterface],
    interface_name: &str,
    requested_subnet: Option<&str>,
) -> Result<&'a NetworkInterface> {
    let name_matches = interfaces
        .iter()
        .filter(|iface| iface.name == interface_name)
        .collect::<Vec<&NetworkInterface>>();

    if let Some(subnet) = requested_subnet {
        if let Some(exact_match) = name_matches
            .iter()
            .copied()
            .find(|iface| iface.subnet == subnet)
        {
            return Ok(exact_match);
        }
    }

    if let Some(first_name_match) = name_matches.first() {
        return Ok(*first_name_match);
    }

    if let Some(subnet) = requested_subnet {
        if let Some(subnet_match) = interfaces.iter().find(|iface| iface.subnet == subnet) {
            return Ok(subnet_match);
        }
    }

    anyhow::bail!("Interface '{}' not found", interface_name)
}

fn build_scan_targets(
    network: Ipv4Net,
    local_ip: Option<Ipv4Addr>,
    max_hosts: usize,
) -> Vec<Ipv4Addr> {
    if max_hosts == 0 || network.prefix_len() >= 31 {
        return Vec::new();
    }

    let first_host = ipv4_to_u32(network.network()).saturating_add(1);
    let last_host = ipv4_to_u32(network.broadcast()).saturating_sub(1);

    if first_host > last_host {
        return Vec::new();
    }

    let total_hosts = (last_host - first_host + 1) as usize;
    let local_in_range = local_ip
        .map(ipv4_to_u32)
        .map(|ip| ip >= first_host && ip <= last_host)
        .unwrap_or(false);
    let available_hosts = total_hosts.saturating_sub(if local_in_range { 1 } else { 0 });
    let target_count = max_hosts.min(available_hosts);

    if target_count == 0 {
        return Vec::new();
    }

    if target_count >= available_hosts {
        return (first_host..=last_host)
            .filter_map(|raw_ip| {
                let ip = Ipv4Addr::from(raw_ip);
                if local_ip == Some(ip) {
                    None
                } else {
                    Some(ip)
                }
            })
            .collect();
    }

    let mut selected_raw_ips = HashSet::with_capacity(target_count);
    let mut targets = Vec::with_capacity(target_count);

    for index in 0..target_count {
        let offset = ((index as u128 * total_hosts as u128) / target_count as u128) as u32;
        let raw_ip = first_host + offset.min(last_host - first_host);

        if !selected_raw_ips.insert(raw_ip) {
            continue;
        }

        let ip = Ipv4Addr::from(raw_ip);
        if local_ip == Some(ip) {
            continue;
        }

        targets.push(ip);
    }

    if targets.len() < target_count {
        for raw_ip in first_host..=last_host {
            if targets.len() == target_count {
                break;
            }

            if selected_raw_ips.contains(&raw_ip) {
                continue;
            }

            let ip = Ipv4Addr::from(raw_ip);
            if local_ip == Some(ip) {
                continue;
            }

            selected_raw_ips.insert(raw_ip);
            targets.push(ip);
        }
    }

    targets.sort_by_key(|ip| ipv4_to_u32(*ip));
    targets
}

enum PortProbeOutcome {
    Open(PortInfo),
    Reachable,
}

fn is_reachable_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

fn is_transient_probe_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(23 | 24 | 55 | 10024 | 10055))
}

pub fn list_network_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();

    for iface in get_if_addrs().context("Failed to list network interfaces")? {
        let IfAddr::V4(v4) = iface.addr else {
            continue;
        };

        if v4.ip.is_loopback() {
            continue;
        }

        let prefix = netmask_to_prefix(v4.netmask);
        if prefix == 0 {
            continue;
        }

        let network = Ipv4Addr::from(ipv4_to_u32(v4.ip) & ipv4_to_u32(v4.netmask));
        let host_count = if prefix >= 31 {
            0
        } else {
            (((1u64 << (32 - prefix)) - 2).min(u32::MAX as u64)) as u32
        };

        interfaces.push(NetworkInterface {
            name: iface.name,
            ip: v4.ip.to_string(),
            cidr: prefix,
            subnet: format!("{}/{}", network, prefix),
            host_count,
        });
    }

    interfaces.sort_by(|a, b| {
        a.name.cmp(&b.name).then_with(|| {
            ipv4_to_u32(parse_ipv4_or_zero(&a.ip)).cmp(&ipv4_to_u32(parse_ipv4_or_zero(&b.ip)))
        })
    });
    interfaces.dedup_by(|a, b| a.name == b.name && a.ip == b.ip);

    Ok(interfaces)
}

pub async fn run_scan<F, G>(
    mut options: ScanOptions,
    cancel_flag: Arc<AtomicBool>,
    mut on_progress: F,
    mut on_host: G,
) -> Result<ScanResult>
where
    F: FnMut(ScanProgress),
    G: FnMut(Host),
{
    let started_at = Utc::now().to_rfc3339();
    let interfaces = list_network_interfaces()?;
    let selected = select_interface(
        &interfaces,
        &options.interface_name,
        options.subnet.as_deref(),
    )?;

    let subnet = options
        .subnet
        .clone()
        .unwrap_or_else(|| selected.subnet.clone());
    options.subnet = Some(subnet.clone());

    let network =
        Ipv4Net::from_str(&subnet).with_context(|| format!("Invalid subnet '{}'", subnet))?;
    let max_hosts = options
        .max_hosts
        .unwrap_or(selected.host_count as usize)
        .clamp(1, 4096);

    let local_ip = Ipv4Addr::from_str(&selected.ip).ok();
    let targets = build_scan_targets(network, local_ip, max_hosts);

    if targets.is_empty() {
        anyhow::bail!("No target hosts found in subnet {}", subnet);
    }

    let timeout_ms = options.timeout_ms.unwrap_or(350).clamp(50, 5000);
    let timeout_duration = Duration::from_millis(timeout_ms);
    let ports = Arc::new(ports_for_profile(&options.port_profile));
    let workers = available_workers();
    let host_concurrency = host_concurrency_for_profile(&options.port_profile, workers);
    let port_concurrency = port_concurrency_for_profile(&options.port_profile, workers);
    let global_connection_limit =
        global_connection_limit_for_profile(&options.port_profile, workers);
    let connection_semaphore = Arc::new(Semaphore::new(global_connection_limit));

    log::info!(
        "scan config: profile={:?} discovery={:?} workers={} hosts={} ports={} max_connections={} timeout_ms={}",
        options.port_profile,
        options.discovery_mode,
        workers,
        host_concurrency,
        port_concurrency,
        global_connection_limit,
        timeout_ms
    );

    let total = targets.len();
    let mut scanned = 0usize;
    let mut found = 0usize;
    let mut hosts = Vec::new();
    let mut unreachable_targets = Vec::new();

    on_progress(ScanProgress {
        scanned,
        total,
        found,
        running: true,
        current_ip: None,
    });

    let mut stream = stream::iter(targets.into_iter().map(|ip| {
        let ports = ports.clone();
        let cancel_flag = cancel_flag.clone();
        let connection_semaphore = connection_semaphore.clone();
        async move {
            if cancel_flag.load(Ordering::Relaxed) {
                return (ip, None);
            }

            let host = scan_host_internal(
                ip,
                ports,
                timeout_duration,
                port_concurrency,
                connection_semaphore,
                cancel_flag,
            )
            .await;
            (ip, host)
        }
    }))
    .buffer_unordered(host_concurrency);

    while let Some((current_ip, maybe_host)) = stream.next().await {
        scanned += 1;

        if let Some(host) = maybe_host {
            found += 1;
            on_host(host.clone());
            hosts.push(host);
        } else {
            unreachable_targets.push(current_ip);
        }

        let cancelled = cancel_flag.load(Ordering::Relaxed);
        let current_ip_text = current_ip.to_string();

        on_progress(ScanProgress {
            scanned,
            total,
            found,
            running: !cancelled,
            current_ip: Some(current_ip_text),
        });

        if cancelled {
            break;
        }
    }

    let cancelled = cancel_flag.load(Ordering::Relaxed);
    if !cancelled && !unreachable_targets.is_empty() {
        let mut discovered_ips = hosts
            .iter()
            .filter_map(|host| Ipv4Addr::from_str(&host.ip).ok())
            .collect::<HashSet<Ipv4Addr>>();

        let arp_table = read_arp_table().await;
        let arp_ips = arp_table
            .keys()
            .filter_map(|ip| Ipv4Addr::from_str(ip).ok())
            .collect::<HashSet<Ipv4Addr>>();

        let discovered_via_arp = unreachable_targets
            .iter()
            .copied()
            .filter(|ip| arp_ips.contains(ip) && !discovered_ips.contains(ip))
            .collect::<Vec<Ipv4Addr>>();

        for ip in &discovered_via_arp {
            discovered_ips.insert(*ip);
        }

        for ip in discovered_via_arp {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let name = resolve_hostname_with_timeout(ip, Duration::from_millis(250)).await;
            let host = discovered_host(ip, name);
            on_host(host.clone());
            hosts.push(host);
        }

        if options.discovery_mode == DiscoveryMode::Hybrid {
            let icmp_candidates = unreachable_targets
                .into_iter()
                .filter(|ip| !discovered_ips.contains(ip))
                .collect::<Vec<Ipv4Addr>>();

            let icmp_timeout = Duration::from_millis(timeout_ms.clamp(200, 1200));
            let discovered_via_icmp =
                discover_hosts_via_icmp(icmp_candidates, icmp_timeout, cancel_flag.clone()).await;

            for ip in discovered_via_icmp {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }

                if !discovered_ips.insert(ip) {
                    continue;
                }

                let name = resolve_hostname_with_timeout(ip, Duration::from_millis(250)).await;
                let host = discovered_host(ip, name);
                on_host(host.clone());
                hosts.push(host);
            }
        }
    }

    hosts.sort_by(|a, b| {
        ipv4_to_u32(parse_ipv4_or_zero(&a.ip)).cmp(&ipv4_to_u32(parse_ipv4_or_zero(&b.ip)))
    });

    Ok(ScanResult {
        started_at,
        completed_at: Some(Utc::now().to_rfc3339()),
        cancelled,
        hosts,
        options,
    })
}

pub async fn scan_single_host(ip: String, profile: PortProfile, timeout_ms: u64) -> Result<Host> {
    let parsed_ip =
        Ipv4Addr::from_str(&ip).with_context(|| format!("Invalid IPv4 address '{}'", ip))?;
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let ports = Arc::new(ports_for_profile(&profile));
    let timeout_duration = Duration::from_millis(timeout_ms.clamp(50, 5000));
    let workers = available_workers();
    let port_concurrency = port_concurrency_for_profile(&profile, workers);
    let connection_semaphore = Arc::new(Semaphore::new(global_connection_limit_for_profile(
        &profile, workers,
    )));

    let (open_ports, reachable) = scan_open_ports(
        parsed_ip,
        ports,
        timeout_duration,
        port_concurrency,
        connection_semaphore,
        cancel_flag,
    )
    .await;
    let name = resolve_hostname_with_timeout(parsed_ip, Duration::from_millis(250)).await;

    Ok(Host {
        ip,
        name,
        reachable,
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
        fingerprint: None,
    })
}

fn discovered_host(ip: Ipv4Addr, name: Option<String>) -> Host {
    Host {
        ip: ip.to_string(),
        name,
        reachable: true,
        open_ports: Vec::new(),
        last_seen: Utc::now().to_rfc3339(),
        fingerprint: None,
    }
}

async fn discover_hosts_via_icmp(
    targets: Vec<Ipv4Addr>,
    probe_timeout: Duration,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<Ipv4Addr> {
    if targets.is_empty() {
        return Vec::new();
    }

    let concurrency = available_workers().clamp(4, 24);
    let mut discovered = Vec::new();

    let mut stream = stream::iter(targets.into_iter().map(|ip| {
        let cancel_flag = cancel_flag.clone();
        async move {
            if cancel_flag.load(Ordering::Relaxed) {
                return None;
            }

            if ping_host(ip, probe_timeout).await {
                Some(ip)
            } else {
                None
            }
        }
    }))
    .buffer_unordered(concurrency);

    while let Some(result) = stream.next().await {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }

        if let Some(ip) = result {
            discovered.push(ip);
        }
    }

    discovered.sort_by_key(|ip| ipv4_to_u32(*ip));
    discovered
}

async fn ping_host(ip: Ipv4Addr, timeout_duration: Duration) -> bool {
    let ip_text = ip.to_string();
    let mut command = TokioCommand::new("ping");

    #[cfg(target_os = "windows")]
    {
        command
            .arg("-n")
            .arg("1")
            .arg("-w")
            .arg(timeout_duration.as_millis().to_string())
            .arg(&ip_text);
    }

    #[cfg(target_os = "macos")]
    {
        command
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(timeout_duration.as_millis().to_string())
            .arg(&ip_text);
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let seconds = timeout_duration.as_secs().clamp(1, 5);
        command
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(seconds.to_string())
            .arg(&ip_text);
    }

    command.kill_on_drop(true);

    match timeout(
        timeout_duration + Duration::from_millis(300),
        command.status(),
    )
    .await
    {
        Ok(Ok(status)) => status.success(),
        Ok(Err(error)) => {
            log::debug!("icmp probe failed for {}: {}", ip, error);
            false
        }
        Err(_) => false,
    }
}

async fn scan_host_internal(
    ip: Ipv4Addr,
    ports: Arc<Vec<u16>>,
    timeout_duration: Duration,
    port_concurrency: usize,
    connection_semaphore: Arc<Semaphore>,
    cancel_flag: Arc<AtomicBool>,
) -> Option<Host> {
    let (open_ports, reachable) = scan_open_ports(
        ip,
        ports,
        timeout_duration,
        port_concurrency,
        connection_semaphore,
        cancel_flag.clone(),
    )
    .await;
    if !reachable {
        return None;
    }

    if cancel_flag.load(Ordering::Relaxed) {
        return None;
    }

    let name = resolve_hostname_with_timeout(ip, Duration::from_millis(250)).await;

    Some(Host {
        ip: ip.to_string(),
        name,
        reachable,
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
        fingerprint: None,
    })
}

async fn scan_open_ports(
    ip: Ipv4Addr,
    ports: Arc<Vec<u16>>,
    timeout_duration: Duration,
    port_concurrency: usize,
    connection_semaphore: Arc<Semaphore>,
    cancel_flag: Arc<AtomicBool>,
) -> (Vec<PortInfo>, bool) {
    let concurrency = port_concurrency.clamp(1, 1024).min(ports.len().max(1));

    let mut stream = stream::iter(ports.iter().copied().map(|port| {
        let cancel_flag = cancel_flag.clone();
        let connection_semaphore = connection_semaphore.clone();
        async move {
            if cancel_flag.load(Ordering::Relaxed) {
                return None;
            }

            scan_port(ip, port, timeout_duration, connection_semaphore).await
        }
    }))
    .buffer_unordered(concurrency);

    let mut open_ports = Vec::new();
    let mut reachable = false;

    while let Some(port) = stream.next().await {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }

        match port {
            Some(PortProbeOutcome::Open(port)) => {
                reachable = true;
                open_ports.push(port);
            }
            Some(PortProbeOutcome::Reachable) => {
                reachable = true;
            }
            None => {}
        }
    }

    open_ports.sort_by_key(|item| item.port);
    (open_ports, reachable)
}

async fn scan_port(
    ip: Ipv4Addr,
    port: u16,
    timeout_duration: Duration,
    connection_semaphore: Arc<Semaphore>,
) -> Option<PortProbeOutcome> {
    const MAX_CONNECT_ATTEMPTS: usize = 2;

    let socket = SocketAddr::new(IpAddr::V4(ip), port);
    let _permit = connection_semaphore.acquire_owned().await.ok()?;

    for attempt in 1..=MAX_CONNECT_ATTEMPTS {
        match timeout(timeout_duration, TcpStream::connect(socket)).await {
            Ok(Ok(mut stream)) => {
                if let Err(error) = stream.shutdown().await {
                    log::debug!(
                        "graceful TCP shutdown failed for {}:{}: {}",
                        ip,
                        port,
                        error
                    );
                }

                return Some(PortProbeOutcome::Open(PortInfo {
                    port,
                    state: "open".to_string(),
                    service: service_name(port).map(ToString::to_string),
                }));
            }
            Ok(Err(error)) if is_reachable_error(&error) => {
                return Some(PortProbeOutcome::Reachable);
            }
            Ok(Err(error))
                if is_transient_probe_error(&error) && attempt < MAX_CONNECT_ATTEMPTS =>
            {
                log::warn!(
                    "transient TCP probe error for {}:{} on attempt {}/{}: {}; retrying",
                    ip,
                    port,
                    attempt,
                    MAX_CONNECT_ATTEMPTS,
                    error
                );
                sleep(Duration::from_millis(20)).await;
            }
            Ok(Err(error)) => {
                if is_transient_probe_error(&error) {
                    log::warn!(
                        "transient TCP probe error for {}:{} after {} attempts: {}",
                        ip,
                        port,
                        MAX_CONNECT_ATTEMPTS,
                        error
                    );
                } else {
                    log::debug!(
                        "unexpected TCP probe error for {}:{} kind={:?} os={:?} message={}",
                        ip,
                        port,
                        error.kind(),
                        error.raw_os_error(),
                        error
                    );
                }
                return None;
            }
            Err(_) => return None,
        }
    }

    None
}

async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    tauri::async_runtime::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok())
        .await
        .ok()
        .flatten()
        .map(|name| name.trim_end_matches('.').to_string())
        .filter(|name| !name.is_empty())
}

async fn resolve_hostname_with_timeout(ip: Ipv4Addr, max_wait: Duration) -> Option<String> {
    timeout(max_wait, resolve_hostname(ip)).await.ok().flatten()
}

type SharedVendorCache = Arc<Mutex<HashMap<String, String>>>;

fn enrichment_concurrency() -> usize {
    available_workers().clamp(2, 12)
}

async fn snapshot_pending_vendors(
    pending_vendor_cache: &SharedVendorCache,
) -> Vec<(String, String)> {
    let cache = pending_vendor_cache.lock().await;
    cache
        .iter()
        .map(|(oui, vendor)| (oui.clone(), vendor.clone()))
        .collect()
}

pub async fn enrich_hosts_with_cache(hosts: Vec<Host>, storage: Arc<Storage>) -> Vec<Host> {
    let arp_table = Arc::new(read_arp_table().await);
    let pending_vendor_cache: SharedVendorCache = Arc::new(Mutex::new(HashMap::new()));
    let concurrency = enrichment_concurrency().min(hosts.len().max(1));

    let mut indexed_hosts = Vec::with_capacity(hosts.len());
    let mut new_fingerprints = Vec::new();

    let mut stream = stream::iter(hosts.into_iter().enumerate().map(|(index, host)| {
        let storage = storage.clone();
        let arp_table = arp_table.clone();
        let pending_vendor_cache = pending_vendor_cache.clone();
        async move {
            let mac = arp_table.get(&host.ip).cloned();
            let (enriched_host, cache_entry) =
                enrich_host_internal(host, mac, &storage, pending_vendor_cache).await;
            (index, enriched_host, cache_entry)
        }
    }))
    .buffer_unordered(concurrency);

    while let Some((index, enriched_host, cache_entry)) = stream.next().await {
        indexed_hosts.push((index, enriched_host));

        if let Some(entry) = cache_entry {
            new_fingerprints.push(entry);
        }
    }

    indexed_hosts.sort_by_key(|(index, _)| *index);
    let enriched_hosts = indexed_hosts
        .into_iter()
        .map(|(_, host)| host)
        .collect::<Vec<Host>>();

    let new_vendors = snapshot_pending_vendors(&pending_vendor_cache).await;

    if let Err(error) = storage.cache_vendors(new_vendors) {
        log::warn!("Failed to persist OUI vendor cache: {}", error);
    }

    if let Err(error) = storage.cache_fingerprints(new_fingerprints) {
        log::warn!("Failed to persist fingerprint cache: {}", error);
    }

    enriched_hosts
}

pub async fn enrich_host_with_cache(host: Host, storage: Arc<Storage>) -> Host {
    let arp_table = read_arp_table().await;
    let mac = arp_table.get(&host.ip).cloned();
    let pending_vendor_cache: SharedVendorCache = Arc::new(Mutex::new(HashMap::new()));

    let (enriched_host, cache_entry) =
        enrich_host_internal(host, mac, &storage, pending_vendor_cache.clone()).await;

    if let Some((key, fingerprint)) = cache_entry {
        if let Err(error) = storage.cache_fingerprints(vec![(key, fingerprint)]) {
            log::warn!("Failed to persist fingerprint cache: {}", error);
        }
    }

    let new_vendors = snapshot_pending_vendors(&pending_vendor_cache).await;

    if let Err(error) = storage.cache_vendors(new_vendors) {
        log::warn!("Failed to persist OUI vendor cache: {}", error);
    }

    enriched_host
}

async fn enrich_host_internal(
    mut host: Host,
    mac_from_arp: Option<String>,
    storage: &Arc<Storage>,
    pending_vendor_cache: SharedVendorCache,
) -> (Host, Option<(String, DeviceFingerprint)>) {
    let mac_address = mac_from_arp.or_else(|| {
        host.fingerprint
            .as_ref()
            .and_then(|item| item.mac_address.clone())
    });

    let primary_key = fingerprint_cache_key(mac_address.as_deref(), &host.ip);
    if let Ok(Some(mut cached)) = storage.get_cached_fingerprint(&primary_key) {
        if cached.mac_address.is_none() {
            cached.mac_address = mac_address;
        }
        host.fingerprint = Some(cached);
        return (host, None);
    }

    let fallback_key = if primary_key.starts_with("mac:") {
        Some(format!("ip:{}", host.ip))
    } else {
        None
    };

    if let Some(ref key) = fallback_key {
        if let Ok(Some(mut cached)) = storage.get_cached_fingerprint(key) {
            if cached.mac_address.is_none() {
                cached.mac_address = mac_address.clone();
            }
            host.fingerprint = Some(cached.clone());
            return (host, Some((primary_key, cached)));
        }
    }

    let fingerprint = build_fingerprint(&host, mac_address, storage, pending_vendor_cache).await;
    host.fingerprint = Some(fingerprint.clone());

    (host, Some((primary_key, fingerprint)))
}

async fn build_fingerprint(
    host: &Host,
    mac_address: Option<String>,
    storage: &Arc<Storage>,
    pending_vendor_cache: SharedVendorCache,
) -> DeviceFingerprint {
    let mut sources = Vec::new();
    let mut notes = Vec::new();

    if mac_address.is_some() {
        sources.push("arp-table".to_string());
    }

    let oui = mac_address.as_deref().and_then(oui_from_mac);

    let mut vendor = None;
    if let Some(ref oui_value) = oui {
        if let Some(cached_vendor) = {
            let cache = pending_vendor_cache.lock().await;
            cache.get(oui_value).cloned()
        } {
            vendor = Some(cached_vendor.clone());
            sources.push("oui-cache".to_string());
        }

        if vendor.is_none() {
            if let Ok(cached_vendor) = storage.get_cached_vendor(oui_value) {
                if let Some(value) = cached_vendor {
                    vendor = Some(value);
                    sources.push("oui-cache".to_string());
                }
            }
        }

        if vendor.is_none() {
            if let Some(mac) = mac_address.as_deref() {
                if let Some(local_vendor) = local_oui_vendor(mac) {
                    {
                        let mut cache = pending_vendor_cache.lock().await;
                        cache.insert(oui_value.clone(), local_vendor.clone());
                    }
                    vendor = Some(local_vendor);
                    sources.push("oui-local".to_string());
                }
            }
        }
    }

    if vendor.is_none() {
        if let Some(ref mac) = mac_address {
            if let Some(lookup_vendor) = lookup_vendor_via_maclookup(mac).await {
                if let Some(ref oui_value) = oui {
                    let mut cache = pending_vendor_cache.lock().await;
                    cache.insert(oui_value.clone(), lookup_vendor.clone());
                }
                vendor = Some(lookup_vendor);
                sources.push("maclookup-app".to_string());
            }
        }
    }

    let mut manufacturer = vendor.clone();
    let mut model_guess = None;
    let mut device_type = None;
    let mut os_guess = None;
    let mut confidence = 10u8;

    if let Some(mac) = mac_address.as_deref() {
        if let Some(fingerbank) = lookup_fingerbank(mac, host.name.as_deref()).await {
            sources.push("fingerbank".to_string());

            if manufacturer.is_none() {
                manufacturer = fingerbank.manufacturer.clone();
            }
            if vendor.is_none() {
                vendor = fingerbank.vendor.clone().or_else(|| manufacturer.clone());
            }

            model_guess = fingerbank.model.or(model_guess);
            device_type = fingerbank.device_type.or(device_type);
            os_guess = fingerbank.os_guess.or(os_guess);

            if let Some(score) = fingerbank.confidence {
                confidence = confidence.max(score);
            } else {
                confidence = confidence.max(75);
            }
        }
    }

    let (heuristic_type, heuristic_os, heuristic_model, heuristic_notes, heuristic_boost) =
        infer_device_profile(host, vendor.as_deref(), manufacturer.as_deref());

    if device_type.is_none() {
        device_type = heuristic_type;
    }
    if os_guess.is_none() {
        os_guess = heuristic_os;
    }
    if model_guess.is_none() {
        model_guess = heuristic_model;
    }

    notes.extend(heuristic_notes);

    if mac_address.is_some() {
        confidence = confidence.saturating_add(20);
    }
    if vendor.is_some() {
        confidence = confidence.saturating_add(15);
    }
    if host.name.is_some() {
        confidence = confidence.saturating_add(8);
        if let Some(name) = host.name.as_ref() {
            notes.push(format!("reverse DNS/mDNS name: {}", name));
            sources.push("reverse-dns".to_string());
        }
    }

    confidence = confidence.saturating_add(heuristic_boost);
    confidence = confidence.clamp(5, 99);

    if !host.open_ports.is_empty() {
        let preview = host
            .open_ports
            .iter()
            .take(6)
            .map(|port| {
                if let Some(service) = &port.service {
                    format!("{}:{}", port.port, service)
                } else {
                    port.port.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join(", ");
        notes.push(format!("open services: {}", preview));
    }

    dedup_strings(&mut sources);
    dedup_strings(&mut notes);

    DeviceFingerprint {
        mac_address,
        oui,
        vendor,
        manufacturer,
        model_guess,
        device_type,
        os_guess,
        confidence,
        sources,
        notes,
        last_updated: Utc::now().to_rfc3339(),
    }
}

struct FingerbankFingerprint {
    vendor: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    device_type: Option<String>,
    os_guess: Option<String>,
    confidence: Option<u8>,
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|item| seen.insert(item.to_ascii_lowercase()));
}

fn fingerprint_cache_key(mac: Option<&str>, ip: &str) -> String {
    if let Some(value) = mac {
        format!("mac:{}", value)
    } else {
        format!("ip:{}", ip)
    }
}

fn oui_from_mac(mac: &str) -> Option<String> {
    let normalized = normalize_mac(mac)?;
    let segments: Vec<&str> = normalized.split(':').collect();
    if segments.len() == 6 {
        Some(format!("{}:{}:{}", segments[0], segments[1], segments[2]))
    } else {
        None
    }
}

fn normalize_mac(mac: &str) -> Option<String> {
    let compact = mac.trim().replace('-', ":").to_ascii_uppercase();
    let parts: Vec<&str> = compact.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut normalized_parts = Vec::new();
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }

        if part.len() == 1 {
            normalized_parts.push(format!("0{}", part));
        } else {
            normalized_parts.push(part.to_string());
        }
    }

    Some(normalized_parts.join(":"))
}

fn extract_ipv4_from_arp_line(line: &str) -> Option<Ipv4Addr> {
    line.split_whitespace().find_map(|token| {
        let candidate = token.trim_matches(|ch: char| !(ch.is_ascii_digit() || ch == '.'));
        if candidate.is_empty() {
            return None;
        }

        Ipv4Addr::from_str(candidate).ok()
    })
}

fn extract_mac_from_arp_line(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|token| {
        if token.to_ascii_lowercase().contains("incomplete") {
            return None;
        }

        let candidate =
            token.trim_matches(|ch: char| !(ch.is_ascii_hexdigit() || ch == ':' || ch == '-'));
        if candidate.is_empty() {
            return None;
        }

        normalize_mac(candidate)
    })
}

async fn read_arp_table() -> HashMap<String, String> {
    tokio::task::spawn_blocking(move || {
        let mut table = HashMap::new();

        #[cfg(target_os = "windows")]
        let output = StdCommand::new("arp").arg("-a").output();

        #[cfg(not(target_os = "windows"))]
        let output = StdCommand::new("arp").arg("-an").output();

        let Ok(output) = output else {
            return table;
        };

        if !output.status.success() {
            return table;
        }

        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            let Some(ip) = extract_ipv4_from_arp_line(line) else {
                continue;
            };

            if ip.is_unspecified() {
                continue;
            }

            let Some(mac) = extract_mac_from_arp_line(line) else {
                continue;
            };

            table.insert(ip.to_string(), mac);
        }

        table
    })
    .await
    .unwrap_or_default()
}

fn local_oui_database() -> &'static OuiDb {
    static DB: OnceLock<OuiDb> = OnceLock::new();
    DB.get_or_init(OuiDb::bundled)
}

fn local_oui_vendor(mac: &str) -> Option<String> {
    let normalized_mac = normalize_mac(mac)?;
    let entry = local_oui_database().lookup(&normalized_mac)?;

    first_non_empty(vec![
        entry.vendor_detail.clone(),
        Some(entry.vendor.clone()),
    ])
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .user_agent("lantenna/0.1")
            .build()
            .expect("failed to build HTTP client")
    })
}

async fn lookup_vendor_via_maclookup(mac: &str) -> Option<String> {
    let url = format!("https://api.maclookup.app/v2/macs/{}", mac);
    let response = http_client()
        .get(url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let value: Value = response.json().await.ok()?;

    first_non_empty(vec![
        string_at_path(&value, &["company"]),
        string_at_path(&value, &["vendor"]),
        string_at_path(&value, &["organization"]),
        string_at_path(&value, &["vendorDetails", "companyName"]),
        string_at_path(&value, &["vendorDetails", "company"]),
        string_at_path(&value, &["vendorDetails", "organizationName"]),
        string_at_path(&value, &["blockDetails", "organizationName"]),
    ])
}

async fn lookup_fingerbank(mac: &str, hostname: Option<&str>) -> Option<FingerbankFingerprint> {
    let api_key = std::env::var("FINGERBANK_API_KEY").ok()?;

    let mut request = http_client()
        .get("https://api.fingerbank.org/api/v2/combinations/interrogate")
        .query(&[("key", api_key.as_str()), ("mac", mac)]);

    if let Some(hostname) = hostname {
        request = request.query(&[("hostname", hostname)]);
    }

    let response = request
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let value: Value = response.json().await.ok()?;

    let confidence = number_at_paths(
        &value,
        vec![
            vec!["score"],
            vec!["confidence"],
            vec!["device", "score"],
            vec!["device", "confidence"],
        ],
    )
    .map(|score| score.clamp(0.0, 100.0).round() as u8);

    let vendor = first_non_empty(vec![
        string_at_path(&value, &["device", "manufacturer", "name"]),
        string_at_path(&value, &["manufacturer", "name"]),
        string_at_path(&value, &["manufacturer"]),
        string_at_path(&value, &["vendor"]),
    ]);

    let model = first_non_empty(vec![
        string_at_path(&value, &["device", "name"]),
        string_at_path(&value, &["device", "model"]),
        string_at_path(&value, &["device", "version"]),
    ]);

    let os_guess = first_non_empty(vec![
        string_at_path(&value, &["os", "name"]),
        string_at_path(&value, &["operating_system", "name"]),
        string_at_path(&value, &["device", "os_name"]),
    ]);

    let device_type = first_non_empty(vec![
        string_at_path(&value, &["device", "type_name"]),
        string_at_path(&value, &["device", "type"]),
        string_at_path(&value, &["device", "device_type"]),
    ]);

    Some(FingerbankFingerprint {
        vendor: vendor.clone(),
        manufacturer: vendor,
        model,
        device_type,
        os_guess,
        confidence,
    })
}

fn infer_device_profile(
    host: &Host,
    vendor_hint: Option<&str>,
    manufacturer_hint: Option<&str>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
    u8,
) {
    let ports = host
        .open_ports
        .iter()
        .map(|item| item.port)
        .collect::<HashSet<u16>>();
    let mut notes = Vec::new();
    let mut confidence_boost = 0u8;
    let mut inferred_type = None;
    let mut inferred_os = None;
    let mut inferred_model = None;

    let host_hints = normalize_hint_text(host.name.as_deref().unwrap_or_default());
    let vendor_hints = normalize_hint_text(vendor_hint.unwrap_or_default());
    let manufacturer_hints = normalize_hint_text(manufacturer_hint.unwrap_or_default());
    let hint_text = format!("{} {} {}", host_hints, vendor_hints, manufacturer_hints);

    let contains_hint = |needles: &[&str]| contains_any_hint(&hint_text, needles);

    let has = |port: u16| ports.contains(&port);
    let has_any = |group: &[u16]| group.iter().any(|port| ports.contains(port));

    if has_any(&[9100, 515, 631])
        || contains_hint(&[
            "printer",
            "laserjet",
            "deskjet",
            "officejet",
            "epson",
            "brother",
            "canon",
            "xerox",
        ])
    {
        set_if_none(&mut inferred_type, "Printer");
        confidence_boost = confidence_boost.saturating_add(24);
        notes.push("printer signature detected (IPP/LPD/JetDirect)".to_string());
    }

    if has_any(&[37777, 37778])
        || contains_hint(&[
            "dahua",
            "amcrest",
            "hikvision",
            "qsee",
            "surveillance",
            "nvr",
            "dvr",
        ])
    {
        set_if_none(&mut inferred_type, "Camera/NVR");
        set_if_none(&mut inferred_model, "Dahua/Amcrest-style DVR/NVR");
        confidence_boost = confidence_boost.saturating_add(24);
        notes.push("DVR/NVR signature detected (ports 37777/37778)".to_string());
    }

    if has_any(&[554, 8554])
        || contains_hint(&[
            "camera",
            "ipcam",
            "onvif",
            "webcam",
            "reolink",
            "axis",
            "hikvision",
            "dahua",
        ])
    {
        set_if_none(&mut inferred_type, "Camera");
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("RTSP/ONVIF profile suggests camera device".to_string());
    }

    if has_any(&[8291, 8728, 8729]) || contains_hint(&["mikrotik", "routeros", "winbox"]) {
        set_if_none(&mut inferred_type, "Network appliance");
        set_if_none(&mut inferred_model, "MikroTik RouterOS device");
        confidence_boost = confidence_boost.saturating_add(24);
        notes.push("MikroTik signature detected (Winbox/API ports)".to_string());
    }

    if has(32400) || contains_hint(&["plex media server", "plex"]) {
        set_if_none(&mut inferred_type, "Media server");
        set_if_none(&mut inferred_model, "Plex Media Server");
        confidence_boost = confidence_boost.saturating_add(20);
        notes.push("Plex signature detected (port 32400)".to_string());
    }

    if has(62078)
        || (contains_hint(&["iphone", "ipad", "ios", "apple watch"]) && has_any(&[5353, 62078]))
    {
        set_if_none(&mut inferred_type, "Mobile device");
        set_if_none(&mut inferred_os, "Apple iOS/iPadOS family");
        set_if_none(&mut inferred_model, "Apple mobile device");
        confidence_boost = confidence_boost.saturating_add(24);
        notes.push("Apple mobile sync signature detected (port 62078)".to_string());
    }

    if (has_any(&[5000, 5001]) && contains_hint(&["synology", "diskstation", "dsm", "nas"]))
        || (has_any(&[5000, 5001]) && has_any(&[445, 139]))
    {
        set_if_none(&mut inferred_type, "NAS/Storage");
        if contains_hint(&["synology", "diskstation", "dsm"]) {
            set_if_none(&mut inferred_model, "Synology NAS (DSM)");
        }
        confidence_boost = confidence_boost.saturating_add(18);
        notes.push("NAS management + file sharing signature detected".to_string());
    }

    if has_any(&[7000, 7001, 3689]) && has(5353) {
        set_if_none(&mut inferred_type, "Apple device");
        set_if_none(&mut inferred_os, "Apple OS family");
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("Bonjour/AirPlay-style Apple service profile detected".to_string());
    }

    if has_any(&[6443, 2375]) {
        set_if_none(&mut inferred_type, "Server/Container host");
        if has(6443) {
            set_if_none(&mut inferred_model, "Kubernetes-capable host");
        }
        confidence_boost = confidence_boost.saturating_add(12);
        notes.push("container/orchestration management ports detected".to_string());
    }

    if has_any(&[3306, 5432, 27017, 6379, 9200]) {
        set_if_none(&mut inferred_type, "Server/Database host");
        confidence_boost = confidence_boost.saturating_add(10);
        notes.push("database/search service ports detected".to_string());
    }

    if contains_hint(&["raspberrypi", "raspberry pi", "raspi", "rpi"]) {
        set_if_none(&mut inferred_type, "Single-board computer");
        set_if_none(&mut inferred_os, "Linux-like");
        set_if_none(&mut inferred_model, "Raspberry Pi");
        confidence_boost = confidence_boost.saturating_add(18);
        notes.push("hostname/vendor hints indicate Raspberry Pi".to_string());
    }

    if contains_hint(&[
        "fritzbox",
        "openwrt",
        "dd wrt",
        "router",
        "gateway",
        "access point",
    ]) || (has_any(&[53, 67, 68, 1900]) && has_any(&[80, 443, 8080, 8443, 5000, 5001]))
    {
        set_if_none(&mut inferred_type, "Network device");
        confidence_boost = confidence_boost.saturating_add(14);
        notes.push("gateway/router service profile detected".to_string());
    }

    if contains_hint(&[
        "vmware",
        "virtualbox",
        "hyper v",
        "qemu",
        "xen",
        "parallels",
    ]) {
        set_if_none(&mut inferred_type, "Virtual machine");
        confidence_boost = confidence_boost.saturating_add(14);
        notes.push("virtualization vendor signature detected".to_string());
    }

    if has_any(&[445, 139, 3389]) {
        set_if_none(&mut inferred_type, "Workstation/Server");
        set_if_none(&mut inferred_os, "Windows-like");
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("SMB/RDP ports suggest a Windows host".to_string());
    }

    if has_any(&[548, 5353, 62078]) {
        set_if_none(&mut inferred_type, "Apple device");
        set_if_none(&mut inferred_os, "Apple OS family");
        confidence_boost = confidence_boost.saturating_add(14);
        notes.push("AFP/mDNS/mobile sync ports suggest an Apple device".to_string());
    }

    if has(22) && !has_any(&[445, 139]) {
        set_if_none(&mut inferred_type, "Workstation/Server");
        set_if_none(&mut inferred_os, "Linux/Unix-like");
        confidence_boost = confidence_boost.saturating_add(12);
        notes.push("SSH-first profile suggests Linux/Unix".to_string());
    }

    if has_any(&[1883, 8883]) || contains_hint(&["esphome", "tasmota", "shelly", "zigbee", "zwave"])
    {
        set_if_none(&mut inferred_type, "IoT device");
        confidence_boost = confidence_boost.saturating_add(12);
        notes.push("IoT/messaging profile detected (MQTT or IoT naming)".to_string());
    }

    (
        inferred_type,
        inferred_os,
        inferred_model,
        notes,
        confidence_boost,
    )
}

fn set_if_none(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_string());
    }
}

fn normalize_hint_text(value: &str) -> String {
    let lowered = value
        .to_lowercase()
        .replace('-', " ")
        .replace('_', " ")
        .replace('.', " ");

    lowered
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == ' ' {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn contains_any_hint(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn first_non_empty(values: Vec<Option<String>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .map(|item| item.trim().to_string())
        .find(|item| !item.is_empty())
}

fn string_at_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }

    current.as_str().map(ToString::to_string)
}

fn number_at_paths(value: &Value, paths: Vec<Vec<&str>>) -> Option<f64> {
    for path in paths {
        let mut current = value;
        let mut found = true;

        for segment in path {
            if let Some(next) = current.get(segment) {
                current = next;
            } else {
                found = false;
                break;
            }
        }

        if !found {
            continue;
        }

        if let Some(score) = current.as_f64() {
            return Some(score);
        }

        if let Some(score) = current.as_u64() {
            return Some(score as f64);
        }
    }

    None
}

fn append_signature_ports(mut ports: Vec<u16>, extras: &[u16]) -> Vec<u16> {
    for port in extras {
        if !ports.contains(port) {
            ports.push(*port);
        }
    }

    ports.sort_unstable();
    ports
}

fn ports_for_profile(profile: &PortProfile) -> Vec<u16> {
    match profile {
        PortProfile::Quick => append_signature_ports(
            vec![
                20, 21, 22, 23, 53, 80, 110, 139, 143, 443, 445, 515, 548, 631, 135, 3389, 5000,
                5353, 5900, 8000, 8080, 8443,
            ],
            &[554, 5001, 62078, 32400],
        ),
        PortProfile::Standard => append_signature_ports(
            vec![
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
                143, 161, 389, 443, 445, 465, 500, 514, 515, 548, 587, 631, 636, 873, 993, 995,
                1080, 1194, 1433, 1521, 1723, 1812, 1900, 2049, 2375, 3000, 3306, 3389, 5000, 5060,
                5353, 5432, 5672, 5900, 6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090,
                9200, 27017,
            ],
            &[554, 5001, 62078, 32400, 8291, 8728, 8729, 37777, 37778],
        ),
        PortProfile::Deep => append_signature_ports(
            (1..=2048).collect(),
            &[5000, 5001, 62078, 32400, 8291, 8728, 8729, 37777, 37778],
        ),
    }
}

fn service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 | 68 => Some("dhcp"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        161 => Some("snmp"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        500 => Some("isakmp"),
        515 => Some("printer"),
        548 => Some("afp"),
        554 => Some("rtsp"),
        587 => Some("smtp-submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        1900 => Some("upnp"),
        2049 => Some("nfs"),
        2375 => Some("docker"),
        3000 => Some("dev-http"),
        32400 => Some("plex"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        37777 => Some("dvr-command"),
        37778 => Some("dvr-media"),
        5000 => Some("upnp/http"),
        5001 => Some("management-https"),
        5060 => Some("sip"),
        5353 => Some("mdns"),
        5432 => Some("postgres"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        62078 => Some("iphone-sync"),
        6379 => Some("redis"),
        6443 => Some("k8s-api"),
        7001 => Some("weblogic"),
        8000 => Some("http-alt"),
        8080 => Some("http-proxy"),
        8291 => Some("mikrotik-winbox"),
        8728 => Some("mikrotik-api"),
        8729 => Some("mikrotik-api-ssl"),
        8443 => Some("https-alt"),
        8554 => Some("rtsp-alt"),
        9000 => Some("app"),
        9090 => Some("metrics"),
        9200 => Some("elasticsearch"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    ipv4_to_u32(mask).count_ones() as u8
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn parse_ipv4_or_zero(value: &str) -> Ipv4Addr {
    Ipv4Addr::from_str(value).unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, subnet: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            ip: ip.to_string(),
            cidr: 24,
            subnet: subnet.to_string(),
            host_count: 254,
        }
    }

    fn host(ip: &str, name: Option<&str>, ports: &[u16]) -> Host {
        Host {
            ip: ip.to_string(),
            name: name.map(|value| value.to_string()),
            reachable: true,
            open_ports: ports
                .iter()
                .map(|port| PortInfo {
                    port: *port,
                    state: "open".to_string(),
                    service: service_name(*port).map(|value| value.to_string()),
                })
                .collect(),
            last_seen: Utc::now().to_rfc3339(),
            fingerprint: None,
        }
    }

    #[test]
    fn build_scan_targets_excludes_local_address() {
        let network = Ipv4Net::from_str("192.168.10.0/29").expect("valid CIDR");
        let local_ip = Some(Ipv4Addr::new(192, 168, 10, 3));

        let targets = build_scan_targets(network, local_ip, 16);

        assert_eq!(targets.len(), 5);
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 10, 3)));
        assert_eq!(
            targets.first().copied(),
            Some(Ipv4Addr::new(192, 168, 10, 1))
        );
        assert_eq!(
            targets.last().copied(),
            Some(Ipv4Addr::new(192, 168, 10, 6))
        );
    }

    #[test]
    fn build_scan_targets_respects_max_hosts() {
        let network = Ipv4Net::from_str("10.0.0.0/24").expect("valid CIDR");

        let targets = build_scan_targets(network, None, 10);

        assert_eq!(targets.len(), 10);
        assert!(targets.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn select_interface_prefers_exact_subnet_match() {
        let interfaces = vec![
            iface("en0", "192.168.1.5", "192.168.1.0/24"),
            iface("en0", "10.0.0.8", "10.0.0.0/24"),
            iface("en1", "172.16.0.2", "172.16.0.0/24"),
        ];

        let selected =
            select_interface(&interfaces, "en0", Some("10.0.0.0/24")).expect("interface exists");

        assert_eq!(selected.ip, "10.0.0.8");
    }

    #[test]
    fn normalize_mac_accepts_short_segments() {
        let normalized = normalize_mac("a:b:c:d:e:f");
        assert_eq!(normalized.as_deref(), Some("0A:0B:0C:0D:0E:0F"));
    }

    #[test]
    fn extract_mac_ignores_incomplete_arp_lines() {
        let line = "? (192.168.1.10) at (incomplete) on en0 ifscope [ethernet]";
        assert_eq!(extract_mac_from_arp_line(line), None);
    }

    #[test]
    fn profile_ports_include_high_signal_fingerprinting_targets() {
        let quick_ports = ports_for_profile(&PortProfile::Quick);
        let standard_ports = ports_for_profile(&PortProfile::Standard);
        let deep_ports = ports_for_profile(&PortProfile::Deep);

        assert!(quick_ports.contains(&62078));
        assert!(quick_ports.contains(&32400));

        assert!(standard_ports.contains(&8291));
        assert!(standard_ports.contains(&37777));

        assert!(deep_ports.contains(&5000));
        assert!(deep_ports.contains(&32400));
        assert!(deep_ports.contains(&37777));
    }

    #[test]
    fn infer_device_profile_identifies_mikrotik_signature() {
        let sample = host("192.168.88.1", Some("routeros-gateway"), &[8291, 8728]);

        let (device_type, os_guess, model_guess, _notes, boost) =
            infer_device_profile(&sample, Some("MikroTik"), None);

        assert_eq!(device_type.as_deref(), Some("Network appliance"));
        assert_eq!(model_guess.as_deref(), Some("MikroTik RouterOS device"));
        assert!(os_guess.is_none());
        assert!(boost >= 20);
    }

    #[test]
    fn infer_device_profile_identifies_apple_mobile_signature() {
        let sample = host("192.168.1.25", Some("iPhone"), &[62078, 5353]);

        let (device_type, os_guess, model_guess, _notes, boost) =
            infer_device_profile(&sample, Some("Apple"), None);

        assert_eq!(device_type.as_deref(), Some("Mobile device"));
        assert_eq!(os_guess.as_deref(), Some("Apple iOS/iPadOS family"));
        assert_eq!(model_guess.as_deref(), Some("Apple mobile device"));
        assert!(boost >= 20);
    }
}

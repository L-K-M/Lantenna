use crate::models::{
    DeviceFingerprint, Host, NetworkInterface, PortInfo, PortProfile, ScanOptions, ScanProgress,
    ScanResult,
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
use std::process::Command;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

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
        if let Some(exact_match) = name_matches.iter().copied().find(|iface| iface.subnet == subnet)
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
        a.name
            .cmp(&b.name)
            .then_with(|| ipv4_to_u32(parse_ipv4_or_zero(&a.ip)).cmp(&ipv4_to_u32(parse_ipv4_or_zero(&b.ip))))
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
    let selected = select_interface(&interfaces, &options.interface_name, options.subnet.as_deref())?;

    let subnet = options.subnet.clone().unwrap_or_else(|| selected.subnet.clone());
    options.subnet = Some(subnet.clone());

    let network = Ipv4Net::from_str(&subnet)
        .with_context(|| format!("Invalid subnet '{}'", subnet))?;
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
    let global_connection_limit = global_connection_limit_for_profile(&options.port_profile, workers);
    let connection_semaphore = Arc::new(Semaphore::new(global_connection_limit));

    log::info!(
        "scan config: profile={:?} workers={} hosts={} ports={} max_connections={} timeout_ms={}",
        options.port_profile,
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
        let arp_table = read_arp_table().await;
        let arp_ips = arp_table
            .keys()
            .filter_map(|ip| Ipv4Addr::from_str(ip).ok())
            .collect::<HashSet<Ipv4Addr>>();

        let discovered_via_arp = unreachable_targets
            .into_iter()
            .filter(|ip| arp_ips.contains(ip))
            .collect::<Vec<Ipv4Addr>>();

        for ip in discovered_via_arp {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let name = resolve_hostname_with_timeout(ip, Duration::from_millis(250)).await;
            let host = Host {
                ip: ip.to_string(),
                name,
                reachable: true,
                open_ports: Vec::new(),
                last_seen: Utc::now().to_rfc3339(),
                fingerprint: None,
            };

            found += 1;
            on_host(host.clone());
            hosts.push(host);
        }
    }

    hosts.sort_by(|a, b| ipv4_to_u32(parse_ipv4_or_zero(&a.ip)).cmp(&ipv4_to_u32(parse_ipv4_or_zero(&b.ip))));

    on_progress(ScanProgress {
        scanned,
        total,
        found,
        running: false,
        current_ip: None,
    });

    Ok(ScanResult {
        started_at,
        completed_at: Some(Utc::now().to_rfc3339()),
        hosts,
        options,
    })
}

pub async fn scan_single_host(ip: String, profile: PortProfile, timeout_ms: u64) -> Result<Host> {
    let parsed_ip = Ipv4Addr::from_str(&ip)
        .with_context(|| format!("Invalid IPv4 address '{}'", ip))?;
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let ports = Arc::new(ports_for_profile(&profile));
    let timeout_duration = Duration::from_millis(timeout_ms.clamp(50, 5000));
    let workers = available_workers();
    let port_concurrency = port_concurrency_for_profile(&profile, workers);
    let connection_semaphore = Arc::new(Semaphore::new(global_connection_limit_for_profile(&profile, workers)));

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
        cancel_flag,
    )
    .await;
    if !reachable {
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
    let socket = SocketAddr::new(IpAddr::V4(ip), port);
    let _permit = connection_semaphore.acquire_owned().await.ok()?;

    match timeout(timeout_duration, TcpStream::connect(socket)).await {
        Ok(Ok(_)) => Some(PortProbeOutcome::Open(PortInfo {
            port,
            state: "open".to_string(),
            service: service_name(port).map(ToString::to_string),
        })),
        Ok(Err(error)) if is_reachable_error(&error) => Some(PortProbeOutcome::Reachable),
        _ => None,
    }
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

pub async fn enrich_hosts_with_cache(hosts: Vec<Host>, storage: Arc<Storage>) -> Vec<Host> {
    let arp_table = read_arp_table().await;
    let mut enriched_hosts = Vec::with_capacity(hosts.len());
    let mut new_fingerprints = Vec::new();
    let mut new_vendors: HashMap<String, String> = HashMap::new();

    for host in hosts {
        let mac = arp_table.get(&host.ip).cloned();
        let (enriched_host, cache_entry) =
            enrich_host_internal(host, mac, &storage, &mut new_vendors).await;

        if let Some(entry) = cache_entry {
            new_fingerprints.push(entry);
        }

        enriched_hosts.push(enriched_host);
    }

    if let Err(error) = storage.cache_vendors(new_vendors.into_iter().collect()) {
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
    let mut new_vendors = HashMap::new();

    let (enriched_host, cache_entry) =
        enrich_host_internal(host, mac, &storage, &mut new_vendors).await;

    if let Some((key, fingerprint)) = cache_entry {
        if let Err(error) = storage.cache_fingerprints(vec![(key, fingerprint)]) {
            log::warn!("Failed to persist fingerprint cache: {}", error);
        }
    }

    if let Err(error) = storage.cache_vendors(new_vendors.into_iter().collect()) {
        log::warn!("Failed to persist OUI vendor cache: {}", error);
    }

    enriched_host
}

async fn enrich_host_internal(
    mut host: Host,
    mac_from_arp: Option<String>,
    storage: &Arc<Storage>,
    pending_vendor_cache: &mut HashMap<String, String>,
) -> (Host, Option<(String, DeviceFingerprint)>) {
    let mac_address = mac_from_arp
        .or_else(|| host.fingerprint.as_ref().and_then(|item| item.mac_address.clone()));

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
    pending_vendor_cache: &mut HashMap<String, String>,
) -> DeviceFingerprint {
    let mut sources = Vec::new();
    let mut notes = Vec::new();

    if mac_address.is_some() {
        sources.push("arp-table".to_string());
    }

    let oui = mac_address.as_deref().and_then(oui_from_mac);

    let mut vendor = None;
    if let Some(ref oui_value) = oui {
        if let Some(cached_vendor) = pending_vendor_cache.get(oui_value) {
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
                    pending_vendor_cache.insert(oui_value.clone(), local_vendor.clone());
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
                    pending_vendor_cache.insert(oui_value.clone(), lookup_vendor.clone());
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
        infer_device_profile(host);

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
        let output = Command::new("arp").arg("-a").output();

        #[cfg(not(target_os = "windows"))]
        let output = Command::new("arp").arg("-an").output();

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

    first_non_empty(vec![entry.vendor_detail.clone(), Some(entry.vendor.clone())])
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

fn infer_device_profile(host: &Host) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
    u8,
) {
    let ports = host.open_ports.iter().map(|item| item.port).collect::<Vec<u16>>();
    let mut notes = Vec::new();
    let mut confidence_boost = 0u8;

    let contains = |port: u16| ports.contains(&port);

    if contains(9100) || contains(515) || contains(631) {
        confidence_boost = confidence_boost.saturating_add(18);
        notes.push("printer signature detected (IPP/LPD/JetDirect)".to_string());
        return (
            Some("Printer".to_string()),
            None,
            None,
            notes,
            confidence_boost,
        );
    }

    if contains(445) || contains(139) || contains(3389) {
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("SMB/RDP ports suggest a Windows host".to_string());
        return (
            Some("Workstation/Server".to_string()),
            Some("Windows-like".to_string()),
            None,
            notes,
            confidence_boost,
        );
    }

    if contains(548) || contains(5353) || contains(62078) {
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("AFP/mDNS ports suggest an Apple device".to_string());
        return (
            Some("Apple device".to_string()),
            Some("Apple OS family".to_string()),
            None,
            notes,
            confidence_boost,
        );
    }

    if contains(22) && !(contains(445) || contains(139)) {
        confidence_boost = confidence_boost.saturating_add(12);
        notes.push("SSH-first profile suggests Linux/Unix".to_string());
        return (
            Some("Workstation/Server".to_string()),
            Some("Linux/Unix-like".to_string()),
            None,
            notes,
            confidence_boost,
        );
    }

    if contains(1900) || contains(5000) || contains(8080) {
        confidence_boost = confidence_boost.saturating_add(10);
        notes.push("UPnP/HTTP-alt ports suggest IoT or media device".to_string());
        return (
            Some("IoT/Media device".to_string()),
            None,
            None,
            notes,
            confidence_boost,
        );
    }

    (None, None, None, notes, confidence_boost)
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

fn ports_for_profile(profile: &PortProfile) -> Vec<u16> {
    match profile {
        PortProfile::Quick => vec![
            20, 21, 22, 23, 53, 80, 110, 139, 143, 443, 445, 515, 548, 631, 135, 3389, 5000,
            5353, 5900, 8000, 8080, 8443,
        ],
        PortProfile::Standard => vec![
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
            143, 161, 389, 443, 445, 465, 500, 514, 515, 548, 587, 631, 636, 873, 993, 995, 1080,
            1194, 1433, 1521, 1723, 1812, 1900, 2049, 2375, 3000, 3306, 3389, 5000, 5060, 5353,
            5432, 5672, 5900, 6379, 6443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
            27017,
        ],
        PortProfile::Deep => (1..=2048).collect(),
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
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5000 => Some("upnp/http"),
        5060 => Some("sip"),
        5353 => Some("mdns"),
        5432 => Some("postgres"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        6443 => Some("k8s-api"),
        7001 => Some("weblogic"),
        8000 => Some("http-alt"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
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

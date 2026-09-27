use crate::models::{
    DeviceFingerprint, DiscoveryMode, FingerbankResult, Host, NetworkInterface, PortInfo,
    PortProfile, ScanOptions, ScanPhase, ScanProgress, ScanResult,
};
use crate::storage::Storage;
use anyhow::{Context, Result};
use chrono::Utc;
use futures::{stream, StreamExt};
use if_addrs::{get_if_addrs, IfAddr};
use ipnet::Ipv4Net;
use ndb_oui::OuiDb;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command as StdCommand;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command as TokioCommand;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout, Duration};

/// Ports probed on every target address to find live hosts. A host is live
/// when any of them answers, open or refused. On the local subnet each probe
/// also makes the kernel ARP for the address, so hosts that silently drop the
/// SYNs still turn up in the ARP table read right after the sweep.
const DISCOVERY_PORTS: [u16; 5] = [22, 80, 443, 445, 62078];

const HOSTNAME_LOOKUP_TIMEOUT: Duration = Duration::from_millis(250);
const HOSTNAME_LOOKUP_CONCURRENCY: usize = 16;

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
            is_default_route: false,
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

    let is_cancelled = || cancel_flag.load(Ordering::Relaxed);
    let mut throttle = ProgressThrottle::new(PROGRESS_EVENT_INTERVAL);
    let mut report_progress = |progress: ScanProgress| {
        if throttle.should_emit(&progress, Instant::now()) {
            on_progress(progress);
        }
    };

    // Live hosts keyed by numeric address, so results come out in address order.
    let mut hosts: BTreeMap<u32, Host> = BTreeMap::new();
    // Hosts that answered a discovery probe. The others were found through ARP
    // or ICMP and get the discovery ports probed again in the port phase.
    let mut answered = HashSet::new();

    // Phase 1: sweep every address with a few ports to find live hosts. Probing
    // the full profile here made each empty address cost one timeout per profile
    // port; now it costs one round of DISCOVERY_PORTS.
    let total = targets.len();
    let mut scanned = 0usize;
    let mut quiet_targets = Vec::new();
    let discovery_ports = Arc::new(DISCOVERY_PORTS.to_vec());
    let discovery_concurrency = (global_connection_limit / DISCOVERY_PORTS.len()).max(1) * 2;

    report_progress(scan_progress(ScanPhase::Discovery, 0, total, 0, true, None));

    let mut sweep = stream::iter(targets.into_iter().map(|ip| {
        let discovery_ports = discovery_ports.clone();
        let cancel_flag = cancel_flag.clone();
        let connection_semaphore = connection_semaphore.clone();
        async move {
            if cancel_flag.load(Ordering::Relaxed) {
                return (ip, None);
            }

            let (open_ports, reachable) = scan_open_ports(
                ip,
                discovery_ports,
                timeout_duration,
                DISCOVERY_PORTS.len(),
                connection_semaphore,
                cancel_flag,
                |_, _, _| {},
            )
            .await;
            if !reachable {
                return (ip, None);
            }

            let name = resolve_hostname_with_timeout(ip, HOSTNAME_LOOKUP_TIMEOUT).await;
            (ip, Some(discovered_host(ip, name, open_ports)))
        }
    }))
    .buffer_unordered(discovery_concurrency);

    while let Some((ip, maybe_host)) = sweep.next().await {
        scanned += 1;

        match maybe_host {
            Some(host) => {
                answered.insert(ip);
                on_host(host.clone());
                hosts.insert(ipv4_to_u32(ip), host);
            }
            None => quiet_targets.push(ip),
        }

        let cancelled = is_cancelled();
        report_progress(scan_progress(
            ScanPhase::Discovery,
            scanned,
            total,
            hosts.len(),
            !cancelled,
            Some(ip),
        ));

        if cancelled {
            break;
        }
    }
    drop(sweep);

    // Every probe above made the kernel ARP for its address, so on the local
    // subnet the ARP table now lists live hosts that ignored all the SYNs.
    // Read it right away: entries for hosts that never answered age out fast.
    if !is_cancelled() && !quiet_targets.is_empty() {
        let arp_ips = read_arp_table()
            .await
            .keys()
            .filter_map(|ip| Ipv4Addr::from_str(ip).ok())
            .collect::<HashSet<Ipv4Addr>>();

        let (seen_in_arp, still_quiet): (Vec<Ipv4Addr>, Vec<Ipv4Addr>) = quiet_targets
            .into_iter()
            .partition(|ip| arp_ips.contains(ip));
        quiet_targets = still_quiet;

        for host in hosts_with_names(seen_in_arp).await {
            on_host(host.clone());
            hosts.insert(ipv4_to_u32(parse_ipv4_or_zero(&host.ip)), host);
        }
    }

    if options.discovery_mode == DiscoveryMode::Hybrid
        && !is_cancelled()
        && !quiet_targets.is_empty()
    {
        let quiet_total = quiet_targets.len();
        let found_before_ping = hosts.len();
        let icmp_timeout = Duration::from_millis(timeout_ms.clamp(200, 1200));

        report_progress(scan_progress(
            ScanPhase::Ping,
            0,
            quiet_total,
            found_before_ping,
            true,
            None,
        ));

        let replies = discover_hosts_via_icmp(
            quiet_targets,
            icmp_timeout,
            cancel_flag.clone(),
            |checked, replied| {
                report_progress(scan_progress(
                    ScanPhase::Ping,
                    checked,
                    quiet_total,
                    found_before_ping + replied,
                    !is_cancelled(),
                    None,
                ));
            },
        )
        .await;

        for host in hosts_with_names(replies).await {
            on_host(host.clone());
            hosts.insert(ipv4_to_u32(parse_ipv4_or_zero(&host.ip)), host);
        }
    }

    // Phase 2: run the chosen profile against live hosts only.
    let live_total = hosts.len();
    if !is_cancelled() && live_total > 0 {
        let profile_ports = ports_for_profile(&options.port_profile);
        let unprobed_ports = Arc::new(
            profile_ports
                .iter()
                .copied()
                .filter(|port| !DISCOVERY_PORTS.contains(port))
                .collect::<Vec<u16>>(),
        );
        let all_profile_ports = Arc::new(profile_ports);
        let live_ips = hosts
            .keys()
            .map(|raw_ip| Ipv4Addr::from(*raw_ip))
            .collect::<Vec<Ipv4Addr>>();
        let mut probed = 0usize;

        report_progress(scan_progress(
            ScanPhase::Ports,
            0,
            live_total,
            live_total,
            true,
            None,
        ));

        let mut probes = stream::iter(live_ips.into_iter().map(|ip| {
            // Hosts found via ARP or ping did not answer the discovery ports
            // either; probe those again too, as a retry for devices that were
            // slow to wake from power saving during the sweep.
            let ports = if answered.contains(&ip) {
                unprobed_ports.clone()
            } else {
                all_profile_ports.clone()
            };
            let cancel_flag = cancel_flag.clone();
            let connection_semaphore = connection_semaphore.clone();
            async move {
                if cancel_flag.load(Ordering::Relaxed) {
                    return (ip, Vec::new());
                }

                let (open_ports, _) = scan_open_ports(
                    ip,
                    ports,
                    timeout_duration,
                    port_concurrency,
                    connection_semaphore,
                    cancel_flag,
                    |_, _, _| {},
                )
                .await;
                (ip, open_ports)
            }
        }))
        .buffer_unordered(host_concurrency);

        while let Some((ip, open_ports)) = probes.next().await {
            probed += 1;

            if let Some(host) = hosts.get_mut(&ipv4_to_u32(ip)) {
                if !open_ports.is_empty() {
                    merge_open_ports(&mut host.open_ports, open_ports);
                    host.last_seen = Utc::now().to_rfc3339();
                    on_host(host.clone());
                }
            }

            let cancelled = is_cancelled();
            report_progress(scan_progress(
                ScanPhase::Ports,
                probed,
                live_total,
                live_total,
                !cancelled,
                Some(ip),
            ));

            if cancelled {
                break;
            }
        }
    }

    let cancelled = is_cancelled();

    // Enrichment runs after this returns; tell the UI what it is waiting for.
    report_progress(scan_progress(
        ScanPhase::Fingerprint,
        0,
        hosts.len(),
        hosts.len(),
        !cancelled,
        None,
    ));

    Ok(ScanResult {
        started_at,
        completed_at: Some(Utc::now().to_rfc3339()),
        cancelled,
        hosts: hosts.into_values().collect(),
        options,
    })
}

fn scan_progress(
    phase: ScanPhase,
    scanned: usize,
    total: usize,
    found: usize,
    running: bool,
    current_ip: Option<Ipv4Addr>,
) -> ScanProgress {
    ScanProgress {
        phase,
        scanned,
        total,
        found,
        running,
        current_ip: current_ip.map(|ip| ip.to_string()),
    }
}

/// Minimum spacing between progress events within a phase. The UI redraws on
/// every event, and one event per address made large scans stutter.
const PROGRESS_EVENT_INTERVAL: Duration = Duration::from_millis(80);

/// Rate-limits progress events. The first and last event of each phase, and
/// any event of a stopped scan, always go through so the UI never shows a
/// stale phase or count.
struct ProgressThrottle {
    interval: Duration,
    last_emit: Option<Instant>,
    last_phase: Option<ScanPhase>,
}

impl ProgressThrottle {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_emit: None,
            last_phase: None,
        }
    }

    fn should_emit(&mut self, progress: &ScanProgress, now: Instant) -> bool {
        let phase_changed = self.last_phase != Some(progress.phase);
        let boundary =
            progress.scanned == 0 || progress.scanned >= progress.total || !progress.running;
        let due = self
            .last_emit
            .is_none_or(|last| now.duration_since(last) >= self.interval);

        if !(phase_changed || boundary || due) {
            return false;
        }

        self.last_emit = Some(now);
        self.last_phase = Some(progress.phase);
        true
    }
}

/// Adds newly found open ports to a host's list, keeping it sorted and free of
/// duplicates.
fn merge_open_ports(existing: &mut Vec<PortInfo>, found: Vec<PortInfo>) {
    for port in found {
        if !existing.iter().any(|known| known.port == port.port) {
            existing.push(port);
        }
    }
    existing.sort_by_key(|port| port.port);
}

/// Builds hosts for addresses that never answered TCP but showed up in ARP or
/// replied to ping, resolving their names concurrently.
async fn hosts_with_names(ips: Vec<Ipv4Addr>) -> Vec<Host> {
    stream::iter(ips.into_iter().map(|ip| async move {
        let name = resolve_hostname_with_timeout(ip, HOSTNAME_LOOKUP_TIMEOUT).await;
        discovered_host(ip, name, Vec::new())
    }))
    .buffer_unordered(HOSTNAME_LOOKUP_CONCURRENCY)
    .collect()
    .await
}

pub async fn scan_single_host_with_progress<F>(
    ip: String,
    profile: PortProfile,
    timeout_ms: u64,
    on_progress: F,
) -> Result<Host>
where
    F: FnMut(usize, usize, usize),
{
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
        on_progress,
    )
    .await;
    let name = resolve_hostname_with_timeout(parsed_ip, HOSTNAME_LOOKUP_TIMEOUT).await;

    Ok(Host {
        ip,
        name,
        reachable,
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
        fingerprint: None,
    })
}

fn discovered_host(ip: Ipv4Addr, name: Option<String>, open_ports: Vec<PortInfo>) -> Host {
    Host {
        ip: ip.to_string(),
        name,
        reachable: true,
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
        fingerprint: None,
    }
}

/// Pings `targets` and returns those that replied. `on_progress` receives the
/// number of addresses checked and the number that replied so far.
async fn discover_hosts_via_icmp<F>(
    targets: Vec<Ipv4Addr>,
    probe_timeout: Duration,
    cancel_flag: Arc<AtomicBool>,
    mut on_progress: F,
) -> Vec<Ipv4Addr>
where
    F: FnMut(usize, usize),
{
    if targets.is_empty() {
        return Vec::new();
    }

    // Each probe is a `ping` child that mostly sits waiting for a reply that
    // never comes, so concurrency is bounded by process count, not CPU.
    let concurrency = (available_workers() * 4).clamp(16, 48);
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

    let mut checked = 0usize;
    while let Some(result) = stream.next().await {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }

        checked += 1;
        if let Some(ip) = result {
            discovered.push(ip);
        }
        on_progress(checked, discovered.len());
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

async fn scan_open_ports<F>(
    ip: Ipv4Addr,
    ports: Arc<Vec<u16>>,
    timeout_duration: Duration,
    port_concurrency: usize,
    connection_semaphore: Arc<Semaphore>,
    cancel_flag: Arc<AtomicBool>,
    mut on_progress: F,
) -> (Vec<PortInfo>, bool)
where
    F: FnMut(usize, usize, usize),
{
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
    let total_ports = ports.len();
    let mut scanned_ports = 0usize;
    let mut found_open_ports = 0usize;

    on_progress(scanned_ports, total_ports, found_open_ports);

    while let Some(port) = stream.next().await {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }

        scanned_ports += 1;

        match port {
            Some(PortProbeOutcome::Open(port)) => {
                reachable = true;
                open_ports.push(port);
                found_open_ports += 1;
            }
            Some(PortProbeOutcome::Reachable) => {
                reachable = true;
            }
            None => {}
        }

        on_progress(scanned_ports, total_ports, found_open_ports);
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
    probe_port(
        ip,
        port,
        banner_kind_for_port(port),
        timeout_duration,
        connection_semaphore,
    )
    .await
}

async fn probe_port(
    ip: Ipv4Addr,
    port: u16,
    banner_kind: BannerKind,
    timeout_duration: Duration,
    connection_semaphore: Arc<Semaphore>,
) -> Option<PortProbeOutcome> {
    const MAX_CONNECT_ATTEMPTS: usize = 2;

    let socket = SocketAddr::new(IpAddr::V4(ip), port);
    let _permit = connection_semaphore.acquire_owned().await.ok()?;

    for attempt in 1..=MAX_CONNECT_ATTEMPTS {
        match timeout(timeout_duration, TcpStream::connect(socket)).await {
            Ok(Ok(mut stream)) => {
                // Read the banner on this connection rather than opening a
                // second one: that doubled the sockets per open port.
                let banner = read_banner(&mut stream, ip, banner_kind).await;
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
                    banner,
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
    let mdns_services_by_host = Arc::new(sweep_mdns_services().await);
    let pending_vendor_cache: SharedVendorCache = Arc::new(Mutex::new(HashMap::new()));
    let concurrency = enrichment_concurrency().min(hosts.len().max(1));

    let mut indexed_hosts = Vec::with_capacity(hosts.len());
    let mut new_fingerbank_results = Vec::new();

    let mut stream = stream::iter(hosts.into_iter().enumerate().map(|(index, mut host)| {
        let storage = storage.clone();
        let arp_table = arp_table.clone();
        let mdns_services_by_host = mdns_services_by_host.clone();
        let pending_vendor_cache = pending_vendor_cache.clone();
        async move {
            let mac = arp_table.get(&host.ip).cloned();
            let mdns_services = Ipv4Addr::from_str(&host.ip)
                .ok()
                .and_then(|ip| mdns_services_by_host.get(&ip))
                .map(|services| services.as_slice())
                .unwrap_or_default();
            let (fingerprint, fingerbank_result) =
                build_fingerprint(&host, mac, mdns_services, &storage, pending_vendor_cache).await;
            host.fingerprint = Some(fingerprint);
            (index, host, fingerbank_result)
        }
    }))
    .buffer_unordered(concurrency);

    while let Some((index, enriched_host, fingerbank_result)) = stream.next().await {
        indexed_hosts.push((index, enriched_host));

        if let Some(entry) = fingerbank_result {
            new_fingerbank_results.push(entry);
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

    if let Err(error) = storage.cache_fingerbank_results(new_fingerbank_results) {
        log::warn!("Failed to persist Fingerbank cache: {}", error);
    }

    enriched_hosts
}

pub async fn enrich_host_with_cache(mut host: Host, storage: Arc<Storage>) -> Host {
    let arp_table = read_arp_table().await;
    let mac = arp_table.get(&host.ip).cloned();
    let mdns_services_by_host = sweep_mdns_services().await;
    let mdns_services = Ipv4Addr::from_str(&host.ip)
        .ok()
        .and_then(|ip| mdns_services_by_host.get(&ip))
        .map(|services| services.as_slice())
        .unwrap_or_default();
    let pending_vendor_cache: SharedVendorCache = Arc::new(Mutex::new(HashMap::new()));

    let (fingerprint, fingerbank_result) = build_fingerprint(
        &host,
        mac,
        mdns_services,
        &storage,
        pending_vendor_cache.clone(),
    )
    .await;
    host.fingerprint = Some(fingerprint);

    if let Some(entry) = fingerbank_result {
        if let Err(error) = storage.cache_fingerbank_results(vec![entry]) {
            log::warn!("Failed to persist Fingerbank cache: {}", error);
        }
    }

    let new_vendors = snapshot_pending_vendors(&pending_vendor_cache).await;

    if let Err(error) = storage.cache_vendors(new_vendors) {
        log::warn!("Failed to persist OUI vendor cache: {}", error);
    }

    host
}

/// Builds a host's fingerprint from what the latest scan saw. Everything is
/// recomputed each time so types, OS guesses and notes follow the current
/// ports; only network lookups (OUI vendor, Fingerbank) come from caches.
/// Returns a new Fingerbank answer to cache, if one was fetched.
async fn build_fingerprint(
    host: &Host,
    mac_address: Option<String>,
    mdns_services: &[DiscoveredService],
    storage: &Arc<Storage>,
    pending_vendor_cache: SharedVendorCache,
) -> (DeviceFingerprint, Option<(String, FingerbankResult)>) {
    let mut sources = Vec::new();
    let mut notes = Vec::new();
    let mut discovered_services = Vec::new();

    if mac_address.is_some() {
        sources.push("arp-table".to_string());
    }

    let oui = mac_address.as_deref().and_then(oui_from_mac);
    // Randomized "private" addresses (phones, tablets, VMs, containers) have
    // no registered vendor, so online lookups would only leak an identifier.
    let private_mac = mac_address
        .as_deref()
        .is_some_and(is_locally_administered_mac);

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
            if let Ok(Some(value)) = storage.get_cached_vendor(oui_value) {
                vendor = Some(value);
                sources.push("oui-cache".to_string());
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

    if vendor.is_none() && !private_mac {
        if let Some(ref oui_value) = oui {
            if let Some(lookup_vendor) = lookup_vendor_via_maclookup(oui_value).await {
                let mut cache = pending_vendor_cache.lock().await;
                cache.insert(oui_value.clone(), lookup_vendor.clone());
                vendor = Some(lookup_vendor);
                sources.push("maclookup-app".to_string());
            }
        }
    }

    if private_mac && vendor.is_none() {
        notes
            .push("private (randomized) MAC address, so there is no vendor to look up".to_string());
    }

    let mut manufacturer = vendor.clone();
    let mut model_guess = None;
    let mut device_type = None;
    let mut os_guess = None;
    let mut confidence = 10u8;

    let mut fingerbank_to_cache = None;
    if let Some(mac) = mac_address.as_deref().filter(|_| !private_mac) {
        let cached = match storage.get_cached_fingerbank(mac) {
            Ok(cached) => cached,
            Err(error) => {
                log::warn!("Failed to read Fingerbank cache for {}: {}", mac, error);
                None
            }
        };
        let from_cache = cached.is_some();

        let fingerbank = match cached {
            Some(result) => Some(result),
            None => match lookup_fingerbank(mac, host.name.as_deref()).await {
                FingerbankLookup::Found(result) => {
                    fingerbank_to_cache = Some((mac.to_string(), result.clone()));
                    Some(result)
                }
                FingerbankLookup::NoMatch => {
                    let no_match = FingerbankResult::no_match(Utc::now().to_rfc3339());
                    fingerbank_to_cache = Some((mac.to_string(), no_match));
                    None
                }
                FingerbankLookup::Unavailable => None,
            },
        }
        .filter(|result| !result.is_no_match());

        if let Some(fingerbank) = fingerbank {
            sources.push(
                if from_cache {
                    "fingerbank-cache"
                } else {
                    "fingerbank"
                }
                .to_string(),
            );

            if manufacturer.is_none() {
                manufacturer = fingerbank.vendor.clone();
            }
            if vendor.is_none() {
                vendor = fingerbank.vendor.clone();
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

    let banner_os = extract_os_from_banners(&host.open_ports);
    if let Some((software, os)) = &banner_os {
        sources.push("banner-grab".to_string());
        if let Some(s) = software {
            notes.push(format!("detected software: {}", s));
        }
        if os_guess.is_none() {
            if let Some(o) = os {
                os_guess = Some(o.clone());
            }
        }
    }

    if !mdns_services.is_empty() {
        sources.push("mdns".to_string());
        for svc in mdns_services {
            discovered_services.push(svc.service_type.clone());
            if let Some(name) = &svc.service_name {
                notes.push(format!("mDNS service: {}", name));
            }
        }
        infer_device_from_mdns(
            mdns_services,
            &mut device_type,
            &mut os_guess,
            &mut model_guess,
            &mut notes,
        );
        confidence = confidence.saturating_add(10);
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
    dedup_strings(&mut discovered_services);

    let fingerprint = DeviceFingerprint {
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
        discovered_services,
        last_updated: Utc::now().to_rfc3339(),
    };

    (fingerprint, fingerbank_to_cache)
}

fn extract_os_from_banners(ports: &[PortInfo]) -> Option<(Option<String>, Option<String>)> {
    for port in ports {
        if let Some(banner) = &port.banner {
            if banner.starts_with("SSH-") {
                if let Some((software, os)) = parse_ssh_banner(banner) {
                    return Some((software, os));
                }
            } else if banner_kind_for_port(port.port) == BannerKind::HttpServerHeader {
                if let Some((software, os)) = parse_http_server_banner(banner) {
                    return Some((software, os));
                }
            }
        }
    }
    None
}

fn infer_device_from_mdns(
    services: &[DiscoveredService],
    device_type: &mut Option<String>,
    os_guess: &mut Option<String>,
    model_guess: &mut Option<String>,
    notes: &mut Vec<String>,
) {
    let service_types: Vec<&str> = services.iter().map(|s| s.service_type.as_str()).collect();

    if service_types
        .iter()
        .any(|s| s.contains("airplay") || s.contains("raop"))
    {
        set_if_none(device_type, "Media device");
        set_if_none(model_guess, "Apple AirPlay device");
        notes.push("AirPlay service detected via mDNS".to_string());
    }

    if service_types.iter().any(|s| s.contains("googlecast")) {
        set_if_none(device_type, "Media device");
        set_if_none(model_guess, "Google Cast device");
        notes.push("Google Cast service detected via mDNS".to_string());
    }

    if service_types
        .iter()
        .any(|s| s.contains("hap") || s.contains("homekit"))
    {
        set_if_none(device_type, "IoT device");
        set_if_none(model_guess, "Apple HomeKit device");
        notes.push("HomeKit service detected via mDNS".to_string());
    }

    if service_types
        .iter()
        .any(|s| s.contains("ipp") || s.contains("printer"))
    {
        set_if_none(device_type, "Printer");
        notes.push("Printer service detected via mDNS".to_string());
    }

    if service_types.iter().any(|s| s.contains("spotify")) {
        set_if_none(device_type, "Media device");
        set_if_none(model_guess, "Spotify Connect speaker");
        notes.push("Spotify Connect service detected via mDNS".to_string());
    }

    if service_types
        .iter()
        .any(|s| s.contains("smb") || s.contains("afpovertcp"))
    {
        set_if_none(device_type, "File server");
        notes.push("File sharing service detected via mDNS".to_string());
    }

    if service_types.iter().any(|s| s.contains("companion-link")) {
        set_if_none(device_type, "Apple device");
        set_if_none(os_guess, "Apple OS family");
        set_if_none(model_guess, "Apple Mac/iOS device");
        notes.push("Apple Companion Link detected via mDNS".to_string());
    }

    if service_types
        .iter()
        .any(|s| s.contains("daap") || s.contains("dacp"))
    {
        set_if_none(device_type, "Media device");
        set_if_none(model_guess, "Apple iTunes/Home Sharing device");
        notes.push("Apple media sharing detected via mDNS".to_string());
    }
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|item| seen.insert(item.to_ascii_lowercase()));
}

/// True for locally administered MACs (bit 0x02 of the first octet): the
/// randomized "private" addresses of phones and tablets, plus VMs and
/// containers. They have no registered vendor.
fn is_locally_administered_mac(mac: &str) -> bool {
    normalize_mac(mac)
        .and_then(|normalized| u8::from_str_radix(&normalized[..2], 16).ok())
        .is_some_and(|first_octet| first_octet & 0x02 != 0)
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

// The commands that can print a neighbour table, in the order they are tried.
//
// Linux leads with `ip neigh`: `arp` lives in `net-tools`, which Ubuntu has not
// installed by default for several releases, so a `.deb` install would
// otherwise find no MAC addresses at all — losing vendor lookup, device-type
// inference and Wake on LAN. `ip` ships in `iproute2`, which carries Debian's
// `Priority: important`, so every standard install has it; `arp` stays as the
// fallback for systems that ship it instead.
#[cfg(target_os = "windows")]
const NEIGHBOUR_COMMANDS: &[(&str, &str)] = &[("arp", "-a")];

#[cfg(target_os = "linux")]
const NEIGHBOUR_COMMANDS: &[(&str, &str)] = &[("ip", "neigh"), ("arp", "-an")];

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
const NEIGHBOUR_COMMANDS: &[(&str, &str)] = &[("arp", "-an")];

async fn read_arp_table() -> HashMap<String, String> {
    tokio::task::spawn_blocking(move || {
        let mut table = HashMap::new();

        // Take the first command that exists and succeeds, keeping every
        // failure's cause: the warning below is the only one anybody sees, so
        // it has to carry them itself.
        let mut failures = Vec::new();
        let output = NEIGHBOUR_COMMANDS.iter().find_map(|(program, argument)| {
            match StdCommand::new(program).arg(argument).output() {
                Ok(output) if output.status.success() => Some(output),
                Ok(output) => {
                    failures.push(format!(
                        "`{program} {argument}` exited with {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                    None
                }
                // A missing binary surfaces here rather than as a status.
                Err(error) => {
                    failures.push(format!("`{program} {argument}` did not run: {error}"));
                    None
                }
            }
        });

        let Some(output) = output else {
            // Losing the neighbour table costs every MAC, and with it vendor
            // lookup, device-type inference and Wake on LAN.
            log::warn!(
                "no neighbour table command succeeded: {}",
                failures.join("; ")
            );
            return table;
        };

        if !failures.is_empty() {
            log::debug!("neighbour table read after {}", failures.join("; "));
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

/// Vendor lookups need only the OUI (the first three octets), so that is all
/// that leaves the machine. The API accepts `AA:BB:CC`. Vendors on MA-M and
/// MA-S blocks (28- and 36-bit prefixes) resolve to the block owner, but the
/// bundled local database, consulted first, covers most of those.
fn maclookup_url(oui: &str) -> String {
    format!("https://api.maclookup.app/v2/macs/{}", oui)
}

async fn lookup_vendor_via_maclookup(oui: &str) -> Option<String> {
    let response = http_client()
        .get(maclookup_url(oui))
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

struct FingerbankQueryParams<'a> {
    mac: &'a str,
    hostname: Option<&'a str>,
    dhcp_fingerprint: Option<&'a str>,
    dhcp_vendor: Option<&'a str>,
    user_agents: Option<Vec<&'a str>>,
    fqdn: Option<&'a str>,
}

/// Outcome of a Fingerbank query. Only `Found` and `NoMatch` are cached;
/// `Unavailable` (no API key, network or server error) is retried next scan.
enum FingerbankLookup {
    Found(FingerbankResult),
    NoMatch,
    Unavailable,
}

async fn lookup_fingerbank_with_params(params: FingerbankQueryParams<'_>) -> FingerbankLookup {
    lookup_fingerbank_response(params)
        .await
        .unwrap_or(FingerbankLookup::Unavailable)
}

async fn lookup_fingerbank_response(params: FingerbankQueryParams<'_>) -> Option<FingerbankLookup> {
    let api_key = std::env::var("FINGERBANK_API_KEY").ok()?;

    let mut request = http_client()
        .get("https://api.fingerbank.org/api/v2/combinations/interrogate")
        .query(&[("key", api_key.as_str()), ("mac", params.mac)]);

    if let Some(hostname) = params.hostname {
        request = request.query(&[("hostname", hostname)]);
    }

    if let Some(dhcp_fingerprint) = params.dhcp_fingerprint {
        request = request.query(&[("dhcp_fingerprint", dhcp_fingerprint)]);
    }

    if let Some(dhcp_vendor) = params.dhcp_vendor {
        request = request.query(&[("dhcp_vendor", dhcp_vendor)]);
    }

    if let Some(fqdn) = params.fqdn {
        request = request.query(&[("fqdn", fqdn)]);
    }

    if let Some(user_agents) = &params.user_agents {
        for ua in user_agents {
            request = request.query(&[("user_agents[]", ua)]);
        }
    }

    let response = request
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .ok()?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Some(FingerbankLookup::NoMatch);
    }

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

    Some(FingerbankLookup::Found(FingerbankResult {
        vendor,
        model,
        device_type,
        os_guess,
        confidence,
        fetched_at: Utc::now().to_rfc3339(),
    }))
}

async fn lookup_fingerbank(mac: &str, hostname: Option<&str>) -> FingerbankLookup {
    lookup_fingerbank_with_params(FingerbankQueryParams {
        mac,
        hostname,
        dhcp_fingerprint: None,
        dhcp_vendor: None,
        user_agents: None,
        fqdn: None,
    })
    .await
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
    // Name hints with no port evidence behind them must match whole words:
    // "pineapple" is not Apple, and "ipadmin" is not an iPad.
    let contains_word_hint = |needles: &[&str]| contains_any_word_hint(&hint_text, needles);

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

    if has(62078) || contains_word_hint(&["iphone", "ipad", "apple watch"]) {
        set_if_none(&mut inferred_type, "Mobile device");
        set_if_none(&mut inferred_os, "Apple iOS/iPadOS family");
        set_if_none(&mut inferred_model, "Apple mobile device");
        confidence_boost = confidence_boost.saturating_add(24);
        notes.push("Apple mobile sync port (62078) or device name detected".to_string());
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

    // Apple before the SMB/SSH rules below: a Mac with file sharing or remote
    // login enabled used to come out as "Windows-like" or "Linux". Only the
    // vendor or name implies Apple: AFP and DAAP are also served by netatalk,
    // older NAS firmware, owntone and iTunes for Windows.
    if contains_word_hint(&[
        "apple",
        "macbook",
        "macbookpro",
        "macbookair",
        "imac",
        "mac mini",
        "mac studio",
    ]) {
        set_if_none(&mut inferred_type, "Apple device");
        set_if_none(&mut inferred_os, "Apple OS family");
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("Apple vendor or device name detected".to_string());
    } else if has_any(&[548, 3689]) {
        confidence_boost = confidence_boost.saturating_add(6);
        notes.push("AFP/DAAP file or media sharing detected".to_string());
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

    // SMB alone says nothing about the OS: Macs, NAS boxes and Samba servers
    // all serve it. MS-RPC and RDP are the Windows-specific signals.
    if has_any(&[135, 3389]) {
        set_if_none(&mut inferred_type, "Workstation/Server");
        set_if_none(&mut inferred_os, "Windows-like");
        confidence_boost = confidence_boost.saturating_add(16);
        notes.push("MS-RPC/RDP ports suggest a Windows host".to_string());
    } else if has_any(&[445, 139]) {
        set_if_none(&mut inferred_type, "Workstation/Server");
        confidence_boost = confidence_boost.saturating_add(8);
        notes.push("SMB file sharing detected".to_string());
    }

    if has(22) && !has_any(&[135, 3389]) {
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
    let lowered = value.to_lowercase().replace(['-', '_', '.'], " ");

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

/// Like `contains_any_hint`, but a needle only matches whole words of the
/// `normalize_hint_text` output. The needle's last word may carry a digit
/// suffix ("iphone13", "imac27"), and a multi-word needle also matches its
/// space-less compound, with the same suffix ("applewatch", "applewatch5").
/// "ipadmin01" still isn't an iPad.
fn contains_any_word_hint(haystack: &str, needles: &[&str]) -> bool {
    let words: Vec<&str> = haystack.split_whitespace().collect();

    needles.iter().any(|needle| {
        let parts: Vec<&str> = needle.split_whitespace().collect();
        if parts.is_empty() {
            return false;
        }

        let joined = parts.concat();
        let matches_part = |index: usize, word: &str| {
            let part = parts[index];
            word == part
                || (index + 1 == parts.len()
                    && word
                        .strip_prefix(part)
                        .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit())))
        };

        words.windows(parts.len()).any(|window| {
            window
                .iter()
                .enumerate()
                .all(|(index, word)| matches_part(index, word))
        }) || words.iter().any(|word| {
            word.strip_prefix(joined.as_str())
                .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit()))
        })
    })
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

/// Ports every profile probes because the device heuristics and icons key
/// off them: web UIs, SSH, SMB, RDP, printers (IPP, JetDirect), cameras
/// (RTSP), Apple (AFP, AirPlay, iOS sync), Google Cast, Plex, NAS admin,
/// MQTT and Home Assistant.
const SIGNATURE_PORTS: [u16; 19] = [
    22, 80, 443, 445, 548, 554, 631, 1883, 3389, 5000, 5001, 7000, 8009, 8080, 8123, 8443, 9100,
    32400, 62078,
];

/// Common services added by Quick on top of the signature ports.
const QUICK_EXTRA_PORTS: [u16; 10] = [21, 23, 53, 110, 135, 139, 143, 515, 5900, 8000];

/// Services added by Standard (and Deep) on top of Quick. TCP only: UDP-only
/// services such as DHCP, NTP, SNMP, SSDP and mDNS can't answer a TCP probe.
const STANDARD_EXTRA_PORTS: [u16; 42] = [
    25, 88, 111, 119, 389, 465, 587, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2375,
    3000, 3306, 3689, 5060, 5432, 5672, 6053, 6379, 6443, 7001, 8008, 8081, 8291, 8554, 8728, 8729,
    8883, 8888, 9000, 9090, 9200, 27017, 37777, 37778,
];

/// Deep scans every port up to this one, plus the Standard ports above it.
const DEEP_RANGE_END: u16 = 2048;

/// Port list for a profile. Each profile probes everything the lighter ones
/// do, so a deeper scan never loses a service a lighter one found.
fn ports_for_profile(profile: &PortProfile) -> Vec<u16> {
    let mut ports = SIGNATURE_PORTS.to_vec();
    ports.extend_from_slice(&QUICK_EXTRA_PORTS);

    if matches!(profile, PortProfile::Standard | PortProfile::Deep) {
        ports.extend_from_slice(&STANDARD_EXTRA_PORTS);
    }

    if matches!(profile, PortProfile::Deep) {
        ports.extend(1..=DEEP_RANGE_END);
    }

    ports.sort_unstable();
    ports.dedup();
    ports
}

fn service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        88 => Some("kerberos"),
        119 => Some("nntp"),
        873 => Some("rsync"),
        1080 => Some("socks"),
        1194 => Some("openvpn"),
        1883 => Some("mqtt"),
        3689 => Some("daap"),
        6053 => Some("esphome"),
        7000 => Some("airplay"),
        8008 => Some("http-alt"),
        8009 => Some("cast"),
        8081 => Some("http-alt"),
        8123 => Some("home-assistant"),
        8883 => Some("mqtt-tls"),
        8888 => Some("http-alt"),
        9100 => Some("jetdirect"),
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

const MDNS_MULTICAST_ADDR: &str = "224.0.0.251";
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DiscoveredService {
    pub service_type: String,
    pub service_name: Option<String>,
    pub port: Option<u16>,
    pub properties: HashMap<String, String>,
}

/// What to read from a port right after it accepts the probe connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BannerKind {
    /// The server speaks first (SSH, FTP): read its greeting line.
    ServerGreeting,
    /// Send a plain-HTTP `HEAD` and read the `Server` header.
    HttpServerHeader,
    /// Nothing to read. This includes TLS ports, where a plaintext request
    /// only burns the read timeout.
    None,
}

/// Plain-HTTP ports whose `Server` header is worth reading. TLS ports (443,
/// 5001, 8443, ...) are deliberately absent.
const HTTP_BANNER_PORTS: [u16; 11] = [
    80, 631, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9000,
];

const GREETING_READ_TIMEOUT: Duration = Duration::from_millis(500);
const HTTP_READ_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_BANNER_READ_BYTES: usize = 8 * 1024;
const MAX_BANNER_CHARS: usize = 200;

fn banner_kind_for_port(port: u16) -> BannerKind {
    match port {
        21 | 22 | 25 | 587 => BannerKind::ServerGreeting,
        port if HTTP_BANNER_PORTS.contains(&port) => BannerKind::HttpServerHeader,
        _ => BannerKind::None,
    }
}

async fn read_banner(stream: &mut TcpStream, ip: Ipv4Addr, kind: BannerKind) -> Option<String> {
    match kind {
        BannerKind::None => None,
        BannerKind::ServerGreeting => {
            let data =
                read_until(stream, GREETING_READ_TIMEOUT, |data| data.contains(&b'\n')).await;
            let text = String::from_utf8_lossy(&data);
            let line = text.lines().next()?.trim();
            // SSH identification string, or an FTP/SMTP-style "220" greeting.
            if line.starts_with("SSH-") || line.starts_with("220") {
                sanitize_banner(line)
            } else {
                None
            }
        }
        BannerKind::HttpServerHeader => {
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                ip
            );
            stream.write_all(request.as_bytes()).await.ok()?;
            let data = read_until(stream, HTTP_READ_TIMEOUT, |data| {
                data.windows(4).any(|window| window == b"\r\n\r\n")
            })
            .await;
            parse_http_server_header(&String::from_utf8_lossy(&data))
                .and_then(|server| sanitize_banner(&server))
        }
    }
}

/// Reads from `stream` until `done` says the data is complete, the peer
/// closes, `MAX_BANNER_READ_BYTES` arrive, or `budget` runs out, and returns
/// whatever arrived.
async fn read_until(
    stream: &mut TcpStream,
    budget: Duration,
    done: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];

    while data.len() < MAX_BANNER_READ_BYTES && !done(&data) {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(read)) if read > 0 => data.extend_from_slice(&chunk[..read]),
            _ => break,
        }
    }

    data
}

/// Extracts the `Server` header from an HTTP response head. Header names are
/// case-insensitive, and some servers omit the space after the colon.
fn parse_http_server_header(response: &str) -> Option<String> {
    response
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Banners come from arbitrary devices: drop control characters and cap the
/// length before they reach the UI and the cache.
fn sanitize_banner(raw: &str) -> Option<String> {
    let cleaned = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_BANNER_CHARS)
        .collect::<String>();
    let trimmed = cleaned.trim();

    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_ssh_banner(banner: &str) -> Option<(Option<String>, Option<String>)> {
    // Banner format: "SSH-<protoversion>-<software> [comment]",
    // e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13".
    let first_token = banner.split_whitespace().next()?;
    let mut pieces = first_token.splitn(3, '-');
    pieces.next()?;
    pieces.next()?;
    let software = pieces
        .next()
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty());

    let lowered = banner.to_ascii_lowercase();
    let os_guess = if lowered.contains("ubuntu") {
        Some("Ubuntu Linux".to_string())
    } else if lowered.contains("debian") || lowered.contains("raspbian") {
        Some("Debian Linux".to_string())
    } else if lowered.contains("centos") || lowered.contains("rhel") || lowered.contains("red hat")
    {
        Some("CentOS/RHEL Linux".to_string())
    } else if lowered.contains("freebsd") {
        Some("FreeBSD".to_string())
    } else if lowered.contains("openbsd") {
        Some("OpenBSD".to_string())
    } else {
        None
    };

    if software.is_none() && os_guess.is_none() {
        return None;
    }

    Some((software, os_guess))
}

fn parse_http_server_banner(banner: &str) -> Option<(Option<String>, Option<String>)> {
    let lowered = banner.to_lowercase();
    let os_guess = if lowered.contains("ubuntu") {
        Some("Ubuntu Linux".to_string())
    } else if lowered.contains("debian") {
        Some("Debian Linux".to_string())
    } else if lowered.contains("centos") {
        Some("CentOS Linux".to_string())
    } else if lowered.contains("windows") || lowered.contains("iis") {
        Some("Windows Server".to_string())
    } else {
        None
    };
    let software = Some(banner.to_string());
    Some((software, os_guess))
}

/// Sends a single multicast mDNS query and groups the responses by the address
/// that sent them, so services are only ever attributed to the host that
/// actually advertised them.
async fn sweep_mdns_services() -> HashMap<Ipv4Addr, Vec<DiscoveredService>> {
    let mut services_by_host: HashMap<Ipv4Addr, Vec<DiscoveredService>> = HashMap::new();
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return services_by_host,
    };
    let queries = [
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_hap._tcp.local",
        "_homekit._tcp.local",
        "_printer._tcp.local",
        "_ipp._tcp.local",
        "_pdl-datastream._tcp.local",
        "_smb._tcp.local",
        "_afpovertcp._tcp.local",
        "_nfs._tcp.local",
        "_ssh._tcp.local",
        "_sftp-ssh._tcp.local",
        "_companion-link._tcp.local",
        "_daap._tcp.local",
        "_dacp._tcp.local",
        "_eppc._tcp.local",
        "_net-assistant._tcp.local",
        "_rfb._tcp.local",
        "_workstation._tcp.local",
        "_device-info._tcp.local",
        "_sleep-proxy._udp.local",
    ];
    let dns_packet = build_mdns_query(&queries);
    let multicast_addr: SocketAddr = format!("{}:{}", MDNS_MULTICAST_ADDR, MDNS_PORT)
        .parse()
        .unwrap();
    if socket.send_to(&dns_packet, multicast_addr).await.is_err() {
        return services_by_host;
    }
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    loop {
        let recv_timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if recv_timeout.is_zero() {
            break;
        }
        match timeout(recv_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let IpAddr::V4(src_ip) = src.ip() else {
                    continue;
                };
                if let Some(parsed) = parse_mdns_response(&buf[..n]) {
                    services_by_host.entry(src_ip).or_default().extend(parsed);
                }
            }
            _ => break,
        }
    }
    services_by_host
}

fn build_mdns_query(services: &[&str]) -> Vec<u8> {
    let mut packet = Vec::new();
    let transaction_id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        & 0xFFFF) as u16;
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&(services.len() as u16).to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    for service in services {
        encode_dns_name(&mut packet, service);
        packet.extend_from_slice(&0x00FFu16.to_be_bytes());
        packet.extend_from_slice(&0x0001u16.to_be_bytes());
    }
    packet
}

fn encode_dns_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        let label_bytes = label.as_bytes();
        packet.push(label_bytes.len() as u8);
        packet.extend_from_slice(label_bytes);
    }
    packet.push(0);
}

fn parse_mdns_response(data: &[u8]) -> Option<Vec<DiscoveredService>> {
    if data.len() < 12 {
        return None;
    }
    let _transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if (flags & 0x8000) == 0 {
        return None;
    }
    let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    if answer_count == 0 {
        return None;
    }
    let mut services = Vec::new();
    let mut offset = 12usize;
    for _ in 0..answer_count {
        if offset >= data.len() {
            break;
        }
        let (name, new_offset) = parse_dns_name(data, offset)?;
        offset = new_offset;
        if offset + 10 > data.len() {
            break;
        }
        let _rr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rr_class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if name.contains("._tcp.") || name.contains("._udp.") {
            if let Some(service_type) = extract_service_type(&name) {
                services.push(DiscoveredService {
                    service_type,
                    service_name: Some(name.clone()),
                    port: None,
                    properties: HashMap::new(),
                });
            }
        }
        offset += rdlength;
    }
    Some(services)
}

/// Longest domain name allowed on the wire (RFC 1035, section 2.3.4).
const MAX_DNS_NAME_WIRE_LEN: usize = 255;

/// Compression pointers followed before a name is rejected. Real responders
/// nest at most a few levels; the cap guarantees termination on pointer cycles.
const MAX_DNS_COMPRESSION_JUMPS: usize = 16;

/// Decodes a (possibly compressed) DNS name starting at `start` and returns it
/// with the offset just past the name in the original record.
///
/// mDNS replies come from any device on the LAN, so the packet is untrusted:
/// truncated labels, reserved label types, pointer cycles and overlong names
/// all return `None` instead of looping or producing a partial name.
fn parse_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut offset = start;
    let mut end_of_name = None;
    let mut jumps = 0usize;
    let mut wire_len = 0usize;

    loop {
        let len = *data.get(offset)? as usize;

        if len == 0 {
            return Some((name, end_of_name.unwrap_or(offset + 1)));
        }

        match len & 0xC0 {
            0xC0 => {
                let low = *data.get(offset + 1)? as usize;
                jumps += 1;
                if jumps > MAX_DNS_COMPRESSION_JUMPS {
                    return None;
                }

                end_of_name.get_or_insert(offset + 2);
                offset = ((len & 0x3F) << 8) | low;
            }
            0x00 => {
                let label = data.get(offset + 1..offset + 1 + len)?;
                wire_len += len + 1;
                // +1 for the terminating root label.
                if wire_len + 1 > MAX_DNS_NAME_WIRE_LEN {
                    return None;
                }

                // DNS-SD forbids ASCII control characters in names (RFC 6763,
                // section 4.1.1); a label carrying them is malformed.
                if label.iter().any(|byte| byte.is_ascii_control()) {
                    return None;
                }

                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                offset += len + 1;
            }
            // 0x40 and 0x80 are reserved/obsolete label types.
            _ => return None,
        }
    }
}

fn extract_service_type(name: &str) -> Option<String> {
    let parts: Vec<&str> = name.split('.').collect();
    for part in parts {
        if part.starts_with('_') && (part.ends_with("_tcp") || part.ends_with("_udp")) {
            return Some(part.to_string());
        }
    }
    None
}

#[allow(dead_code)]
pub async fn discover_ssdp_devices() -> Vec<DiscoveredService> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let m_search = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: ssdp:all\r\n",
        "\r\n"
    );
    let multicast_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    if socket
        .send_to(m_search.as_bytes(), multicast_addr)
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut devices = Vec::new();
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(2000);
    loop {
        let recv_timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if recv_timeout.is_zero() {
            break;
        }
        match timeout(recv_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _src))) => {
                if let Some(device) = parse_ssdp_response(&buf[..n]) {
                    devices.push(device);
                }
            }
            _ => break,
        }
    }
    devices
}

#[allow(dead_code)]
fn parse_ssdp_response(data: &[u8]) -> Option<DiscoveredService> {
    let text = std::str::from_utf8(data).ok()?;
    let mut properties = HashMap::new();
    let mut service_type = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            match key.as_str() {
                "st" | "nt" => {
                    service_type = Some(value.clone());
                    properties.insert("search_target".to_string(), value);
                }
                "server" => {
                    properties.insert("server".to_string(), value);
                }
                "location" => {
                    properties.insert("location".to_string(), value);
                }
                "usn" => {
                    properties.insert("usn".to_string(), value);
                }
                _ => {
                    properties.insert(key, value);
                }
            }
        }
    }
    service_type.map(|st| DiscoveredService {
        service_type: st,
        service_name: properties.get("server").cloned(),
        port: Some(1900),
        properties,
    })
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
            is_default_route: false,
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
                    banner: None,
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

    fn progress_at(phase: ScanPhase, scanned: usize, total: usize) -> ScanProgress {
        scan_progress(phase, scanned, total, 0, true, None)
    }

    #[test]
    fn progress_throttle_limits_events_within_a_phase() {
        let mut throttle = ProgressThrottle::new(Duration::from_secs(3600));
        let start = Instant::now();

        assert!(throttle.should_emit(&progress_at(ScanPhase::Discovery, 0, 254), start));
        assert!(!throttle.should_emit(&progress_at(ScanPhase::Discovery, 1, 254), start));
        assert!(!throttle.should_emit(&progress_at(ScanPhase::Discovery, 200, 254), start));
        assert!(
            throttle.should_emit(&progress_at(ScanPhase::Discovery, 254, 254), start),
            "the last event of a phase always goes through"
        );
    }

    #[test]
    fn progress_throttle_passes_phase_changes_stops_and_due_events() {
        let mut throttle = ProgressThrottle::new(Duration::from_millis(80));
        let start = Instant::now();

        assert!(throttle.should_emit(&progress_at(ScanPhase::Discovery, 3, 254), start));
        assert!(throttle.should_emit(&progress_at(ScanPhase::Ports, 1, 20), start));

        let stopped = scan_progress(ScanPhase::Ports, 2, 20, 0, false, None);
        assert!(throttle.should_emit(&stopped, start));

        assert!(!throttle.should_emit(&progress_at(ScanPhase::Ports, 3, 20), start));
        let later = start + Duration::from_millis(81);
        assert!(throttle.should_emit(&progress_at(ScanPhase::Ports, 4, 20), later));
    }

    #[test]
    fn merge_open_ports_keeps_ports_sorted_and_unique() {
        let open = |port: u16| PortInfo {
            port,
            state: "open".to_string(),
            service: service_name(port).map(ToString::to_string),
            banner: None,
        };
        let mut known = vec![open(22), open(443)];

        merge_open_ports(&mut known, vec![open(8080), open(22), open(80)]);

        let ports = known.iter().map(|port| port.port).collect::<Vec<u16>>();
        assert_eq!(ports, vec![22, 80, 443, 8080]);
    }

    #[test]
    fn discovery_ports_are_probed_by_every_profile() {
        for profile in [PortProfile::Quick, PortProfile::Standard, PortProfile::Deep] {
            let ports = ports_for_profile(&profile);
            for port in DISCOVERY_PORTS {
                assert!(
                    ports.contains(&port),
                    "{:?} should include discovery port {}",
                    profile,
                    port
                );
            }
        }
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

    /// Serves `port` on loopback, counting accepted connections and running
    /// `respond` on each one.
    async fn loopback_server<F, Fut>(respond: F) -> (u16, Arc<std::sync::atomic::AtomicUsize>)
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                respond(stream).await;
            }
        });
        (port, accepted)
    }

    async fn probe_loopback(port: u16, kind: BannerKind) -> Option<PortProbeOutcome> {
        probe_port(
            Ipv4Addr::LOCALHOST,
            port,
            kind,
            Duration::from_millis(500),
            Arc::new(Semaphore::new(4)),
        )
        .await
    }

    #[tokio::test]
    async fn probe_reads_ssh_banner_on_the_probe_connection() {
        let (port, accepted) = loopback_server(|mut stream| async move {
            let _ = stream
                .write_all(b"SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13\r\n")
                .await;
            sleep(Duration::from_millis(50)).await;
        })
        .await;

        let outcome = probe_loopback(port, BannerKind::ServerGreeting).await;

        let Some(PortProbeOutcome::Open(info)) = outcome else {
            panic!("expected an open port");
        };
        assert_eq!(
            info.banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13")
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "one connection per probe"
        );
    }

    #[tokio::test]
    async fn probe_reads_http_server_header_case_insensitively() {
        let (port, accepted) = loopback_server(|mut stream| async move {
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nserver: nginx/1.24.0 (Ubuntu)\r\n\r\n")
                .await;
        })
        .await;

        let outcome = probe_loopback(port, BannerKind::HttpServerHeader).await;

        let Some(PortProbeOutcome::Open(info)) = outcome else {
            panic!("expected an open port");
        };
        assert_eq!(info.banner.as_deref(), Some("nginx/1.24.0 (Ubuntu)"));
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "one connection per probe"
        );
    }

    #[tokio::test]
    async fn probe_reports_open_port_when_server_stays_silent() {
        let (port, _) = loopback_server(|stream| async move {
            sleep(Duration::from_millis(900)).await;
            drop(stream);
        })
        .await;

        let started = std::time::Instant::now();
        let outcome = probe_loopback(port, BannerKind::ServerGreeting).await;

        let Some(PortProbeOutcome::Open(info)) = outcome else {
            panic!("expected an open port");
        };
        assert!(info.banner.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(800),
            "banner wait is bounded"
        );
    }

    #[test]
    fn parse_http_server_header_handles_case_and_missing_header() {
        assert_eq!(
            parse_http_server_header("HTTP/1.1 200 OK\r\nSERVER: lighttpd/1.4\r\n\r\n"),
            Some("lighttpd/1.4".to_string())
        );
        assert_eq!(
            parse_http_server_header("HTTP/1.1 200 OK\r\nServer:Apache\r\n\r\n"),
            Some("Apache".to_string())
        );
        assert_eq!(parse_http_server_header("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn banner_kind_skips_tls_ports() {
        assert_eq!(banner_kind_for_port(22), BannerKind::ServerGreeting);
        assert_eq!(banner_kind_for_port(21), BannerKind::ServerGreeting);
        assert_eq!(banner_kind_for_port(25), BannerKind::ServerGreeting);
        assert_eq!(banner_kind_for_port(8123), BannerKind::HttpServerHeader);
        assert_eq!(banner_kind_for_port(8080), BannerKind::HttpServerHeader);
        for tls_port in [443, 5001, 8443] {
            assert_eq!(banner_kind_for_port(tls_port), BannerKind::None);
        }
    }

    #[test]
    fn deeper_profiles_probe_everything_lighter_ones_do() {
        let quick = ports_for_profile(&PortProfile::Quick);
        let standard = ports_for_profile(&PortProfile::Standard);
        let deep = ports_for_profile(&PortProfile::Deep);

        for port in &quick {
            assert!(
                standard.contains(port),
                "Standard is missing Quick port {}",
                port
            );
        }
        for port in &standard {
            assert!(
                deep.contains(port),
                "Deep is missing Standard port {}",
                port
            );
        }
    }

    #[test]
    fn every_profile_probes_signature_ports() {
        for profile in [PortProfile::Quick, PortProfile::Standard, PortProfile::Deep] {
            let ports = ports_for_profile(&profile);
            for port in SIGNATURE_PORTS {
                assert!(ports.contains(&port), "{:?} is missing {}", profile, port);
            }
        }
    }

    #[test]
    fn tcp_profiles_skip_udp_only_services() {
        let standard = ports_for_profile(&PortProfile::Standard);
        let quick = ports_for_profile(&PortProfile::Quick);
        for port in [67, 68, 69, 123, 137, 138, 161, 500, 1812, 1900, 5353] {
            assert!(
                !standard.contains(&port),
                "Standard probes UDP-only {}",
                port
            );
            assert!(!quick.contains(&port), "Quick probes UDP-only {}", port);
        }
    }

    #[test]
    fn normalize_mac_accepts_short_segments() {
        let normalized = normalize_mac("a:b:c:d:e:f");
        assert_eq!(normalized.as_deref(), Some("0A:0B:0C:0D:0E:0F"));
    }

    #[test]
    fn extract_parses_ip_neigh_lines() {
        // `ip neigh` on Linux, where `arp` is usually absent.
        let line = "192.0.2.1 dev eth0 lladdr 02:fc:00:00:00:05 REACHABLE";
        assert_eq!(
            extract_ipv4_from_arp_line(line),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            extract_mac_from_arp_line(line).as_deref(),
            Some("02:FC:00:00:00:05")
        );
    }

    #[test]
    fn extract_mac_ignores_ip_neigh_lines_without_lladdr() {
        // A neighbour that never answered has no lladdr to extract.
        let line = "192.0.2.55 dev eth0 FAILED";
        assert_eq!(extract_mac_from_arp_line(line), None);
    }

    #[test]
    fn extract_ignores_ipv6_neigh_lines() {
        // `ip neigh` lists IPv6 neighbours too — link-local ones are on every
        // Linux box — and the hosts table is keyed by IPv4. Rejecting the
        // address is what keeps the line out; its lladdr looks like any other.
        let line = "fe80::1 dev eth0 lladdr 02:fc:00:00:00:05 STALE";
        assert_eq!(extract_ipv4_from_arp_line(line), None);
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

    #[tokio::test]
    async fn enrichment_recomputes_fingerprint_when_ports_change() {
        // Loopback has no ARP entry, so no MAC and therefore no online vendor
        // or Fingerbank lookup: the test stays offline.
        let storage = Arc::new(Storage::in_memory());

        let first = enrich_host_with_cache(
            host("127.0.0.1", Some("office-box"), &[22]),
            storage.clone(),
        )
        .await;
        let first_type = first
            .fingerprint
            .and_then(|fingerprint| fingerprint.device_type);
        assert_eq!(first_type.as_deref(), Some("Workstation/Server"));

        let second = enrich_host_with_cache(
            host("127.0.0.1", Some("office-box"), &[22, 631, 9100]),
            storage,
        )
        .await;
        let fingerprint = second.fingerprint.expect("fingerprint");
        assert_eq!(fingerprint.device_type.as_deref(), Some("Printer"));
        assert!(
            fingerprint.notes.iter().any(|note| note.contains("9100")),
            "notes should describe the current ports: {:?}",
            fingerprint.notes
        );
    }

    #[test]
    fn mac_with_file_sharing_is_not_labelled_windows() {
        let mac = host(
            "192.168.1.10",
            Some("Studio-Mac-mini.local"),
            &[22, 445, 548],
        );

        let (device_type, os_guess, _, _, _) =
            infer_device_profile(&mac, Some("Apple, Inc."), None);

        assert_eq!(device_type.as_deref(), Some("Apple device"));
        assert_eq!(os_guess.as_deref(), Some("Apple OS family"));
    }

    #[test]
    fn nas_with_smb_is_not_labelled_windows() {
        let nas = host(
            "192.168.1.30",
            Some("diskstation"),
            &[22, 80, 139, 445, 5000, 5001],
        );

        let (device_type, os_guess, model_guess, _, _) =
            infer_device_profile(&nas, Some("Synology Incorporated"), None);

        assert_eq!(device_type.as_deref(), Some("NAS/Storage"));
        assert_eq!(model_guess.as_deref(), Some("Synology NAS (DSM)"));
        assert_eq!(os_guess.as_deref(), Some("Linux/Unix-like"));
    }

    #[test]
    fn apple_name_hints_match_whole_words_only() {
        let pineapple = host("192.168.1.60", Some("wifi-pineapple"), &[80]);
        let (device_type, os_guess, _, _, _) = infer_device_profile(&pineapple, None, None);
        assert_ne!(device_type.as_deref(), Some("Apple device"));
        assert_ne!(os_guess.as_deref(), Some("Apple OS family"));

        let admin = host("192.168.1.61", Some("ipadmin01"), &[22]);
        let (device_type, _, _, _, _) = infer_device_profile(&admin, None, None);
        assert_ne!(device_type.as_deref(), Some("Mobile device"));

        let ipad = host("192.168.1.62", Some("Lukas-iPad"), &[]);
        let (device_type, _, _, _, _) = infer_device_profile(&ipad, None, None);
        assert_eq!(device_type.as_deref(), Some("Mobile device"));

        let phone = host("192.168.1.65", Some("iphone13"), &[]);
        let (device_type, _, _, _, _) = infer_device_profile(&phone, None, None);
        assert_eq!(device_type.as_deref(), Some("Mobile device"));

        for name in ["applewatch", "applewatch5"] {
            let watch = host("192.168.1.66", Some(name), &[]);
            let (device_type, _, _, _, _) = infer_device_profile(&watch, None, None);
            assert_eq!(device_type.as_deref(), Some("Mobile device"), "{name}");
        }

        let watch = host("192.168.1.67", Some("applewatchmini"), &[]);
        let (device_type, _, _, _, _) = infer_device_profile(&watch, None, None);
        assert_ne!(device_type.as_deref(), Some("Mobile device"));

        let laptop = host("192.168.1.64", Some("Lukas-MacBookAir.local"), &[22]);
        let (_, os_guess, _, _, _) = infer_device_profile(&laptop, None, None);
        assert_eq!(os_guess.as_deref(), Some("Apple OS family"));
    }

    #[test]
    fn rpc_and_rdp_still_mean_windows() {
        let desktop = host(
            "192.168.1.50",
            Some("DESKTOP-8H2K9QX"),
            &[135, 139, 445, 3389],
        );

        let (device_type, os_guess, _, _, _) = infer_device_profile(&desktop, None, None);

        assert_eq!(device_type.as_deref(), Some("Workstation/Server"));
        assert_eq!(os_guess.as_deref(), Some("Windows-like"));
    }

    #[test]
    fn itunes_on_windows_stays_windows() {
        let desktop = host("192.168.1.52", Some("gaming-pc"), &[135, 445, 3389, 3689]);

        let (_, os_guess, _, _, _) = infer_device_profile(&desktop, None, None);

        assert_eq!(os_guess.as_deref(), Some("Windows-like"));
    }

    #[test]
    fn nas_with_afp_is_not_labelled_apple() {
        let nas = host(
            "192.168.1.31",
            Some("diskstation"),
            &[22, 139, 445, 548, 5000, 5001],
        );

        let (device_type, os_guess, _, _, _) =
            infer_device_profile(&nas, Some("Synology Incorporated"), None);

        assert_eq!(device_type.as_deref(), Some("NAS/Storage"));
        assert_eq!(os_guess.as_deref(), Some("Linux/Unix-like"));
    }

    #[test]
    fn smb_alone_makes_no_os_claim() {
        let share = host("192.168.1.60", None, &[445]);

        let (_, os_guess, _, _, _) = infer_device_profile(&share, None, None);

        assert_eq!(os_guess, None);
    }

    #[test]
    fn locally_administered_macs_are_detected() {
        assert!(is_locally_administered_mac("5A:12:34:56:78:9A"));
        assert!(is_locally_administered_mac("02:42:ac:11:00:02"));
        assert!(!is_locally_administered_mac("A4:83:E7:10:20:30"));
        assert!(!is_locally_administered_mac("not-a-mac"));
    }

    #[test]
    fn maclookup_request_carries_only_the_oui() {
        let url = maclookup_url("3C:A6:2F");

        assert_eq!(url, "https://api.maclookup.app/v2/macs/3C:A6:2F");
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

    #[test]
    fn parse_ssh_banner_extracts_software_and_os_from_ubuntu_banner() {
        let (software, os_guess) =
            parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13").expect("parsed banner");

        assert_eq!(software.as_deref(), Some("OpenSSH_8.9p1"));
        assert_eq!(os_guess.as_deref(), Some("Ubuntu Linux"));
    }

    #[test]
    fn parse_ssh_banner_handles_banner_without_comment() {
        let (software, os_guess) = parse_ssh_banner("SSH-2.0-OpenSSH_9.6").expect("parsed banner");

        assert_eq!(software.as_deref(), Some("OpenSSH_9.6"));
        assert!(os_guess.is_none());
    }

    /// Runs `parse` on a helper thread so a parser that never terminates fails
    /// the test instead of hanging the whole suite.
    fn run_with_deadline<T: Send + 'static>(
        parse: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        // On timeout the helper thread keeps running (threads can't be killed).
        // That's fine for pure parsing code, but don't reuse this for code
        // that holds locks.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(parse());
        });
        receiver.recv_timeout(Duration::from_secs(2)).ok()
    }

    fn mdns_response_header(answer_count: u16) -> Vec<u8> {
        let mut packet = vec![0x00, 0x00, 0x84, 0x00, 0x00, 0x00];
        packet.extend_from_slice(&answer_count.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet
    }

    #[test]
    fn parse_dns_name_follows_compression_pointers() {
        let mut packet = mdns_response_header(0);
        encode_dns_name(&mut packet, "_airplay._tcp.local");
        let second_name = packet.len();
        packet.extend_from_slice(&[0x02, b't', b'v', 0xC0, 0x0C]);

        let (name, next_offset) = parse_dns_name(&packet, second_name).expect("valid name");

        assert_eq!(name, "tv._airplay._tcp.local");
        assert_eq!(next_offset, packet.len());
    }

    #[test]
    fn parse_dns_name_rejects_self_referencing_pointer() {
        let mut packet = mdns_response_header(1);
        packet.extend_from_slice(&[0xC0, 0x0C]);

        let result = run_with_deadline(move || parse_dns_name(&packet, 12));

        assert_eq!(
            result,
            Some(None),
            "parser must terminate and reject the name"
        );
    }

    #[test]
    fn parse_dns_name_rejects_pointer_cycle_through_labels() {
        let mut packet = mdns_response_header(1);
        packet.extend_from_slice(&[0x01, b'a', 0xC0, 0x0C]);

        let result = run_with_deadline(move || parse_dns_name(&packet, 12));

        assert_eq!(
            result,
            Some(None),
            "parser must terminate and reject the name"
        );
    }

    #[test]
    fn parse_dns_name_rejects_truncated_label() {
        let mut packet = mdns_response_header(1);
        packet.extend_from_slice(&[0x05, b'a', b'b']);

        assert_eq!(parse_dns_name(&packet, 12), None);
    }

    #[test]
    fn parse_dns_name_rejects_control_characters() {
        let mut packet = mdns_response_header(1);
        packet.extend_from_slice(&[0x04, b't', 0x01, b'v', 0x1B, 0x00]);

        assert_eq!(parse_dns_name(&packet, 12), None);
    }

    #[test]
    fn parse_dns_name_keeps_utf8_instance_names() {
        let mut packet = mdns_response_header(1);
        let label = "Küche TV".as_bytes();
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.push(0);

        let (name, _) = parse_dns_name(&packet, 12).expect("valid UTF-8 name");

        assert_eq!(name, "Küche TV");
    }

    #[test]
    fn parse_dns_name_rejects_overlong_name() {
        let mut packet = mdns_response_header(1);
        for _ in 0..5 {
            packet.push(63);
            packet.extend_from_slice(&[b'x'; 63]);
        }
        packet.push(0);

        assert_eq!(parse_dns_name(&packet, 12), None);
    }

    #[test]
    fn parse_mdns_response_survives_pointer_loop() {
        let mut packet = mdns_response_header(1);
        packet.extend_from_slice(&[0xC0, 0x0C]);
        packet.extend_from_slice(&[0; 10]);

        let result = run_with_deadline(move || parse_mdns_response(&packet).is_none());

        assert_eq!(
            result,
            Some(true),
            "a malformed packet must be dropped, not spin"
        );
    }

    #[test]
    fn parse_ssh_banner_handles_dashes_inside_software_version() {
        let (software, os_guess) =
            parse_ssh_banner("SSH-2.0-dropbear_2022.83-debian").expect("parsed banner");

        assert_eq!(software.as_deref(), Some("dropbear_2022.83-debian"));
        assert_eq!(os_guess.as_deref(), Some("Debian Linux"));
    }
}

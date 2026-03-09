use crate::models::{
    Host, NetworkInterface, PortInfo, PortProfile, ScanOptions, ScanProgress, ScanResult,
};
use anyhow::{Context, Result};
use chrono::Utc;
use futures::{stream, StreamExt};
use if_addrs::{get_if_addrs, IfAddr};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

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
    let selected = interfaces
        .into_iter()
        .find(|iface| iface.name == options.interface_name)
        .with_context(|| format!("Interface '{}' not found", options.interface_name))?;

    let subnet = options.subnet.clone().unwrap_or_else(|| selected.subnet.clone());
    options.subnet = Some(subnet.clone());

    let network = Ipv4Net::from_str(&subnet)
        .with_context(|| format!("Invalid subnet '{}'", subnet))?;
    let max_hosts = options.max_hosts.unwrap_or(512).clamp(1, 4096);

    let targets: Vec<Ipv4Addr> = network
        .hosts()
        .filter(|ip| ip.to_string() != selected.ip)
        .take(max_hosts)
        .collect();

    if targets.is_empty() {
        anyhow::bail!("No target hosts found in subnet {}", subnet);
    }

    let timeout_ms = options.timeout_ms.unwrap_or(350).clamp(50, 5000);
    let timeout_duration = Duration::from_millis(timeout_ms);
    let ports = Arc::new(ports_for_profile(&options.port_profile));

    let host_concurrency = match options.port_profile {
        PortProfile::Quick => 64,
        PortProfile::Standard => 48,
        PortProfile::Deep => 24,
    };

    let total = targets.len();
    let mut scanned = 0usize;
    let mut found = 0usize;
    let mut hosts = Vec::new();

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
        async move {
            let current_ip = ip.to_string();
            if cancel_flag.load(Ordering::Relaxed) {
                return (current_ip, None);
            }

            let host = scan_host_internal(ip, ports, timeout_duration, cancel_flag).await;
            (current_ip, host)
        }
    }))
    .buffer_unordered(host_concurrency);

    while let Some((current_ip, maybe_host)) = stream.next().await {
        scanned += 1;

        if let Some(host) = maybe_host {
            found += 1;
            on_host(host.clone());
            hosts.push(host);
        }

        let cancelled = cancel_flag.load(Ordering::Relaxed);

        on_progress(ScanProgress {
            scanned,
            total,
            found,
            running: !cancelled,
            current_ip: Some(current_ip),
        });

        if cancelled {
            break;
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

    let open_ports = scan_open_ports(parsed_ip, ports, timeout_duration, cancel_flag).await;
    let name = resolve_hostname(parsed_ip).await;

    Ok(Host {
        ip,
        name,
        reachable: !open_ports.is_empty(),
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
    })
}

async fn scan_host_internal(
    ip: Ipv4Addr,
    ports: Arc<Vec<u16>>,
    timeout_duration: Duration,
    cancel_flag: Arc<AtomicBool>,
) -> Option<Host> {
    let open_ports = scan_open_ports(ip, ports, timeout_duration, cancel_flag).await;
    if open_ports.is_empty() {
        return None;
    }

    let name = resolve_hostname(ip).await;

    Some(Host {
        ip: ip.to_string(),
        name,
        reachable: true,
        open_ports,
        last_seen: Utc::now().to_rfc3339(),
    })
}

async fn scan_open_ports(
    ip: Ipv4Addr,
    ports: Arc<Vec<u16>>,
    timeout_duration: Duration,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<PortInfo> {
    let concurrency = if ports.len() > 512 { 128 } else { 64 };

    let mut stream = stream::iter(ports.iter().copied().map(|port| {
        let cancel_flag = cancel_flag.clone();
        async move {
            if cancel_flag.load(Ordering::Relaxed) {
                return None;
            }

            scan_port(ip, port, timeout_duration).await
        }
    }))
    .buffer_unordered(concurrency);

    let mut open_ports = Vec::new();
    while let Some(port) = stream.next().await {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }
        if let Some(port) = port {
            open_ports.push(port);
        }
    }

    open_ports.sort_by_key(|item| item.port);
    open_ports
}

async fn scan_port(ip: Ipv4Addr, port: u16, timeout_duration: Duration) -> Option<PortInfo> {
    let socket = SocketAddr::new(IpAddr::V4(ip), port);

    match timeout(timeout_duration, TcpStream::connect(socket)).await {
        Ok(Ok(_)) => Some(PortInfo {
            port,
            state: "open".to_string(),
            service: service_name(port).map(ToString::to_string),
        }),
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

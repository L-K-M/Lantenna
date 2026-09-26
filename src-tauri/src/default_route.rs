//! Finds the interface that carries the IPv4 default route, so the UI can
//! start on the network the machine actually uses instead of a VM bridge or
//! a VPN tunnel that happens to sort first.

use crate::models::NetworkInterface;

/// Name of the interface that owns the IPv4 default route, if any. Blocks on
/// a subprocess; call it off the async runtime.
#[cfg(target_os = "macos")]
pub fn default_route_interface() -> Option<String> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Name of the interface that owns the IPv4 default route, if any.
#[cfg(target_os = "linux")]
pub fn default_route_interface() -> Option<String> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_net_route(&table)
}

/// Name of the interface that owns the IPv4 default route, if any.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_route_interface() -> Option<String> {
    None
}

/// Flags the interfaces named `default_interface` as carrying the default route.
pub fn mark_default_route(interfaces: &mut [NetworkInterface], default_interface: Option<&str>) {
    for interface in interfaces {
        interface.is_default_route = Some(interface.name.as_str()) == default_interface;
    }
}

/// Reads the `interface:` line of `route -n get default` output (macOS/BSD).
#[cfg(any(target_os = "macos", test))]
fn parse_route_get_interface(output: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("interface:"))
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(ToString::to_string)
}

/// Picks the lowest-metric default route (destination and mask 0) from the
/// Linux `/proc/net/route` table.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_route(table: &str) -> Option<String> {
    const RTF_UP: u32 = 0x1;

    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<&str>>();
            let (name, destination, flags, metric, mask) = (
                fields.first()?,
                fields.get(1)?,
                fields.get(3)?,
                fields.get(6)?,
                fields.get(7)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let is_default = *destination == "00000000" && *mask == "00000000";

            (is_default && flags & RTF_UP != 0)
                .then(|| (metric.parse::<u32>().unwrap_or(u32::MAX), name.to_string()))
        })
        .min()
        .map(|(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, ip: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            ip: ip.to_string(),
            cidr: 24,
            subnet: String::new(),
            host_count: 254,
            is_default_route: false,
        }
    }

    #[test]
    fn parses_macos_route_get_output() {
        let output = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

        assert_eq!(parse_route_get_interface(output).as_deref(), Some("en0"));
        assert_eq!(
            parse_route_get_interface("route: writing to routing socket: not in table"),
            None
        );
    }

    #[test]
    fn parses_lowest_metric_linux_default_route() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

        assert_eq!(parse_proc_net_route(table).as_deref(), Some("eth0"));
    }

    #[test]
    fn linux_table_without_default_route_has_no_default() {
        let table =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00004D0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";

        assert_eq!(parse_proc_net_route(table), None);
    }

    #[test]
    fn marks_only_the_default_route_interface() {
        let mut interfaces = vec![
            interface("bridge100", "192.168.64.1"),
            interface("en0", "192.168.1.100"),
            interface("utun4", "10.8.0.2"),
        ];

        mark_default_route(&mut interfaces, Some("en0"));

        let marked = interfaces
            .iter()
            .filter(|item| item.is_default_route)
            .map(|item| item.name.as_str())
            .collect::<Vec<&str>>();
        assert_eq!(marked, vec!["en0"]);
    }
}

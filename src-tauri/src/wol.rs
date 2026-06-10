use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const WOL_PORT: u16 = 9;

/// Sends a Wake-on-LAN magic packet for the given MAC address to the limited
/// broadcast address. The target device must have WoL enabled in its
/// firmware/OS for this to have any effect.
pub async fn send_magic_packet(mac: &str) -> Result<()> {
    let octets =
        parse_mac_octets(mac).with_context(|| format!("Invalid MAC address '{}'", mac))?;
    let packet = build_magic_packet(octets);

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind UDP socket for Wake-on-LAN")?;
    socket
        .set_broadcast(true)
        .context("Failed to enable UDP broadcast")?;

    let target = SocketAddr::from((Ipv4Addr::BROADCAST, WOL_PORT));
    socket
        .send_to(&packet, target)
        .await
        .context("Failed to send Wake-on-LAN magic packet")?;

    Ok(())
}

fn parse_mac_octets(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.trim().split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }

    let mut octets = [0u8; 6];
    for (slot, part) in octets.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }

    Some(octets)
}

fn build_magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(6 + 16 * 6);
    packet.extend_from_slice(&[0xFF; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_octets_accepts_colon_and_dash_separators() {
        assert_eq!(
            parse_mac_octets("AA:BB:CC:00:11:22"),
            Some([0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22])
        );
        assert_eq!(
            parse_mac_octets("aa-bb-cc-00-11-22"),
            Some([0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22])
        );
        assert_eq!(
            parse_mac_octets("a:b:c:0:1:2"),
            Some([0x0A, 0x0B, 0x0C, 0x00, 0x01, 0x02])
        );
    }

    #[test]
    fn parse_mac_octets_rejects_malformed_input() {
        assert_eq!(parse_mac_octets(""), None);
        assert_eq!(parse_mac_octets("AA:BB:CC:00:11"), None);
        assert_eq!(parse_mac_octets("AA:BB:CC:00:11:22:33"), None);
        assert_eq!(parse_mac_octets("GG:BB:CC:00:11:22"), None);
        assert_eq!(parse_mac_octets("AAA:BB:CC:00:11:22"), None);
    }

    #[test]
    fn build_magic_packet_has_correct_layout() {
        let mac = [0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22];
        let packet = build_magic_packet(mac);

        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        for repetition in 0..16 {
            let start = 6 + repetition * 6;
            assert_eq!(&packet[start..start + 6], &mac);
        }
    }
}

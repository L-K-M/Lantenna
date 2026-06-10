Several online databases allow programs to query device manufacturer via MAC address OUI, with some extending to product models and other details using LAN fingerprints like DHCP options.[1][2][3]

## OUI Lookup Services
These focus on manufacturer/vendor from the MAC address's first 3 bytes (OUI), registered with IEEE.[4][5]
- **maclookup.app**: Free REST API for vendor, address, and block info; accepts full MAC or OUI.[3]
- **macaddress.io**: API retrieves vendor, location, VM detection.[6]
- **IEEE OUI**: Downloadable text/CSV for local use; no hosted query API but basis for others.[5]

## Advanced Device Fingerprinting
**Fingerbank** (fingerbank.org) provides the most comprehensive API for LAN devices.[2][7]
- Queries with MAC, DHCP fingerprints (options order), User-Agent, etc., to identify manufacturer, model (e.g., "Samsung Galaxy S8"), OS, and confidence score.[8][2]
- REST API (v2) requires free API key via GitHub signup; supports interrogation endpoint for profiling.[9][2]
- Example: Submit device signals to get structured JSON with device name, manufacturer, version.[8]

## Integration Tips
Download IEEE OUI for offline/local lookup in scripts (e.g., Python dict from oui.txt).[10][11]
For full product info, combine with LAN protocols like LLDP/mDNS or nmap for fingerprints before API query.[12][13]
APIs are lightweight; rate limits apply (e.g., maclookup free tier).[3]

## Practical improvements implemented in Lantenna

Based on the references above and additional port-signature research, fingerprinting was improved with local-first signals:

### Phase 1: Port Signatures and Heuristics (Implemented)

- Expanded scan profiles with high-signal identification ports:
  - Apple mobile sync: `62078`
  - MikroTik RouterOS / Winbox + API: `8291`, `8728`, `8729`
  - Plex Media Server: `32400`
  - DVR/NVR families (Dahua/Amcrest-style): `37777`, `37778`
  - Camera/streaming and NAS admin signals: `554`, `5001`
- Added richer heuristic inference combining:
  - open-port signatures
  - reverse-DNS/hostname text hints
  - vendor/manufacturer hints from OUI/fingerprint sources
- Added stronger device-class/model guesses for:
  - cameras and NVRs
  - routers/network appliances (including MikroTik)
  - NAS/storage (including Synology-style profiles)
  - Apple mobile/Apple ecosystem hosts
  - media servers (Plex)
  - virtualization hosts/VMs
  - database/container-oriented server profiles

### Phase 2: Enhanced Fingerprinting (Implemented)

#### Service Banner Grabbing
Automatically extracts version and OS information from service banners:
- **SSH (port 22)**: Parses `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` style banners to detect:
  - SSH software and version
  - Operating system (Ubuntu, Debian, CentOS, FreeBSD, OpenBSD)
- **HTTP (ports 80, 443, 8080, 8443, 8000, 3000, 5000, 9000)**: Sends HEAD request, parses `Server:` header for:
  - Web server software (nginx, Apache, IIS, etc.)
  - Operating system hints
- **FTP (port 21)**: Captures welcome banner for FTP server identification

Banners are stored in `PortInfo.banner` field and used for OS fingerprinting.

#### mDNS/Bonjour Service Discovery
Queries mDNS multicast address to discover device services:
- Sends DNS-SD queries to `224.0.0.251:5353`
- Discovers services including:
  - `_airplay._tcp` / `_raop._tcp` - AirPlay devices (Apple TV, speakers)
  - `_googlecast._tcp` - Google Cast devices (Chromecast, speakers)
  - `_hap._tcp` / `_homekit._tcp` - Apple HomeKit devices
  - `_ipp._tcp` / `_printer._tcp` / `_pdl-datastream._tcp` - Network printers
  - `_spotify-connect._tcp` - Spotify Connect speakers
  - `_smb._tcp` / `_afpovertcp._tcp` - File servers
  - `_companion-link._tcp` - Apple Mac/iOS devices
  - `_daap._tcp` / `_dacp._tcp` - Apple media sharing

Discovered services stored in `DeviceFingerprint.discovered_services` and used to infer device type.

#### SSDP/UPnP Discovery
Multicast SSDP discovery for device information:
- Sends M-SEARCH to `239.255.255.250:1900`
- Parses responses for:
  - Device search target (ST/NT)
  - Server identification
  - Location URL for device description XML
  - USN (unique service name)

Useful for discovering: Smart TVs, media renderers, routers, NAS devices, IoT devices.

#### Enhanced Fingerbank Integration
Extended Fingerbank API to support all parameters:
- `mac` - MAC address (existing)
- `hostname` - Device hostname (existing)
- `dhcp_fingerprint` - Ordered DHCP options (infrastructure added)
- `dhcp_vendor` - DHCP vendor class identifier (infrastructure added)
- `user_agents` - Array of HTTP User-Agent strings (infrastructure added)
- `fqdn` - Fully qualified domain name (infrastructure added)

The `FingerbankQueryParams` struct enables future integration with DHCP fingerprinting.

---

## Implementation Status Summary

| Feature | Status | Impact |
|---------|--------|--------|
| Port signature scanning | ✅ Phase 1 | High |
| OUI vendor lookup | ✅ Phase 1 | High |
| Heuristic device inference | ✅ Phase 1 | High |
| Fingerbank API (basic) | ✅ Phase 1 | High |
| Service banner grabbing | ✅ Phase 2 | High |
| mDNS service discovery | ✅ Phase 2 | High |
| SSDP/UPnP discovery | ✅ Phase 2 | Medium |
| Enhanced Fingerbank params | ✅ Phase 2 (infra) | Medium |
| DHCP fingerprint capture | ❌ Not implemented | High |
| LLDP capture | ❌ Not implemented | High |
| SNMP probing | ❌ Not implemented | Medium |
| Nmap-style OS detection | ❌ Not implemented | High |

---

## Additional Fingerprinting Techniques (Not Yet Implemented)

### LLDP (Link Layer Discovery Protocol) - IEEE 802.1AB

LLDP provides authoritative device information via multicast frames:
- System name and description
- Port name and description
- VLAN name and IP management address
- System capabilities (switch, router, station, etc.)
- MAC/PHY information
- Power over Ethernet status

**Technical details:**
- Multicast address: `01:80:C2:00:00:0E`
- EtherType: `0x88CC`
- Frame contains TLV (Type-Length-Value) structures
- Cross-platform capture via pcap or raw sockets

### DHCP Fingerprinting

Capture DHCP packets to extract:
- DHCP option ordering (unique per OS)
- Vendor class identifier
- Client architecture hints

**Implementation:** Requires packet capture integration (pcap/socket)

### SNMP Device Identification

Network infrastructure often exposes SNMP:
- `1.3.6.1.2.1.1.1.0` - System description (sysDescr)
- `1.3.6.1.2.1.1.5.0` - System name (sysName)
- `1.3.6.1.2.1.1.2.0` - System OID (identifies vendor/model)

### Nmap-Style TCP/IP Fingerprinting

Advanced OS detection via protocol behavior:
- **ISN analysis**: Initial Sequence Number patterns reveal OS
- **TCP options ordering**: Different per OS (MSS, WScale, SACK, Timestamp)
- **Window size patterns**: 64=Linux, 128=Windows, varied for embedded
- **IP TTL initial values**: 64=Unix/Linux, 128=Windows, 255=Cisco/network
- **IP ID sequence**: Random (modern), incremental (Windows), zero (embedded)

*Note: Requires raw socket access and elevated privileges*

### NetBIOS/SMB Enumeration

For Windows host identification:
- NetBIOS name query on port 137/UDP
- SMB negotiate response for Windows version
- Workgroup/domain membership discovery

---

## Code Locations

| Component | File | Description |
|-----------|------|-------------|
| Port profiles | `scanner.rs` | `ports_for_profile()` function |
| Heuristic inference | `scanner.rs` | `infer_device_profile()` function |
| Banner grabbing | `scanner.rs` | `grab_banner_for_port()`, `grab_ssh_banner()`, etc. |
| mDNS discovery | `scanner.rs` | `query_mdns_services()`, `parse_mdns_response()` |
| SSDP discovery | `scanner.rs` | `discover_ssdp_devices()`, `parse_ssdp_response()` |
| Fingerbank query | `scanner.rs` | `lookup_fingerbank_with_params()`, `FingerbankQueryParams` |
| Fingerprint building | `scanner.rs` | `build_fingerprint()` function |
| Data models | `models.rs` | `PortInfo`, `DeviceFingerprint` structs |

---

Sources
[1] MAC Address Lookup | MAC/OUI/IAB/IEEE Vendor Search https://dnschecker.org/mac-lookup.php
[2] API documentation - Fingerbank https://api.fingerbank.org/api_doc/2.html
[3] Api V2 Documentation - MAC Address Lookup https://maclookup.app/api-v2/documentation
[4] standards‑oui.ieee.org https://standards-oui.ieee.org
[5] Registration Authority - IEEE Standards Association https://standards.ieee.org/products-programs/regauth/
[6] MAC address, OUI, IAB vendor API - MAC Address Vendor Lookup https://macaddress.io/api
[7] Fingerbank | Device Fingerprints https://www.fingerbank.org
[8] GET /api/v2/combinations/interrogate - Fingerbank https://api.fingerbank.org/api_doc/2/combinations/interrogate.html
[9] Fingerbank API - Free API Documentation | FindAPIs https://findapis.com/de/api/fingerbank
[10] Python script to get device vendor name from MAC Address https://www.tutorialspoint.com/python-script-to-get-device-vendor-name-from-mac-address
[11] Bash script for OUI lookups using IEEE OUI data file - Reddit https://www.reddit.com/r/networking/comments/rwpniq/bash_script_for_oui_lookups_using_ieee_oui_data/
[12] LanIdentifier Class (Windows.Networking.Connectivity) https://learn.microsoft.com/fr-fr/uwp/api/windows.networking.connectivity.lanidentifier?view=winrt-28000
[13] FingerBank: Device Fingerprinting & Identification Database https://datadome.co/anti-detect-tools/fingerbank/
[14] MAC Address Vendor Lookup: MAC/OUI/IAB/IEEE Vendor ... https://macaddress.io
[15] OUI Lookup Tool - Wireshark https://www.wireshark.org/tools/oui-lookup.html
[16] MAC Address Lookup - MAC/OUI Vendor Search https://macaddresslookup.io
[17] MAC Manufacturer Search - ipchecktool.com https://www.ipchecktool.com/tool/macfinder
[18] Get the device data for the given device id (Uuid) - Cisco DevNet https://developer.cisco.com/docs/dna-center/2-3-7-6/get-the-device-data-for-the-given-device-id-uuid/
[19] How to get device details from a mac address - Stack Overflow https://stackoverflow.com/questions/56730561/how-get-device-details-from-a-mac-address
[20] MAC Address Lookup: MAC Address Vendor Lookup https://maclookup.app
[21] Read Network Device Information with REST API and Store ... https://blog.ipspace.net/2019/06/read-network-device-information-with/
[22] MAC Address Lookup - Find Vendor - ScaniteX https://scanitex.com/en/tools/mac-lookup
[23] GET /api/v1/combinations/interogate - Fingerbank https://api.fingerbank.org/api_doc/1/combinations/interogate.html
[24] Implement API calls on fingerbank.org - GitHub https://github.com/siddharoodh/fingerbank-api
[25] MAC address vendor lookup API https://publicapis.io/mac-address-vendor-lookup-api
[26] Device Knowledge Base https://www.devicekb.com
[27] How to Use https://www.fingerbank.org/usage/
[28] Get Model Identifier of Device in Network https://stackoverflow.com/questions/75698677/get-model-identifier-of-device-in-network
[29] API documentation https://api.fingerbank.org/api_doc/2/static.html
[30] Link Layer Discovery Protocol - Wikipedia https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
[31] Nmap OS Detection Methods https://nmap.org/book/osdetect-methods.html
[32] DNS-SD Service Types https://www.dns-sd.org/ServiceTypes.html

![Wire-MCP Banner](wiremcp-rs.png)

# WireMCP-rs

MCP server for real-time network analysis — live packet capture, WiFi monitor mode scanning, threat detection — powered by native Rust parsing.

Forked from [0xKoda/WireMCP](https://github.com/0xKoda/WireMCP) and rewritten with Rust backends for performance (60x faster than tshark on packet parsing).

## Features

### MCP Tools

| Tool | Description | Backend |
|------|-------------|---------|
| **`capture_packets`** | Live packet capture with JSON output. Modes: `basic` (native Rust) or `full` (tshark deep dissection) | Rust |
| **`get_summary_stats`** | Protocol hierarchy statistics (eth, ip, tcp, udp, dns, tls, http...) | Rust |
| **`get_conversations`** | TCP/UDP conversation tracking with bytes, packets, duration per flow | Rust |
| **`check_threats`** | Capture IPs and check against URLhaus blacklist | Rust + JS |
| **`check_ip_threats`** | Check a specific IP against URLhaus IOCs | JS |
| **`analyze_pcap`** | Analyze existing PCAP files. Modes: `basic` or `full` | Rust |
| **`extract_credentials`** | Extract credentials from PCAP (HTTP Basic, FTP, Telnet, Kerberos hashes) | tshark |
| **`analyze_ddos`** | DDoS attack detection and analysis (25+ attack patterns, live or PCAP) | Rust |
| **`monitor_scan`** | WiFi monitor mode scan with HTML report (clients, vendors, WiFi standards, signal) | Rust |

### Native Rust Parsing (basic mode)

The `capture-rs` binary parses packets natively without tshark:

- **Ethernet** (MAC addresses, VLAN 802.1Q)
- **IPv4 / IPv6** (addresses, TTL, hop limit)
- **TCP** (ports, flags SYN/ACK/FIN/RST/PSH, seq, ack, window)
- **UDP** (ports, length)
- **ICMP** (type, code, description)
- **ARP** (request/reply, MACs, IPs)
- **DNS** (queries, responses with A/AAAA/CNAME records, name compression)
- **TLS** (SNI from ClientHello, version 1.0-1.3 via Supported Versions extension)
- **HTTP/1.x** (method, URI, Host, User-Agent, status, Content-Type, Server)
- **DHCP** (message type, hostname, vendor class, assigned IP)

### DDoS Detection Engine (analyze_ddos)

The `analyze_ddos` tool detects 25+ attack patterns from live traffic or PCAP files:

**L3/L4 Volumetric Floods:**
- SYN Flood (SYN/SYN+ACK ratio analysis)
- ACK Flood, RST Flood, FIN Flood
- UDP Flood (volume-based detection)
- ICMP Flood
- IP Fragmentation attack

**Amplification/Reflection (14 protocols):**

| Protocol | Port | Max Amplification |
|----------|------|-------------------|
| DNS | 53 | x54 000 |
| Memcached | 11211 | x51 000 |
| WS-Discovery | 3702 | x500 |
| NTP | 123 | x556 |
| Chargen | 19 | x358 |
| Jenkins | 33848 | x100 |
| CLDAP | 389 | x70 |
| ARMS | 3283 | x35 |
| CoAP | 5683 | x34 |
| SSDP/UPnP | 1900 | x30 |
| RPC Portmap | 111 | x7 |
| SNMP | 161 | x6.3 |
| Steam | 27015 | x5.5 |
| NetBIOS | 137 | x3.8 |

**L7 Application Layer:**
- HTTP/S GET Flood
- HTTP/S POST Flood
- WordPress XML-RPC Flood (pingback abuse)
- Random Path / Cache Bypass Flood (unique URI tracking)
- Rotating User-Agent Bot Detection (L7 botnet fingerprinting)
- HTTP Carpet Bombing (requests spread across many destination IPs)

**Slow Attacks:**
- Slowloris detection (many connections, small packets over long duration)
- Slow POST / RUDY detection

**DNS Attacks:**
- DNS Carpet Bombing (many unique subdomains of the same base domain)

**Meta Detection:**
- Multi-vector attack detection (automatic identification of simultaneous attack types)
- Distributed attack detection (many sources, high packet rate)
- Port scan / Scattershot detection
- Traffic timeline with per-second packet and bandwidth visualization

### WiFi Monitor Mode (monitor-scan-rs)

The `monitor-scan-rs` binary handles 802.11 monitor mode:

- Switches interface to monitor mode, captures, then restores managed mode
- Native radiotap header parsing (signal, data rate, MCS/VHT)
- 802.11 frame parsing with IE extraction (HT/VHT/HE for WiFi 4/5/6 detection)
- Auto channel detection (scans 2.4GHz + 5GHz channels)
- Generates a styled HTML report with:
  - Client table (MAC, vendor, WiFi standard, signal, AP, probes)
  - Statistics (vendor distribution, WiFi standards, AP distribution)
  - Signal strength bars, randomized MAC detection, power save status

## Installation

### Prerequisites

- Linux (tested on Fedora)
- [Wireshark](https://www.wireshark.org/download.html) (`tshark` in PATH — only needed for `full` mode and `extract_credentials`)
- Node.js (v16+)
- Rust toolchain (`cargo`)
- `libpcap-dev` / `libpcap-devel`

### Setup

```bash
git clone https://github.com/RomainRicord/WireMCP-rs.git
cd WireMCP-rs

# Install Node dependencies
npm install

# Build Rust binaries
cd capture-rs && cargo build --release && cd ..
cd monitor-scan-rs && cargo build --release && cd ..

# Set network capabilities (required for live capture without root)
sudo setcap cap_net_raw,cap_net_admin=eip capture-rs/target/release/capture-packets
sudo setcap cap_net_raw,cap_net_admin=eip monitor-scan-rs/target/release/monitor-scan
```

> **Note:** `setcap` must be re-run after each `cargo build --release`.

### Sudoers (for monitor mode)

Monitor mode requires `sudo` for `ip`, `iw`, and `nmcli`. Add to `/etc/sudoers`:

```
your_user ALL=(ALL) NOPASSWD: /usr/sbin/ip, /usr/sbin/iw
```

### Run

```bash
node index.js
```

## Usage with MCP Clients

### Claude Desktop / Cursor

Add to your MCP config:

```json
{
  "mcpServers": {
    "wiremcp-rs": {
      "command": "node",
      "args": ["/path/to/WireMCP-rs/index.js"]
    }
  }
}
```

### Standalone CLI (no MCP)

The monitor scan can also be used without MCP/LLM:

```bash
# Node.js CLI
node monitor-scan.js --interface wlo1 --channel 0 --duration 30 --output report.html

# Or directly with the Rust binary
./monitor-scan-rs/target/release/monitor-scan --interface wlo1 --channel 0 --duration 30 --output report.html

# Packet capture
./capture-rs/target/release/capture-packets --interface wlo1 --duration 5 --mode basic
./capture-rs/target/release/capture-packets --mode stats --file capture.pcap
./capture-rs/target/release/capture-packets --mode conversations --interface wlo1 --duration 10

# DDoS analysis (live or PCAP)
./capture-rs/target/release/capture-packets --mode ddos --interface eth0 --duration 60
./capture-rs/target/release/capture-packets --mode ddos --file attack.pcap
```

## Performance

| Operation | tshark (JS) | Rust native | Speedup |
|-----------|-------------|-------------|---------|
| Parse 125 packets | 0.124s | 0.002s | **60x** |
| Monitor scan (15k frames) | 1.33s CPU | 0.13s CPU | **10x** |
| Binary size | — | 859K (stripped) | — |

## Architecture

```
WireMCP-rs/
  index.js              # MCP server (9 tools, prompts)
  monitor-scan.js       # Standalone monitor mode CLI
  capture-rs/           # Rust: packet capture + parsing + DDoS detection
    src/main.rs         #   Modes: basic, full, stats, conversations, ddos
  monitor-scan-rs/      # Rust: WiFi monitor mode scanner
    src/main.rs         #   802.11 parsing, HTML report generation
```

## License

[MIT](LICENSE)

## Acknowledgments

- [0xKoda/WireMCP](https://github.com/0xKoda/WireMCP) — original project
- Wireshark/tshark — deep protocol dissection
- [pcap crate](https://crates.io/crates/pcap) — Rust libpcap bindings
- URLhaus — threat intelligence data
- Model Context Protocol — framework and specifications

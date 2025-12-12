# Vibe-DNS User Manual

A comprehensive, policy-driven DNS filtering server written in Python.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration Reference](#configuration-reference)
   - [Logging](#logging)
   - [Server Networking](#server-networking)
   - [GeoIP Configuration](#geoip-configuration)
   - [Upstream Resolution](#upstream-resolution)
   - [Caching](#caching)
   - [Rate Limiting](#rate-limiting)
   - [Response Modification](#response-modification)
   - [Domain Categorization](#domain-categorization)
   - [Client Groups](#client-groups)
   - [Schedules](#schedules)
   - [Filter Lists](#filter-lists)
   - [Policies](#policies)
   - [Assignments](#assignments)
5. [Use Cases & Examples](#use-cases--examples)
6. [GeoIP & ASN Blocking](#geoip--asn-blocking)
7. [Command Line Options](#command-line-options)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

Vibe-DNS is a smart, policy-driven DNS filtering engine that lets you build tailored DNS behaviour for different users, devices, and networks. It supports:

- **Client-aware filtering** - Identify clients by IP, subnet, MAC address, or server binding
- **Time-based controls** - Schedules for policies like "bedtime" or "school hours"
- **Domain categorization** - Classify domains (ads, adult, gambling, etc.) with confidence scoring
- **GeoIP and ASN blocking** - Block traffic based on geographic location or network ownership
- **Flexible policy engine** - Block, filter, sinkhole, or allow with upstream selection
- **Multiple blocklist sources** - Remote or local sources, hosts files, custom lists
- **Upstream resolver intelligence** - Load balancing, failover, health checks
- **Caching with prefetch** - Proactive cache refresh for low latency
- **Rate limiting** - Protection against abuse and flooding
- **Response shaping** - TTL clamping, CNAME flattening, round-robin

---

## Installation

### Requirements

- Python 3.12+ (tested on 3.14)
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Core dependencies:**
- `dnspython` - DNS protocol handling
- `httpx` - HTTP/2 client for DoH
- `PyYAML` - Configuration parsing
- `maxminddb` - GeoIP database support
- `regex` - Extended regex support

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/your-repo/vibe-dns/releases) page:

- `vibe-dns-server-linux-amd64`
- `vibe-dns-server-macos-arm64`
- `geoip-compiler-linux-amd64`
- `geoip-compiler-macos-arm64`

---

## Quick Start

### 1. Create a minimal configuration

Create `config.yaml`:

```yaml
server:
  bind_ip: ["0.0.0.0"]
  port_udp: [53]
  port_tcp: [53]

upstream:
  groups:
    Default:
      servers:
        - "udp://8.8.8.8:53"
        - "udp://1.1.1.1:53"

policies:
  Default:
    upstream_group: "Default"
```

### 2. Start the server

```bash
# With Python
python3 server.py --config config.yaml

# With binary
./vibe-dns-server-linux-amd64 --config config.yaml
```

### 3. Test it

```bash
dig @127.0.0.1 google.com
```

---

## Configuration Reference

### Logging

Controls how and where the server records events.

```yaml
logging:
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: "INFO"
  
  # Console output
  enable_console: true
  console_timestamp: true  # Set false for systemd/docker
  
  # File logging
  enable_file: false
  file_path: "./dns_server.log"
  
  # Syslog
  enable_syslog: false
  syslog_address: "/dev/log"  # Or "host:port" for remote
  syslog_protocol: "UDP"      # UDP or TCP
```

---

### Server Networking

Listener configuration and EDNS handling.

```yaml
server:
  # IPs to listen on ("0.0.0.0" for all IPv4, "::" for all IPv6)
  bind_ip: 
    - "0.0.0.0"
    - "::"
  
  # Or bind by interface name
  # bind_interfaces:
  #   - "eth0"
  #   - "wg0"
  
  # Ports (port 53 requires root)
  port_udp: [53]
  port_tcp: [53]
  
  # EDNS Client Subnet (ECS)
  use_ecs: true
  forward_ecs_mode: "none"  # none, preserve, add
  
  # MAC Address handling (EDNS option 65001)
  use_edns_mac: true
  forward_mac_mode: "none"  # none, preserve, add
```

**ECS Modes:**
| Mode | Description |
|------|-------------|
| `none` | Strip ECS data (privacy default) |
| `preserve` | Forward client's ECS if present |
| `add` | Inject client's actual IP as ECS |

---

### GeoIP Configuration

Geographic filtering and location awareness.

```yaml
geoip:
  enabled: true
  
  # Path to compiled database (use geoip_compiler.py)
  unified_database: "./geoip.vibe"
  
  # Country code TLD logic
  # - geoip_only:  Ignore TLDs, only use IP lookup (most accurate)
  # - cctld_first: If TLD matches blocked location, block immediately
  # - cctld_geoip: Use TLD as hint to disambiguate IP location
  cctld_mode: "geoip_only"
```

**Compile GeoIP Database:**

```bash
python3 geoip_compiler.py --output geoip.vibe
# Or with binary
./geoip-compiler-linux-amd64 --output geoip.vibe
```

---

### Upstream Resolution

Configuration for external DNS resolvers.

```yaml
upstream:
  # Check upstreams before starting
  startup_check_enabled: true
  
  # Use bootstrap servers if all fail
  fallback_enabled: false
  
  # Allow underscores in domain names (non-RFC)
  allow_underscores: false
  
  # Load balancing strategy
  mode: "fastest"
  
  # Health check interval (seconds)
  monitor_interval: 60
  monitor_on_query: true
  
  # Test domain for latency probes
  test_domain: "www.google.com"
  
  # HTTP/2 connection limit for DoH
  connection_limit: 20
  
  # Circuit breaker
  circuit_breaker_enabled: true
  circuit_failure_threshold: 3
  circuit_recovery_timeout: 30
  
  # Bootstrap DNS (for resolving DoH/DoT hostnames)
  bootstrap:
    - "8.8.8.8"
    - "1.1.1.1"
  
  # Server groups
  groups:
    Default:
      servers:
        - "udp://8.8.8.8:53"
        - "udp://1.1.1.1:53"
    
    Secure:
      servers:
        # DoT with forced IP
        - "tls://1.1.1.1:853#1.1.1.1"
        # DoH
        - "https://dns.google:443/dns-query#8.8.4.4"
```

**Load Balancing Modes:**

| Mode | Description |
|------|-------------|
| `fastest` | Use server with lowest latency |
| `loadbalance` | Distribute based on average response time |
| `failover` | Use first server; switch only on failure |
| `random` | Pick random server per request |
| `roundrobin` | Rotate through servers sequentially |
| `sticky` | Pin client IP to specific upstream |
| `none` | Use first available (dumb forwarder) |

**Upstream URL Syntax:**

```
protocol://host:port/path#forced_ip
```

| Protocol | Default Port | Example |
|----------|--------------|---------|
| `udp` | 53 | `udp://8.8.8.8:53` |
| `tcp` | 53 | `tcp://8.8.8.8:53` |
| `tls` (DoT) | 853 | `tls://1.1.1.1:853#1.1.1.1` |
| `https` (DoH) | 443 | `https://dns.google/dns-query#8.8.4.4` |

The `#forced_ip` suffix bypasses bootstrap resolution.

---

### Caching

Internal DNS response caching.

```yaml
cache:
  # Max cached records (0 = disabled)
  size: 10000
  
  # Garbage collection interval (seconds)
  gc_interval: 300
  
  # TTL for NXDOMAIN/failures
  negative_ttl: 60
  
  # Prefetch margin (seconds before expiry)
  # 0 = disabled
  prefetch_margin: 10
  
  # Minimum hits before prefetch kicks in
  prefetch_min_hits: 3

# Cache for policy decisions
decision_cache:
  size: 50000
  ttl: 300

# Request deduplication
deduplication:
  enabled: true  # Merge identical concurrent requests
```

---

### Rate Limiting

Protection against abuse and flooding.

```yaml
rate_limit:
  enabled: true
  
  # Time window (seconds)
  window_seconds: 60
  
  # Subnet grouping (32/128 = individual IPs)
  ipv4_mask: 32
  ipv6_mask: 128
  
  # UDP queries before forcing TCP (TC flag)
  udp_threshold: 100
  
  # Total queries before dropping
  total_threshold: 200
```

---

### Response Modification

How the server constructs answers.

```yaml
response:
  # Randomize A/AAAA record order
  round_robin_enabled: false
  
  # CNAME flattening (collapse to final IP)
  cname_collapse: true
  cname_empty_rcode: "NXDOMAIN"  # Or NOERROR
  
  # Strip Authority/Additional sections
  minimize_response: false
  
  # TTL normalization
  min_ttl: 0
  max_ttl: 86400
  ttl_sync_mode: "none"  # none, first, last, lowest, highest, average
  
  # Blocking behaviour
  block_rcode: "REFUSED"  # REFUSED, NXDOMAIN, NOERROR, SERVFAIL
  block_ttl: 60
  
  # Sinkhole IP ("NULL" = 0.0.0.0 / ::)
  block_ip: "NULL"
  
  # IP block mode
  # - filter: Remove only blocked IPs from answer
  # - block:  Block entire response if any IP is blocked
  ip_block_mode: "filter"
  
  # Check all answer IPs against blocklists
  match_answers_globally: false
```

---

### Domain Categorization

Built-in domain classification engine.

```yaml
categorization_enabled: true
categories_file: "categories.json"
```

**Available Categories:**

| Category | Description |
|----------|-------------|
| `ads` | Advertising and tracking |
| `adult` / `pornography` | Adult content |
| `gambling` | Betting and casinos |
| `social_media` | Social networks |
| `malware` | Known malicious domains |
| `phishing` | Phishing attempts |
| `crypto` | Cryptocurrency sites |
| `games` | Gaming platforms |
| `streaming_media` | Video/audio streaming |
| `file_sharing` | P2P and file hosts |
| `hacking_tools` | Security/hacking tools |
| `tracking` | Analytics and telemetry |

Categories use keyword matching, regex patterns, and TLD analysis to assign confidence scores (0-100%).

---

### Client Groups

Map clients to identifiers for policy assignment.

```yaml
# MAC cache refresh interval
mac_cache_refresh_interval: 300

# Group definitions
groups:
  admin_devices:
    - "10.0.0.5"
    - "AA:BB:CC:DD:EE:FF"
  
  iot_vlan:
    - { default_action: "ALLOW" }  # Optional override
    - "10.0.50.0/24"
    - "server_ip:10.0.50.1"
  
  kids:
    - "10.0.0.10"
    - "geoip:NL"  # Match by GeoIP
    
  vpn_users:
    - "server_ip:10.8.0.1"
    - "server_port:5353"

# Load groups from files
group_files:
  refresh_interval: 300
  kids: "./groups/kids.txt"
```

**Identifier Types:**

| Type | Example | Description |
|------|---------|-------------|
| IP Address | `192.168.1.5` | Exact IP match |
| CIDR Subnet | `192.168.1.0/24` | Subnet match |
| MAC Address | `aa:bb:cc:dd:ee:ff` | Hardware address |
| GeoIP Tag | `geoip:US` | Geographic location |
| Server IP | `server_ip:10.0.0.1` | Match by listener IP |
| Server Port | `server_port:5353` | Match by listener port |

---

### Schedules

Time-based policy activation.

```yaml
schedules:
  bedtime:
    - days: ["Mon", "Tue", "Wed", "Thu", "Sun"]
      start: "21:00"
      end: "07:00"
    - days: ["Fri", "Sat"]
      start: "23:00"
      end: "08:00"
  
  school_hours:
    - days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
      start: "08:00"
      end: "15:00"
  
  work_time:
    - days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
      start: "09:00"
      end: "17:00"
```

**Day Names:** `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat`, `Sun`

Schedules support overnight spans (e.g., 21:00-07:00).

---

### Filter Lists

Sources for blocking/allow rules.

```yaml
# Auto-refresh interval (seconds)
list_refresh_interval: 86400

lists:
  # Remote HTTP source
  ad_servers:
    - source: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      hosts_domain_type: "inclusive"
  
  # Local file
  my_whitelist:
    - source: "./lists/whitelist.txt"
      hosts_domain_type: "exact"
  
  # GeoIP list
  geo_block:
    - source: "./lists/geo.txt"
```

**Domain Match Types:**

| Type | Behaviour |
|------|-----------|
| `exact` | Matches domain exactly |
| `inclusive` | Matches domain and all subdomains |
| `exclusive` | Matches only subdomains (`*.example.com`) |

**List File Formats:**

```
# Hosts file format (0.0.0.0 or 127.0.0.1 prefix stripped)
0.0.0.0 ads.example.com
127.0.0.1 tracking.example.com

# Plain domain list
ads.example.com
tracking.example.com

# Regex patterns
/^ad[s]?-.*\.example\.com$/

# GeoIP tags (see GeoIP section)
@@CN
@RUSSIA
@AS15169
```

---

### Policies

Logic combining upstreams, lists, and actions.

```yaml
policies:
  Default:
    upstream_group: "Default"
  
  KidsPolicy:
    upstream_group: "Secure"
    
    # Lists to apply
    allow: ["my_whitelist"]
    block: ["ad_servers", "geo_block"]
    drop: []  # Silent drop (no response)
    
    # Query type filtering
    allowed_types: ["A", "AAAA", "CNAME", "HTTPS"]
    blocked_types: ["TXT", "ANY"]
    dropped_types: []
    
    # Category-based rules
    category_rules:
      gambling:
        min_confidence: 85
        action: "BLOCK"
      adult:
        min_confidence: 60
        action: "BLOCK"
      social_media:
        min_confidence: 90
        action: "DROP"
```

**Actions:**

| Action | Response |
|--------|----------|
| `ALLOW` | Process normally |
| `BLOCK` | Return configured block RCODE/IP |
| `DROP` | No response (timeout) |

**Built-in Policies:** `ALLOW`, `BLOCK`, `DROP` (can be used without definition)

---

### Assignments

Linking groups to policies and schedules.

```yaml
assignments:
  kids:
    policy: "KidsPolicy"
    schedule: "bedtime"
    schedule_policy: "BLOCK"  # Policy when schedule is active
  
  iot_vlan:
    policy: "Default"
  
  admin_devices:
    policy: "Default"
```

When a schedule is active, `schedule_policy` overrides the normal `policy`.

---

## Use Cases & Examples

### Example 1: Family Home Network

Block ads, adult content, and gambling for kids with bedtime enforcement.

```yaml
server:
  bind_ip: ["192.168.1.1"]
  port_udp: [53]

upstream:
  mode: "fastest"
  groups:
    Default:
      servers:
        - "udp://8.8.8.8:53"
        - "udp://1.1.1.1:53"
    Secure:
      servers:
        - "tls://1.1.1.1:853#1.1.1.1"

lists:
  ads:
    - source: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      hosts_domain_type: "inclusive"

groups:
  kids:
    - "192.168.1.100"
    - "192.168.1.101"
    - "AA:BB:CC:DD:EE:FF"

schedules:
  bedtime:
    - days: ["Sun", "Mon", "Tue", "Wed", "Thu"]
      start: "21:00"
      end: "07:00"
    - days: ["Fri", "Sat"]
      start: "23:00"
      end: "09:00"

policies:
  Default:
    upstream_group: "Default"
    block: ["ads"]
  
  KidsPolicy:
    upstream_group: "Secure"
    block: ["ads"]
    category_rules:
      adult:
        min_confidence: 50
        action: "BLOCK"
      gambling:
        min_confidence: 70
        action: "BLOCK"

assignments:
  kids:
    policy: "KidsPolicy"
    schedule: "bedtime"
    schedule_policy: "BLOCK"
```

---

### Example 2: IoT VLAN Isolation

Restrict IoT devices to specific DNS queries, block all external lookups.

```yaml
server:
  bind_ip:
    - "192.168.1.1"   # Main LAN
    - "192.168.50.1"  # IoT VLAN

upstream:
  groups:
    Default:
      servers:
        - "udp://8.8.8.8:53"
    IoT:
      servers:
        - "udp://192.168.1.1:53"  # Internal only

lists:
  iot_allowed:
    - source: "./lists/iot-allowed.txt"
      hosts_domain_type: "inclusive"

groups:
  iot_devices:
    - { default_action: "BLOCK" }
    - "192.168.50.0/24"
    - "server_ip:192.168.50.1"

policies:
  IoTPolicy:
    upstream_group: "IoT"
    allow: ["iot_allowed"]

assignments:
  iot_devices:
    policy: "IoTPolicy"
```

**iot-allowed.txt:**
```
# Allow specific cloud services
api.smart-home.com
updates.iot-vendor.com
time.google.com
```

---

### Example 3: Office Network with Work Hours

Different policies for work hours vs. after hours.

```yaml
server:
  bind_ip: ["10.0.0.1"]
  port_udp: [53]

upstream:
  groups:
    Default:
      servers:
        - "udp://8.8.8.8:53"
    Work:
      servers:
        - "https://dns.google/dns-query#8.8.8.8"

lists:
  social:
    - source: "./lists/social-media.txt"
      hosts_domain_type: "inclusive"
  streaming:
    - source: "./lists/streaming.txt"
      hosts_domain_type: "inclusive"

groups:
  employees:
    - "10.0.0.0/24"

schedules:
  work_hours:
    - days: ["Mon", "Tue", "Wed", "Thu", "Fri"]
      start: "09:00"
      end: "17:00"

policies:
  Default:
    upstream_group: "Default"
  
  WorkPolicy:
    upstream_group: "Work"
    block: ["social", "streaming"]

assignments:
  employees:
    policy: "Default"
    schedule: "work_hours"
    schedule_policy: "WorkPolicy"
```

---

### Example 4: GeoIP Country Blocking

Block all traffic from specific countries and ASNs.

```yaml
geoip:
  enabled: true
  unified_database: "./geoip.vibe"

lists:
  geo_restrictions:
    - source: "./lists/geo-block.txt"

policies:
  Default:
    upstream_group: "Default"
    block: ["geo_restrictions"]
```

**geo-block.txt:**
```
# Block Russia (both query and answer)
@@RU
@@RUSSIA

# Block China (query only - ccTLD)
@CN

# Block specific ASNs
@AS15169  # Google (example)
@AS13335  # Cloudflare (example)

# Block entire continents
@@ASIA
@AFRICA
```

---

### Example 5: Pi-hole Replacement

Full ad-blocking with multiple blocklists.

```yaml
server:
  bind_ip: ["0.0.0.0"]
  port_udp: [53]
  port_tcp: [53]

cache:
  size: 50000
  prefetch_margin: 30
  prefetch_min_hits: 2

upstream:
  mode: "fastest"
  monitor_interval: 30
  groups:
    Default:
      servers:
        - "tls://1.1.1.1:853#1.1.1.1"
        - "tls://1.0.0.1:853#1.0.0.1"

lists:
  stevenblack:
    - source: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      hosts_domain_type: "inclusive"
  
  energized:
    - source: "https://block.energized.pro/basic/formats/hosts"
      hosts_domain_type: "inclusive"
  
  whitelist:
    - source: "./lists/whitelist.txt"
      hosts_domain_type: "exact"

policies:
  Default:
    upstream_group: "Default"
    allow: ["whitelist"]
    block: ["stevenblack", "energized"]

response:
  block_rcode: "NXDOMAIN"
  block_ip: "NULL"
```

---

## GeoIP & ASN Blocking

### Rule Syntax

| Syntax | Scope | Example |
|--------|-------|---------|
| `@@TAG` | Block query (ccTLD) AND answer (IP) | `@@CN` |
| `@TAG` | Block query (ccTLD) only | `@RU` |
| `@AS###` | Block answer (ASN) only | `@AS15169` |

### Available Tags

**Countries (ISO 3166-1 alpha-2):**
```
US, CN, RU, DE, FR, GB, JP, AU, BR, IN, NL, ...
```

**Continents:**
```
AF (Africa), AN (Antarctica), AS (Asia), 
EU (Europe), NA (North America), 
OC (Oceania), SA (South America)
```

**Regions:**
```
AMERICA, ARABIA, EUROPE, ASIA, AFRICA, 
AL_MAGHRIB, BALTIC, BENELUX, NORDIC, OCEANIA, ...
```

### Generate Reference

```bash
python3 geoip_compiler.py --export-rules geoip.txt
```

This creates a complete reference of all available tags.

---

## Command Line Options

```bash
python3 server.py [OPTIONS]

Options:
  -c, --config PATH     Path to YAML config file (default: config.yaml)
  --validate-only       Validate configuration and exit
```

**Examples:**

```bash
# Start with custom config
python3 server.py --config /etc/vibe-dns/config.yaml

# Validate configuration
python3 server.py --config config.yaml --validate-only
```

---

## Troubleshooting

### Common Issues

**Port 53 permission denied:**
```bash
# Option 1: Run as root (not recommended for production)
sudo python3 server.py

# Option 2: Use setcap
sudo setcap 'cap_net_bind_service=+ep' $(which python3)

# Option 3: Use a port above 1024
port_udp: [5353]
```

**Upstream resolution fails:**
```
ERROR: Bootstrap resolution failed for 'dns.google'
```
Ensure bootstrap servers are reachable and correctly configured:
```yaml
upstream:
  bootstrap:
    - "8.8.8.8"
    - "1.1.1.1"
```

**GeoIP not working:**
```
WARNING: GeoIP database not found
```
Compile the database first:
```bash
python3 geoip_compiler.py --output geoip.vibe
```

**MAC resolution not working:**
Ensure the server can access the ARP/neighbour table:
```bash
# Linux
ip neigh show

# Check permissions
cat /proc/net/arp
```

### Debug Mode

Enable debug logging for detailed information:

```yaml
logging:
  level: "DEBUG"
```

### Configuration Validation

Always validate before deploying:

```bash
python3 server.py --config config.yaml --validate-only
```

This will report:
- **Errors** - Configuration problems that prevent startup
- **Warnings** - Non-critical issues to be aware of

---

## Performance Tuning

### High-Traffic Deployments

```yaml
cache:
  size: 100000        # Increase cache size
  prefetch_margin: 60
  prefetch_min_hits: 1

decision_cache:
  size: 100000

upstream:
  connection_limit: 50  # More DoH connections
  monitor_interval: 30

rate_limit:
  enabled: true
  udp_threshold: 500
  total_threshold: 1000
```

### Low-Memory Devices

```yaml
cache:
  size: 1000
  gc_interval: 60

decision_cache:
  size: 5000

categorization_enabled: false  # Disable if not needed
```

---

## License

This project is provided as-is for testing purposes. Use at your own risk.

---

*Generated for vibe-dns v9.0.0+*

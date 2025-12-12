# Vibe-DNS User Manual

**Vibe-DNS** is a high-performance, policy-driven DNS filtering server written in Python. It provides granular control over network traffic, allowing administrators to define rules based on client identity, time of day, geolocation, and domain categorization.

Whether you are securing a home network, managing a small office, or isolating IoT devices, Vibe-DNS allows you to mix blocking, allow-listing, and upstream selection strategies per user group.

---

## 📚 Table of Contents

1. [Features](#-features)
2. [Installation](#-installation)
    - [Method 1: Pre-built Binaries (Recommended)](#method-1-pre-built-binaries-recommended)
    - [Method 2: Running from Source](#method-2-running-from-source)
3. [Initial Setup (Crucial)](#-initial-setup-crucial)
    - [Compiling the GeoIP Database](#compiling-the-geoip-database)
4. [Configuration Guide](#-configuration-guide)
    - [Server & Networking](#server--networking)
    - [Defining Client Groups](#defining-client-groups)
    - [Upstream Resolvers (DoH/DoT)](#upstream-resolvers-dohdot)
    - [Filter Lists & Categories](#filter-lists--categories)
    - [Policies & Assignments](#policies--assignments)
5. [Use Case Examples](#-use-case-examples)
    - [Scenario 1: Parental Controls](#scenario-1-parental-controls-scheduling)
    - [Scenario 2: IoT Isolation](#scenario-2-iot-isolation-whitelist-only)
    - [Scenario 3: Geo-Blocking](#scenario-3-geo-blocking)
6. [Operational Management](#-operational-management)

---

## 🚀 Features

* **Granular Policies:** Apply different rules to different devices (Kids, IoT, Guests, Admin).
* **Smart Identification:** Identify clients by IP, Subnet (CIDR), MAC address (ARP/Neighbor lookup), or EDNS0 options.
* **GeoIP & ASN Blocking:** Block domains or IPs based on country, continent, or Autonomous System Number (ASN).
* **Time-Based Schedules:** Enforce rules only during specific times (e.g., "Bedtime").
* **Modern Upstreams:** Support for UDP, TCP, **DNS-over-HTTPS (DoH)**, and **DNS-over-TLS (DoT)** upstreams.
* **Intelligent Load Balancing:** Strategies include `fastest`, `loadbalance`, `failover`, `sticky`, and `random`.
* **Privacy Features:** ECS (EDNS Client Subnet) stripping/masking, QNAME minimization support, and DoH/DoT encryption.
* **Categorization:** Built-in engine to classify domains (e.g., Gambling, Social Media, Adult) with confidence scoring.
* **High Performance:** In-memory caching, prefetching, and request deduplication.

---

## 📥 Installation

### Method 1: Pre-built Binaries (Recommended)

Vibe-DNS provides standalone executables for Linux (AMD64) and macOS (Apple Silicon). These generally do not require Python to be installed on the system.

1.  Go to the [Releases](https://github.com/cbuijs/vibe-dns/releases) page of the repository.
2.  Download the binary matching your OS (e.g., `vibe-dns-server-linux-amd64`).
3.  Download the required configuration assets:
    * `config.yaml` (renamed from `full_config.yaml`)
    * `categories.json`
    * `geoip.txt`
4.  Make the binary executable:
    ```bash
    chmod +x vibe-dns-server-linux-amd64
    ```

### Method 2: Running from Source

Requirements: Python 3.11 or higher.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/cbuijs/vibe-dns.git
    cd vibe-dns
    ```

2.  **Set up a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```

---

## ⚙️ Initial Setup (Crucial)

**⚠️ Important:** Before running the server, you must compile the GeoIP database. The server relies on this for location-based blocking and ASN rules.

### Compiling the GeoIP Database

Vibe-DNS uses a custom high-performance binary format (`.vibe`). You can compile this from free data sources like IPInfo or MaxMind.

**Step 1: Get Source Data**
Download a free IP-to-Country JSON database (e.g., IPInfo Lite).
```bash
wget "https://ipinfo.io/data/ipinfo_lite.json.gz?token=<YOUR_TOKEN>" -O - | zcat > ipinfo_lite.json
```
*(Note: You can sign up for a free token at ipinfo.io)*

**Step 2: Run the Compiler**
Run the compiler tool included in the repo (or the `geoip-compiler` binary if you downloaded releases).

**From Source:**
```bash
python3 geoip_compiler.py --json ipinfo_lite.json --unified-output geoip.vibe
```

**Using Binary:**
```bash
./geoip-compiler-linux-amd64 --json ipinfo_lite.json --unified-output geoip.vibe
```

This generates a `geoip.vibe` file. Ensure this file is referenced in your `config.yaml`.

---

## 📝 Configuration Guide

The core configuration lives in `config.yaml` (renamed from `full_config.yaml`).

### Server & Networking
Configure where the DNS server listens.
```yaml
server:
  bind_ip: 
    - "0.0.0.0"  # Listen on all IPv4
    - "::"       # Listen on all IPv6
  port_udp: [53]
  port_tcp: [53]
  
  # Forwarding Client Subnet (ECS) for privacy
  forward_ecs_mode: "privacy" # Masks IP before sending to upstream
  ecs_ipv4_mask: 24
```

### Defining Client Groups
Groups identify *who* is making the request.
```yaml
groups:
  # Identification by IP or MAC
  kids_devices:
    - "192.168.1.50"
    - "AA:BB:CC:DD:EE:FF"
  
  # Identification by Subnet (VLAN)
  iot_vlan:
    - { default_action: "BLOCK" } # Default to blocking unknown traffic
    - "192.168.10.0/24"
    
  # Identification by Incoming Port (useful for VLAN gateways)
  guest_network:
    - "server_port:5353"
```

### Upstream Resolvers (DoH/DoT)
Define where queries go if they aren't blocked.
```yaml
upstream:
  mode: "fastest" # Uses the fastest responder
  groups:
    Default:
      servers:
        - "udp://1.1.1.1:53"
        - "udp://8.8.8.8:53"
    
    # Encrypted DNS for sensitive groups
    Secure:
      servers:
        - "https://dns.google:443/dns-query" # DoH
        - "tls://1.1.1.1:853"                # DoT
```

### Filter Lists & Categories
Define sources for blocklists.
```yaml
lists:
  ad_servers:
    - source: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  
  my_whitelist:
    - source: "./lists/whitelist.txt"
  
  # Special GeoIP list
  geo_block:
    - source: "./lists/geo.txt"
```

*Note on GeoIP Rules:*
* `@@CN` = Block Query (ccTLD .cn) **AND** Answer (IPs in China).
* `@CN` = Block Query (ccTLD .cn) only.
* `@AS13335` = Block IPs belonging to ASN 13335 (Cloudflare).

### Policies & Assignments
**Policies** define *what* to do (Allow/Block lists, Upstream usage).
**Assignments** link **Groups** to **Policies**.

```yaml
policies:
  KidsPolicy:
    upstream_group: "Secure"
    block: ["ad_servers", "geo_block"]
    category_rules:
      adult: { action: "BLOCK" }
      gambling: { action: "BLOCK" }

assignments:
  kids_devices:
    policy: "KidsPolicy"
    schedule: "bedtime"
    schedule_policy: "BLOCK" # Blocks everything during schedule
```

---

## 💡 Use Case Examples

### Scenario 1: Parental Controls & Scheduling
**Goal:** Block adult content for the Kids' iPad and disable internet entirely at night.

1.  **Define Schedule:**
    ```yaml
    schedules:
      bedtime:
        - { days: ["Sun", "Mon", "Tue", "Wed", "Thu"], start: "20:00", end: "07:00" }
        - { days: ["Fri", "Sat"], start: "22:00", end: "08:00" }
    ```
2.  **Define Policy:**
    ```yaml
    policies:
      SafeKids:
        category_rules:
          adult: { action: "BLOCK", min_confidence: 60 }
          social_media: { action: "BLOCK" }
    ```
3.  **Assign:**
    ```yaml
    assignments:
      kids_devices:
        policy: "SafeKids"
        schedule: "bedtime"
        schedule_policy: "BLOCK" # Hard block during bedtime
    ```

### Scenario 2: IoT Isolation (Whitelist Only)
**Goal:** Prevent a smart fridge from talking to anything except the manufacturer.

1.  **Define Group with Default Block:**
    ```yaml
    groups:
      smart_fridge:
        - { default_action: "BLOCK" } # Everything blocked by default
        - "192.168.1.55"
    ```
2.  **Define Whitelist:**
    Create `whitelist.txt` containing `samsung.com` and `aws.amazon.com`.
3.  **Define Policy:**
    ```yaml
    policies:
      IoT_Allow:
        allow: ["my_whitelist"] # Only allows domains in this list
    ```
4.  **Assign:**
    ```yaml
    assignments:
      smart_fridge:
        policy: "IoT_Allow"
    ```

### Scenario 3: Geo-Blocking
**Goal:** Block traffic to/from high-risk countries (e.g., North Korea, Russia) for the whole network.

1.  **Create Geo List:**
    Create `lists/geo.txt`:
    ```text
    @@KP  # North Korea
    @@RU  # Russia
    ```
2.  **Add to Default Policy:**
    ```yaml
    policies:
      Default:
        block: ["geo_block"]
    ```

---

## 🛠 Operational Management

### Running the Server
**From Source:**
```bash
python3 server.py --config config.yaml
```

**Using Binary:**
```bash
./vibe-dns-server-linux-amd64 --config config.yaml
```

### Logging
Logging is configured in the `logging` section of the config.
* **Console:** Good for debugging (`console_timestamp: true`).
* **File:** Set `enable_file: true` and `file_path: "/var/log/vibe-dns.log"`.
* **Syslog:** Supports sending logs to remote syslog servers via UDP/TCP.

### Reloading
Currently, Vibe-DNS loads configuration at startup. To apply changes to `config.yaml`, restart the service. However, **lists** and **group files** referenced by path are automatically refreshed in the background based on `refresh_interval` (default 300s).

### Troubleshooting
* **"GeoIP Database not found"**: Ensure you ran `geoip_compiler.py` and pointed `unified_database` in config to the correct path.
* **Permission Denied**: Binding to port 53 usually requires root privileges (`sudo`).
* **MAC Address not detected**: Ensure the server is on the same L2 network segment as the client, or use an EDNS-capable relay/router.

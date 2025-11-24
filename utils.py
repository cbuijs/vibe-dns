#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# Updated: 2025-11-24 14:20:00
# -----------------------------------------------------------------------------

import logging
import logging.handlers
import asyncio
import subprocess
import shutil
import time
import ipaddress
import sys
import os
import socket
import psutil

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
# This function sets up where the server logs its activities. It reads the
# 'logging' section from your config.yaml.
# It supports printing to the console (TTY), writing to a file, and sending logs
# to the system logger (Syslog) either locally or over the network.
# -----------------------------------------------------------------------------
def setup_logger(config):
    log_cfg = config.get('logging', {})
    logger = logging.getLogger("DNSFilter")
    
    # Determine log level (DEBUG/INFO/WARNING/ERROR). Defaults to INFO.
    # We strip whitespace just in case the config file is messy.
    level_str = log_cfg.get('level', 'INFO').upper().strip()
    numeric_level = getattr(logging, level_str, logging.INFO)
    
    logger.setLevel(numeric_level)
    
    # If we are reloading config, clear old handlers so we don't log everything twice!
    if logger.hasHandlers(): logger.handlers.clear()
    
    # Prevent logs from bubbling up to the root logger, which might have different settings.
    logger.propagate = False

    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # 1. Console Handler (Standard Output)
    if log_cfg.get('enable_console', True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric_level) # Ensure this handler respects our level
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # 2. File Handler (Writes to disk)
    if log_cfg.get('enable_file', False):
        file_path = log_cfg.get('file_path', './dns_server.log')
        try:
            fh = logging.FileHandler(file_path, encoding='utf-8')
            fh.setLevel(numeric_level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")

    # 3. Syslog Handler (System logs)
    if log_cfg.get('enable_syslog', False):
        syslog_addr = log_cfg.get('syslog_address', '/dev/log')
        syslog_proto = log_cfg.get('syslog_protocol', 'UDP').upper()
        
        try:
            address = syslog_addr
            socktype = socket.SOCK_DGRAM # Default UDP for Syslog
            
            # Check if address looks like a local file path (starts with /)
            is_local = syslog_addr.startswith('/')
            
            if not is_local:
                # It's a network address. Handle host:port format.
                if ':' in syslog_addr:
                    host, port = syslog_addr.split(':')
                    address = (host, int(port))
                else:
                    address = (syslog_addr, 514) # Default syslog port
                
                # Use TCP if requested for remote logging
                if syslog_proto == 'TCP':
                    socktype = socket.SOCK_STREAM
            
            # Windows doesn't have /dev/log, so we warn the user.
            if is_local and os.name != 'posix':
                print("Local syslog socket not supported on non-POSIX systems.")
            else:
                sh = logging.handlers.SysLogHandler(address=address, socktype=socktype)
                sh.setLevel(numeric_level)
                # Syslog daemon adds its own timestamp usually, so we use a simpler format.
                syslog_formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
                sh.setFormatter(syslog_formatter)
                logger.addHandler(sh)
                
        except Exception as e:
             print(f"Failed to setup Syslog: {e}")
    
    return logger

# Create a default logger so other modules don't crash on import before setup runs.
logger = logging.getLogger("DNSFilter")
logging.basicConfig(level=logging.INFO)

# -----------------------------------------------------------------------------
# Network Interface Helpers
# -----------------------------------------------------------------------------
# Reads the 'bind_ip' and 'bind_interfaces' from config.
# It finds all IP addresses associated with interface names like 'eth0' or 'wlan0'
# using the psutil library so the server knows exactly where to listen.
# -----------------------------------------------------------------------------
def get_server_ips(config):
    ips = set()
    
    # Grab explicit IPs listed in config
    bind_ips = config['server'].get('bind_ip', [])
    if isinstance(bind_ips, str): bind_ips = [bind_ips]
    for ip in bind_ips: ips.add(ip)
        
    # Resolve interface names (e.g., eth0) to actual IPs
    interfaces = config['server'].get('bind_interfaces', [])
    if isinstance(interfaces, str): interfaces = [interfaces]
        
    if interfaces:
        try:
            net_if_addrs = psutil.net_if_addrs()
            for iface in interfaces:
                if iface in net_if_addrs:
                    for snic in net_if_addrs[iface]:
                        # Add IPv4 addresses
                        if snic.family == socket.AF_INET:
                             ips.add(snic.address)
                        # Add IPv6 addresses (stripping the %scope_id part if present)
                        elif snic.family == socket.AF_INET6:
                            ip_clean = snic.address.split('%')[0]
                            ips.add(ip_clean)
                else:
                    logger.warning(f"Interface '{iface}' not found.")
        except Exception as e:
            logger.error(f"Failed to resolve interfaces: {e}")
            
    return list(ips)

def is_ip_in_network(ip_str, network_str):
    """Helper to check if an IP belongs to a CIDR range (e.g. 192.168.1.5 in 192.168.1.0/24)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(network_str, strict=False)
        return ip in net
    except ValueError:
        return False

# -----------------------------------------------------------------------------
# MAC Address Mapper
# -----------------------------------------------------------------------------
# This class figures out the MAC address of a client based on their IP.
# It uses the system's 'ip neigh' command (Linux only) and caches the result.
# It includes a background garbage collector to remove stale entries.
# -----------------------------------------------------------------------------
class MacMapper:
    def __init__(self, refresh_interval=300):
        self.cache = {}  # Stores {ip: (mac, timestamp)}
        self.refresh_interval = refresh_interval
        self.ip_cmd_available = shutil.which("ip") is not None
        
        # Fire up the background cleanup task
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        """Periodically removes old MAC entries to keep memory usage low."""
        while True:
            await asyncio.sleep(60) # Check every minute
            now = time.time()
            
            # Find IPs that haven't been refreshed recently
            expired = [ip for ip, (mac, ts) in self.cache.items() if now - ts > self.refresh_interval]
            
            for ip in expired:
                del self.cache[ip]
            
            if expired:
                logger.info(f"MAC CACHE GC: Flushed {len(expired)} expired entries.")

    def get_mac(self, ip_str):
        """Returns MAC for IP, using cache if valid, otherwise fetching fresh."""
        now = time.time()
        if ip_str in self.cache:
            mac, ts = self.cache[ip_str]
            # If cache is fresh, return it
            if now - ts < self.refresh_interval: return mac

        # Fetch fresh from system
        mac = self._fetch_mac(ip_str)
        if mac:
            self.cache[ip_str] = (mac, now)
        return mac

    def _fetch_mac(self, ip):
        """Runs the system command 'ip neigh show' to find MAC."""
        if not self.ip_cmd_available: return None
        try:
            cmd = ["ip", "neigh", "show", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            output = result.stdout.strip()
            parts = output.split()
            
            logger.debug(f"MAC LOOKUP CMD: {' '.join(cmd)} -> OUTPUT: {output}")
            
            # Output looks like: 192.168.1.5 dev eth0 lladdr 00:11:22:33:44:55 STALE
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mac = parts[idx + 1]
                    logger.debug(f"MAC FOUND for {ip}: {mac}")
                    return mac
        except Exception as e:
            logger.warning(f"MAC LOOKUP FAILED for {ip}: {e}")
        return None


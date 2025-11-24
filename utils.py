#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.1.8
# Updated: 2025-11-24 14:35:00
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
# Logging Configuration
# -----------------------------------------------------------------------------

def setup_logger(config):
    """
    Configures the global logger based on config.yaml settings.
    Supports TTY, File, and Syslog (Local/Remote, UDP/TCP).
    """
    log_cfg = config.get('logging', {})
    logger = logging.getLogger("DNSFilter")
    
    # Parse Level
    level_str = log_cfg.get('level', 'INFO').upper().strip()
    numeric_level = getattr(logging, level_str, logging.INFO)
    
    # Set Logger Level
    logger.setLevel(numeric_level)
    
    # Clear existing handlers to prevent duplicates on reload
    if logger.hasHandlers():
        logger.handlers.clear()

    # Do not propagate to root logger to avoid double logging if root has handlers
    logger.propagate = False

    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # 1. Console / TTY
    if log_cfg.get('enable_console', True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric_level) # Ensure handler respects level
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # 2. File Output
    if log_cfg.get('enable_file', False):
        file_path = log_cfg.get('file_path', './dns_server.log')
        try:
            fh = logging.FileHandler(file_path, encoding='utf-8')
            fh.setLevel(numeric_level) # Ensure handler respects level
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")

    # 3. Syslog Output (Local or Remote)
    if log_cfg.get('enable_syslog', False):
        syslog_addr = log_cfg.get('syslog_address', '/dev/log')
        syslog_proto = log_cfg.get('syslog_protocol', 'UDP').upper()
        
        try:
            address = syslog_addr
            socktype = socket.SOCK_DGRAM # Default UDP
            
            # Determine if Local or Remote
            is_local = syslog_addr.startswith('/')
            
            if not is_local:
                # Parse Host:Port
                if ':' in syslog_addr:
                    host, port = syslog_addr.split(':')
                    address = (host, int(port))
                else:
                    address = (syslog_addr, 514) # Default syslog port
                
                # Set Protocol for Remote
                if syslog_proto == 'TCP':
                    socktype = socket.SOCK_STREAM
            
            # Only allow local logging on POSIX systems
            if is_local and os.name != 'posix':
                print("Local syslog socket not supported on non-POSIX systems.")
            else:
                sh = logging.handlers.SysLogHandler(address=address, socktype=socktype)
                sh.setLevel(numeric_level) # Ensure handler respects level
                
                # Simplified format for Syslog (Daemon usually adds timestamp)
                syslog_formatter = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
                sh.setFormatter(syslog_formatter)
                logger.addHandler(sh)
                
        except Exception as e:
             print(f"Failed to setup Syslog: {e}")
    
    return logger

logger = logging.getLogger("DNSFilter")
# Set a default handler to avoid "No handler found" warnings before setup
logging.basicConfig(level=logging.INFO)

# -----------------------------------------------------------------------------
# Network Helpers
# -----------------------------------------------------------------------------

def get_server_ips(config):
    """
    Resolves all IPs to bind to from config (bind_ip list + bind_interfaces).
    """
    ips = set()
    
    # 1. Explicit IPs
    bind_ips = config['server'].get('bind_ip', [])
    if isinstance(bind_ips, str):
        bind_ips = [bind_ips]
    for ip in bind_ips:
        ips.add(ip)
        
    # 2. Interfaces
    interfaces = config['server'].get('bind_interfaces', [])
    if isinstance(interfaces, str):
        interfaces = [interfaces]
        
    if interfaces:
        try:
            net_if_addrs = psutil.net_if_addrs()
            for iface in interfaces:
                if iface in net_if_addrs:
                    for snic in net_if_addrs[iface]:
                        if snic.family == socket.AF_INET: # IPv4
                            ips.add(snic.address)
                        elif snic.family == socket.AF_INET6: # IPv6
                            # Remove scope ID (percentage sign) if present for binding
                            ip_clean = snic.address.split('%')[0]
                            ips.add(ip_clean)
                else:
                    logger.warning(f"Interface '{iface}' not found.")
        except Exception as e:
            logger.error(f"Failed to resolve interfaces: {e}")
            
    return list(ips)

def is_ip_in_network(ip_str, network_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(network_str, strict=False)
        return ip in net
    except ValueError:
        return False

# -----------------------------------------------------------------------------
# MAC Address Lookup
# -----------------------------------------------------------------------------

class MacMapper:
    def __init__(self, refresh_interval=300):
        self.cache = {}  # Stores {ip: (mac, timestamp)}
        self.refresh_interval = refresh_interval
        self.ip_cmd_available = shutil.which("ip") is not None
        
        # Start GC/Expire Loop
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(60) # Check every minute
            now = time.time()
            # Optimize cleanup: avoid creating list if cache is empty
            if not self.cache: continue
            
            expired = [ip for ip, (mac, ts) in self.cache.items() if now - ts > self.refresh_interval]
            
            for ip in expired:
                del self.cache[ip]
            
            if expired:
                logger.info(f"MAC CACHE GC: Flushed {len(expired)} expired entries.")

    def get_mac(self, ip_str):
        now = time.time()
        
        # Check cache first
        if ip_str in self.cache:
            mac, ts = self.cache[ip_str]
            if now - ts < self.refresh_interval:
                # Return cached MAC (could be None for negative cache)
                return mac

        # If not in cache or expired, fetch fresh
        mac = self._fetch_mac(ip_str)
        
        # Cache result (even if None/negative)
        self.cache[ip_str] = (mac, now)
        return mac

    def _fetch_mac(self, ip):
        if not self.ip_cmd_available: return None
        try:
            cmd = ["ip", "neigh", "show", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            output = result.stdout.strip()
            parts = output.split()
            
            logger.debug(f"MAC LOOKUP CMD: {' '.join(cmd)} -> OUTPUT: {output}")
            
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    mac = parts[idx + 1]
                    logger.debug(f"MAC FOUND for {ip}: {mac}")
                    return mac
        except Exception as e:
            logger.warning(f"MAC LOOKUP FAILED for {ip}: {e}")
        
        # Return None if not found (will be cached as negative result)
        return None


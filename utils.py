#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.1
# Updated: 2025-11-25 08:00:00
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
# Sets up logging handlers (Console, File, Syslog).
# Configures formatters based on settings (e.g. toggling timestamp for TTY).
# -----------------------------------------------------------------------------
def setup_logger(config):
    log_cfg = config.get('logging', {})
    logger = logging.getLogger("DNSFilter")
    
    level_str = log_cfg.get('level', 'INFO').upper().strip()
    numeric_level = getattr(logging, level_str, logging.INFO)
    
    logger.setLevel(numeric_level)
    if logger.hasHandlers(): logger.handlers.clear()
    logger.propagate = False

    # Formatters
    fmt_full = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fmt_simple = logging.Formatter('[%(levelname)s] %(message)s')

    # 1. Console Handler (TTY)
    if log_cfg.get('enable_console', True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric_level)
        # Check config option to decide which formatter to use for console
        if log_cfg.get('console_timestamp', True):
            ch.setFormatter(fmt_full)
        else:
            ch.setFormatter(fmt_simple)
        logger.addHandler(ch)

    # 2. File Handler (Always includes timestamp)
    if log_cfg.get('enable_file', False):
        file_path = log_cfg.get('file_path', './dns_server.log')
        try:
            fh = logging.FileHandler(file_path, encoding='utf-8')
            fh.setLevel(numeric_level)
            fh.setFormatter(fmt_full)
            logger.addHandler(fh)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")

    # 3. Syslog Handler (Timestamp usually handled by syslog daemon)
    if log_cfg.get('enable_syslog', False):
        syslog_addr = log_cfg.get('syslog_address', '/dev/log')
        syslog_proto = log_cfg.get('syslog_protocol', 'UDP').upper()
        try:
            address = syslog_addr
            socktype = socket.SOCK_DGRAM 
            is_local = syslog_addr.startswith('/')
            
            if not is_local:
                if ':' in syslog_addr:
                    host, port = syslog_addr.split(':')
                    address = (host, int(port))
                else: address = (syslog_addr, 514)
                if syslog_proto == 'TCP': socktype = socket.SOCK_STREAM
            
            if is_local and os.name != 'posix':
                print("Local syslog socket not supported on non-POSIX systems.")
            else:
                sh = logging.handlers.SysLogHandler(address=address, socktype=socktype)
                sh.setLevel(numeric_level)
                # Use simple format for syslog as the daemon adds metadata
                sh.setFormatter(logging.Formatter('%(name)s: [%(levelname)s] %(message)s'))
                logger.addHandler(sh)
        except Exception as e: print(f"Failed to setup Syslog: {e}")
    return logger

logger = logging.getLogger("DNSFilter")
logging.basicConfig(level=logging.INFO)

# -----------------------------------------------------------------------------
# Network Interface Helpers
# -----------------------------------------------------------------------------
def get_server_ips(config):
    ips = set()
    bind_ips = config['server'].get('bind_ip', [])
    if isinstance(bind_ips, str): bind_ips = [bind_ips]
    for ip in bind_ips: ips.add(ip)
        
    interfaces = config['server'].get('bind_interfaces', [])
    if isinstance(interfaces, str): interfaces = [interfaces]
        
    if interfaces:
        try:
            net_if_addrs = psutil.net_if_addrs()
            for iface in interfaces:
                if iface in net_if_addrs:
                    for snic in net_if_addrs[iface]:
                        if snic.family == socket.AF_INET: ips.add(snic.address)
                        elif snic.family == socket.AF_INET6:
                            ip_clean = snic.address.split('%')[0]
                            ips.add(ip_clean)
                else: logger.warning(f"Interface '{iface}' not found.")
        except Exception as e: logger.error(f"Failed to resolve interfaces: {e}")
    return list(ips)

def is_ip_in_network(ip_str, network_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(network_str, strict=False)
        return ip in net
    except ValueError: return False

# -----------------------------------------------------------------------------
# MAC Address Lookup
# -----------------------------------------------------------------------------
class MacMapper:
    def __init__(self, refresh_interval=300):
        self.cache = {} 
        self.refresh_interval = refresh_interval
        self.ip_cmd_available = shutil.which("ip") is not None
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(60)
            now = time.time()
            if not self.cache: continue
            
            expired = [ip for ip, (mac, ts) in self.cache.items() if now - ts > self.refresh_interval]
            for ip in expired: del self.cache[ip]
            if expired: logger.info(f"MAC CACHE GC: Flushed {len(expired)} expired entries.")

    def get_mac(self, ip_str):
        now = time.time()
        if ip_str in self.cache:
            mac, ts = self.cache[ip_str]
            if now - ts < self.refresh_interval: return mac
        mac = self._fetch_mac(ip_str)
        # Cache negative result (None) as well to avoid spamming system calls
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
                if idx + 1 < len(parts): return parts[idx + 1]
        except Exception as e: pass
        return None


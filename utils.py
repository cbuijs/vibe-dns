#!/usr/bin/env python3
# filename: utils.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.3.1 (No Link-Local Binding) - Compatible with v3.0.0
# -----------------------------------------------------------------------------
"""
Utility functions and classes.

Contains:
1. ContextAdapter: Logging adapter for injecting request context.
2. Logging setup helper.
3. Network Interface discovery.
4. MAC Address Mapping (ARP/Neighbour table lookups).
"""

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
import re

class ContextAdapter(logging.LoggerAdapter):
    """
    Prepends context variables (ID, IP, MAC, PROTO) to log messages.
    """
    def process(self, msg, kwargs):
        priority = ['id', 'ip', 'mac', 'proto']
        context_parts = []
        for key in priority:
            if key in self.extra:
                val = self.extra[key]
                if val: context_parts.append(f"[{key.upper()}:{val}]")
        for key, val in self.extra.items():
            if key not in priority and val:
                context_parts.append(f"[{key.upper()}:{val}]")
        prefix = " ".join(context_parts)
        return f"{prefix} {msg}", kwargs

def get_logger(name):
    """Factory for namespaced loggers."""
    return logging.getLogger(f"DNSFilter.{name}")

def setup_logger(config):
    """Configures handlers (Console, File, Syslog) based on config dict."""
    log_cfg = config.get('logging', {})
    root_logger = logging.getLogger("DNSFilter")
    level_str = log_cfg.get('level', 'INFO').upper().strip()
    numeric_level = getattr(logging, level_str, logging.INFO)
    root_logger.setLevel(numeric_level)
    if root_logger.hasHandlers(): root_logger.handlers.clear()
    root_logger.propagate = False
    
    fmt_full = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fmt_simple = logging.Formatter('[%(levelname)s] [%(name)s] %(message)s')

    # Console Handler
    if log_cfg.get('enable_console', True):
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(numeric_level)
        if log_cfg.get('console_timestamp', True): ch.setFormatter(fmt_full)
        else: ch.setFormatter(fmt_simple)
        root_logger.addHandler(ch)

    # File Handler
    if log_cfg.get('enable_file', False):
        file_path = log_cfg.get('file_path', './dns_server.log')
        try:
            fh = logging.FileHandler(file_path, encoding='utf-8')
            fh.setLevel(numeric_level)
            fh.setFormatter(fmt_full)
            root_logger.addHandler(fh)
        except Exception as e: print(f"FATAL: Failed to setup file logging: {e}")

    # Syslog Handler
    if log_cfg.get('enable_syslog', False):
        try:
            syslog_addr = log_cfg.get('syslog_address', '/dev/log')
            syslog_proto = log_cfg.get('syslog_protocol', 'UDP').upper()
            address = syslog_addr
            socktype = socket.SOCK_DGRAM 
            if not syslog_addr.startswith('/'):
                if ':' in syslog_addr:
                    host, port = syslog_addr.split(':')
                    address = (host, int(port))
                else: address = (syslog_addr, 514)
                if syslog_proto == 'TCP': socktype = socket.SOCK_STREAM
            sh = logging.handlers.SysLogHandler(address=address, socktype=socktype)
            sh.setLevel(numeric_level)
            syslog_fmt = logging.Formatter('%(name)s: [%(levelname)s] %(message)s')
            sh.setFormatter(syslog_fmt)
            root_logger.addHandler(sh)
        except Exception as e: print(f"FATAL: Failed to setup Syslog: {e}")

    return root_logger

def get_server_ips(config):
    """
    Returns a list of IP addresses to bind to.
    Parses 'bind_ip' and 'bind_interfaces' from config.
    """
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
                            try:
                                ip_obj = ipaddress.ip_address(ip_clean)
                                if not ip_obj.is_link_local: ips.add(ip_clean)
                            except ValueError: pass
        except Exception: pass
    return list(ips)

def is_ip_in_network(ip_str, network_str):
    """Helper to check if an IP string belongs to a CIDR network string."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(network_str, strict=False)
        return ip in net
    except ValueError: return False

class MacMapper:
    """
    Maintains a mapping of IP addresses to MAC addresses by querying 
    system ARP/Neighbour tables. Used for client identification.
    """
    def __init__(self, refresh_interval=300):
        self.cache = {} 
        self.refresh_interval = refresh_interval
        self.ip_cmd_available = shutil.which("ip") is not None
        self.populate_from_system_arp()
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        """Garbage collects old MAC entries."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            expired = [ip for ip, (mac, ts) in self.cache.items() if now - ts > self.refresh_interval]
            for ip in expired: del self.cache[ip]

    def populate_from_system_arp(self):
        """Initial population of ARP cache."""
        now = time.time()
        try:
            if sys.platform == 'linux' and self.ip_cmd_available:
                cmd = ["ip", "neigh", "show"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        try:
                            ip = parts[0]
                            idx = parts.index("lladdr")
                            if idx + 1 < len(parts):
                                self.cache[ip] = (parts[idx + 1].upper(), now)
                        except: pass
            elif sys.platform == 'win32':
                cmd = ["arp", "-a"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                pattern = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})')
                for match in pattern.finditer(result.stdout):
                    ip, mac_raw = match.groups()
                    self.cache[ip] = (mac_raw.replace('-', ':').upper(), now)
            elif sys.platform == 'darwin':
                cmd = ["arp", "-a"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                for line in result.stdout.splitlines():
                    try:
                        ip_start = line.find('(')
                        ip_end = line.find(')')
                        if ip_start != -1 and ip_end != -1:
                            ip = line[ip_start+1:ip_end]
                            at_index = line.find(" at ")
                            if at_index != -1:
                                remainder = line[at_index+4:].split()
                                if remainder:
                                    mac_raw = remainder[0]
                                    if ':' in mac_raw:
                                        self.cache[ip] = (':'.join(f'{int(x, 16):02x}' for x in mac_raw.split(':')).upper(), now)
                    except: pass
        except Exception: pass

    def get_mac(self, ip_str):
        """Retrieves MAC for an IP. Checks cache first, then OS."""
        now = time.time()
        if ip_str in self.cache:
            mac, ts = self.cache[ip_str]
            if now - ts < self.refresh_interval: return mac
        mac = self._fetch_mac(ip_str)
        self.cache[ip_str] = (mac, now)
        return mac

    def _fetch_mac(self, ip):
        """Platform-specific command to get MAC for a single IP."""
        if sys.platform == 'linux' and self.ip_cmd_available:
            try:
                cmd = ["ip", "neigh", "show", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
                output = result.stdout.strip()
                parts = output.split()
                if "lladdr" in parts:
                    return parts[parts.index("lladdr") + 1].upper()
            except Exception: pass
        return None


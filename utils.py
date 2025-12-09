#!/usr/bin/env python3
# filename: utils.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 5.0.0 (Optimized - Cached Platform Detection)
# -----------------------------------------------------------------------------
"""
Utility functions and classes with performance optimizations.
"""

import logging
import logging.handlers
import subprocess
import ipaddress
import asyncio
import time
from pathlib import Path

# Global logger dictionary
_loggers = {}

def setup_logger(config):
    """Configure logging based on config."""
    log_config = config.get('logging', {})
    level_str = log_config.get('level', 'INFO').upper()
    level = getattr(logging, level_str, logging.INFO)
    
    # Root logger configuration
    root_logger = logging.getLogger('DNSFilter')
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    
    # Console handler
    if log_config.get('enable_console', True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        if log_config.get('console_timestamp', True):
            formatter = logging.Formatter('[%(levelname)s] [%(name)s] %(message)s')
        else:
            formatter = logging.Formatter('[%(levelname)s] [%(name)s] %(message)s')
        
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_config.get('enable_file', False):
        file_path = log_config.get('file_path', './dns_server.log')
        try:
            file_handler = logging.FileHandler(file_path)
            file_handler.setLevel(level)
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            print(f"Failed to setup file logging: {e}")
    
    # Syslog handler
    if log_config.get('enable_syslog', False):
        try:
            syslog_addr = log_config.get('syslog_address', '/dev/log')
            if syslog_addr.startswith('/'):
                syslog_handler = logging.handlers.SysLogHandler(address=syslog_addr)
            else:
                host, port = syslog_addr.split(':')
                protocol = log_config.get('syslog_protocol', 'UDP').upper()
                socktype = logging.handlers.socket.SOCK_DGRAM if protocol == 'UDP' else logging.handlers.socket.SOCK_STREAM
                syslog_handler = logging.handlers.SysLogHandler(
                    address=(host, int(port)),
                    socktype=socktype
                )
            
            syslog_handler.setLevel(level)
            formatter = logging.Formatter('[%(name)s] %(message)s')
            syslog_handler.setFormatter(formatter)
            root_logger.addHandler(syslog_handler)
        except Exception as e:
            print(f"Failed to setup syslog: {e}")

def get_logger(name):
    """Get or create a logger with the given name."""
    full_name = f"DNSFilter.{name}"
    if full_name not in _loggers:
        _loggers[full_name] = logging.getLogger(full_name)
    return _loggers[full_name]

class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds context to log messages."""
    def process(self, msg, kwargs):
        ctx = self.extra
        prefix_parts = []
        if 'id' in ctx:
            prefix_parts.append(f"[ID:{ctx['id']}]")
        if 'ip' in ctx:
            prefix_parts.append(f"[IP:{ctx['ip']}]")
        if 'mac' in ctx:
            prefix_parts.append(f"[MAC:{ctx['mac']}]")
        if 'proto' in ctx:
            prefix_parts.append(f"[PROTO:{ctx['proto']}]")
        
        prefix = ' '.join(prefix_parts)
        return f"{prefix} {msg}" if prefix else msg, kwargs

def is_ip_in_network(ip_str, cidr_str):
    """Check if IP is in CIDR network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except Exception:
        return False

def is_link_local(ip_str):
    """Check if IP is link-local (simplified)"""
    try:
        return ipaddress.ip_address(ip_str).is_link_local
    except Exception:
        return False

def get_server_ips(config):
    """
    Get list of IPs to bind to based on config.
    Supports both explicit bind_ip and bind_interfaces.
    Filters out link-local addresses.
    """
    logger = get_logger("Utils")
    server_cfg = config.get('server', {})
    ips = []
    
    # Explicit IP addresses
    if 'bind_ip' in server_cfg:
        bind_ips = server_cfg['bind_ip']
        if isinstance(bind_ips, str):
            ips.append(bind_ips)
        elif isinstance(bind_ips, list):
            ips.extend(bind_ips)
        logger.debug(f"Using explicit bind_ip: {ips}")
    
    # Interface names (resolve to IPs)
    if 'bind_interfaces' in server_cfg:
        interfaces = server_cfg['bind_interfaces']
        if isinstance(interfaces, str):
            interfaces = [interfaces]
        
        logger.debug(f"Resolving interfaces: {interfaces}")
        
        try:
            import netifaces
            logger.debug("Using netifaces for interface resolution")
            
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    
                    # IPv4
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            if 'addr' in addr_info:
                                ip = addr_info['addr']
                                if is_link_local(ip):
                                    logger.debug(f"Skipping link-local address on {iface}: {ip}")
                                    continue
                                ips.append(ip)
                                logger.debug(f"Interface {iface} IPv4: {ip}")
                    
                    # IPv6
                    if netifaces.AF_INET6 in addrs:
                        for addr_info in addrs[netifaces.AF_INET6]:
                            if 'addr' in addr_info:
                                ip6 = addr_info['addr'].split('%')[0]
                                if is_link_local(ip6):
                                    logger.debug(f"Skipping link-local address on {iface}: {ip6}")
                                    continue
                                ips.append(ip6)
                                logger.debug(f"Interface {iface} IPv6: {ip6}")
                
                except ValueError as e:
                    logger.warning(f"Interface {iface} not found: {e}")
                except Exception as e:
                    logger.warning(f"Failed to get IPs for interface {iface}: {e}")
                    
        except ImportError:
            logger.info("netifaces not installed, using system commands as fallback")
            
            for iface in interfaces:
                try:
                    result = subprocess.run(
                        ['ip', 'addr', 'show', iface],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            line = line.strip()
                            
                            if line.startswith('inet '):
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip = parts[1].split('/')[0]
                                    if is_link_local(ip):
                                        continue
                                    ips.append(ip)
                                    logger.debug(f"Interface {iface} IPv4: {ip}")
                            
                            elif line.startswith('inet6 '):
                                parts = line.split()
                                if len(parts) >= 2:
                                    ip6 = parts[1].split('/')[0]
                                    if is_link_local(ip6):
                                        continue
                                    ips.append(ip6)
                                    logger.debug(f"Interface {iface} IPv6: {ip6}")
                    else:
                        logger.warning(f"Failed to query interface {iface} with 'ip' command")
                        
                except FileNotFoundError:
                    try:
                        result = subprocess.run(
                            ['ifconfig', iface],
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        
                        if result.returncode == 0:
                            for line in result.stdout.splitlines():
                                line = line.strip()
                                
                                if line.startswith('inet '):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        ip = parts[1]
                                        if is_link_local(ip):
                                            continue
                                        ips.append(ip)
                                        logger.debug(f"Interface {iface} IPv4: {ip}")
                                
                                elif line.startswith('inet6 '):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        ip6 = parts[1].split('%')[0]
                                        if is_link_local(ip6):
                                            continue
                                        ips.append(ip6)
                                        logger.debug(f"Interface {iface} IPv6: {ip6}")
                        else:
                            logger.warning(f"Failed to query interface {iface} with 'ifconfig' command")
                            
                    except Exception as e:
                        logger.error(f"Failed to get IPs for interface {iface}: {e}")
                        
                except Exception as e:
                    logger.error(f"Error resolving interface {iface}: {e}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    
    if unique_ips:
        logger.info(f"Resolved {len(unique_ips)} unique IPs for binding: {unique_ips}")
    else:
        logger.warning("No IPs resolved - check bind_ip or bind_interfaces configuration")
    
    return unique_ips

class MacMapper:
    """
    Maps IP addresses to MAC addresses using system neighbor table.
    Optimized with cached platform detection and command selection.
    """
    def __init__(self, refresh_interval=300):
        self.cache = {}
        self.refresh_interval = refresh_interval
        self.last_refresh = 0
        self.logger = get_logger("MacMapper")
        
        # Cache platform detection
        self.platform = self._detect_platform()
        self.arp_command = self._select_arp_command()
        self.ipv6_supported = False
        
        # Initial load
        self._refresh_cache()
        
        # Start background refresh task
        asyncio.create_task(self._refresh_loop())
    
    def _detect_platform(self):
        """Detect the operating system platform (cached)"""
        import platform
        system = platform.system().lower()
        
        if system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'macos'
        elif system == 'windows':
            return 'windows'
        else:
            self.logger.warning(f"Unknown platform '{system}', defaulting to linux")
            return 'linux'
    
    def _select_arp_command(self):
        """Select appropriate ARP command for platform (cached)"""
        if self.platform == 'linux':
            return ['ip', 'neigh', 'show']
        elif self.platform == 'macos':
            return ['arp', '-na']
        elif self.platform == 'windows':
            return ['arp', '-a']
        return ['arp', '-an']
    
    def _parse_mac(self, mac_str):
        """Parse and validate MAC address, normalizing format"""
        if not mac_str:
            return None
        
        clean = mac_str.upper().replace(':', '').replace('-', '').replace('.', '')
        
        if len(clean) != 12:
            return None
        
        try:
            int(clean, 16)
        except ValueError:
            return None
        
        return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
    
    def _parse_linux_ip_neigh(self, output):
        """Parse 'ip neigh show' output (Linux)"""
        new_cache = {}
        ipv6_count = 0
        
        for line in output.splitlines():
            parts = line.split()
            
            if len(parts) < 4:
                continue
            
            try:
                ip = parts[0]
                
                if 'lladdr' in parts:
                    idx = parts.index('lladdr')
                    if idx + 1 < len(parts):
                        mac = self._parse_mac(parts[idx + 1])
                        if mac:
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if ip_obj.version == 6:
                                    ipv6_count += 1
                                    self.ipv6_supported = True
                            except ValueError:
                                continue
                            
                            new_cache[ip] = mac
            except (ValueError, IndexError):
                continue
        
        if ipv6_count > 0:
            self.logger.debug(f"Found {ipv6_count} IPv6 neighbors")
        
        return new_cache
    
    def _parse_linux_arp(self, output):
        """Parse 'arp -an' output (Linux fallback)"""
        new_cache = {}
        
        for line in output.splitlines():
            parts = line.split()
            
            if len(parts) < 4:
                continue
            
            try:
                ip = parts[1].strip('()')
                
                if parts[2] == 'at':
                    mac = self._parse_mac(parts[3])
                    if mac:
                        new_cache[ip] = mac
            except (ValueError, IndexError):
                continue
        
        return new_cache
    
    def _parse_macos_arp(self, output):
        """Parse 'arp -na' output (macOS)"""
        new_cache = {}
        
        for line in output.splitlines():
            parts = line.split()
            
            if len(parts) < 4:
                continue
            
            try:
                ip = parts[1].strip('()')
                
                if parts[2] == 'at':
                    mac = self._parse_mac(parts[3])
                    if mac:
                        new_cache[ip] = mac
            except (ValueError, IndexError):
                continue
        
        return new_cache
    
    def _parse_windows_arp(self, output):
        """Parse 'arp -a' output (Windows)"""
        new_cache = {}
        
        for line in output.splitlines():
            line = line.strip()
            
            if not line or 'Interface:' in line or 'Internet Address' in line:
                continue
            
            parts = line.split()
            
            if len(parts) < 2:
                continue
            
            try:
                ip = parts[0]
                mac = self._parse_mac(parts[1])
                
                if mac:
                    ipaddress.ip_address(ip)
                    new_cache[ip] = mac
            except (ValueError, IndexError):
                continue
        
        return new_cache
    
    def _refresh_cache(self):
        """Refresh MAC cache from system neighbor table"""
        start_time = time.time()
        new_cache = {}
        method_used = "unknown"
        
        try:
            result = subprocess.run(
                self.arp_command,
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                if self.platform == 'linux' and self.arp_command[0] == 'ip':
                    new_cache = self._parse_linux_ip_neigh(result.stdout)
                    method_used = "ip neigh"
                elif self.platform == 'linux':
                    new_cache = self._parse_linux_arp(result.stdout)
                    method_used = "arp (IPv4 only)"
                elif self.platform == 'macos':
                    new_cache = self._parse_macos_arp(result.stdout)
                    method_used = "arp -na (IPv4 only)"
                elif self.platform == 'windows':
                    new_cache = self._parse_windows_arp(result.stdout)
                    method_used = "arp -a (IPv4 only)"
        
        except FileNotFoundError as e:
            self.logger.error(f"ARP command not found on {self.platform}: {e}")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"ARP command timed out on {self.platform}")
        except Exception as e:
            self.logger.error(f"Failed to refresh MAC cache: {e}")
        
        # Calculate changes
        added = set(new_cache.keys()) - set(self.cache.keys())
        removed = set(self.cache.keys()) - set(new_cache.keys())
        updated = {ip for ip in new_cache if ip in self.cache and new_cache[ip] != self.cache[ip]}
        
        duration = time.time() - start_time
        
        # Update cache
        old_cache = self.cache
        self.cache = new_cache
        self.last_refresh = time.time()
        
        # Log summary
        if not self.cache:
            self.logger.warning(f"MAC cache is empty - neighbor table may be unavailable ({method_used})")
        else:
            ipv4_count = sum(1 for ip in self.cache if ':' not in ip)
            ipv6_count = len(self.cache) - ipv4_count
            
            version_info = f"IPv4: {ipv4_count}, IPv6: {ipv6_count}" if ipv6_count > 0 else f"IPv4: {ipv4_count}"
            
            self.logger.info(
                f"MAC cache refreshed via '{method_used}': {len(self.cache)} entries ({version_info}) "
                f"(+{len(added)}, -{len(removed)}, ~{len(updated)}) "
                f"in {duration:.3f}s"
            )
            
            if self.logger.isEnabledFor(logging.DEBUG):
                for ip in added:
                    self.logger.debug(f"MAC Added: {ip} -> {new_cache[ip]}")
                for ip in removed:
                    self.logger.debug(f"MAC Removed: {ip} -> {old_cache.get(ip, 'Unknown')}")
                for ip in updated:
                    self.logger.debug(f"MAC Updated: {ip} -> {old_cache.get(ip)} to {new_cache[ip]}")
    
    async def _refresh_loop(self):
        """Background task to periodically refresh cache"""
        while True:
            await asyncio.sleep(self.refresh_interval)
            self._refresh_cache()
    
    def get_mac(self, ip):
        """Get MAC address for an IP (IPv4 or IPv6)"""
        if time.time() - self.last_refresh > self.refresh_interval:
            self._refresh_cache()
        
        return self.cache.get(ip)

class GroupFileLoader:
    """
    Loads client groups from external files with auto-refresh.
    """
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("GroupFileLoader")
        self.file_groups = {}
        self.file_mtimes = {}
        self.refresh_interval = config.get('group_files', {}).get('refresh_interval', 300)
        
        # Initial load
        self._load_all_files()
        
        # Start background refresh if enabled
        if self.refresh_interval > 0:
            asyncio.create_task(self._refresh_loop())
            self.logger.info(f"Group file auto-refresh enabled (interval: {self.refresh_interval}s)")
        else:
            self.logger.info("Group file auto-refresh disabled")
    
    def _load_all_files(self):
        """Load all configured group files."""
        group_files_config = self.config.get('group_files', {})
        
        for group_name, file_path in group_files_config.items():
            if group_name == 'refresh_interval':
                continue
            
            if not isinstance(file_path, str):
                continue
            
            self._load_file(group_name, file_path)
    
    def _load_file(self, group_name, file_path):
        """Load identifiers from a file."""
        try:
            path = Path(file_path)
            
            if not path.exists():
                self.logger.warning(f"Group file not found: {file_path} for group '{group_name}'")
                return
            
            mtime = path.stat().st_mtime
            if file_path in self.file_mtimes and self.file_mtimes[file_path] == mtime:
                return
            
            with open(path, 'r') as f:
                lines = f.readlines()
            
            identifiers = set()
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                identifier = line.lower()
                
                if any(c in identifier for c in [' ', '\t', '\n']):
                    self.logger.warning(f"Invalid identifier in {file_path}:{line_num}: '{line}' (contains whitespace)")
                    continue
                
                identifiers.add(identifier)
            
            old_count = len(self.file_groups.get(group_name, set()))
            self.file_groups[group_name] = identifiers
            self.file_mtimes[file_path] = mtime
            
            self.logger.info(
                f"Loaded group '{group_name}' from {file_path}: "
                f"{len(identifiers)} identifiers (was {old_count})"
            )
            
            if self.logger.isEnabledFor(logging.DEBUG):
                for ident in identifiers:
                    self.logger.debug(f"  - {ident}")
        
        except Exception as e:
            self.logger.error(f"Failed to load group file {file_path}: {e}")
    
    async def _refresh_loop(self):
        """Background task to check for file changes."""
        while True:
            await asyncio.sleep(self.refresh_interval)
            self._load_all_files()
    
    def get_group_identifiers(self, group_name):
        """Get identifiers for a group from loaded files."""
        return self.file_groups.get(group_name, set())
    
    def get_all_groups(self):
        """Get all loaded groups."""
        return self.file_groups

def merge_groups(inline_groups, file_loader):
    """
    Merge inline groups from config with groups loaded from files.
    File groups take precedence and are added to inline groups.
    """
    merged = {}
    
    for group_name, identifiers in inline_groups.items():
        if isinstance(identifiers, list):
            merged[group_name] = set(id.lower().strip() for id in identifiers)
        else:
            merged[group_name] = set()
    
    if file_loader:
        for group_name, file_identifiers in file_loader.get_all_groups().items():
            if group_name not in merged:
                merged[group_name] = set()
            merged[group_name].update(file_identifiers)
    
    return {name: list(ids) for name, ids in merged.items()}


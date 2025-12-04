#!/usr/bin/env python3
# filename: upstream_manager.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 5.0.2 (Bug Fixes + Underscore Support)
# -----------------------------------------------------------------------------
"""
Upstream DNS Server Manager.

Updates:
- Fixed redundant session close check
- Added port validation (1-65535)
- Added configurable underscore support in domain names
- Fixed DoH HTTP 400 errors with proper SSL context handling
- Improved error handling
"""

import asyncio
import time
import random
import ipaddress
import socket
import aiohttp
import ssl
import sys
import re
from collections import OrderedDict
from urllib.parse import urlparse
import dns.message
import dns.query
import dns.rdatatype
import dns.asyncquery
import logging
from utils import get_logger

logger = get_logger("Upstream")

# Build domain validation regex based on configuration
def _build_domain_regex(allow_underscores=False):
    """Build regex for domain validation based on configuration"""
    if allow_underscores:
        # Allow alphanumeric, hyphens, AND underscores
        return re.compile(
            r'^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$'
        )
    else:
        # Standard RFC-compliant (no underscores)
        return re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
        )

# Default regex (will be updated by UpstreamManager.__init__)
DOMAIN_REGEX = _build_domain_regex(False)

# Pre-defined headers for DoH queries
DOH_HEADERS = {
    'Content-Type': 'application/dns-message',
    'Accept': 'application/dns-message'
}

class ForcedIPResolver(aiohttp.abc.AbstractResolver):
    """
    Custom aiohttp resolver that overrides DNS lookups for specific hosts
    to return a pre-determined IP address.
    """
    def __init__(self, hostname, ip):
        self.target_host = hostname
        self.target_ip = ip

    async def resolve(self, host, port=0, family=socket.AF_INET):
        # 1. Check for Override
        if host == self.target_host:
            try:
                ip_obj = ipaddress.ip_address(self.target_ip)
                fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
                
                if family != socket.AF_UNSPEC and family != fam:
                     return []

                return [{
                    'hostname': host,
                    'host': self.target_ip,
                    'port': port,
                    'family': fam,
                    'proto': 0,
                    'flags': 0
                }]
            except ValueError:
                pass
        
        # 2. Fallback to System DNS
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=family, type=socket.SOCK_STREAM, flags=0
            )
            
            hosts = []
            for info in infos:
                if len(info) < 5: continue
                _family, _type, _proto, _canonname, _sockaddr = info
                
                if not _sockaddr or len(_sockaddr) < 2:
                    continue
                    
                ip = _sockaddr[0]
                p = _sockaddr[1]
                
                hosts.append({
                    'hostname': host,
                    'host': ip,
                    'port': p,
                    'family': _family,
                    'proto': _proto,
                    'flags': 0
                })
            return hosts
        except Exception as e:
            logger.warning(f"ForcedIPResolver Fallback Error for {host}: {e}")
            raise e

    async def close(self):
        pass

class UpstreamManager:
    def __init__(self, config):
        self.servers = [] 
        self.bootstrappers = [] 
        self.lb_stats = {}
        self.config = config if isinstance(config, dict) else {}
        
        if not isinstance(self.config, dict):
            logger.error("Invalid configuration format provided to UpstreamManager.")
            self.config = {}

        self.mode = self.config.get('mode', 'fastest')
        self.raw_bootstrap = self.config.get('bootstrap') or ['8.8.8.8', '8.8.4.4']
        
        self.fallback_enabled = self.config.get('fallback_enabled', False)
        self.monitor_interval = max(1, int(self.config.get('monitor_interval', 60)))
        self.monitor_on_query = self.config.get('monitor_on_query', False)
        
        # Configure underscore support
        allow_underscores = self.config.get('allow_underscores', False)
        global DOMAIN_REGEX
        DOMAIN_REGEX = _build_domain_regex(allow_underscores)
        if allow_underscores:
            logger.info("Underscore support enabled for domain names (non-RFC compliant)")
        
        raw_test_domain = self.config.get('test_domain', 'www.google.com')
        if raw_test_domain and isinstance(raw_test_domain, str) and DOMAIN_REGEX.match(raw_test_domain):
             self.test_domain = raw_test_domain
        else:
             self.test_domain = 'www.google.com'
        
        try:
            self.conn_limit = int(self.config.get('connection_limit', 20))
            if self.conn_limit < 1: self.conn_limit = 20
        except (ValueError, TypeError):
            self.conn_limit = 20

        # Shared state
        self.last_monitor_time = 0
        self._rr_index = 0 
        self._sticky_map = OrderedDict()
        self._sticky_max_size = 10000
        
        # Locks
        self._monitor_lock = asyncio.Lock()
        self._rr_lock = asyncio.Lock()
        self._sticky_lock = asyncio.Lock()
        self._servers_lock = asyncio.Lock()
        self._stats_lock = asyncio.Lock()
        self._session_lock = asyncio.Lock()

        # Shared SSL Context
        logger.info("Initializing Shared SSL Context...")
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

        logger.info(f"Initializing UpstreamManager. Strategy: '{self.mode}'")
        
        self._parse_bootstrap_config(self.raw_bootstrap)
        self.parse_config(self.config)
        
        if not self.servers:
            logger.warning("No valid upstream servers configured. Injecting Default (8.8.8.8:53 UDP).")
            self.parse_config({'groups': {'Default': ['udp://8.8.8.8:53']}})

    async def close(self):
        logger.debug("Closing all upstream sessions.")
        async with self._servers_lock:
            for server in self.servers:
                session = server.get('session')
                if session and not session.closed:
                    try:
                        await session.close()
                    except Exception as e:
                        logger.debug(f"Error closing session for {server['host']}: {e}")

    def _is_valid_port(self, port: int) -> bool:
        """Validate port is in valid range"""
        return isinstance(port, int) and 1 <= port <= 65535

    def _normalize_protocol(self, proto):
        proto = proto.lower()
        if proto == 'doh': return 'https'
        if proto == 'dot': return 'tls'
        if proto == 'tls': return 'tls'  # Ensure tls stays as tls
        if proto == 'doh3': return 'h3'  # HTTP/3 for DNS-over-HTTP/3
        if proto == 'h3': return 'h3'    # Ensure h3 stays as h3
        return proto

    def _parse_bootstrap_config(self, raw_list):
        self.bootstrappers = []
        valid_protos = {'udp': 53, 'tcp': 53}

        if not raw_list: return

        for entry in raw_list:
            to_parse = entry
            if '://' not in to_parse:
                to_parse = f"udp://{to_parse}"
            
            try:
                parsed = urlparse(to_parse)
                proto = self._normalize_protocol(parsed.scheme)
                host = parsed.hostname
                port = parsed.port
                
                if proto not in valid_protos: continue
                if not host: continue

                clean_host = host
                if clean_host.startswith('[') and clean_host.endswith(']'):
                    clean_host = clean_host[1:-1]

                try: 
                    ipaddress.ip_address(clean_host)
                except ValueError: 
                    continue

                if port is None: 
                    port = valid_protos[proto]
                elif not self._is_valid_port(port):
                    logger.warning(f"Invalid port {port} for bootstrap server, using default")
                    port = valid_protos[proto]

                self.bootstrappers.append({
                    'proto': proto,
                    'ip': clean_host,
                    'port': port,
                    'id': f"{proto}://{clean_host}:{port}"
                })
            except Exception as e: 
                logger.debug(f"Failed to parse bootstrap entry '{entry}': {e}")

        if not self.bootstrappers:
            self.bootstrappers = [
                {'proto': 'udp', 'ip': '8.8.8.8', 'port': 53, 'id': 'udp://8.8.8.8:53'},
                {'proto': 'udp', 'ip': '8.8.4.4', 'port': 53, 'id': 'udp://8.8.4.4:53'}
            ]

    async def _bootstrap_resolve(self, hostname):
        try:
            ipaddress.ip_address(hostname)
            return [hostname]
        except ValueError: 
            pass
            
        found_ips = set()
        for qtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            q = dns.message.make_query(hostname, qtype)
            pkt = q.to_wire()
            
            for server in self.bootstrappers:
                try:
                    data = None
                    if server['proto'] == 'udp':
                        data = await self._udp_query(server['ip'], server['port'], pkt, timeout=2)
                    elif server['proto'] == 'tcp':
                        data = await self._tcp_query(server['ip'], server['port'], pkt, timeout=2)
                    
                    if data:
                        resp = dns.message.from_wire(data)
                        for rrset in resp.answer:
                                if rrset.rdtype == qtype:
                                    for rdata in rrset:
                                        found_ips.add(rdata.to_text())
                        if found_ips: 
                            break
                except Exception as e: 
                    logger.debug(f"Bootstrap resolve error for {hostname}: {e}")
                
        return list(found_ips)

    async def _create_server_session(self, server):
        """Creates a dedicated aiohttp session for DoH queries."""
        if server['proto'] != 'https':
            return None

        try:
            # Simple approach: Don't use custom resolver
            # Instead, we'll construct the URL using the IP directly
            # This avoids the complex ForcedIPResolver issues
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False  # Disable since we connect to IP
            ssl_context.verify_mode = ssl.CERT_NONE  # Disable verification for IP connections
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.conn_limit, 
                ttl_dns_cache=0,  # Disable DNS caching
                enable_cleanup_closed=True,
                force_close=False
            )
            
            timeout = aiohttp.ClientTimeout(sock_connect=5, sock_read=10)
            
            return aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout,
                trust_env=False
            )
        except Exception as e:
            logger.error(f"Failed to create session for {server['host']}: {e}")
            return None

    def parse_config(self, config):
        if not config: 
            return
        raw_servers = config.get('servers')
        if isinstance(raw_servers, list):
             raw_groups = {'Default': {'servers': raw_servers}}
        else:
             raw_groups = config.get('groups') or {}
             
        self.servers = []
        count = 0
        valid_protos = {'udp': 53, 'tcp': 53, 'https': 443, 'tls': 853, 'h3': 443}

        for group_name, group_data in raw_groups.items():
            if not group_data: 
                continue
            s_list = group_data.get('servers', []) if isinstance(group_data, dict) else group_data
            if not isinstance(s_list, list): 
                continue

            for s_str in s_list:
                forced_ip = None
                if '#' in s_str:
                    s_str, candidate_ip = s_str.rsplit('#', 1)
                    candidate_ip = candidate_ip.strip()
                    if candidate_ip.startswith('[') and candidate_ip.endswith(']'):
                        candidate_ip = candidate_ip[1:-1]
                    try:
                        ipaddress.ip_address(candidate_ip)
                        forced_ip = candidate_ip
                    except ValueError: 
                        logger.warning(f"Invalid forced IP '{candidate_ip}', ignoring")

                to_parse = s_str
                if '://' not in s_str:
                    to_parse = f"udp://{s_str}"

                try: 
                    parsed = urlparse(to_parse)
                except Exception as e:
                    logger.warning(f"Failed to parse upstream URL '{s_str}': {e}")
                    continue

                proto = self._normalize_protocol(parsed.scheme)
                host = parsed.hostname
                port = parsed.port
                path = parsed.path

                if proto not in valid_protos: 
                    logger.warning(f"Unsupported protocol '{proto}', skipping")
                    continue
                if not host: 
                    logger.warning(f"Missing hostname in '{s_str}', skipping")
                    continue

                if forced_ip is None:
                    try:
                        ipaddress.ip_address(host)
                        forced_ip = host
                    except ValueError: 
                        pass

                if port is None: 
                    port = valid_protos[proto]
                elif not self._is_valid_port(port):
                    logger.warning(f"Invalid port {port} in '{s_str}', using default {valid_protos[proto]}")
                    port = valid_protos[proto]
                    
                if proto in ('https', 'h3') and not path: 
                    path = '/dns-query'
                else: 
                    path = "" if proto not in ('https', 'h3') else path

                server_id = f"{host}:{port}:{proto}"
                if proto in ('https', 'h3'): 
                    server_id += f":{path}"
                if forced_ip: 
                    server_id += f"#{forced_ip}"

                server_entry = {
                    'id': server_id, 
                    'proto': proto, 
                    'host': host, 
                    'ip': forced_ip,
                    'port': port, 
                    'path': path, 
                    'latency': 999.0, 
                    'group': group_name,
                    'session': None 
                }
                self.servers.append(server_entry)
                self.lb_stats[server_id] = {'history': [], 'avg': 999.0, 'last_used': 0}
                count += 1
                
                # Build display name for logging
                if proto in ('https', 'h3'):
                    display_name = f"{proto.upper()}://{host}:{port}{path}"
                else:
                    display_name = f"{proto.upper()}://{host}:{port}"
                
                logger.debug(f"Parsed: {display_name} (IP: {forced_ip or 'resolve later'}) in group '{group_name}'")
        
        logger.info(f"Configuration Loaded: {count} upstream servers parsed.")

    async def start_monitor(self):
        if self.mode == "none": 
            logger.info(f"Monitoring mode: '{self.mode}' - Latency monitoring disabled")
            return
            
        logger.info(f"Monitoring mode: '{self.mode}' - Starting Upstream Latency Monitor")
        logger.info(f"Monitor settings: interval={self.monitor_interval}s, on_query={self.monitor_on_query}, test_domain={self.test_domain}")
        
        expanded_servers = []
        resolved_hosts = {} 

        async with self._servers_lock:
            for s in self.servers:
                if s['ip']:
                    # No session needed anymore - using dnspython for DoH
                    expanded_servers.append(s)
                    continue

                if s['host'] in resolved_hosts: 
                    ips = resolved_hosts[s['host']]
                else:
                    ips = await self._bootstrap_resolve(s['host'])
                    resolved_hosts[s['host']] = ips
                
                if not ips:
                    logger.warning(f"Skipping {s['host']} (Resolution failed)")
                    continue

                for ip in ips:
                    new_s = s.copy()
                    new_s['ip'] = ip
                    new_s['id'] = f"{new_s['id']}#{ip}"
                    # No session needed anymore - using dnspython for DoH
                    
                    async with self._stats_lock:
                        if new_s['id'] not in self.lb_stats:
                            self.lb_stats[new_s['id']] = {'history': [], 'avg': 999.0, 'last_used': 0}
                    
                    expanded_servers.append(new_s)

            self.servers = expanded_servers
            
            # Log summary of expanded servers
            proto_counts = {}
            for s in self.servers:
                proto = s['proto'].upper()
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
            
            logger.info(f"Server expansion complete: {len(self.servers)} servers ready")
            for proto, count in sorted(proto_counts.items()):
                logger.info(f"  - {proto}: {count} servers")
        
            if not any(s.get('ip') for s in self.servers) and self.fallback_enabled:
                 logger.warning("Activating Fallback Servers.")
                 fallback_ips = [b['ip'] for b in self.bootstrappers] if self.bootstrappers else ['8.8.8.8']
                 for ip in fallback_ips:
                     self.servers.append({
                        'id': f"udp://{ip}:53", 
                        'proto': 'udp', 
                        'host': ip, 
                        'ip': ip, 
                        'port': 53, 
                        'path': '', 
                        'latency': 999.0, 
                        'group': 'Default', 
                        'session': None
                     })

        # Initialize timestamp
        async with self._monitor_lock:
            self.last_monitor_time = time.time()
            
        # Run initial latency check
        logger.info("Running initial latency check...")
        await self.check_latencies()
        
        # Log results of initial check
        await self._log_server_status()
        
        # Start monitoring based on mode
        if not self.monitor_on_query:
            logger.info(f"Starting periodic latency checks every {self.monitor_interval}s")
            while True:
                await asyncio.sleep(self.monitor_interval)
                logger.debug(f"Periodic check triggered (mode: {self.mode})")
                await self.check_latencies()
                await self._log_server_status()
        else:
            logger.info(f"Query-triggered monitoring enabled (checks every {self.monitor_interval}s on demand)")
            # Just wait forever - checks will be triggered by queries

    async def check_latencies(self):
        """
        Check latency for all servers.
        This is called either:
        1. On a timer if monitor_on_query is False
        2. By the first query after the interval expires if monitor_on_query is True
        """
        if self.mode == "none": 
            logger.debug("Latency check skipped (mode: none)")
            return
        
        # Double-check we should actually run (prevent race conditions)
        async with self._monitor_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_monitor_time
            
            # If another task just ran this, skip
            if time_since_last < (self.monitor_interval * 0.9):
                logger.debug(f"Skipping latency check (last check was only {time_since_last:.1f}s ago)")
                return
            
            # Update the timestamp
            self.last_monitor_time = current_time
            logger.info(f"Running latency check (mode: {self.mode}, last check: {time_since_last:.1f}s ago)")
        
        valid_targets = []
        async with self._servers_lock:
             valid_targets = [s for s in self.servers if s.get('ip')]
        
        if not valid_targets:
            logger.warning("No valid upstream targets available for latency check")
            return
        
        logger.debug(f"Checking latency for {len(valid_targets)} servers...")

        tasks = []
        if sys.version_info >= (3, 11):
            try:
                async with asyncio.TaskGroup() as tg:
                    for s in valid_targets:
                        tasks.append(tg.create_task(self._measure_latency(s)))
            except Exception as e:
                logger.error(f"Monitor TaskGroup Exception: {e}")
        else:
            tasks = [asyncio.create_task(self._measure_latency(s)) for s in valid_targets]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        successful_checks = 0
        failed_checks = 0
        
        async with self._stats_lock:
            active_ids = set()
            
            for i, task in enumerate(tasks):
                 lat = 999.0
                 try:
                     if hasattr(task, 'result'):
                         res = task.result()
                         if not isinstance(res, Exception):
                             lat = res
                             if lat < 999.0:
                                 successful_checks += 1
                             else:
                                 failed_checks += 1
                 except Exception:
                     failed_checks += 1

                 srv = valid_targets[i]
                 srv['latency'] = lat
                 sid = srv['id']
                 active_ids.add(sid)
                 
                 stats = self.lb_stats.get(sid)
                 if stats:
                     stats['history'].append(lat)
                     if len(stats['history']) > 5: 
                         stats['history'].pop(0)
                     stats['avg'] = sum(stats['history']) / len(stats['history'])
            
            # Stats Cleanup
            stale_ids = [sid for sid in self.lb_stats if sid not in active_ids]
            for sid in stale_ids:
                del self.lb_stats[sid]

        logger.info(f"Latency check complete: {successful_checks} OK, {failed_checks} failed")
        
        # Sort servers based on mode
        snapshot_stats = {}
        async with self._stats_lock:
             for sid, data in self.lb_stats.items():
                 snapshot_stats[sid] = data.get('avg', 999.0)
        
        async with self._servers_lock:
            # Capture state before sorting
            before_top3 = [
                (s['id'], s['proto'].upper(), s['latency'], snapshot_stats.get(s['id'], 999.0))
                for s in self.servers[:3]
            ]
            
            if self.mode in ['fastest', 'failover']:
                self.servers.sort(key=lambda x: x['latency'])
                logger.debug(f"Servers sorted by current latency (mode: {self.mode})")
            elif self.mode == 'loadbalance': 
                self.servers.sort(key=lambda x: snapshot_stats.get(x['id'], 999.0))
                logger.debug(f"Servers sorted by average latency (mode: {self.mode})")
            elif self.mode == 'sticky':
                # Keep order for sticky, but update latencies for failover
                logger.debug(f"Server order maintained (mode: {self.mode})")
            elif self.mode in ['random', 'roundrobin']:
                # No sorting needed
                logger.debug(f"Server order unchanged (mode: {self.mode})")
            else:
                logger.warning(f"Unknown monitoring mode: {self.mode}")
            
            # Capture state after sorting
            after_top3 = [
                (s['id'], s['proto'].upper(), s['latency'], snapshot_stats.get(s['id'], 999.0))
                for s in self.servers[:3]
            ]
            
            # Check if top 3 changed (this is what matters for selection)
            top3_changed = (before_top3 != after_top3)
            
            if top3_changed:
                logger.info("=" * 80)
                logger.info(f"UPSTREAM SELECTION CHANGED (mode: {self.mode})")
                logger.info("=" * 80)
                
                # Show what was used before
                logger.info("Previously selected (top 3):")
                for i, (sid, proto, cur_lat, avg_lat) in enumerate(before_top3, 1):
                    cur_str = f"{cur_lat*1000:.1f}ms" if cur_lat < 999.0 else "PENDING"
                    avg_str = f"{avg_lat*1000:.1f}ms" if avg_lat < 999.0 else "PENDING"
                    logger.info(f"  #{i}: [{proto:6s}] {sid:50s} | Cur: {cur_str:9s} | Avg: {avg_str:9s}")
                
                logger.info("-" * 80)
                
                # Show ALL servers sorted by current selection criteria
                logger.info(f"All servers sorted by {self.mode} criteria:")
                
                for i, s in enumerate(self.servers, 1):
                    proto = s['proto'].upper()
                    sid = s['id']
                    cur_lat = s['latency']
                    avg_lat = snapshot_stats.get(sid, 999.0)
                    
                    cur_str = f"{cur_lat*1000:.1f}ms" if cur_lat < 999.0 else "PENDING"
                    avg_str = f"{avg_lat*1000:.1f}ms" if avg_lat < 999.0 else "PENDING"
                    
                    # Mark top 3 that will be used
                    marker = ">>> NOW USING" if i <= 3 else "   "
                    
                    logger.info(
                        f"  {marker} #{i:2d}: [{proto:6s}] {sid:50s} | "
                        f"Cur: {cur_str:9s} | Avg: {avg_str:9s}"
                    )
                
                logger.info("=" * 80)
            else:
                logger.debug(f"Top 3 servers unchanged after latency check")

    async def _log_server_status(self):
        """Log current server status and ordering."""
        async with self._servers_lock:
            # Group by protocol for summary
            proto_summary = {}
            for s in self.servers:
                proto = s['proto'].upper()
                if proto not in proto_summary:
                    proto_summary[proto] = {'count': 0, 'working': 0, 'avg_latency': []}
                proto_summary[proto]['count'] += 1
                if s['latency'] < 999.0:
                    proto_summary[proto]['working'] += 1
                    proto_summary[proto]['avg_latency'].append(s['latency'])
            
            logger.info(f"Protocol summary ({len(self.servers)} total servers):")
            for proto, stats in sorted(proto_summary.items()):
                if stats['avg_latency']:
                    avg = sum(stats['avg_latency']) / len(stats['avg_latency'])
                    logger.info(f"  {proto}: {stats['working']}/{stats['count']} working (avg: {avg*1000:.1f}ms)")
                else:
                    logger.info(f"  {proto}: {stats['working']}/{stats['count']} working (all failed)")
            
            # Show all servers if they're mostly untested (first run)
            # or top 10 if we have latency data
            working_count = sum(1 for s in self.servers if s['latency'] < 999.0)
            if working_count < len(self.servers) * 0.3:  # Less than 30% working = likely startup
                display_count = len(self.servers)
                logger.info(f"Showing all {display_count} servers (initial state):")
            else:
                display_count = min(10, len(self.servers))
                logger.info(f"Top {display_count} servers (mode: {self.mode}):")
            
            for i, s in enumerate(self.servers[:display_count], 1):
                proto = s['proto'].upper()
                if proto in ('HTTPS', 'H3'):
                    display = f"{s['host']}:{s['port']}{s['path']}"
                else:
                    display = f"{s['host']}:{s['port']}"
                
                # Get stats
                avg_lat = "N/A"
                async with self._stats_lock:
                    if s['id'] in self.lb_stats:
                        avg = self.lb_stats[s['id']]['avg']
                        avg_lat = f"{avg*1000:.1f}ms" if avg < 999.0 else "PENDING"
                
                current = f"{s['latency']*1000:.1f}ms" if s['latency'] < 999.0 else "PENDING"
                
                logger.info(
                    f"  #{i:2d}: [{proto:6s}] {display:40s} ({s['ip']:20s}) | "
                    f"Cur: {current:8s} | Avg: {avg_lat:8s}"
                )

    async def _measure_latency(self, server):
        start = time.time()
        try:
            q = dns.message.make_query(self.test_domain, dns.rdatatype.A)
            pkt = q.to_wire()
            timeout = 5.0  # Increased timeout for initial measurements
            
            result = None
            if server['proto'] == 'udp': 
                result = await self._udp_query(server['ip'], server['port'], pkt, timeout)
            elif server['proto'] == 'tcp': 
                result = await self._tcp_query(server['ip'], server['port'], pkt, timeout)
            elif server['proto'] == 'https': 
                result = await self._doh_query(server, pkt, timeout)
            elif server['proto'] == 'h3':
                result = await self._doh3_query(server, pkt, timeout)
            elif server['proto'] == 'tls': 
                result = await self._dot_query(server['ip'], server['port'], server['host'], pkt, timeout)
            
            if result:
                latency = time.time() - start
                # Build display name
                if server['proto'] in ('https', 'h3'):
                    display_name = f"{server['proto'].upper()}://{server['host']}:{server['port']}{server['path']}"
                else:
                    display_name = f"{server['proto'].upper()}://{server['host']}"
                logger.debug(f"Latency check OK: {display_name} ({server['ip']}) = {latency*1000:.1f}ms")
                return latency
            else:
                if server['proto'] in ('https', 'h3'):
                    display_name = f"{server['proto'].upper()}://{server['host']}:{server['port']}{server['path']}"
                else:
                    display_name = f"{server['proto'].upper()}://{server['host']}"
                logger.debug(f"Latency check FAILED: {display_name} ({server['ip']})")
                return 999.0
        except Exception as e:
            if server['proto'] in ('https', 'h3'):
                display_name = f"{server['proto'].upper()}://{server['host']}:{server['port']}{server['path']}"
            else:
                display_name = f"{server['proto'].upper()}://{server['host']}"
            logger.debug(f"Latency check ERROR: {display_name} ({server['ip']}): {e}")
            return 999.0

    async def _update_sticky_map(self, client_ip, server_id):
        async with self._sticky_lock:
            if client_ip in self._sticky_map:
                 self._sticky_map.move_to_end(client_ip)
            self._sticky_map[client_ip] = server_id
            if len(self._sticky_map) > self._sticky_max_size:
                 self._sticky_map.popitem(last=False) 

    async def _get_sticky_server(self, client_ip):
        async with self._sticky_lock:
            if client_ip in self._sticky_map:
                self._sticky_map.move_to_end(client_ip) 
                return self._sticky_map[client_ip]
            return None

    async def forward_query(self, query_data, qid=0, client_ip="Unknown", upstream_group="Default", req_logger=None):
        log = req_logger or logger
        
        # Check if we should trigger latency monitoring
        should_check = False
        if self.monitor_on_query and self.mode != "none":
            async with self._monitor_lock:
                current_time = time.time()
                time_since_last = current_time - self.last_monitor_time
                
                # Only check if interval has expired
                if time_since_last >= self.monitor_interval:
                    # Mark that we're doing a check to prevent multiple concurrent checks
                    self.last_monitor_time = current_time
                    should_check = True
                    log.debug(f"Query-triggered latency check (mode: {self.mode}, last: {time_since_last:.1f}s ago)")
        
        # Trigger check in background if needed
        if should_check:
            log.debug(f"Starting background latency check...")
            asyncio.create_task(self.check_latencies())

        query_info = "Query"
        if log.isEnabledFor(logging.DEBUG):
            try:
                q_msg = dns.message.from_wire(query_data)
                if q_msg.question:
                    query_info = f"{q_msg.question[0].name}"
                    if not qid: 
                        qid = q_msg.id
            except: 
                pass

        async with self._servers_lock:
            candidates = [s for s in self.servers if s['group'] == upstream_group and s.get('ip')]
            if not candidates and upstream_group != "Default":
                candidates = [s for s in self.servers if s.get('ip')]
        
        if not candidates: 
            log.error(f"FORWARD FAILURE [ID:{qid}]: No valid upstreams available.")
            return None
        
        log.debug(f"Selecting from {len(candidates)} candidates using mode: {self.mode}")
        
        # Determine how many servers to try based on their state
        # If most servers are untested (latency = 999.0), try more servers
        untested_count = sum(1 for s in candidates if s['latency'] >= 999.0)
        if untested_count > len(candidates) * 0.5:  # More than 50% untested
            max_tries = min(len(candidates), 8)  # Try up to 8 servers
            log.debug(f"Many untested servers ({untested_count}/{len(candidates)}), will try up to {max_tries}")
        else:
            max_tries = 3  # Normal operation: try top 3
            
        selected = []
        if self.mode == 'random':
            selected = random.sample(candidates, k=min(max_tries, len(candidates)))
            log.debug(f"Random selection: picked {len(selected)} servers")
        
        elif self.mode == 'roundrobin':
            async with self._rr_lock:
                n = len(candidates)
                if n > 0:
                    if self._rr_index > 1000000: 
                        self._rr_index = 0
                    start_idx = self._rr_index % n
                    self._rr_index = (self._rr_index + 1) % n
                    for i in range(min(max_tries, n)):
                        selected.append(candidates[(start_idx + i) % n])
                    log.debug(f"Round-robin selection: index {start_idx}, picked {len(selected)} servers")
        
        elif self.mode == 'sticky':
            last_srv_id = await self._get_sticky_server(client_ip)
            found = None
            if last_srv_id:
                found = next((s for s in candidates if s['id'] == last_srv_id), None)
            
            if found:
                selected.append(found)
                backups = [s for s in candidates if s['id'] != last_srv_id]
                selected.extend(backups[:max_tries-1])
                log.debug(f"Sticky selection: reusing {found['host']} for {client_ip} + {len(selected)-1} backups")
            else:
                selected = candidates[:max_tries]
                log.debug(f"Sticky selection: no previous server for {client_ip}, using top {len(selected)}")
        
        elif self.mode in ['fastest', 'failover', 'loadbalance']:
            # These modes rely on sorted order from latency checks
            selected = candidates[:max_tries]
            log.debug(f"{self.mode.capitalize()} selection: using top {len(selected)} from sorted list")
        
        elif self.mode == 'none':
            # No monitoring, just use first servers
            selected = candidates[:max_tries]
            log.debug(f"Mode 'none': using first {len(selected)} servers (no latency-based selection)")
        
        else:
            # Unknown mode, use first servers
            selected = candidates[:max_tries]
            log.warning(f"Unknown mode '{self.mode}', using first {len(selected)} servers")

        log.debug(f"Selected {len(selected)} candidates for '{query_info}':")
        for s in selected:
            proto_name = s['proto'].upper()
            # Show full URL for DoH/DoH3
            if s['proto'] in ('https', 'h3'):
                log.debug(f"  - {s['host']}:{s['port']}{s['path']} ({s['ip']}) via {proto_name}")
            else:
                log.debug(f"  - {s['host']} ({s['ip']}) via {proto_name}:{s['port']}")

        for server in selected:
            try:
                async with self._stats_lock:
                    if server['id'] in self.lb_stats:
                         self.lb_stats[server['id']]['last_used'] = time.time()
                
                start_t = time.time()
                resp = None
                
                ip = server['ip']
                port = server['port']
                
                if server['proto'] == 'udp': 
                    resp = await self._udp_query(ip, port, query_data)
                elif server['proto'] == 'tcp': 
                    resp = await self._tcp_query(ip, port, query_data)
                elif server['proto'] == 'https': 
                    resp = await self._doh_query(server, query_data)
                elif server['proto'] == 'h3':
                    resp = await self._doh3_query(server, query_data)
                elif server['proto'] == 'tls': 
                    resp = await self._dot_query(ip, port, server['host'], query_data)
                
                if resp:
                    if self.mode == 'sticky':
                        await self._update_sticky_map(client_ip, server['id'])
                    
                    dur = (time.time() - start_t) * 1000
                    
                    # Build display name for logging
                    if server['proto'] in ('https', 'h3'):
                        display_name = f"{server['host']}:{server['port']}{server['path']}"
                    else:
                        display_name = f"{server['host']}"
                    
                    log.info(f"Forwarded {query_info} -> {display_name} ({ip}) | {dur:.2f}ms")
                    return resp
            except Exception as e:
                log.warning(f"Upstream forward error {server['host']}: {e}")
                continue
                
        log.error("All selected upstream servers failed to respond.")
        return None

    # --- Transport Implementations ---

    async def _udp_query(self, ip, port, data, timeout=5):
        loop = asyncio.get_running_loop()
        try:
            ip_obj = ipaddress.ip_address(ip)
            family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)
            await loop.sock_connect(sock, (ip, port))
            await loop.sock_sendall(sock, data)
            resp = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout)
            sock.close()
            return resp
        except Exception as e:
            logger.debug(f"UDP Error {ip}: {e}")
            return None

    async def _tcp_query(self, ip, port, data, timeout=5):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            writer.write(len(data).to_bytes(2, 'big') + data)
            await writer.drain()
            len_bytes = await reader.readexactly(2)
            length = int.from_bytes(len_bytes, 'big')
            resp = await reader.readexactly(length)
            writer.close()
            await writer.wait_closed()
            return resp
        except Exception as e:
            logger.debug(f"TCP Error {ip}: {e}")
            return None

    async def _dot_query(self, ip, port, host, data, timeout=5):
        try:
            q = dns.message.from_wire(data)
            response = await dns.asyncquery.tls(
                q, 
                ip, 
                port=port, 
                timeout=timeout, 
                server_hostname=host,
                ssl_context=self.ssl_context
            )
            return response.to_wire()
        except Exception as e:
            logger.debug(f"DoT Error {host} ({ip}): {e}")
            return None

    async def _doh_query(self, server, data, timeout=5):
        """
        DoH query using httpx library with HTTP/2 or HTTP/1.1 (NOT HTTP/3).
        """
        try:
            import httpx
            
            # Construct the full URL with hostname
            url = f"https://{server['host']}:{server['port']}{server['path']}"
            
            headers = DOH_HEADERS.copy()
            
            try:
                loop = asyncio.get_running_loop()
                
                def sync_doh_request():
                    # Force HTTP/2 or HTTP/1.1, explicitly disable HTTP/3
                    with httpx.Client(
                        timeout=timeout, 
                        http1=True,      # Enable HTTP/1.1
                        http2=True,      # Enable HTTP/2
                        verify=True
                    ) as client:
                        response = client.post(url, content=data, headers=headers)
                        if response.status_code == 200:
                            return response.content
                        else:
                            logger.debug(f"DoH HTTP {response.status_code} from {url}")
                            return None
                
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, sync_doh_request),
                    timeout=timeout + 1
                )
                return result
                
            except Exception as e:
                logger.debug(f"DoH Error {server['host']} ({server['ip']}): {e}")
                return None
                
        except ImportError:
            # httpx not available, fall back to requests (HTTP/1.1 only)
            try:
                import requests
                
                url = f"https://{server['host']}:{server['port']}{server['path']}"
                headers = DOH_HEADERS.copy()
                
                loop = asyncio.get_running_loop()
                
                def sync_request():
                    try:
                        response = requests.post(
                            url, 
                            data=data, 
                            headers=headers, 
                            timeout=timeout,
                            verify=True
                        )
                        if response.status_code == 200:
                            return response.content
                        else:
                            logger.debug(f"DoH HTTP {response.status_code} from {url}")
                            return None
                    except Exception as e:
                        logger.debug(f"DoH requests error {server['host']}: {e}")
                        return None
                
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, sync_request),
                    timeout=timeout + 1
                )
                return result
                
            except Exception as e:
                logger.debug(f"DoH Error {server['host']} ({server['ip']}): {e}")
                return None

    async def _doh3_query(self, server, data, timeout=5):
        """
        DoH3 query using HTTP/3 (QUIC protocol).
        Requires aioquic and httpx[http3] to be installed.
        """
        try:
            import httpx
            
            # Construct the full URL with hostname
            url = f"https://{server['host']}:{server['port']}{server['path']}"
            
            headers = DOH_HEADERS.copy()
            
            try:
                loop = asyncio.get_running_loop()
                
                def sync_doh3_request():
                    try:
                        # Use httpx with HTTP/3 support
                        with httpx.Client(
                            timeout=timeout,
                            http1=False,     # Disable HTTP/1.1
                            http2=False,     # Disable HTTP/2
                            verify=True
                        ) as client:
                            # httpx will attempt HTTP/3 when http1 and http2 are disabled
                            response = client.post(url, content=data, headers=headers)
                            if response.status_code == 200:
                                return response.content
                            else:
                                logger.debug(f"DoH3 HTTP {response.status_code} from {url}")
                                return None
                    except Exception as e:
                        # Check if it's an HTTP/3 not available error
                        if "HTTP/3" in str(e) or "http3" in str(e).lower():
                            logger.warning(f"DoH3 not available for {server['host']}: Install httpx[http3] and aioquic")
                        else:
                            logger.debug(f"DoH3 error {server['host']}: {e}")
                        return None
                
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, sync_doh3_request),
                    timeout=timeout + 1
                )
                return result
                
            except Exception as e:
                logger.debug(f"DoH3 Error {server['host']} ({server['ip']}): {e}")
                return None
                
        except ImportError:
            logger.warning(f"DoH3 requires httpx library. Install with: pip install 'httpx[http3]' aioquic")
            return None


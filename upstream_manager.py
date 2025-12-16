#!/usr/bin/env python3
# filename: upstream_manager.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 7.4.0 (Distributed Mode)
# -----------------------------------------------------------------------------
"""
Upstream DNS Server Manager with Priority Support & Strict DoH IP Targeting.
Includes configurable connection reuse and detailed connection logging.
Now features 'distributed' mode and live latency tracking.
"""

import asyncio
import time
import random
import ipaddress
import socket
import ssl
import re
from collections import OrderedDict, defaultdict
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any
import dns.message
import dns.query
import dns.rdatatype
import dns.asyncquery
import logging
from utils import get_logger

logger = get_logger("Upstream")


def _build_domain_regex(allow_underscores=False):
    if allow_underscores:
        return re.compile(
            r'^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$'
        )
    else:
        return re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
        )


DOH_HEADERS = {
    'Content-Type': 'application/dns-message',
    'Accept': 'application/dns-message'
}


class CircuitBreaker:
    def __init__(self, name="Unknown", failure_threshold=3, recovery_timeout=30, half_open_max_calls=1):
        self.name = name  # Server ID / Full URL
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = 'CLOSED'
        self.half_open_calls = 0
        
    def can_attempt(self) -> bool:
        if self.state == 'CLOSED':
            return True
        elif self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = 'HALF_OPEN'
                self.half_open_calls = 0
                logger.info(f"Circuit breaker for {self.name} entering HALF_OPEN state (Probing...)")
                return True
            return False
        elif self.state == 'HALF_OPEN':
            if self.half_open_calls < self.half_open_max_calls:
                self.half_open_calls += 1
                return True
            return False
        return False
    
    def record_success(self):
        if self.state == 'HALF_OPEN':
            logger.info(f"Circuit breaker for {self.name} recovery SUCCESSFUL. State: CLOSED")
            self.state = 'CLOSED'
            self.failure_count = 0
        elif self.state == 'CLOSED':
            self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == 'HALF_OPEN':
            logger.warning(f"Circuit breaker for {self.name} recovery FAILED. State: OPEN")
            self.state = 'OPEN'
        elif self.failure_count >= self.failure_threshold:
            if self.state != 'OPEN':
                logger.warning(f"Circuit breaker for {self.name} OPENING after {self.failure_count} failures")
            self.state = 'OPEN'


class UpstreamManager:
    def __init__(self, config):
        self.servers = []
        self.bootstrappers = []
        self.lb_stats = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.config = config if isinstance(config, dict) else {}
        
        if not isinstance(self.config, dict):
            logger.error("Invalid configuration format provided to UpstreamManager.")
            self.config = {}

        self.mode = self.config.get('mode', 'fastest')
        self.raw_bootstrap = self.config.get('bootstrap') or ['86.54.11.1', '9.9.9.9', '1.1.1.2', '8.8.8.8']
        
        self.bootstrap_resolution_mode = self.config.get('bootstrap_resolution_mode', 'auto').lower()
        
        self.fallback_enabled = self.config.get('fallback_enabled', False)
        self.monitor_interval = max(1, int(self.config.get('monitor_interval', 60)))
        self.monitor_on_query = self.config.get('monitor_on_query', False)
        self.connection_reuse = self.config.get('connection_reuse', False)
        
        self.circuit_breaker_enabled = self.config.get('circuit_breaker_enabled', True)
        self.circuit_failure_threshold = self.config.get('circuit_failure_threshold', 3)
        self.circuit_recovery_timeout = self.config.get('circuit_recovery_timeout', 30)
        
        allow_underscores = self.config.get('allow_underscores', False)
        self.domain_regex = _build_domain_regex(allow_underscores)
        if allow_underscores:
            logger.info("Underscore support enabled for domain names (non-RFC compliant)")
        
        raw_test_domain = self.config.get('test_domain', 'www.google.com')
        if raw_test_domain and isinstance(raw_test_domain, str) and self.domain_regex.match(raw_test_domain):
            self.test_domain = raw_test_domain
        else:
            self.test_domain = 'www.google.com'
        
        try:
            self.conn_limit = int(self.config.get('connection_limit', 20))
            if self.conn_limit < 1:
                self.conn_limit = 20
        except (ValueError, TypeError):
            self.conn_limit = 20

        self.last_monitor_time = 0
        self._rr_index = 0
        self._sticky_map = OrderedDict()
        self._sticky_max_size = 10000
        self._last_sticky_cleanup = time.time()
        
        self._monitor_lock = asyncio.Lock()
        self._rr_lock = asyncio.Lock()
        self._sticky_lock = asyncio.Lock()
        self._servers_lock = asyncio.Lock()
        self._stats_lock = asyncio.Lock()

        # DoT Connection Pool
        self._dot_pool = {}
        self._dot_locks = defaultdict(asyncio.Lock)

        logger.info("Initializing Shared SSL Context for DoT...")
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

        self.doh_client = None
        self._doh_init_lock = asyncio.Lock()

        logger.info(f"Initializing UpstreamManager. Strategy: '{self.mode}', Connection Reuse: {self.connection_reuse}")
        logger.info(f"Bootstrap Resolution Mode: '{self.bootstrap_resolution_mode}'")
        
        self._parse_bootstrap_config(self.raw_bootstrap)
        self.parse_config(self.config)
        
        if not self.servers:
            logger.warning("No valid upstream servers configured. Injecting defaults.")
            self.parse_config({'groups': {'Default': {'servers': [
                'udp://86.54.11.1:53',
                'udp://9.9.9.9:53',
                'udp://1.1.1.2:53',
                'udp://8.8.8.8:53'
            ]}}})

    # =========================================================================
    # INITIALIZATION & CONFIG
    # =========================================================================

    async def _ensure_doh_client(self):
        if not self.connection_reuse:
            return

        if self.doh_client is not None:
            return
            
        async with self._doh_init_lock:
            if self.doh_client is not None:
                return
                
            try:
                import httpx
                
                self.doh_client = httpx.AsyncClient(
                    http2=True,
                    verify=True,
                    timeout=httpx.Timeout(10.0),
                    limits=httpx.Limits(
                        max_keepalive_connections=self.conn_limit,
                        max_connections=self.conn_limit * 2,
                        keepalive_expiry=30.0
                    )
                )
                logger.info("Persistent DoH async client initialized (KeepAlive Enabled)")
            except ImportError:
                logger.error("httpx is required for DoH support. Install with: pip install httpx")
                raise

    async def close(self):
        logger.debug("Closing all upstream sessions.")
        
        if self.doh_client is not None:
            try:
                await self.doh_client.aclose()
                logger.debug("Persistent DoH client closed")
            except Exception as e:
                logger.debug(f"Error closing DoH client: {e}")
        
        for key, (reader, writer) in self._dot_pool.items():
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                host = key[2]
                logger.debug(f"Closed pooled DoT connection to {host}")
            except Exception:
                pass
        self._dot_pool.clear()

    def _is_valid_port(self, port: int) -> bool:
        return isinstance(port, int) and 1 <= port <= 65535

    def _is_valid_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _normalize_protocol(self, proto):
        proto = proto.lower()
        if proto == 'doh':
            return 'https'
        if proto == 'dot':
            return 'tls'
        return proto

    def _parse_bootstrap_config(self, raw_list):
        self.bootstrappers = []
        valid_protos = {'udp': 53, 'tcp': 53}

        if not raw_list:
            logger.warning("No bootstrap servers configured, using defaults")
            return

        for entry in raw_list:
            to_parse = entry
            if '://' not in to_parse:
                to_parse = f"udp://{to_parse}"
            
            try:
                parsed = urlparse(to_parse)
                proto = self._normalize_protocol(parsed.scheme)
                host = parsed.hostname
                port = parsed.port
                
                if proto not in valid_protos:
                    logger.warning(f"Unsupported bootstrap protocol '{proto}' in '{entry}'")
                    continue
                if not host:
                    logger.warning(f"Missing hostname in bootstrap entry '{entry}'")
                    continue

                clean_host = host
                if clean_host.startswith('[') and clean_host.endswith(']'):
                    clean_host = clean_host[1:-1]

                if not self._is_valid_ip(clean_host):
                    logger.warning(f"Bootstrap must be IP address, not hostname: '{entry}'")
                    continue

                if port is None:
                    port = valid_protos[proto]

                self.bootstrappers.append({
                    'proto': proto,
                    'ip': clean_host,
                    'port': port
                })
                logger.debug(f"Bootstrap server: {proto}://{clean_host}:{port}")
            except Exception as e:
                logger.warning(f"Failed to parse bootstrap entry '{entry}': {e}")

        if not self.bootstrappers:
            logger.warning("No valid bootstrap servers, using fallback")
            for ip in ['8.8.8.8', '1.1.1.1']:
                self.bootstrappers.append({'proto': 'udp', 'ip': ip, 'port': 53})

    async def _bootstrap_resolve(self, hostname):
        found_ips = set()
        
        # Determine which query types to use based on mode
        qtypes = []
        mode = self.bootstrap_resolution_mode
        
        if mode == 'auto':
            has_v4 = False
            has_v6 = False
            v4_count = 0
            v6_count = 0
            
            for bs in self.bootstrappers:
                try:
                    ip = ipaddress.ip_address(bs['ip'])
                    if ip.version == 4:
                        has_v4 = True
                        v4_count += 1
                    elif ip.version == 6:
                        has_v6 = True
                        v6_count += 1
                except ValueError:
                    pass
            
            logger.debug(f"Bootstrap Auto-Detection: Found {v4_count} IPv4 and {v6_count} IPv6 bootstrap servers.")

            if has_v4 and not has_v6:
                qtypes = [dns.rdatatype.A]
                logger.info(f"Bootstrap Mode 'auto' -> IPv4 Only (Bootstrap servers are all IPv4)")
            elif has_v6 and not has_v4:
                qtypes = [dns.rdatatype.AAAA]
                logger.info(f"Bootstrap Mode 'auto' -> IPv6 Only (Bootstrap servers are all IPv6)")
            else:
                qtypes = [dns.rdatatype.A, dns.rdatatype.AAAA]
                logger.info(f"Bootstrap Mode 'auto' -> Dual Stack (Mixed or no bootstrap IPs found)")
        
        elif mode == 'ipv4':
            qtypes = [dns.rdatatype.A]
            logger.debug("Bootstrap Mode: IPv4 Only (Configured)")
        elif mode == 'ipv6':
            qtypes = [dns.rdatatype.AAAA]
            logger.debug("Bootstrap Mode: IPv6 Only (Configured)")
        elif mode == 'both':
            qtypes = [dns.rdatatype.A, dns.rdatatype.AAAA]
            logger.debug("Bootstrap Mode: Dual Stack (Configured)")
        else:
            qtypes = [dns.rdatatype.A, dns.rdatatype.AAAA] # Default

        logger.info(f"Resolving upstream host '{hostname}' using mode '{mode}' (Types: {[dns.rdatatype.to_text(t) for t in qtypes]})")

        for qtype in qtypes:
            q = dns.message.make_query(hostname, qtype)
            pkt = q.to_wire()
            
            for server in self.bootstrappers:
                try:
                    data = None
                    server_url = f"{server['proto']}://{server['ip']}:{server['port']}"
                    if server['proto'] == 'udp':
                        data = await self._udp_query(server['ip'], server['port'], pkt, timeout=2, server_id=server_url)
                    elif server['proto'] == 'tcp':
                        data = await self._tcp_query(server['ip'], server['port'], pkt, timeout=2, server_id=server_url)
                    
                    if data:
                        resp = dns.message.from_wire(data)
                        found_type_ips = False
                        for rrset in resp.answer:
                            if rrset.rdtype == qtype:
                                for rdata in rrset:
                                    ip_txt = rdata.to_text()
                                    found_ips.add(ip_txt)
                                    logger.debug(f"  + Resolved {hostname} -> {ip_txt} ({dns.rdatatype.to_text(qtype)}) via {server['ip']}")
                                    found_type_ips = True
                        if found_type_ips:
                            break
                except Exception as e:
                    logger.debug(f"Bootstrap resolve error for {hostname} via {server['ip']}: {e}")
        
        if found_ips:
            logger.info(f"Successfully resolved '{hostname}': {list(found_ips)}")
        else:
            logger.error(f"Bootstrap resolution failed for '{hostname}' - tried all bootstrap servers (Mode: {mode})")
            
        return list(found_ips)

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
        valid_protos = {'udp': 53, 'tcp': 53, 'https': 443, 'tls': 853}

        for group_name, group_data in raw_groups.items():
            if not group_data:
                continue
            s_list = group_data.get('servers', []) if isinstance(group_data, dict) else group_data
            if not isinstance(s_list, list):
                continue

            for s_item in s_list:
                if isinstance(s_item, dict):
                    s_str = s_item.get('url', '')
                    priority = s_item.get('priority', 100)
                else:
                    s_str = s_item
                    priority = 100

                if not s_str:
                    logger.warning(f"Empty server URL in group '{group_name}', skipping")
                    continue
                
                forced_ip = None
                if '#' in s_str:
                    s_str, candidate_ip = s_str.rsplit('#', 1)
                    candidate_ip = candidate_ip.strip()
                    if candidate_ip.startswith('[') and candidate_ip.endswith(']'):
                        candidate_ip = candidate_ip[1:-1]
                    if self._is_valid_ip(candidate_ip):
                        forced_ip = candidate_ip
                    else:
                        logger.warning(f"Invalid forced IP '{candidate_ip}' in '{s_str}', ignoring")

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
                    logger.warning(f"Unsupported protocol '{proto}' in '{s_str}', skipping")
                    continue
                if not host:
                    logger.warning(f"Missing hostname in '{s_str}', skipping")
                    continue

                if forced_ip is None:
                    if self._is_valid_ip(host):
                        forced_ip = host

                if port is None:
                    port = valid_protos[proto]
                elif not self._is_valid_port(port):
                    logger.warning(f"Invalid port in '{s_str}', using default")
                    port = valid_protos[proto]

                if proto == 'https' and not path:
                    path = '/dns-query'

                count += 1
                server_id = f"{proto}://{host}:{port}{path}"
                
                server_entry = {
                    'id': server_id,
                    'proto': proto,
                    'host': host,
                    'ip': forced_ip,
                    'port': port,
                    'path': path,
                    'latency': float('inf'),
                    'group': group_name,
                    'priority': priority
                }
                
                self.servers.append(server_entry)
                
                if self.circuit_breaker_enabled:
                    self.circuit_breakers[server_id] = CircuitBreaker(
                        name=server_id,
                        failure_threshold=self.circuit_failure_threshold,
                        recovery_timeout=self.circuit_recovery_timeout
                    )
                
                self.lb_stats[server_id] = {'history': [], 'avg': float('inf'), 'last_used': 0}
                
                if forced_ip:
                    logger.debug(f"Upstream: {server_id} -> {forced_ip} (Group: {group_name}, Priority: {priority})")
                else:
                    logger.debug(f"Upstream: {server_id} (Group: {group_name}, Priority: {priority}, Needs Bootstrap)")

        logger.info(f"Parsed {count} upstream servers from configuration")

    # =========================================================================
    # MONITORING
    # =========================================================================

    async def start_monitor(self):
        await self._ensure_doh_client()
        
        if self.mode == "none":
            logger.info(f"Monitoring mode: '{self.mode}' - Latency monitoring disabled")
            return
            
        logger.info(f"Monitoring mode: '{self.mode}' - Starting Upstream Latency Monitor")
        logger.info(f"Monitor settings: interval={self.monitor_interval}s, on_query={self.monitor_on_query}, test_domain={self.test_domain}")
        
        expanded_servers = []
        resolved_hosts = {}
        parent_to_children = {}

        async with self._servers_lock:
            for s in self.servers:
                if s['ip']:
                    expanded_servers.append(s)
                    continue

                if s['host'] in resolved_hosts:
                    ips = resolved_hosts[s['host']]
                else:
                    ips = await self._bootstrap_resolve(s['host'])
                    resolved_hosts[s['host']] = ips
                
                if not ips:
                    logger.warning(f"Skipping {s['id']} (Resolution failed)")
                    continue

                children = []
                for ip in ips:
                    new_s = s.copy()
                    new_s['ip'] = ip
                    new_s['id'] = f"{new_s['id']}#{ip}"
                    
                    async with self._stats_lock:
                        if new_s['id'] not in self.lb_stats:
                            self.lb_stats[new_s['id']] = {'history': [], 'avg': float('inf'), 'last_used': 0}
                    
                    if self.circuit_breaker_enabled:
                        parent_cb = self.circuit_breakers.get(s['id'])
                        if parent_cb and new_s['id'] not in self.circuit_breakers:
                            new_cb = CircuitBreaker(
                                name=new_s['id'],
                                failure_threshold=self.circuit_failure_threshold,
                                recovery_timeout=self.circuit_recovery_timeout
                            )
                            new_cb.failure_count = parent_cb.failure_count
                            new_cb.last_failure_time = parent_cb.last_failure_time
                            new_cb.state = parent_cb.state
                            self.circuit_breakers[new_s['id']] = new_cb
                        elif new_s['id'] not in self.circuit_breakers:
                            self.circuit_breakers[new_s['id']] = CircuitBreaker(
                                name=new_s['id'],
                                failure_threshold=self.circuit_failure_threshold,
                                recovery_timeout=self.circuit_recovery_timeout
                            )
                    
                    expanded_servers.append(new_s)
                    children.append(new_s['id'])
                
                if children:
                    parent_to_children[s['id']] = children

            self.servers = expanded_servers
            
            proto_counts = {}
            for s in self.servers:
                proto = s['proto'].upper()
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
            
            logger.info(f"Server expansion complete: {len(self.servers)} servers ready")
            for proto, count in sorted(proto_counts.items()):
                logger.info(f"  - {proto}: {count} servers")
        
            if not any(s.get('ip') for s in self.servers) and self.fallback_enabled:
                logger.warning("Activating Fallback Servers.")
                fallback_ips = [b['ip'] for b in self.bootstrappers] if self.bootstrappers else ['86.54.11.1', '9.9.9.9', '1.1.1.2', '8.8.8.8']
                for ip in fallback_ips:
                    fallback_id = f"udp://{ip}:53"
                    self.servers.append({
                        'id': fallback_id,
                        'proto': 'udp',
                        'host': ip,
                        'ip': ip,
                        'port': 53,
                        'path': '',
                        'latency': float('inf'),
                        'group': 'Default',
                        'priority': 100
                    })
                    if self.circuit_breaker_enabled:
                        self.circuit_breakers[fallback_id] = CircuitBreaker(
                            name=fallback_id,
                            failure_threshold=self.circuit_failure_threshold,
                            recovery_timeout=self.circuit_recovery_timeout
                        )

        # Removed redundant setting of last_monitor_time to time.time() which prevented immediate execution
        # self.last_monitor_time = time.time() 
        
        logger.info("Running initial performance test to determine real upstream speeds...")
        # Use force=True to bypass interval check on startup
        await self.check_latencies(force=True)
        
        await self._log_server_status()
        
        logger.info("Running second performance test for better accuracy...")
        await asyncio.sleep(0.5)
        await self.check_latencies(force=True)
        await self._log_server_status()
        
        logger.info("Initial performance testing complete, starting monitoring loop")
        
        if not self.monitor_on_query:
            logger.info(f"Starting periodic latency checks every {self.monitor_interval}s")
            while True:
                await asyncio.sleep(self.monitor_interval)
                logger.debug(f"Periodic check triggered (mode: {self.mode})")
                await self.check_latencies()
                await self._log_server_status()
        else:
            logger.info(f"Query-triggered monitoring enabled (checks every {self.monitor_interval}s on demand)")

    async def check_latencies(self, force=False):
        if self.mode == "none":
            logger.debug("Latency check skipped (mode: none)")
            return
        
        if self._monitor_lock.locked():
            logger.debug("Latency check already in progress, skipping")
            return
            
        async with self._monitor_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_monitor_time
            
            if not force and time_since_last < (self.monitor_interval * 0.9):
                logger.debug(f"Skipping latency check (last check was only {time_since_last:.1f}s ago)")
                return
            
            self.last_monitor_time = current_time
            logger.info(f"Running latency check (mode: {self.mode}, last check: {time_since_last:.1f}s ago)")
        
            valid_targets = []
            async with self._servers_lock:
                valid_targets = [s for s in self.servers if s.get('ip')]
            
            if not valid_targets:
                logger.warning("No valid upstream targets available for latency check")
                return
            
            logger.debug(f"Checking latency for {len(valid_targets)} servers...")

            tasks = [asyncio.create_task(self._measure_latency(s)) for s in valid_targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successful_checks = 0
            failed_checks = 0
            
            async with self._stats_lock:
                active_ids = set()
                
                for i, result in enumerate(results):
                    lat = 999.0
                    srv = valid_targets[i]
                    sid = srv['id']
                    
                    if not isinstance(result, Exception):
                        lat = result
                        if lat < 900.0:
                            successful_checks += 1
                            logger.debug(f"  -> {sid}: {lat*1000:.2f}ms")
                        else:
                            failed_checks += 1
                            logger.debug(f"  -> {sid}: Timeout/Fail")
                    else:
                        failed_checks += 1
                        logger.debug(f"  -> {sid}: Error {result}")

                    srv['latency'] = lat
                    active_ids.add(sid)
                    
                    stats = self.lb_stats.get(sid)
                    if stats:
                        stats['history'].append(lat)
                        if len(stats['history']) > 5:
                            stats['history'].pop(0)
                        stats['avg'] = sum(stats['history']) / len(stats['history'])
                
                stale_ids = [sid for sid in self.lb_stats if sid not in active_ids]
                for sid in stale_ids:
                    del self.lb_stats[sid]

            logger.info(f"Latency check complete: {successful_checks} OK, {failed_checks} failed")
            
            snapshot_stats = {}
            async with self._stats_lock:
                for sid, data in self.lb_stats.items():
                    snapshot_stats[sid] = data.get('avg', float('inf'))
            
            async with self._servers_lock:
                before_top3 = [
                    (s['id'], s['proto'].upper(), s['latency'], snapshot_stats.get(s['id'], float('inf')), s.get('priority', 100))
                    for s in self.servers[:3]
                ]
                
                if self.mode in ['fastest', 'failover']:
                    self.servers.sort(key=lambda x: (x.get('priority', 100), x['latency']))
                elif self.mode == 'loadbalance':
                    self.servers.sort(key=lambda x: (x.get('priority', 100), snapshot_stats.get(x['id'], 999.0)))
                # Note: random, roundrobin, sticky, none don't need sorting here
                
                after_top3 = [
                    (s['id'], s['proto'].upper(), s['latency'], snapshot_stats.get(s['id'], float('inf')), s.get('priority', 100))
                    for s in self.servers[:3]
                ]
                
                top3_changed = (before_top3 != after_top3)
                
                if top3_changed:
                    logger.info("UPSTREAM SELECTION CHANGED")
                    for i, s in enumerate(self.servers[:3]):
                        logger.info(f"  #{i+1}: {s['id']} (Lat: {s['latency']*1000:.1f}ms, Avg: {snapshot_stats.get(s['id'], 999)*1000:.1f}ms)")
                elif logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Upstream order unchanged. Current Top 3:")
                    for i, s in enumerate(self.servers[:3]):
                        logger.debug(f"  #{i+1}: {s['id']} (Lat: {s['latency']*1000:.1f}ms)")

    async def _log_server_status(self):
        async with self._servers_lock:
            working_count = sum(1 for s in self.servers if s['latency'] < 900.0)
            if working_count < len(self.servers) * 0.3:
                display_count = len(self.servers)
            else:
                display_count = min(10, len(self.servers))
            
            targets = self.servers[:display_count]
            if not targets:
                return

            for i, s in enumerate(targets, 1):
                logger.debug(f"#{i} {s['id']} Latency: {s['latency']*1000:.1f}ms")

    async def _measure_latency(self, server):
        start = time.time()
        server_id = server['id']
        logger.debug(f"Probing {server_id}...")
        try:
            q = dns.message.make_query(self.test_domain, dns.rdatatype.A)
            pkt = q.to_wire()
            timeout = 5.0
            
            result = None
            if server['proto'] == 'udp':
                result = await self._udp_query(server['ip'], server['port'], pkt, timeout, server_id=server_id)
            elif server['proto'] == 'tcp':
                result = await self._tcp_query(server['ip'], server['port'], pkt, timeout, server_id=server_id)
            elif server['proto'] == 'https':
                result = await self._doh_query(server, pkt, timeout)
            elif server['proto'] == 'tls':
                result = await self._dot_query(server['ip'], server['port'], server['host'], pkt, timeout, server_id=server_id)
            
            if result:
                duration = time.time() - start
                logger.debug(f"Probe {server_id} success: {duration*1000:.2f}ms")
                return duration
            else:
                logger.debug(f"Probe {server_id} failed (no response)")
                return 999.0
        except Exception as e:
            logger.debug(f"Probe {server_id} exception: {e}")
            return 999.0

    # =========================================================================
    # STICKY MAP HELPERS
    # =========================================================================

    async def _update_sticky_map(self, client_ip, server_id):
        async with self._sticky_lock:
            if client_ip in self._sticky_map:
                self._sticky_map.move_to_end(client_ip)
            self._sticky_map[client_ip] = server_id
            if len(self._sticky_map) > self._sticky_max_size:
                self._sticky_map.popitem(last=False)
            
            now = time.time()
            if now - self._last_sticky_cleanup > 3600:
                self._last_sticky_cleanup = now
                stale = [k for k, _ in list(self._sticky_map.items())[:len(self._sticky_map)//2]]
                for k in stale:
                    del self._sticky_map[k]

    async def _get_sticky_server(self, client_ip):
        async with self._sticky_lock:
            if client_ip in self._sticky_map:
                self._sticky_map.move_to_end(client_ip)
                return self._sticky_map[client_ip]
            return None

    # =========================================================================
    # FORWARDING - MAIN ENTRY POINT
    # =========================================================================

    async def forward_query(self, query_data, qid=0, client_ip="Unknown", upstream_group="Default", req_logger=None):
        log = req_logger or logger
        
        await self._ensure_doh_client()
        
        # Trigger background latency check if needed
        should_check = False
        if self.monitor_on_query and self.mode != "none":
            current_time = time.time()
            time_since_last = current_time - self.last_monitor_time
            if time_since_last >= self.monitor_interval and not self._monitor_lock.locked():
                should_check = True
        
        if should_check:
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

        # --- SERVER SELECTION ---
        selected = None
        
        # Handle sticky mode first - check if client already has a pinned server
        if self.mode == 'sticky':
            sticky_server_id = await self._get_sticky_server(client_ip)
            if sticky_server_id:
                async with self._servers_lock:
                    for s in self.servers:
                        if s['id'] == sticky_server_id and s['group'] == upstream_group and s.get('ip'):
                            # Check circuit breaker
                            if self.circuit_breaker_enabled:
                                cb = self.circuit_breakers.get(s['id'])
                                if cb and not cb.can_attempt():
                                    log.debug(f"Sticky server {sticky_server_id} circuit open, falling back")
                                    break
                            selected = [s]
                            break
        
        # If no sticky match (or not sticky mode), do normal selection
        if not selected:
            async with self._servers_lock:
                candidates = [s for s in self.servers if s['group'] == upstream_group and s.get('ip')]
                if not candidates and upstream_group != "Default":
                    candidates = [s for s in self.servers if s.get('ip')]
                
                if not candidates:
                    log.error(f"FORWARD FAILURE [ID:{qid}]: No valid upstreams available")
                    return None
                
                # Apply circuit breaker filter
                if self.circuit_breaker_enabled:
                    candidates = [
                        s for s in candidates
                        if s['id'] not in self.circuit_breakers or self.circuit_breakers[s['id']].can_attempt()
                    ]
                
                if not candidates:
                    log.error(f"FORWARD FAILURE [ID:{qid}]: All upstreams circuit-broken")
                    return None
                
                # Mode-specific selection
                if self.mode == 'none':
                    # Use first available, no sorting
                    selected = candidates[:3]
                    
                elif self.mode == 'random':
                    # Shuffle and pick
                    shuffled = candidates.copy()
                    random.shuffle(shuffled)
                    selected = shuffled[:3]
                    
                elif self.mode == 'roundrobin':
                    # Rotate through servers
                    async with self._rr_lock:
                        idx = self._rr_index % len(candidates)
                        self._rr_index += 1
                    # Reorder: start from idx, wrap around
                    selected = candidates[idx:] + candidates[:idx]
                    selected = selected[:3]
                    
                elif self.mode == 'sticky':
                    # No existing sticky match, pick fastest and will pin on success
                    candidates.sort(key=lambda x: (x.get('priority', 100), x['latency']))
                    selected = candidates[:3]
                    
                elif self.mode == 'loadbalance':
                    snapshot_stats = {}
                    async with self._stats_lock:
                        for s in candidates:
                            snapshot_stats[s['id']] = self.lb_stats.get(s['id'], {}).get('avg', float('inf'))
                    candidates.sort(key=lambda x: (x.get('priority', 100), snapshot_stats.get(x['id'], 999.0)))
                    selected = candidates[:3]

                elif self.mode == 'distributed':
                    # Weighted distribution: Low Latency + High Staleness = Better Score
                    now = time.time()
                    scored_candidates = []
                    
                    async with self._stats_lock:
                        for s in candidates:
                            sid = s['id']
                            stats = self.lb_stats.get(sid, {})
                            
                            # 1. Get Average Latency (use 0.1s as baseline if missing)
                            avg_lat = stats.get('avg', s.get('latency', 0.1))
                            if avg_lat <= 0: avg_lat = 0.001
                            
                            # 2. Calculate Staleness (Time since last use)
                            last_used = stats.get('last_used', 0)
                            staleness = now - last_used
                            
                            # 3. Calculate Score
                            # Logic: Artificial latency reduction based on staleness.
                            # Every 60 seconds of staleness reduces the "effective" latency score by 50%.
                            # This floats rarely used servers to the top.
                            staleness_factor = 1.0 + (staleness / 60.0)
                            
                            # Priority penalty (higher priority value = worse score)
                            prio_penalty = s.get('priority', 100) / 100.0
                            if prio_penalty <= 0: prio_penalty = 1.0

                            # Lower Score is Better
                            score = (avg_lat * prio_penalty) / staleness_factor
                            scored_candidates.append((score, s))
                    
                    # Sort by lowest score
                    scored_candidates.sort(key=lambda x: x[0])
                    selected = [x[1] for x in scored_candidates[:3]]

                elif self.mode == 'failover':
                    # Sort by priority then latency, try in order
                    candidates.sort(key=lambda x: (x.get('priority', 100), x['latency']))
                    selected = candidates[:3]
                    
                else:  # 'fastest' or default
                    candidates.sort(key=lambda x: (x.get('priority', 100), x['latency']))
                    selected = candidates[:3]
                
                if log.isEnabledFor(logging.DEBUG) and selected:
                    sel_log = ", ".join([f"{s['id']} ({s['latency']*1000:.1f}ms)" for s in selected])
                    log.debug(f"Selected upstreams ({self.mode}): {sel_log}")
        
        # --- QUERY EXECUTION ---
        for server in selected:
            try:
                async with self._stats_lock:
                    if server['id'] in self.lb_stats:
                        self.lb_stats[server['id']]['last_used'] = time.time()
                
                start_t = time.time()
                resp = None
                
                ip = server['ip']
                port = server['port']
                server_id = server['id']
                
                if server['proto'] == 'udp':
                    resp = await self._udp_query(ip, port, query_data, server_id=server_id)
                elif server['proto'] == 'tcp':
                    resp = await self._tcp_query(ip, port, query_data, server_id=server_id)
                elif server['proto'] == 'https':
                    resp = await self._doh_query(server, query_data)
                elif server['proto'] == 'tls':
                    resp = await self._dot_query(ip, port, server['host'], query_data, server_id=server_id)
                
                if resp:
                    dur_sec = time.time() - start_t
                    dur_ms = dur_sec * 1000
                    
                    if self.circuit_breaker_enabled and server['id'] in self.circuit_breakers:
                        self.circuit_breakers[server['id']].record_success()
                    
                    if self.mode == 'sticky':
                        await self._update_sticky_map(client_ip, server['id'])
                    
                    # --- NEW: Live Statistic Update ---
                    if self.mode in ['distributed', 'loadbalance', 'fastest']:
                        async with self._stats_lock:
                            stats = self.lb_stats.get(server_id)
                            if stats:
                                stats['history'].append(dur_sec)
                                if len(stats['history']) > 10: 
                                    stats['history'].pop(0)
                                stats['avg'] = sum(stats['history']) / len(stats['history'])
                                server['latency'] = stats['avg']

                    log.info(f"Forwarded {query_info} -> {server_id} ({dur_ms:.2f}ms)")
                    return resp
                else:
                    if self.circuit_breaker_enabled and server['id'] in self.circuit_breakers:
                        self.circuit_breakers[server['id']].record_failure()
                    
            except Exception as e:
                if self.circuit_breaker_enabled and server['id'] in self.circuit_breakers:
                    self.circuit_breakers[server['id']].record_failure()
                
                log.warning(f"Upstream forward error {server['id']}: {e}")
                continue
                
        log.error("All selected upstream servers failed to respond")
        return None

    # =========================================================================
    # TRANSPORT: UDP & TCP
    # =========================================================================

    async def _udp_query(self, ip, port, data, timeout=5, server_id=None):
        loop = asyncio.get_running_loop()
        server_label = server_id if server_id else f"udp://{ip}:{port}"
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
            logger.debug(f"UDP Error {server_label}: {e}")
            return None

    async def _tcp_query(self, ip, port, data, timeout=5, server_id=None):
        server_label = server_id if server_id else f"tcp://{ip}:{port}"
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
            logger.debug(f"TCP Error {server_label}: {e}")
            return None

    # =========================================================================
    # TRANSPORT: DoT (DNS-over-TLS)
    # =========================================================================

    async def _dot_query(self, ip, port, host, data, timeout=5, server_id=None):
        if self.connection_reuse:
            return await self._dot_query_reusing(ip, port, host, data, timeout, server_id)
        else:
            return await self._dot_query_oneshot(ip, port, host, data, timeout, server_id)

    async def _dot_query_oneshot(self, ip, port, host, data, timeout=5, server_id=None):
        """Standard DoT query with a fresh connection per request"""
        server_label = server_id if server_id else f"tls://{host}:{port}"
        logger.debug(f"DEBUG: DoT Connection OPEN to {server_label}")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=self.ssl_context, server_hostname=host),
                timeout
            )
            
            try:
                writer.write(len(data).to_bytes(2, 'big') + data)
                await writer.drain()
                
                len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
                length = int.from_bytes(len_bytes, 'big')
                resp = await asyncio.wait_for(reader.readexactly(length), timeout)
                return resp
            finally:
                logger.debug(f"DEBUG: DoT Connection CLOSE to {server_label}")
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            logger.debug(f"DoT Oneshot Error {server_label}: {e}")
            return None

    async def _dot_query_reusing(self, ip, port, host, data, timeout=5, server_id=None):
        """Pooled DoT query with connection reuse and smart retry"""
        key = (ip, port, host)
        server_label = server_id if server_id else f"tls://{host}:{port}"

        async with self._dot_locks[key]:
            for attempt in range(2):
                connection = self._dot_pool.get(key)
                
                if connection:
                    reader, writer = connection
                    if writer.is_closing():
                        logger.debug(f"DEBUG: DoT Connection STALE to {server_label} - removing")
                        del self._dot_pool[key]
                        connection = None

                is_reused = (connection is not None)

                if not connection:
                    logger.debug(f"DEBUG: DoT Connection OPEN to {server_label}")
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port, ssl=self.ssl_context, server_hostname=host),
                            timeout
                        )
                        connection = (reader, writer)
                        self._dot_pool[key] = connection
                    except Exception as e:
                        logger.debug(f"DoT Connect Error {server_label}: {e}")
                        return None

                reader, writer = connection
                try:
                    writer.write(len(data).to_bytes(2, 'big') + data)
                    await writer.drain()
                    
                    len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
                    length = int.from_bytes(len_bytes, 'big')
                    resp = await asyncio.wait_for(reader.readexactly(length), timeout)
                    
                    if is_reused:
                        logger.debug(f"DEBUG: DoT Connection REUSE SUCCESS to {server_label}")
                    return resp
                    
                except Exception as e:
                    logger.debug(f"DoT Error {server_label} [Reuse={is_reused}]: {e}")
                    
                    try:
                        writer.close()
                    except:
                        pass
                        
                    if key in self._dot_pool:
                        del self._dot_pool[key]
                    
                    if is_reused and attempt == 0:
                        logger.debug(f"DEBUG: Retrying DoT query with fresh connection to {server_label}")
                        continue
                    
                    return None
            
            return None

    # =========================================================================
    # TRANSPORT: DoH (DNS-over-HTTPS)
    # =========================================================================

    async def _doh_query(self, server, data, timeout=5):
        if self.connection_reuse:
            return await self._doh_query_reusing(server, data, timeout)
        else:
            return await self._doh_query_oneshot(server, data, timeout)

    async def _doh_query_reusing(self, server, data, timeout=5):
        """Uses the persistent httpx client with retry logic"""
        try:
            await self._ensure_doh_client()
            
            ip = server.get('ip')
            host = server['host']
            port = server['port']
            path = server['path']
            server_id = server.get('id', f"https://{host}:{port}{path}")
            
            if ip:
                url_ip = f"[{ip}]" if ':' in ip and not ip.startswith('[') else ip
                url = f"https://{url_ip}:{port}{path}"
                headers = DOH_HEADERS.copy()
                headers['Host'] = host
                extensions = {'sni_hostname': host}
            else:
                url = f"https://{host}:{port}{path}"
                headers = DOH_HEADERS.copy()
                extensions = {}

            for attempt in range(2):
                try:
                    msg = "KeepAlive" if attempt == 0 else "Retry"
                    logger.debug(f"DEBUG: DoH Request ({msg}) to {server_id}")
                    
                    response = await asyncio.wait_for(
                        self.doh_client.post(url, content=data, headers=headers, extensions=extensions),
                        timeout=timeout
                    )
                    
                    if response.status_code == 200:
                        return response.content
                    else:
                        logger.debug(f"DoH HTTP {response.status_code} from {server_id}")
                        return None
                        
                except Exception as e:
                    is_network_error = True
                    
                    if attempt == 0 and is_network_error:
                        logger.debug(f"DoH KeepAlive failed ({e}) to {server_id}, retrying...")
                        continue
                    
                    logger.debug(f"DoH Error {server_id}: {e}")
                    return None
                    
        except Exception as e:
            logger.debug(f"DoH Setup Error {server.get('id', host)}: {e}")
            return None

    async def _doh_query_oneshot(self, server, data, timeout=5):
        """Creates a fresh httpx client context for each request"""
        try:
            import httpx
            
            ip = server.get('ip')
            host = server['host']
            port = server['port']
            path = server['path']
            server_id = server.get('id', f"https://{host}:{port}{path}")
            
            if ip:
                url_ip = f"[{ip}]" if ':' in ip and not ip.startswith('[') else ip
                url = f"https://{url_ip}:{port}{path}"
                headers = DOH_HEADERS.copy()
                headers['Host'] = host
                extensions = {'sni_hostname': host}
            else:
                url = f"https://{host}:{port}{path}"
                headers = DOH_HEADERS.copy()
                extensions = {}

            logger.debug(f"DEBUG: DoH Connection OPEN to {server_id}")
            
            async with httpx.AsyncClient(http2=True, verify=True) as client:
                response = await asyncio.wait_for(
                    client.post(url, content=data, headers=headers, extensions=extensions),
                    timeout=timeout
                )
                
                logger.debug(f"DEBUG: DoH Connection CLOSE to {server_id}")
                
                if response.status_code == 200:
                    return response.content
                else:
                    logger.debug(f"DoH HTTP {response.status_code} from {server_id}")
                    return None
                    
        except ImportError:
            logger.error("httpx is required for DoH support. Install with: pip install httpx")
            return None
        except Exception as e:
            logger.debug(f"DoH Oneshot Error {server.get('id', host)}: {e}")
            return None


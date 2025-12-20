#!/usr/bin/env python3
# filename: recursive_resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.5.0 (Performance Optimizations)
# -----------------------------------------------------------------------------
"""
Iterative DNS resolver with performance optimizations:
- Circuit breaker for failing nameservers
- Timeout management (separate DNSSEC timeout)
- ThreadPoolExecutor for DNSSEC crypto
- Fixed validation infinite loop
"""

import asyncio
import socket
import random
import time
import logging
from typing import Optional, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.rrset
import dns.inet

from utils import get_logger
from root_hints import RootHintsManager, TrustAnchorManager
from dnssec_validator import DNSSECValidator, DNSSECStatus

logger = get_logger("Recursive")

# Global executor for CPU-bound crypto tasks (DNSSEC)
_CRYPTO_EXECUTOR = None 

def get_crypto_executor():
    global _CRYPTO_EXECUTOR
    if _CRYPTO_EXECUTOR is None:
        import multiprocessing
        # Use ThreadPoolExecutor instead of ProcessPoolExecutor
        # dnspython crypto is fast enough, ProcessPool has huge IPC overhead
        workers = max(2, multiprocessing.cpu_count() // 2)
        _CRYPTO_EXECUTOR = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="DNSSEC")
    return _CRYPTO_EXECUTOR


class CircuitBreaker:
    """Prevent queries to consistently failing nameservers"""
    
    def __init__(self, failure_threshold=3, recovery_time=60):
        self.failures: Dict[str, int] = {}
        self.blocked_until: Dict[str, float] = {}
        self.threshold = failure_threshold
        self.recovery = recovery_time
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip not in self.blocked_until:
            return False  # Not blocked if never failed
        
        # Check if recovery period passed
        if time.time() > self.blocked_until[ip]:
            del self.blocked_until[ip]
            self.failures[ip] = 0
            logger.debug(f"Circuit breaker: {ip} recovered")
            return False
        
        return True  # Still blocked
    
    def record_failure(self, ip: str):
        """Record failure and potentially block IP"""
        self.failures[ip] = self.failures.get(ip, 0) + 1
        
        if self.failures[ip] >= self.threshold:
            self.blocked_until[ip] = time.time() + self.recovery
            logger.warning(f"Circuit breaker: Blocking {ip} for {self.recovery}s after {self.failures[ip]} failures")
    
    def record_success(self, ip: str):
        """Reset failure counter on success"""
        if ip in self.failures and self.failures[ip] > 0:
            logger.debug(f"Circuit breaker: {ip} success, clearing {self.failures[ip]} failures")
        self.failures[ip] = 0
        if ip in self.blocked_until:
            del self.blocked_until[ip]


class SRTTTracker:
    """Tracks Smoothed Round Trip Time (SRTT) for nameservers"""
    
    def __init__(self):
        self._rtt = {}
        self._default_rtt = 0.5
    
    def update(self, ip: str, duration: float):
        if ip in self._rtt:
            self._rtt[ip] = (self._rtt[ip] * 0.7) + (duration * 0.3)
        else:
            self._rtt[ip] = duration
    
    def get(self, ip: str) -> float:
        return self._rtt.get(ip, self._default_rtt)
    
    def sort_nameservers(self, nameservers: List[Tuple[str, List[str]]]) -> List[Tuple[str, List[str]]]:
        return sorted(nameservers, key=lambda x: min([self.get(ip) for ip in x[1]] or [999]))


class NSCache:
    """LRU cache for nameserver records"""
    
    def __init__(self, max_size=10000):
        self.max_size = max_size
        self.cache: OrderedDict = OrderedDict()
    
    def get(self, zone: str):
        zone = zone.lower().rstrip('.') + '.'
        if zone in self.cache:
            ns_list, expiry = self.cache[zone]
            if time.time() < expiry:
                return ns_list
            del self.cache[zone]
        return None
    
    def put(self, zone: str, ns_records: List[Tuple[str, List[str]]], ttl: int = 86400):
        zone = zone.lower().rstrip('.') + '.'
        if len(self.cache) >= self.max_size and zone not in self.cache:
            self.cache.popitem(last=False)
        self.cache[zone] = (ns_records, time.time() + ttl)
    
    def get_deepest_match(self, qname: dns.name.Name) -> Tuple[dns.name.Name, List[Tuple[str, List[str]]]]:
        current = qname
        while True:
            zone_str = str(current)
            ns_list = self.get(zone_str)
            if ns_list:
                return current, ns_list
            
            if current == dns.name.root:
                break
            try:
                current = current.parent()
            except:
                break
        return None, None


class RecursiveResolver:
    MAX_REFERRALS = 30
    MAX_CNAMES = 10
    QUERY_TIMEOUT = 4.0
    DNSSEC_QUERY_TIMEOUT = 2.0  # Shorter timeout for DNSSEC
    TOTAL_TIMEOUT = 15.0  # Absolute max
    
    def __init__(self, config: dict, upstream_manager):
        self.config = config or {}
        self.upstream_manager = upstream_manager
        self.enabled = self.config.get('enabled', False)
        self.qm_mode = self.config.get('qname_minimization', 'strict').lower()
        self.prefer_ipv6 = self.config.get('prefer_ipv6', False)
        
        self.fallback_enabled = self.config.get('fallback_enabled', False)
        self.fallback_group = self.config.get('fallback_group', 'Default')
        
        self.root_hints = RootHintsManager(self.config.get('root_hints', {}))
        self.trust_anchor_manager = TrustAnchorManager(self.config.get('trust_anchors', {}))
        
        self.dnssec_mode = self.config.get('dnssec', {}).get('mode', 'none')
        self.dnssec_validator: Optional[DNSSECValidator] = None
        
        self.ns_cache = NSCache(max_size=self.config.get('ns_cache_size', 10000))
        self.srtt = SRTTTracker()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.get('circuit_breaker_threshold', 3),
            recovery_time=self.config.get('circuit_breaker_recovery', 60)
        )
    
    async def initialize(self) -> bool:
        if not self.enabled:
            return True
        
        if not await self.root_hints.initialize():
            return False
        await self.trust_anchor_manager.initialize()
        
        if self.dnssec_mode != 'none':
            self.dnssec_validator = DNSSECValidator(
                config=self.config.get('dnssec', {}),
                trust_anchors=self.trust_anchor_manager.get_trust_anchors(),
                query_func=self._raw_query_shim 
            )
            get_crypto_executor()
        
        await self.root_hints.start_refresh_task()
        await self.trust_anchor_manager.start_refresh_task()
        return True
    
    async def resolve(self, qname: str, qtype: int, req_logger=None) -> Optional[dns.message.Message]:
        """Main entry with total timeout"""
        log = req_logger or logger
        if not self.enabled:
            return None
        
        qname_obj = dns.name.from_text(qname)
        log.info(f"Recursive resolve: {qname} [{dns.rdatatype.to_text(qtype)}]")
        
        try:
            return await asyncio.wait_for(
                self._resolve_with_fallback(qname_obj, qtype, log),
                timeout=self.TOTAL_TIMEOUT
            )
        except asyncio.TimeoutError:
            log.error(f"Total resolution timeout ({self.TOTAL_TIMEOUT}s) for {qname}")
            return self._make_servfail(qname_obj, qtype)
    
    async def _resolve_with_fallback(self, qname_obj, qtype, log):
        """Resolution with fallback logic"""
        try:
            response = await self._resolve_iterative(qname_obj, qtype, log)
            if response and response.rcode() == dns.rcode.NOERROR:
                return response
        except Exception as e:
            log.warning(f"Recursive resolution failed: {e}")
        
        if self.fallback_enabled and self.upstream_manager:
            log.info(f"Falling back to upstream group: {self.fallback_group}")
            msg = await self.upstream_manager.resolve(
                str(qname_obj), qtype, group=self.fallback_group, logger=log
            )
            if msg:
                return dns.message.from_wire(msg)
        
        return self._make_servfail(qname_obj, qtype)
    
    async def _resolve_iterative(self, qname, qtype, log, skip_validation=False):
        """Iterative resolution (loop-based to prevent stack overflow)"""
        original_qname = qname
        current_qname = qname
        accumulated_cnames = []
        cname_count = 0
        chain_length = 0
        
        resolved_response = None
        
        while cname_count < self.MAX_CNAMES and chain_length < self.MAX_REFERRALS:
            cached_match_zone, cached_ns = self.ns_cache.get_deepest_match(current_qname)
            
            if cached_match_zone:
                current_zone = cached_match_zone
                nameservers = cached_ns
            else:
                current_zone = dns.name.root
                nameservers = self._get_root_nameservers()
            
            current_depth = len(current_zone.labels) - 1
            target_labels = current_qname.labels
            
            while chain_length < self.MAX_REFERRALS:
                chain_length += 1
                
                if self.qm_mode == 'off':
                    q_name_current = current_qname
                    q_type_current = qtype
                else:
                    if current_depth >= len(target_labels):
                        q_name_current = current_qname
                        q_type_current = qtype
                    else:
                        depth_from_right = len(target_labels) - current_depth
                        q_name_current = dns.name.Name(target_labels[-depth_from_right:])
                        q_type_current = dns.rdatatype.A
                
                response, used_server_ip = await self._query_any_server(nameservers, q_name_current, q_type_current, log)
                
                if not response:
                    if self.qm_mode == 'relaxed' and q_name_current != current_qname:
                        log.debug(f"Minimization failed, trying full QNAME")
                        current_depth = len(target_labels)
                        continue
                    
                    log.warning(f"Failed to get response for {q_name_current} from {current_zone}")
                    return None
                
                rcode = response.rcode()
                
                # Referral
                referral = self._extract_referral(response)
                if referral:
                    new_zone, new_ns = referral
                    
                    if new_zone == current_zone:
                        log.warning("Loop: Referral to same zone")
                        break
                    
                    self.ns_cache.put(str(new_zone), new_ns)
                    current_zone = new_zone
                    nameservers = new_ns
                    current_depth = len(new_zone.labels) - 1
                    continue
                
                # NXDOMAIN
                if rcode == dns.rcode.NXDOMAIN:
                    if q_name_current != current_qname:
                        if self.qm_mode == 'relaxed':
                            current_depth = len(target_labels)
                            continue
                    return await self._finalize_response(response, original_qname, qtype, log, accumulated_cnames, skip_validation)
                
                # NOERROR
                if rcode == dns.rcode.NOERROR:
                    if q_name_current != current_qname:
                        current_depth += 1
                        continue
                    
                    cname_rr = self._find_cname(response, current_qname)
                    if cname_rr:
                        target = cname_rr[0].target
                        
                        if any(rr[0].target == target for rr in accumulated_cnames):
                            log.error(f"CNAME Loop detected: {target}")
                            return self._make_servfail(original_qname, qtype)
                        
                        log.info(f"Following CNAME {current_qname} -> {target}")
                        accumulated_cnames.append(cname_rr)
                        current_qname = target
                        cname_count += 1
                        resolved_response = None
                        break
                    
                    return await self._finalize_response(response, original_qname, qtype, log, accumulated_cnames, skip_validation)
                
                # Other errors
                log.warning(f"Got RCODE {dns.rcode.to_text(rcode)} from {current_zone}")
                return await self._finalize_response(response, original_qname, qtype, log, accumulated_cnames, skip_validation)
            
            if cname_count > self.MAX_CNAMES:
                log.error("Max CNAME depth exceeded")
                return self._make_servfail(original_qname, qtype)
            
            if not resolved_response and chain_length >= self.MAX_REFERRALS:
                log.error("Max referrals exceeded")
                return self._make_servfail(original_qname, qtype)
        
        return self._make_servfail(original_qname, qtype)
    
    async def _query_any_server(self, nameservers, qname, qtype, log) -> Tuple[Optional[dns.message.Message], str]:
        """Try nameservers with circuit breaker and glue resolution"""
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        wire = query.to_wire()
        
        total_tried = 0
        total_blocked = 0
        
        for ns_name, ips in nameservers:
            # Resolve nameserver IPs if missing (glue-less delegation)
            if not ips:
                log.debug(f"Nameserver {ns_name} has no glue, resolving...")
                resolved_ips = await self._resolve_nameserver(ns_name, log)
                if resolved_ips:
                    ips = resolved_ips
                    log.debug(f"Resolved {ns_name} to {ips}")
                else:
                    log.debug(f"Failed to resolve {ns_name}, skipping")
                    continue
            
            available_ips = [ip for ip in ips if not self.circuit_breaker.is_blocked(ip)]
            blocked_count = len(ips) - len(available_ips)
            total_blocked += blocked_count
            
            if not available_ips:
                log.debug(f"All {len(ips)} IPs for {ns_name} circuit-broken")
                continue
            
            if blocked_count > 0:
                log.debug(f"Nameserver {ns_name}: {blocked_count}/{len(ips)} IPs blocked")
            
            sorted_ips = sorted(
                available_ips,
                key=lambda ip: (':' not in ip if self.prefer_ipv6 else ':' in ip, self.srtt.get(ip))
            )
            
            for ip in sorted_ips:
                total_tried += 1
                t0 = time.time()
                try:
                    resp_wire = await self._udp_query(ip, wire)
                    if resp_wire:
                        duration = time.time() - t0
                        self.srtt.update(ip, duration)
                        self.circuit_breaker.record_success(ip)
                        
                        msg = dns.message.from_wire(resp_wire)
                        if msg.flags & dns.flags.TC:
                            resp_wire_tcp = await self._tcp_query(ip, wire)
                            if resp_wire_tcp:
                                msg = dns.message.from_wire(resp_wire_tcp)
                                return msg, ip
                        else:
                            return msg, ip
                    else:
                        self.srtt.update(ip, 2.0)
                        self.circuit_breaker.record_failure(ip)
                except Exception:
                    self.srtt.update(ip, 2.0)
                    self.circuit_breaker.record_failure(ip)
                    continue
        
        if total_tried == 0:
            log.warning(f"No nameservers available for {qname} (blocked: {total_blocked})")
        
        return None, None
    
    async def _finalize_response(self, response, original_qname, qtype, log, accumulated_cnames=None, skip_validation=False):
        """Perform DNSSEC validation and cleanup"""
        if not response:
            return None
        
        response.question = [dns.rrset.RRset(original_qname, dns.rdataclass.IN, qtype)]
        
        if accumulated_cnames:
            response.answer = accumulated_cnames + list(response.answer)
        
        # Skip validation for internal DNSSEC queries
        if skip_validation or self.dnssec_mode == 'none' or not self.dnssec_validator:
            return response
        
        try:
            status, validated_response = await self.dnssec_validator.validate_response(
                response, str(original_qname), qtype, log
            )
            
            if status == DNSSECStatus.BOGUS and self.dnssec_mode in ['standard', 'strict']:
                log.error(f"DNSSEC Failure (BOGUS) for {original_qname}")
                return self._make_servfail(original_qname, qtype)
            
            if validated_response:
                response = validated_response
        except Exception as e:
            log.error(f"DNSSEC Validation crashed: {e}")
            if self.dnssec_mode == 'strict':
                return self._make_servfail(original_qname, qtype)
        
        return response
    
    def _extract_referral(self, response):
        ns_rrset = None
        for rr in response.authority:
            if rr.rdtype == dns.rdatatype.NS:
                ns_rrset = rr
                break
        
        if not ns_rrset:
            return None
        
        ref_zone = ns_rrset.name
        
        ns_ips = {}
        for rr in response.additional:
            if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                name = str(rr.name).lower()
                if name not in ns_ips:
                    ns_ips[name] = []
                for rd in rr:
                    ns_ips[name].append(rd.to_text())
        
        result_ns = []
        for rd in ns_rrset:
            ns_name = str(rd.target).lower()
            ips = ns_ips.get(ns_name, [])
            result_ns.append((ns_name, ips))
        
        return ref_zone, result_ns
    
    def _find_cname(self, response, qname):
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.CNAME and rr.name == qname:
                return rr
        return None
    
    async def _udp_query(self, ip, wire):
        loop = asyncio.get_running_loop()
        try:
            fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
            sock = socket.socket(fam, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            await loop.sock_connect(sock, (ip, 53))
            await loop.sock_sendall(sock, wire)
            
            data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=self.QUERY_TIMEOUT)
            sock.close()
            return data
        except (asyncio.TimeoutError, OSError):
            return None
    
    async def _tcp_query(self, ip, wire):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 53), timeout=self.QUERY_TIMEOUT
            )
            writer.write(len(wire).to_bytes(2, 'big') + wire)
            await writer.drain()
            
            len_bytes = await reader.readexactly(2)
            length = int.from_bytes(len_bytes, 'big')
            data = await reader.readexactly(length)
            
            writer.close()
            await writer.wait_closed()
            return data
        except:
            return None
    
    def _make_servfail(self, qname, qtype):
        r = dns.message.make_response(dns.message.make_query(qname, qtype))
        r.set_rcode(dns.rcode.SERVFAIL)
        return r
    
    async def _raw_query_shim(self, wire):
        """DNSSEC query shim with shorter timeout - MUST NOT trigger validation"""
        try:
            msg = dns.message.from_wire(wire)
            q = msg.question[0]
            log = logging.LoggerAdapter(logger, {'id': 'DNSSEC', 'ip': 'Int', 'proto': 'INT'})
            
            # CRITICAL: skip_validation=True to break infinite loop
            resp = await asyncio.wait_for(
                self._resolve_iterative(q.name, q.rdtype, log, skip_validation=True),
                timeout=self.DNSSEC_QUERY_TIMEOUT
            )
            return resp.to_wire() if resp else None
        except asyncio.TimeoutError:
            logger.debug(f"DNSSEC query timeout for {q.name}")
            return None
        except:
            return None
    
    def _get_root_nameservers(self):
        return [(s.name, s.get_ips(self.prefer_ipv6)) for s in self.root_hints.root_servers]
    
    async def _resolve_nameserver(self, ns_name: str, log) -> List[str]:
        """Resolve nameserver hostname to IPs (for glue-less delegations)"""
        if not hasattr(self, '_ns_resolution_cache'):
            self._ns_resolution_cache = {}
        
        ns_name_str = str(ns_name).lower().rstrip('.')
        
        # Check cache
        if ns_name_str in self._ns_resolution_cache:
            cached_ips, expiry = self._ns_resolution_cache[ns_name_str]
            if time.time() < expiry:
                return cached_ips
        
        ips = []
        
        # FALLBACK: Use upstream forwarder for NS resolution if recursive fails
        # This prevents REFUSED errors from authoritative servers with ACLs
        if self.upstream_manager:
            try:
                log.debug(f"Attempting upstream resolution for {ns_name_str}")
                
                # Try A record via upstream
                wire = await self.upstream_manager.forward_query(
                    dns.message.make_query(ns_name_str, dns.rdatatype.A).to_wire(),
                    qid=0,
                    client_ip="127.0.0.1",
                    upstream_group="Default",
                    req_logger=log
                )
                if wire:
                    response = dns.message.from_wire(wire)
                    for rrset in response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            ips.extend([rdata.to_text() for rdata in rrset])
                
                # Try AAAA if needed
                if self.prefer_ipv6 or not ips:
                    wire = await self.upstream_manager.forward_query(
                        dns.message.make_query(ns_name_str, dns.rdatatype.AAAA).to_wire(),
                        qid=0,
                        client_ip="127.0.0.1",
                        upstream_group="Default",
                        req_logger=log
                    )
                    if wire:
                        response = dns.message.from_wire(wire)
                        for rrset in response.answer:
                            if rrset.rdtype == dns.rdatatype.AAAA:
                                ips.extend([rdata.to_text() for rdata in rrset])
                
                if ips:
                    log.debug(f"Upstream resolved {ns_name_str} to {ips}")
                    self._ns_resolution_cache[ns_name_str] = (ips, time.time() + 3600)
                    return ips
            except Exception as e:
                log.debug(f"Upstream resolution failed for {ns_name_str}: {e}")
        
        # Try recursive resolution as last resort
        try:
            a_response = await asyncio.wait_for(
                self._resolve_iterative(dns.name.from_text(ns_name_str), dns.rdatatype.A, log, skip_validation=True),
                timeout=3.0
            )
            if a_response and a_response.rcode() == dns.rcode.NOERROR:
                for rrset in a_response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        ips.extend([rdata.to_text() for rdata in rrset])
        except asyncio.TimeoutError:
            log.debug(f"Timeout resolving A for {ns_name_str}")
        except Exception as e:
            log.debug(f"Error resolving A for {ns_name_str}: {e}")
        
        if self.prefer_ipv6 or not ips:
            try:
                aaaa_response = await asyncio.wait_for(
                    self._resolve_iterative(dns.name.from_text(ns_name_str), dns.rdatatype.AAAA, log, skip_validation=True),
                    timeout=3.0
                )
                if aaaa_response and aaaa_response.rcode() == dns.rcode.NOERROR:
                    for rrset in aaaa_response.answer:
                        if rrset.rdtype == dns.rdatatype.AAAA:
                            ips.extend([rdata.to_text() for rdata in rrset])
            except asyncio.TimeoutError:
                log.debug(f"Timeout resolving AAAA for {ns_name_str}")
            except Exception as e:
                log.debug(f"Error resolving AAAA for {ns_name_str}: {e}")
        
        if ips:
            self._ns_resolution_cache[ns_name_str] = (ips, time.time() + 3600)
        
        return ips


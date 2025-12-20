#!/usr/bin/env python3
"""
DNS Iterator - Unbound-inspired recursive resolver core
Handles iterative resolution from root servers with proper state machine
"""
import asyncio
import socket
import random
import time
from typing import Optional, List, Tuple
from collections import OrderedDict
from enum import Enum

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.rrset

from utils import get_logger
from .hints import RootHints
from .validator import Validator, ValidationStatus

logger = get_logger("Iterator")


class IterState(Enum):
    """Iterator state machine states"""
    INIT = "init"
    QUERY_ROOT = "query_root"
    QUERY_NS = "query_ns"
    ANSWER_RESPONSE = "answer_response"
    FINISHED = "finished"


class NSCache:
    """Cache nameserver delegations"""
    def __init__(self, max_size=10000):
        self.cache = OrderedDict()
        self.max_size = max_size
    
    def get(self, zone: dns.name.Name):
        zone_str = str(zone).lower()
        if zone_str in self.cache:
            ns_list, expiry = self.cache[zone_str]
            if time.time() < expiry:
                return ns_list
            del self.cache[zone_str]
        return None
    
    def put(self, zone: dns.name.Name, ns_records: List[Tuple[str, List[str]]], ttl=86400):
        zone_str = str(zone).lower()
        if len(self.cache) >= self.max_size and zone_str not in self.cache:
            self.cache.popitem(last=False)
        self.cache[zone_str] = (ns_records, time.time() + ttl)
    
    def find_deepest_match(self, qname: dns.name.Name):
        """Find longest matching zone delegation"""
        current = qname
        while current:
            ns_list = self.get(current)
            if ns_list:
                return current, ns_list
            if current == dns.name.root:
                break
            try:
                current = current.parent()
            except:
                break
        return None, None


class ServerSelection:
    """RTT-based server selection with lameness detection"""
    def __init__(self):
        self.rtt = {}  # {ip: (avg_rtt, last_update)}
        self.failures = {}  # {ip: failure_count}
        self.lame_zones = {}  # {(ip, zone): expiry}
        
    def record_rtt(self, ip: str, rtt_ms: float):
        """Exponentially weighted moving average"""
        if ip not in self.rtt:
            self.rtt[ip] = (rtt_ms, time.time())
        else:
            old_rtt, _ = self.rtt[ip]
            # EWMA: 0.75 * old + 0.25 * new
            new_rtt = 0.75 * old_rtt + 0.25 * rtt_ms
            self.rtt[ip] = (new_rtt, time.time())
    
    def record_failure(self, ip: str):
        self.failures[ip] = self.failures.get(ip, 0) + 1
    
    def record_success(self, ip: str):
        self.failures[ip] = 0
    
    def is_lame(self, ip: str, zone: dns.name.Name):
        """Check if server is lame for zone"""
        key = (ip, str(zone))
        if key in self.lame_zones:
            if time.time() < self.lame_zones[key]:
                return True
            del self.lame_zones[key]
        return False
    
    def mark_lame(self, ip: str, zone: dns.name.Name, duration=3600):
        """Mark server as lame for zone"""
        key = (ip, str(zone))
        self.lame_zones[key] = time.time() + duration
    
    def select_target(self, targets: List[str], zone: dns.name.Name):
        """Select best target based on RTT and lameness"""
        valid = []
        for ip in targets:
            if self.failures.get(ip, 0) >= 3:
                continue
            if self.is_lame(ip, zone):
                continue
            rtt_val, _ = self.rtt.get(ip, (1000, 0))
            valid.append((rtt_val, ip))
        
        if not valid:
            return None
        
        valid.sort()
        return valid[0][1]


class Iterator:
    """Iterative DNS resolver - unbound-style"""
    
    MAX_REFERRALS = 30
    MAX_CNAME_CHAIN = 10
    QUERY_TIMEOUT = 4.0
    
    def __init__(self, config: dict, root_hints: RootHints, validator: Optional['Validator'] = None):
        self.config = config
        self.root_hints = root_hints
        self.validator = validator
        self.prefer_ipv6 = config.get('prefer_ipv6', False)
        self.qname_min = config.get('qname_minimization', 'relaxed')
        
        self.ns_cache = NSCache(config.get('ns_cache_size', 10000))
        self.server_selection = ServerSelection()
    
    async def resolve(self, qname: dns.name.Name, qtype: int, log=None):
        """Main resolution entry point"""
        log = log or logger
    
        state = IterState.INIT
        current_qname = qname
        referral_count = 0
        cname_chain = []
        cname_count = 0
    
        current_zone = dns.name.root
        current_ns = self.root_hints.get_servers(self.prefer_ipv6)
    
        log.info(f"🔄 Starting recursive resolution: {qname} [{dns.rdatatype.to_text(qtype)}]")
    
        while state != IterState.FINISHED:
            if referral_count >= self.MAX_REFERRALS:
                log.error(f"❌ Max referrals ({self.MAX_REFERRALS}) exceeded for {qname}")
                return self._make_servfail(qname, qtype)
        
            if state == IterState.INIT:
                # Check NS cache for delegation
                cached_zone, cached_ns = self.ns_cache.find_deepest_match(current_qname)
                if cached_zone:
                    current_zone = cached_zone
                    current_ns = cached_ns
                    log.info(f"📦 Cache hit: Using cached NS for {current_zone}")
                else:
                    log.info(f"🌐 Starting from root servers")
                state = IterState.QUERY_NS
        
            elif state == IterState.QUERY_NS:
                # Query nameserver
                query_name = self._minimize_qname(current_qname, current_zone) if self.qname_min != 'off' else current_qname
            
                if query_name != current_qname:
                    log.info(f"🔒 QNAME minimization: querying {query_name} instead of {current_qname}")
            
                log.info(f"📡 Querying NS for zone {current_zone}")
                response = await self._query_nameservers(query_name, qtype, current_ns, log)
            
                if not response:
                    log.warning(f"⚠️  No response from NS for {current_zone}")
                    return self._make_servfail(qname, qtype)
            
                # Check response
                rcode = response.rcode()
                log.debug(f"   Response RCODE: {dns.rcode.to_text(rcode)}")
            
                if rcode != dns.rcode.NOERROR:
                    if rcode == dns.rcode.NXDOMAIN:
                        log.info(f"❌ NXDOMAIN: {qname} does not exist")
                    else:
                        log.warning(f"⚠️  Got {dns.rcode.to_text(rcode)} from {current_zone}")
                    return response
            
                # Got answer?
                if response.answer:
                    # Check for CNAME
                    cname_rr = self._find_cname(response, current_qname)
                    if cname_rr:
                        if cname_count >= self.MAX_CNAME_CHAIN:
                            log.error(f"❌ CNAME loop detected for {qname}")
                            return self._make_servfail(qname, qtype)
                    
                        target = cname_rr[0].target
                        log.info(f"🔗 CNAME: {current_qname} → {target}")
                        cname_chain.append(cname_rr)
                        current_qname = target
                        cname_count += 1
                        referral_count += 1
                        state = IterState.INIT
                        continue
                
                    # Real answer
                    log.info(f"✅ Got answer for {qname} ({len(response.answer)} RRsets)")
                    state = IterState.ANSWER_RESPONSE
                    continue
            
                # Got referral?
                ref = self._extract_referral(response)
                if ref:
                    ref_zone, ref_ns = ref
                
                    # Check for progress
                    if not current_qname.is_subdomain(ref_zone):
                        # Bad referral
                        log.warning(f"⚠️  Bad referral from {current_zone} to {ref_zone} (not a parent)")
                        # Mark as lame
                        for _, ips in current_ns:
                            for ip in ips:
                                self.server_selection.mark_lame(ip, current_zone)
                        return self._make_servfail(qname, qtype)
                
                    # Accept referral
                    log.info(f"➡️  Referral: {current_zone} → {ref_zone} ({len(ref_ns)} NS)")
                    current_zone = ref_zone
                    current_ns = ref_ns
                    self.ns_cache.put(ref_zone, ref_ns, ttl=86400)
                    referral_count += 1
                
                    # Log nameservers
                    for ns_name, ips in ref_ns[:3]:  # Show first 3
                        if ips:
                            log.debug(f"   NS: {ns_name} ({', '.join(ips[:2])})")
                        else:
                            log.debug(f"   NS: {ns_name} (no glue)")
                
                    continue
            
                # No answer, no referral - probably NODATA
                log.info(f"ℹ️  NODATA response for {qname}")
                state = IterState.ANSWER_RESPONSE
        
            elif state == IterState.ANSWER_RESPONSE:
                # Assemble final response
                final_response = response
                final_response.question = [dns.rrset.RRset(qname, dns.rdataclass.IN, qtype)]
            
                if cname_chain:
                    final_response.answer = cname_chain + list(response.answer)
            
                # DNSSEC validation
                if self.validator:
                    log.info(f"🔐 Starting DNSSEC validation for {qname}")
                    status, validated = await self.validator.validate(final_response, str(qname), qtype, log)
                
                    if status == ValidationStatus.BOGUS:
                        log.error(f"❌ DNSSEC validation FAILED (BOGUS) for {qname}")
                        if self.validator.is_enforcing():
                            return self._make_servfail(qname, qtype)
                    elif status == ValidationStatus.SECURE:
                        log.info(f"✅ DNSSEC validation PASSED (SECURE) - AD flag set")
                    elif status == ValidationStatus.INSECURE:
                        log.info(f"ℹ️  Zone is INSECURE (no DNSSEC)")
                
                    if validated:
                        final_response = validated
            
                return final_response
    
        return self._make_servfail(qname, qtype)
    
    def _minimize_qname(self, qname: dns.name.Name, zone: dns.name.Name):
        """RFC 9156 QNAME minimization"""
        if qname == zone or zone == dns.name.root:
            return qname
        
        # Send one label below zone
        try:
            labels_below = qname.relativize(zone)
            if len(labels_below) == 1:
                return qname
            # Send just zone + 1 label
            minimized = dns.name.Name(labels_below[:1] + zone.labels)
            return minimized
        except:
            return qname
    
    async def _query_nameservers(self, qname: dns.name.Name, qtype: int, nameservers: List[Tuple[str, List[str]]], log):
        """Query list of nameservers, return first good response"""
        # Flatten to IPs, resolving glueless NS
        all_ips = []
        for ns_name, ips in nameservers:
            if ips:
                all_ips.extend(ips)
            else:
                # No glue - need to resolve nameserver
                log.debug(f"   🔍 Resolving glueless NS: {ns_name}")
                resolved_ips = await self._resolve_nameserver(ns_name, log)
                if resolved_ips:
                    log.debug(f"   ✅ Resolved {ns_name} → {', '.join(resolved_ips[:2])}")
                    all_ips.extend(resolved_ips)
                else:
                    log.debug(f"   ❌ Failed to resolve {ns_name}")
    
        if not all_ips:
            log.warning(f"   ⚠️  No IPs available for any nameserver")
            return None
    
        # Try best server first
        best_ip = self.server_selection.select_target(all_ips, qname)
        if best_ip:
            result = await self._query_single(best_ip, qname, qtype, log)
            if result:
                return result
    
        # Fallback to random selection
        random.shuffle(all_ips)
        for ip in all_ips[:3]:  # Try up to 3 servers
            result = await self._query_single(ip, qname, qtype, log)
            if result:
                return result
    
        return None

    async def _resolve_nameserver(self, ns_name: str, log) -> List[str]:
        """
        Resolve a nameserver name to IP addresses.
        This is a sub-query that doesn't trigger validation (to avoid loops).
        """
        try:
            ns_name_obj = dns.name.from_text(ns_name)
            ips = []
        
            # Try A record
            log.debug(f"      Querying A for {ns_name}")
            a_response = await self._resolve_iterative_internal(ns_name_obj, dns.rdatatype.A, log)
            if a_response and a_response.answer:
                for rrset in a_response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            ips.append(rdata.to_text())
        
            # Try AAAA record if IPv6 preferred
            if self.prefer_ipv6:
                log.debug(f"      Querying AAAA for {ns_name}")
                aaaa_response = await self._resolve_iterative_internal(ns_name_obj, dns.rdatatype.AAAA, log)
                if aaaa_response and aaaa_response.answer:
                    for rrset in aaaa_response.answer:
                        if rrset.rdtype == dns.rdatatype.AAAA:
                            for rdata in rrset:
                                ips.append(rdata.to_text())
        
            return ips
        
        except Exception as e:
            log.debug(f"      ❌ Exception resolving {ns_name}: {e}")
            return []

    async def _resolve_iterative_internal(self, qname: dns.name.Name, qtype: int, log):
        """
        Internal iterative resolution without validation.
        Used to resolve nameserver names (to avoid circular dependencies).
        """
        state = IterState.INIT
        current_qname = qname
        referral_count = 0
    
        current_zone = dns.name.root
        current_ns = self.root_hints.get_servers(self.prefer_ipv6)
    
        while state != IterState.FINISHED and referral_count < self.MAX_REFERRALS:
            if state == IterState.INIT:
                cached_zone, cached_ns = self.ns_cache.find_deepest_match(current_qname)
                if cached_zone:
                    current_zone = cached_zone
                    current_ns = cached_ns
                state = IterState.QUERY_NS
        
            elif state == IterState.QUERY_NS:
                # Simple query without QNAME minimization
                response = await self._query_nameservers_simple(current_qname, qtype, current_ns, log)
            
                if not response:
                    return None
            
                if response.rcode() != dns.rcode.NOERROR:
                    return response
            
                if response.answer:
                    return response
            
                ref = self._extract_referral(response)
                if ref:
                    ref_zone, ref_ns = ref
                    if not current_qname.is_subdomain(ref_zone):
                        return None
                    current_zone = ref_zone
                    current_ns = ref_ns
                    self.ns_cache.put(ref_zone, ref_ns, ttl=86400)
                    referral_count += 1
                    continue
            
                return response
    
        return None

    async def _query_nameservers_simple(self, qname: dns.name.Name, qtype: int, nameservers: List[Tuple[str, List[str]]], log):
        """
        Simple nameserver query - only uses nameservers with glue.
        Doesn't trigger recursive NS resolution (to avoid infinite loops).
        """
        all_ips = []
        for ns_name, ips in nameservers:
            if ips:  # Only use nameservers that already have IPs
                all_ips.extend(ips)
    
        if not all_ips:
            return None
    
        # Try a few servers
        random.shuffle(all_ips)
        for ip in all_ips[:3]:
            result = await self._query_single(ip, qname, qtype, log)
            if result:
                return result
    
        return None

    async def _query_single(self, ip: str, qname: dns.name.Name, qtype: int, log):
        """Query single server"""
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        wire = query.to_wire()
        
        start = time.time()
        try:
            result_wire = await asyncio.wait_for(self._udp_query(ip, wire), timeout=self.QUERY_TIMEOUT)
            elapsed = (time.time() - start) * 1000
            
            if not result_wire:
                self.server_selection.record_failure(ip)
                return None
            
            response = dns.message.from_wire(result_wire)
            self.server_selection.record_rtt(ip, elapsed)
            self.server_selection.record_success(ip)
            return response
            
        except asyncio.TimeoutError:
            log.debug(f"Timeout querying {ip}")
            self.server_selection.record_failure(ip)
            return None
        except Exception as e:
            log.debug(f"Error querying {ip}: {e}")
            self.server_selection.record_failure(ip)
            return None
    
    async def _udp_query(self, ip: str, wire: bytes):
        """Raw UDP query"""
        loop = asyncio.get_running_loop()
        try:
            fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
            sock = socket.socket(fam, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            await loop.sock_sendto(sock, wire, (ip, 53))
            data, _ = await loop.sock_recvfrom(sock, 4096)
            sock.close()
            return data
        except Exception:
            return None
    
    def _extract_referral(self, response):
        """Extract NS referral from authority section"""
        ns_rrset = None
        for rr in response.authority:
            if rr.rdtype == dns.rdatatype.NS:
                ns_rrset = rr
                break
        
        if not ns_rrset:
            return None
        
        ref_zone = ns_rrset.name
        
        # Extract glue
        ns_ips = {}
        for rr in response.additional:
            if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                name = str(rr.name).lower()
                if name not in ns_ips:
                    ns_ips[name] = []
                for rd in rr:
                    ns_ips[name].append(rd.to_text())
        
        # Build NS list
        result_ns = []
        for rd in ns_rrset:
            ns_name = str(rd.target).lower()
            ips = ns_ips.get(ns_name, [])
            result_ns.append((ns_name, ips))
        
        return ref_zone, result_ns
    
    def _find_cname(self, response, qname):
        """Find CNAME in answer"""
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.CNAME and rr.name == qname:
                return rr
        return None
    
    def _make_servfail(self, qname, qtype):
        """Create SERVFAIL response"""
        resp = dns.message.make_response(dns.message.make_query(qname, qtype))
        resp.set_rcode(dns.rcode.SERVFAIL)
        return resp


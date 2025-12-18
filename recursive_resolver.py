#!/usr/bin/env python3
# filename: recursive_resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.7.1 (QNAME Minimization Modes: strict/relaxed/off - Updated)
# -----------------------------------------------------------------------------
"""
Iterative DNS resolver that walks the DNS tree.
Optimized to use NSCache to skip root/TLD steps when possible.
Includes improved loop detection and DNSSEC record stripping.
Fix: Properly propagates CNAME chains through recursion.
Feature: QNAME Minimization modes (strict, relaxed, off).
"""

import asyncio
import socket
import random
import time
import logging
from typing import Optional, Dict, List, Tuple, Set, Union
from dataclasses import dataclass, field

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.rrset

from utils import get_logger
from root_hints import RootHintsManager, TrustAnchorManager
from dnssec_validator import DNSSECValidator, DNSSECStatus

logger = get_logger("Recursive")


@dataclass
class RecursiveStats:
    """Statistics for recursive resolution"""
    queries_total: int = 0
    queries_success: int = 0
    queries_failed: int = 0
    queries_from_cache: int = 0
    referrals_followed: int = 0
    root_queries: int = 0
    avg_chain_length: float = 0.0
    _chain_lengths: List[int] = field(default_factory=list)
    
    def record_query(self, success: bool, chain_length: int = 0, from_cache: bool = False):
        self.queries_total += 1
        if success: self.queries_success += 1
        else: self.queries_failed += 1
        if from_cache: self.queries_from_cache += 1
        if chain_length > 0:
            self._chain_lengths.append(chain_length)
            self.avg_chain_length = sum(self._chain_lengths) / len(self._chain_lengths)
    
    def get_stats(self) -> dict:
        return {
            'queries_total': self.queries_total,
            'queries_success': self.queries_success,
            'queries_failed': self.queries_failed,
            'success_rate': f"{(self.queries_success / self.queries_total * 100):.1f}%" if self.queries_total > 0 else "0%"
        }


class NSCache:
    """Cache for nameserver records discovered during resolution"""
    def __init__(self, max_size: int = 10000, default_ttl: int = 86400):
        self.cache: Dict[str, Tuple[List[Tuple[str, List[str]]], float]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
    
    def get(self, zone: str) -> Optional[List[Tuple[str, List[str]]]]:
        zone = zone.lower().rstrip('.') + '.'
        if zone in self.cache:
            ns_list, expiry = self.cache[zone]
            if time.time() < expiry: return ns_list
            del self.cache[zone]
        return None
    
    def put(self, zone: str, ns_records: List[Tuple[str, List[str]]], ttl: int = None):
        if self.max_size <= 0: return
        zone = zone.lower().rstrip('.') + '.'
        if len(self.cache) >= self.max_size and zone not in self.cache:
            try:
                oldest = min(self.cache.items(), key=lambda x: x[1][1])
                del self.cache[oldest[0]]
            except: pass
        self.cache[zone] = (ns_records, time.time() + (ttl or self.default_ttl))

    def get_deepest_match(self, qname: dns.name.Name) -> Tuple[dns.name.Name, List[Tuple[str, List[str]]]]:
        """Find the deepest cached zone that covers qname."""
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

    def clear(self): self.cache.clear()


class RecursiveResolver:
    """Iterative resolver with CNAME logic and RFC 9156 QNAME minimization."""
    
    MAX_REFERRALS = 25
    QUERY_TIMEOUT = 5
    
    def __init__(self, config: dict):
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        
        # Parse qname_minimization mode
        # Options: "strict", "relaxed", "off"
        qm_config = self.config.get('qname_minimization', 'strict')
        if isinstance(qm_config, str):
            if qm_config.lower() in ['relaxed', 'off']:
                self.qm_mode = qm_config.lower()
            else:
                self.qm_mode = 'strict' # Default to strict for "strict" or unknown strings
        else:
            self.qm_mode = 'strict' # Default if not string
            
        logger.info(f"QNAME Minimization Mode: {self.qm_mode}")

        self.root_hints = RootHintsManager(self.config.get('root_hints', {}))
        self.trust_anchor_manager = TrustAnchorManager(self.config.get('trust_anchors', {}))
        self.dnssec_mode = self.config.get('dnssec', {}).get('mode', 'none')
        self.dnssec_validator: Optional[DNSSECValidator] = None
        self.ns_cache = NSCache(max_size=self.config.get('ns_cache_size', 10000))
        self.stats = RecursiveStats()
        self.prefer_ipv6 = self.config.get('prefer_ipv6', False)
        self.query_timeout = self.config.get('query_timeout', self.QUERY_TIMEOUT)
    
    async def initialize(self) -> bool:
        if not self.enabled: return True
        if not await self.root_hints.initialize(): return False
        if not await self.trust_anchor_manager.initialize(): self.dnssec_mode = 'none'
        
        if self.dnssec_mode != 'none':
            self.dnssec_validator = DNSSECValidator(
                config=self.config.get('dnssec', {}),
                trust_anchors=self.trust_anchor_manager.get_trust_anchors(),
                query_func=self._raw_query
            )
        await self.root_hints.start_refresh_task()
        await self.trust_anchor_manager.start_refresh_task()
        return True
    
    async def resolve(self, qname: str, qtype: int, req_logger=None) -> Optional[dns.message.Message]:
        log = req_logger or logger
        if not self.enabled: return None
        
        qname_obj = dns.name.from_text(qname) if isinstance(qname, str) else qname
        # Differentiate user queries from internal ones
        log.info(f"Recursive resolve started: {str(qname_obj).lower()} [{dns.rdatatype.to_text(qtype)}]")
        
        try:
            # accumulated_cnames is None initially
            response, chain_len = await self._resolve_iterative(qname_obj, qtype, log, validate=True, original_qname=qname_obj)
            if response:
                self.stats.record_query(True, chain_len)
                return response
            self.stats.record_query(False)
            return self._make_servfail(qname_obj, qtype)
        except Exception as e:
            log.error(f"Recursive resolution fatal error for {qname}: {e}")
            return self._make_servfail(qname_obj, qtype)

    async def _resolve_iterative(self, qname: dns.name.Name, qtype: int, log, validate: bool = True, original_qname: dns.name.Name = None, accumulated_cnames: List[dns.rrset.RRset] = None) -> Tuple[Optional[dns.message.Message], int]:
        # --- Optimization: Check NS Cache for deepest match ---
        cached_zone, cached_ns = self.ns_cache.get_deepest_match(qname)
        
        if cached_zone and cached_ns:
            current_zone = cached_zone
            nameservers = cached_ns
            # log.debug(f"NSCache Hit: Resuming from zone '{current_zone}'")
        else:
            current_zone = dns.name.root
            nameservers = self._get_root_nameservers()
            
        visited_zones = set()
        if accumulated_cnames is None:
            accumulated_cnames = []
        chain_length = 0
        original_qname = original_qname or qname

        # State for QNAME Minimization (RFC 9156)
        target_labels = list(qname.labels)
        if target_labels and target_labels[-1] == b'': target_labels.pop() # Strip root
        
        # If we started from a cached zone, jump start minimization depth
        if current_zone != dns.name.root:
            current_min_labels = len(current_zone.labels) - 1 # -1 for root label count adjustment
            if current_min_labels < 1: current_min_labels = 1
        else:
            current_min_labels = 1

        minimization_failed = False  # Track if minimization has failed for this zone

        while chain_length < self.MAX_REFERRALS:
            chain_length += 1
            zone_str = str(current_zone)
            
            # Check for loops
            if zone_str in visited_zones and self.qm_mode == 'off':
                log.warning(f"Loop detected: Zone '{zone_str}' already visited")
                break
            visited_zones.add(zone_str)
            
            # Determine effective query name for this step
            use_minimization = (
                self.qm_mode != 'off'
                and not minimization_failed
                and current_min_labels < len(target_labels)
            )

            if use_minimization:
                sub_labels = target_labels[-current_min_labels:] + [b'']
                query_name = dns.name.Name(sub_labels)
                query_type = dns.rdatatype.A # Ping the sub-zone [RFC 9156]
                log.debug(f"Step {chain_length}: Minimizing -> {query_name} [A] via '{zone_str}'")
            else:
                query_name = qname
                query_type = qtype
                log.debug(f"Step {chain_length}: Iterating -> {query_name} [{dns.rdatatype.to_text(query_type)}] via '{zone_str}'")

            # Execute Query
            response = await self._query_nameservers(nameservers, query_name, query_type, log)
            
            # --- QNAME Minimization Logic (Strict vs Relaxed) ---
            if use_minimization:
                if not response:
                    # No response (timeout/network error)
                    if self.qm_mode == 'relaxed':
                        log.debug(f"Minimization timeout for {query_name}, relaxed mode: falling back to full QNAME")
                        minimization_failed = True
                        current_min_labels = len(target_labels)
                        chain_length -= 1
                        continue
                    else:
                        # Strict mode: Failure to respond is a hard failure
                        log.warning(f"Step {chain_length}: No response from zone '{zone_str}' (Strict Minimization)")
                        break
                
                if response.rcode() == dns.rcode.NXDOMAIN:
                    # NXDOMAIN on minimized query -> Name truly doesn't exist OR Empty Non-Terminal issue
                    # RFC 9156 says we should stop. 
                    # Relaxed mode tries full QNAME just in case server is broken.
                    if self.qm_mode == 'relaxed':
                        log.debug(f"Minimization NXDOMAIN for {query_name}, relaxed mode: trying full QNAME")
                        minimization_failed = True
                        current_min_labels = len(target_labels)
                        chain_length -= 1
                        continue
                    # Strict mode continues to normal NXDOMAIN handling below
            
            if not response:
                log.warning(f"Step {chain_length}: No response from zone '{zone_str}'")
                break
            
            # Reset fallback flag on success
            if minimization_failed:
                minimization_failed = False

            # 1. Handle Referrals (Delegations)
            referral = self._extract_referral(response, query_name)
            if referral:
                new_zone, new_ns = referral
                
                # LOOP PROTECTION: Ensure we are actually going deeper
                if new_zone == current_zone:
                    log.warning(f"Referral loop detected: {current_zone} referred to itself")
                    break
                if not qname.is_subdomain(new_zone):
                     log.warning(f"Invalid referral: {new_zone} is not a parent of {qname}")
                     break

                log.info(f"Referral from '{zone_str}' to zone '{new_zone}' ({len(new_ns)} NS)")
                current_zone, nameservers = new_zone, new_ns
                self.ns_cache.put(str(current_zone), nameservers, self._get_min_ttl(response.authority))
                
                if self.qm_mode != 'off':
                    # We found a deeper delegation, update minimization progress
                    current_min_labels = max(current_min_labels, len(new_zone.labels))
                continue
            
            # 2. Handle CNAMEs (Only on final target query)
            if query_name == qname and response.answer:
                # Check if this IS the answer we wanted
                found_final = False
                for rrset in response.answer:
                    if rrset.name == qname and rrset.rdtype == qtype:
                        found_final = True
                        break
                
                if found_final:
                     return await self._finalize(response, original_qname, accumulated_cnames, qtype, log, validate), chain_length

                # Look for CNAMEs to follow
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
                        target = rrset[0].target
                        
                        # LOOP PROTECTION: CNAME loop check
                        if any(cname_rr[0].target == target for cname_rr in accumulated_cnames):
                             log.warning(f"CNAME loop detected: {target} already visited")
                             return self._make_servfail(original_qname, qtype), chain_length

                        log.info(f"Following CNAME: {qname} -> {target}")
                        accumulated_cnames.append(rrset)
                        # Pass updated accumulated_cnames to recursive call
                        return await self._resolve_iterative(target, qtype, log, validate, original_qname, accumulated_cnames)
                
            # 3. Handle intermediate minimization answers
            if self.qm_mode != 'off' and query_name != qname:
                # log.debug(f"Minimization info: {dns.rcode.to_text(response.rcode())} for {query_name}")
                # Name exists or NXDOMAIN (handled by fallback loop above), proceed deeper
                current_min_labels += 1
                continue

            # 4. Final Data, Empty Answer or NXDOMAIN
            return await self._finalize(response, original_qname, accumulated_cnames, qtype, log, validate), chain_length

        return None, chain_length

    async def _finalize(self, response, original_qname, accumulated_cnames, qtype, log, validate):
        """Assemble final message, strip DNSSEC records, and run validation."""
        response.question = [dns.rrset.RRset(original_qname, dns.rdataclass.IN, qtype)]
        if accumulated_cnames:
            # Prepend accumulated CNAMEs to the answer section
            response.answer = accumulated_cnames + list(response.answer)

        # DNSSEC Validation happens BEFORE stripping records
        if validate and self.dnssec_validator:
            log.info(f"DNSSEC validation [Mode: {self.dnssec_mode}] for {original_qname}")
            status, validated = await self.dnssec_validator.validate_response(response, str(original_qname).lower(), qtype, log)
            
            if validated:
                log.info(f"DNSSEC result: {status.value.upper()}")
                response = validated # Use the validated response which might have AD bit set
            else:
                log.error(f"DNSSEC result: BOGUS - Response blocked")
                return self._make_servfail(original_qname, qtype)

        # CLEANUP: Strip DNSSEC records from final response unless specifically requested (e.g. by a validator)
        if qtype not in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
             self._strip_dnssec_records(response)

        return response

    def _strip_dnssec_records(self, response):
        """Remove RRSIG, NSEC, NSEC3 records from response sections."""
        for section in (response.answer, response.authority, response.additional):
            if not section: continue
            # Filter in-place
            new_section = [rr for rr in section if rr.rdtype not in (
                dns.rdatatype.RRSIG, 
                dns.rdatatype.NSEC, 
                dns.rdatatype.NSEC3,
                dns.rdatatype.NSEC3PARAM
            )]
            section[:] = new_section

    def _get_root_nameservers(self):
        return [(s.name, s.get_ips(self.prefer_ipv6)) for s in self.root_hints.root_servers]

    def _extract_referral(self, response, qname):
        ns_map = {}
        ref_zone = None
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS and qname.is_subdomain(rrset.name):
                ref_zone = rrset.name
                for rd in rrset: ns_map[rd.target] = []
        if not ref_zone: return None
        for rrset in response.additional:
            if rrset.name in ns_map and rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                for rd in rrset: ns_map[rrset.name].append(rd.to_text())
        return ref_zone, [(str(name), ips) for name, ips in ns_map.items()]

    async def _query_nameservers(self, nameservers, qname, qtype, log):
        ns_list = list(nameservers)
        random.shuffle(ns_list)
        for ns_name, ips in ns_list:
            if not ips:
                # Avoid infinite recursion: don't resolve NS names if we are currently resolving a NS name
                if qtype == dns.rdatatype.A and qname == dns.name.from_text(ns_name):
                    continue
                    
                log.debug(f"Resolving out-of-bailiwick IP for: {ns_name}")
                ips = await self._resolve_ns_name(ns_name, log)
                if not ips: continue
            
            for ip in ips:
                try:
                    res = await self._send_query(ip, qname, qtype, log)
                    if res: return res
                except: continue
        return None

    async def _resolve_ns_name(self, ns_name: str, log):
        obj = dns.name.from_text(ns_name)
        # Disable validation for NS glue to prevent recursion loops
        res, _ = await self._resolve_iterative(obj, dns.rdatatype.A, log, validate=False)
        if res and res.answer:
            return [rd.to_text() for rrset in res.answer for rd in rrset if rrset.rdtype == dns.rdatatype.A]
        return []

    async def _send_query(self, ip, qname, qtype, log):
        query = dns.message.make_query(qname, qtype, want_dnssec=True)
        query.flags |= dns.flags.RD # Recursive desired
        wire = query.to_wire()
        
        resp_wire = await self._udp_query(ip, wire)
        if resp_wire:
            resp = dns.message.from_wire(resp_wire)
            if resp.flags & dns.flags.TC:
                resp_wire = await self._tcp_query(ip, wire)
                if resp_wire: resp = dns.message.from_wire(resp_wire)
            return resp
        return None

    async def _raw_query(self, wire: bytes) -> Optional[bytes]:
        try:
            q_msg = dns.message.from_wire(wire)
            qn, qt = q_msg.question[0].name, q_msg.question[0].rdtype
            # Use module logger, not request-scoped logger, to distinguish in logs
            # Added custom prefix to logger for internal queries
            log_prefix = logging.LoggerAdapter(logger, {'id': 'DNSSEC', 'ip': 'Internal', 'proto': 'INT'})
            res, _ = await self._resolve_iterative(qn, qt, log_prefix, validate=False)
            return res.to_wire() if res else None
        except: return None

    async def _udp_query(self, ip, wire):
        loop = asyncio.get_running_loop()
        fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, 53)), timeout=self.query_timeout)
            await loop.sock_sendall(sock, wire)
            return await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=self.query_timeout)
        except: return None
        finally: sock.close()

    async def _tcp_query(self, ip, wire):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, 53), timeout=self.query_timeout)
            w.write(len(wire).to_bytes(2, 'big') + wire)
            await w.drain()
            l_bytes = await asyncio.wait_for(r.readexactly(2), timeout=self.query_timeout)
            data = await asyncio.wait_for(r.readexactly(int.from_bytes(l_bytes, 'big')), timeout=self.query_timeout)
            w.close()
            return data
        except: return None

    def _get_min_ttl(self, rrsets):
        ttls = [rr.ttl for rr in rrsets if rr]
        return min(ttls) if ttls else 86400

    def _make_servfail(self, qname, qtype):
        res = dns.message.Message()
        res.set_rcode(dns.rcode.SERVFAIL)
        res.question.append(dns.rrset.RRset(qname, dns.rdataclass.IN, qtype))
        return res

    def get_stats(self): return self.stats.get_stats()


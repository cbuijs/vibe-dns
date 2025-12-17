#!/usr/bin/env python3
# filename: recursive_resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.1.0 (Added RFC 9156 QNAME Minimization)
# -----------------------------------------------------------------------------
"""
Iterative DNS resolver that walks the DNS tree from root servers.
Supports DNSSEC validation and implements QNAME Minimization (RFC 9156).
"""

import asyncio
import socket
import random
import time
import logging
from typing import Optional, Dict, List, Tuple, Set
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

    def clear(self): self.cache.clear()


class RecursiveResolver:
    """Iterative resolver with CNAME logic and RFC 9156 QNAME minimization."""
    
    MAX_REFERRALS = 25
    QUERY_TIMEOUT = 5
    
    def __init__(self, config: dict):
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.qname_minimization = self.config.get('qname_minimization', True)
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
        log.info(f"Recursive resolve started: {str(qname_obj).lower()} [{dns.rdatatype.to_text(qtype)}]")
        
        try:
            response, chain_len = await self._resolve_iterative(qname_obj, qtype, log, validate=True, original_qname=qname_obj)
            if response:
                self.stats.record_query(True, chain_len)
                return response
            self.stats.record_query(False)
            return self._make_servfail(qname_obj, qtype)
        except Exception as e:
            log.error(f"Recursive resolution fatal error for {qname}: {e}")
            return self._make_servfail(qname_obj, qtype)

    async def _resolve_iterative(self, qname: dns.name.Name, qtype: int, log, validate: bool = True, original_qname: dns.name.Name = None) -> Tuple[Optional[dns.message.Message], int]:
        current_zone = dns.name.root
        nameservers = self._get_root_nameservers()
        visited_zones = set()
        accumulated_cnames = []
        chain_length = 0
        original_qname = original_qname or qname

        # State for QNAME Minimization (RFC 9156)
        target_labels = list(qname.labels)
        if target_labels and target_labels[-1] == b'': target_labels.pop() # Strip root
        
        # Start by querying the TLD via Root
        current_min_labels = 1

        while chain_length < self.MAX_REFERRALS:
            chain_length += 1
            zone_str = str(current_zone)
            
            # Check for loops
            if zone_str in visited_zones and not self.qname_minimization:
                log.warning(f"Loop detected: Zone '{zone_str}' already visited")
                break
            visited_zones.add(zone_str)
            
            # Determine effective query name for this step
            if self.qname_minimization and current_min_labels < len(target_labels):
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
            if not response:
                log.warning(f"Step {chain_length}: No response from zone '{zone_str}'")
                break
            
            # 1. Handle Referrals (Delegations)
            referral = self._extract_referral(response, query_name)
            if referral:
                new_zone, new_ns = referral
                log.info(f"Referral from '{zone_str}' to zone '{new_zone}' ({len(new_ns)} NS)")
                current_zone, nameservers = new_zone, new_ns
                self.ns_cache.put(str(current_zone), nameservers, self._get_min_ttl(response.authority))
                
                if self.qname_minimization:
                    # We found a deeper delegation, update minimization progress
                    current_min_labels = max(current_min_labels, len(new_zone.labels))
                continue
            
            # 2. Handle CNAMEs (Only on final target query)
            if query_name == qname and response.answer:
                found_cname = False
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
                        if qtype == dns.rdatatype.CNAME: break # Final answer is CNAME
                        
                        target = rrset[0].target
                        log.info(f"Following CNAME: {qname} -> {target}")
                        accumulated_cnames.append(rrset)
                        
                        # Restart iterative logic for the new target
                        return await self._resolve_iterative(target, qtype, log, validate, original_qname)
                
                # No CNAME, or CNAME was the answer we wanted
                return await self._finalize(response, original_qname, accumulated_cnames, qtype, log, validate), chain_length

            # 3. Handle intermediate minimization answers
            if self.qname_minimization and query_name != qname:
                log.debug(f"Minimization info: {dns.rcode.to_text(response.rcode())} for {query_name}")
                # Name exists or NXDOMAIN, proceed deeper
                current_min_labels += 1
                continue

            # 4. Final Data, Empty Answer or NXDOMAIN
            return await self._finalize(response, original_qname, accumulated_cnames, qtype, log, validate), chain_length

        return None, chain_length

    async def _finalize(self, response, original_qname, accumulated_cnames, qtype, log, validate):
        """Assemble final message and run validation."""
        response.question = [dns.rrset.RRset(original_qname, dns.rdataclass.IN, qtype)]
        if accumulated_cnames:
            response.answer = accumulated_cnames + list(response.answer)

        if validate and self.dnssec_validator:
            log.info(f"DNSSEC validation [Mode: {self.dnssec_mode}] for {original_qname}")
            status, validated = await self.dnssec_validator.validate_response(response, str(original_qname).lower(), qtype, log)
            if validated:
                log.info(f"DNSSEC result: {status.value.upper()}")
                return validated
            else:
                log.error(f"DNSSEC result: BOGUS - Response blocked")
                return self._make_servfail(original_qname, qtype)
        
        return response

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
            res, _ = await self._resolve_iterative(qn, qt, logger, validate=False)
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


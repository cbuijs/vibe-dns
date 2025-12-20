#!/usr/bin/env python3
# filename: dnssec_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.2.0 (Performance Optimizations)
# -----------------------------------------------------------------------------
"""
DNSSEC Validator with optimizations:
- Expiring cache for DNSKEY/DS records
- Batch deduplication for concurrent lookups
- Answer-only validation (skip authority/additional)
- Zone signing detection
"""

import time
import asyncio
from enum import Enum
from typing import Optional, Tuple, Dict

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.dnssec
import dns.flags

from utils import get_logger

logger = get_logger("DNSSEC")


class DNSSECStatus(Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


class DNSSECValidator:
    CACHE_TTL = 3600  # 1 hour for keys/DS
    
    def __init__(self, config: dict, trust_anchors: dict, query_func):
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors or {}
        self.query_func = query_func
        self.failure_rcode = getattr(
            dns.rcode, 
            config.get('validation_failure_rcode', 'SERVFAIL').upper(), 
            dns.rcode.SERVFAIL
        )
        
        # Expiring caches: (data, expiry_timestamp)
        self.key_cache: Dict[str, tuple] = {}
        self.ds_cache: Dict[str, tuple] = {}
        
        # Deduplication for concurrent requests
        self._pending_keys: Dict[str, asyncio.Future] = {}
        self._pending_ds: Dict[str, asyncio.Future] = {}
        
        if self.mode != "none":
            logger.info(f"DNSSEC Validator initialized (Mode: {self.mode})")
    
    def _cache_get(self, cache_dict: dict, key: str):
        """Get from cache with auto-expiry"""
        if key not in cache_dict:
            return None
        
        data, expiry = cache_dict[key]
        if time.time() > expiry:
            del cache_dict[key]
            return None
        
        return data
    
    def _cache_put(self, cache_dict: dict, key: str, data, ttl: int = None):
        """Put into cache with TTL"""
        if ttl is None:
            ttl = self.CACHE_TTL
        cache_dict[key] = (data, time.time() + ttl)
    
    async def validate_response(self, response: dns.message.Message, qname: str, qtype: int, log=None) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        """Main validation entry point - only validates answer section"""
        log = log or logger
        
        if self.mode == "none":
            return DNSSECStatus.SECURE, response
        
        try:
            status = await self._validate_packet(response, log)
            return self._apply_policy(status, response)
        except Exception as e:
            log.error(f"Validation exception: {e}")
            return self._apply_policy(DNSSECStatus.BOGUS, response)
    
    async def _validate_packet(self, response: dns.message.Message, log) -> DNSSECStatus:
        """Validate answer section only (performance optimization)"""
        
        if response.rcode() == dns.rcode.NXDOMAIN:
            return await self._validate_denial_of_existence(response, log)
        
        # Only validate answer section - authority/additional is expensive
        status = DNSSECStatus.SECURE
        
        for rrset in response.answer:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                continue
            
            rrsig = self._find_rrsig(response.answer, rrset.name, rrset.rdtype)
            
            if not rrsig:
                # No signature - check if zone should be signed
                if await self._zone_is_signed(rrset.name, log):
                    log.warning(f"BOGUS: Missing signature for {rrset.name}")
                    return DNSSECStatus.BOGUS
                else:
                    status = DNSSECStatus.INSECURE
                continue
            
            # Verify signature
            if not await self._verify_rrsig(rrset, rrsig, log):
                log.warning(f"BOGUS: Invalid signature for {rrset.name}")
                return DNSSECStatus.BOGUS
        
        return status
    
    async def _zone_is_signed(self, zone_name: dns.name.Name, log) -> bool:
        """Quick check if zone uses DNSSEC"""
        try:
            parent = zone_name.parent()
        except:
            return False
        
        ds = await self._fetch_ds_record(zone_name, log)
        return ds is not None
    
    async def _verify_rrsig(self, rrset, rrsig, log) -> bool:
        """Verify RRset signature"""
        signer = rrsig[0].signer
        
        keys = await self._get_dnskeys_batched(signer, log)
        if not keys:
            log.debug(f"Missing keys for signer {signer}")
            return False
        
        try:
            dns.dnssec.validate(rrset, rrsig, {signer: keys}, None)
            return True
        except dns.dnssec.ValidationFailure:
            return False
    
    async def _get_dnskeys_batched(self, zone: dns.name.Name, log):
        """Fetch DNSKEY with deduplication"""
        zone_str = str(zone)
        
        # Check cache
        cached = self._cache_get(self.key_cache, zone_str)
        if cached is not None:
            log.debug(f"DNSKEY cache hit for {zone_str}")
            return cached
        
        # Check if already fetching
        if zone_str in self._pending_keys:
            log.debug(f"Joining pending DNSKEY fetch for {zone_str}")
            return await self._pending_keys[zone_str]
        
        # Create new fetch
        future = asyncio.Future()
        self._pending_keys[zone_str] = future
        
        try:
            keys = await self._fetch_and_validate_keys(zone, log)
            self._cache_put(self.key_cache, zone_str, keys, ttl=self.CACHE_TTL)
            future.set_result(keys)
            return keys
        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            del self._pending_keys[zone_str]
    
    async def _fetch_and_validate_keys(self, zone: dns.name.Name, log):
        """Fetch DNSKEY and validate against parent DS"""
        wire = await self.query_func(
            dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True).to_wire()
        )
        if not wire:
            return None
        
        response = dns.message.from_wire(wire)
        
        keys = None
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.DNSKEY and rr.name == zone:
                keys = rr
                break
        
        if not keys:
            return None
        
        # Root check
        if zone == dns.name.root:
            if self._check_root_anchor(keys):
                return keys
            return None
        
        # Validate against parent DS
        ds_rrset = await self._fetch_ds_record(zone, log)
        
        if not ds_rrset:
            # No DS = unsigned zone
            return None
        
        # Verify KSK matches DS
        for ds in ds_rrset:
            for key in keys:
                try:
                    ds_calc = dns.dnssec.make_ds(zone, key, ds.digest_type)
                    if ds_calc.digest == ds.digest:
                        return keys
                except:
                    continue
        
        log.warning(f"Keys for {zone} do not match parent DS")
        return None
    
    async def _fetch_ds_record(self, zone: dns.name.Name, log):
        """Fetch DS with caching"""
        zone_str = str(zone)
        
        cached = self._cache_get(self.ds_cache, zone_str)
        if cached is not None:
            log.debug(f"DS cache hit for {zone_str}")
            return cached
        
        wire = await self.query_func(
            dns.message.make_query(zone, dns.rdatatype.DS, want_dnssec=True).to_wire()
        )
        
        if not wire:
            self._cache_put(self.ds_cache, zone_str, None, ttl=300)
            return None
        
        response = dns.message.from_wire(wire)
        
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.DS and rr.name == zone:
                rrsig = self._find_rrsig(response.answer, rr.name, dns.rdatatype.DS)
                if rrsig and await self._verify_rrsig(rr, rrsig, log):
                    self._cache_put(self.ds_cache, zone_str, rr, ttl=min(rr.ttl, self.CACHE_TTL))
                    return rr
        
        self._cache_put(self.ds_cache, zone_str, None, ttl=300)
        return None
    
    async def _validate_denial_of_existence(self, response, log) -> DNSSECStatus:
        """Validate NSEC/NSEC3 proof for NXDOMAIN"""
        for rr in response.authority:
            if rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                rrsig = self._find_rrsig(response.authority, rr.name, rr.rdtype)
                if rrsig:
                    if await self._verify_rrsig(rr, rrsig, log):
                        return DNSSECStatus.SECURE
        
        return DNSSECStatus.BOGUS
    
    def _find_rrsig(self, section, name, covered_type):
        """Find RRSIG covering specific RRset"""
        for rr in section:
            if rr.rdtype == dns.rdatatype.RRSIG and rr.name == name:
                if rr[0].type_covered == covered_type:
                    return rr
        return None
    
    def _check_root_anchor(self, keys: dns.rrset.RRset) -> bool:
        """Verify against root trust anchor"""
        for key in keys:
            tag = dns.dnssec.key_id(key)
            if tag in self.trust_anchors:
                return True
        return False
    
    def _apply_policy(self, status: DNSSECStatus, response: dns.message.Message):
        """Apply validation policy"""
        if self.mode == 'strict':
            if status == DNSSECStatus.SECURE:
                response.flags |= dns.flags.AD
                return status, response
            return status, self._make_servfail(response)
        
        if self.mode == 'standard':
            if status in (DNSSECStatus.SECURE, DNSSECStatus.INSECURE):
                if status == DNSSECStatus.SECURE:
                    response.flags |= dns.flags.AD
                return status, response
            return status, self._make_servfail(response)
        
        # Log mode
        return status, response
    
    def _make_servfail(self, response):
        """Create SERVFAIL response"""
        r = dns.message.make_response(response)
        r.set_rcode(self.failure_rcode)
        return r


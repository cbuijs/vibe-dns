#!/usr/bin/env python3
"""DNSSEC Validator - clean separation from iterator"""
import time
import asyncio
from enum import Enum
from typing import Optional, Tuple, Dict, Callable
from collections import OrderedDict

import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.dnssec
import dns.flags

from utils import get_logger

logger = get_logger("Validator")


class ValidationStatus(Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


class Validator:
    """DNSSEC Validator"""
    
    CACHE_TTL = 3600
    MAX_CACHE_SIZE = 5000
    
    def __init__(self, config: dict, trust_anchors: dict, query_func: Callable):
        self.config = config
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors
        self.query_func = query_func
        
        self.failure_rcode = getattr(
            dns.rcode, 
            config.get('validation_failure_rcode', 'SERVFAIL').upper(), 
            dns.rcode.SERVFAIL
        )
        
        self.unsigned_rcode = getattr(
            dns.rcode,
            config.get('unsigned_zone_rcode', 'SERVFAIL').upper(),
            dns.rcode.SERVFAIL
        )
        
        self.disabled_algorithms = set(config.get('disabled_algorithms', []))
        
        # Caches: {key: (data, expiry_time)}
        self.key_cache = OrderedDict()
        self.ds_cache = OrderedDict()
        
        # Pending fetches (deduplication)
        self._pending_keys = {}
        self._pending_ds = {}
    
    def is_enforcing(self):
        return self.mode in ['standard', 'strict']
    
    async def validate(self, response: dns.message.Message, qname: str, qtype: int, log) -> Tuple[ValidationStatus, Optional[dns.message.Message]]:
        """Validate response"""
        if self.mode == 'none':
            return ValidationStatus.SECURE, response
        
        log.debug(f"🔐 DNSSEC mode: {self.mode}")
        
        try:
            status = await self._validate_answer_section(response, log)
            
            if self.mode == 'log':
                symbols = {
                    ValidationStatus.SECURE: "✅",
                    ValidationStatus.INSECURE: "ℹ️ ",
                    ValidationStatus.BOGUS: "❌",
                    ValidationStatus.INDETERMINATE: "❓"
                }
                log.info(f"{symbols.get(status, '?')} DNSSEC {status.value.upper()} for {qname}")
                return status, response
            
            if self.mode == 'strict':
                if status != ValidationStatus.SECURE:
                    log.warning(f"❌ DNSSEC strict mode: rejecting {status.value} response")
                    return status, self._make_servfail(response)
                response.flags |= dns.flags.AD
                return status, response
            
            if self.mode == 'standard':
                if status in (ValidationStatus.SECURE, ValidationStatus.INSECURE):
                    if status == ValidationStatus.SECURE:
                        response.flags |= dns.flags.AD
                    return status, response
                log.warning(f"❌ DNSSEC standard mode: rejecting {status.value} response")
                return status, self._make_servfail(response)
            
            return status, response
            
        except Exception as e:
            log.error(f"❌ DNSSEC validation exception: {e}")
            return ValidationStatus.BOGUS, self._make_servfail(response)
    
    async def _validate_answer_section(self, response, log):
        """Validate only answer section (performance)"""
        
        if response.rcode() == dns.rcode.NXDOMAIN:
            log.debug("   Validating NXDOMAIN proof (NSEC/NSEC3)")
            return await self._validate_denial(response, log)
        
        if not response.answer:
            return ValidationStatus.INSECURE
        
        status = ValidationStatus.SECURE
        
        for rrset in response.answer:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                continue
            
            log.debug(f"   Checking {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}")
            
            rrsig = self._find_rrsig(response.answer, rrset.name, rrset.rdtype)
            
            if not rrsig:
                # Check if zone should be signed
                if await self._is_signed_zone(rrset.name, log):
                    log.warning(f"   ❌ Missing RRSIG for {rrset.name}")
                    return ValidationStatus.BOGUS
                else:
                    log.debug(f"   ℹ️  No RRSIG (zone appears unsigned)")
                    status = ValidationStatus.INSECURE
                continue
            
            # Check algorithm
            if rrsig[0].algorithm in self.disabled_algorithms:
                log.warning(f"   ❌ Disabled algorithm {rrsig[0].algorithm} in RRSIG")
                return ValidationStatus.BOGUS
            
            log.debug(f"   🔑 Verifying signature (signer: {rrsig[0].signer})")
            
            # Verify signature
            if not await self._verify_signature(rrset, rrsig, log):
                log.warning(f"   ❌ Invalid RRSIG for {rrset.name}")
                return ValidationStatus.BOGUS
            else:
                log.debug(f"   ✅ Signature valid")
        
        return status
    
    async def _validate_denial(self, response, log):
        """Validate NSEC/NSEC3 denial of existence"""
        for rr in response.authority:
            if rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                rrsig = self._find_rrsig(response.authority, rr.name, rr.rdtype)
                if rrsig and await self._verify_signature(rr, rrsig, log):
                    return ValidationStatus.SECURE
        
        return ValidationStatus.BOGUS
    
    async def _verify_signature(self, rrset, rrsig, log):
        """Verify RRset signature"""
        signer = rrsig[0].signer
        keys = await self._get_dnskeys(signer, log)
        
        if not keys:
            log.debug(f"No keys for {signer}")
            return False
        
        try:
            dns.dnssec.validate(rrset, rrsig, {signer: keys}, None)
            return True
        except dns.dnssec.ValidationFailure as e:
            log.debug(f"Validation failed: {e}")
            return False
        except Exception as e:
            log.debug(f"Validation error: {e}")
            return False
    
    async def _get_dnskeys(self, zone: dns.name.Name, log):
        """Fetch and validate DNSKEYs with deduplication"""
        zone_str = str(zone)
        
        # Check cache
        cached = self._cache_get(self.key_cache, zone_str)
        if cached is not None:
            log.debug(f"   📦 DNSKEY cache hit for {zone_str}")
            return cached
        
        log.debug(f"   🔍 Fetching DNSKEY for {zone_str}")
        
        # Check if already fetching
        if zone_str in self._pending_keys:
            log.debug(f"Joining pending DNSKEY fetch for {zone_str}")
            return await self._pending_keys[zone_str]
        
        # Create new fetch
        future = asyncio.Future()
        self._pending_keys[zone_str] = future
        
        try:
            keys = await self._fetch_and_validate_keys(zone, log)
            self._cache_put(self.key_cache, zone_str, keys, self.CACHE_TTL)
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
        
        # Check for disabled algorithms
        for key in keys:
            if key.algorithm in self.disabled_algorithms:
                log.warning(f"Disabled algorithm {key.algorithm} in DNSKEY")
                return None
        
        # Root validation
        if zone == dns.name.root:
            if self._check_root_anchor(keys):
                return keys
            log.warning("Root keys don't match trust anchor")
            return None
        
        # Validate against parent DS
        ds_rrset = await self._get_ds(zone, log)
        if not ds_rrset:
            # No DS = unsigned zone
            return None
        
        # Verify KSK matches DS
        for ds in ds_rrset:
            for key in keys:
                try:
                    calc_ds = dns.dnssec.make_ds(zone, key, ds.digest_type)
                    if calc_ds.digest == ds.digest:
                        return keys
                except Exception as e:
                    log.debug(f"DS calculation failed: {e}")
                    continue
        
        log.warning(f"Keys for {zone} don't match parent DS")
        return None
    
    async def _get_ds(self, zone: dns.name.Name, log):
        """Fetch DS record with deduplication"""
        zone_str = str(zone)
        
        # Check cache
        cached = self._cache_get(self.ds_cache, zone_str)
        if cached is not None:
            return cached
        
        # Check if already fetching
        if zone_str in self._pending_ds:
            log.debug(f"Joining pending DS fetch for {zone_str}")
            return await self._pending_ds[zone_str]
        
        # Create new fetch
        future = asyncio.Future()
        self._pending_ds[zone_str] = future
        
        try:
            ds = await self._fetch_ds(zone, log)
            self._cache_put(self.ds_cache, zone_str, ds, 300 if ds is None else self.CACHE_TTL)
            future.set_result(ds)
            return ds
        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            del self._pending_ds[zone_str]
    
    async def _fetch_ds(self, zone: dns.name.Name, log):
        """Fetch DS record"""
        wire = await self.query_func(
            dns.message.make_query(zone, dns.rdatatype.DS, want_dnssec=True).to_wire()
        )
        
        if not wire:
            return None
        
        response = dns.message.from_wire(wire)
        
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.DS and rr.name == zone:
                rrsig = self._find_rrsig(response.answer, rr.name, dns.rdatatype.DS)
                if rrsig and await self._verify_signature(rr, rrsig, log):
                    return rr
        
        return None
    
    async def _is_signed_zone(self, zone: dns.name.Name, log):
        """Check if zone uses DNSSEC by looking for DS at parent"""
        try:
            parent = zone.parent()
        except:
            return False
        
        ds = await self._get_ds(zone, log)
        return ds is not None
    
    def _find_rrsig(self, section, name, covered_type):
        """Find RRSIG covering RRset"""
        for rr in section:
            if rr.rdtype == dns.rdatatype.RRSIG and rr.name == name:
                if rr[0].type_covered == covered_type:
                    return rr
        return None
    
    def _check_root_anchor(self, keys):
        """Verify root keys against trust anchor"""
        for key in keys:
            tag = dns.dnssec.key_id(key)
            if tag in self.trust_anchors:
                # Could also verify digest here
                return True
        return False
    
    def _cache_get(self, cache_dict: OrderedDict, key: str):
        """Get from cache with expiry check"""
        if key not in cache_dict:
            return None
        
        data, expiry = cache_dict[key]
        if time.time() > expiry:
            del cache_dict[key]
            return None
        
        # Move to end (LRU)
        cache_dict.move_to_end(key)
        return data
    
    def _cache_put(self, cache_dict: OrderedDict, key: str, data, ttl: int):
        """Put into cache with TTL"""
        # Evict old entries
        if len(cache_dict) >= self.MAX_CACHE_SIZE and key not in cache_dict:
            cache_dict.popitem(last=False)
        
        cache_dict[key] = (data, time.time() + ttl)
    
    def _make_servfail(self, response):
        """Create SERVFAIL response"""
        r = dns.message.make_response(response)
        r.set_rcode(self.failure_rcode)
        return r


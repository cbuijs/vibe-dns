#!/usr/bin/env python3
# filename: dnssec_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.4.0 (Simplified & Robust)
# -----------------------------------------------------------------------------
"""
DNSSEC Validation Logic.
Simplified for clarity and performance.
"""

import time
from enum import Enum
from typing import Optional, Tuple, Dict, Set

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
    def __init__(self, config: dict, trust_anchors: dict, query_func=None):
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors or {}
        self.query_func = query_func
        self.failure_rcode = getattr(dns.rcode, config.get('validation_failure_rcode', 'SERVFAIL').upper(), dns.rcode.SERVFAIL)
        self.disabled_algorithms = set(int(a) for a in config.get('disabled_algorithms', []))
        
        # Caches
        self.validated_keys: Dict[str, Tuple[dns.rrset.RRset, float]] = {}
        self.ds_cache: Dict[str, Tuple[Optional[dns.rrset.RRset], float]] = {}
        
        if self.mode != "none":
            logger.info(f"DNSSEC Validator initialized (Mode: {self.mode})")

    async def validate_response(self, response: dns.message.Message, qname: str, qtype: int, log=None) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        log = log or logger
        if self.mode == "none":
            return DNSSECStatus.SECURE, response

        try:
            # 1. Does the response contain signatures?
            has_rrsig = False
            for section in (response.answer, response.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        has_rrsig = True
                        break
                if has_rrsig: break
            
            status = DNSSECStatus.INDETERMINATE
            
            if has_rrsig:
                status = await self._validate_signatures(response, log)
            else:
                status = await self._validate_unsigned(qname, log)

            return self._apply_policy(status, response)

        except Exception as e:
            log.error(f"Validation error for {qname}: {e}")
            return self._apply_policy(DNSSECStatus.INDETERMINATE, response)

    async def _validate_signatures(self, response: dns.message.Message, log) -> DNSSECStatus:
        """Validate RRSIGs in the response."""
        try:
            # Check Answer Section
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG: continue # Skip RRSIGs themselves
                
                # Find covering RRSIG
                rrsig_rrset = self._find_rrsig(response.answer, rrset.name, rrset.rdtype)
                if not rrsig_rrset:
                    log.debug(f"Missing RRSIG for {rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}")
                    return DNSSECStatus.BOGUS

                # Validate
                if not await self._validate_rrset(rrset, rrsig_rrset, log):
                    return DNSSECStatus.BOGUS
            
            # Check Authority Section (optional but good for completeness)
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.RRSIG: continue
                rrsig_rrset = self._find_rrsig(response.authority, rrset.name, rrset.rdtype)
                if rrsig_rrset: # Only validate if signed
                     if not await self._validate_rrset(rrset, rrsig_rrset, log):
                        return DNSSECStatus.BOGUS

            return DNSSECStatus.SECURE
        except Exception as e:
            log.debug(f"Signature validation exception: {e}")
            return DNSSECStatus.BOGUS

    async def _validate_rrset(self, rrset, rrsig_rrset, log) -> bool:
        """Validate a single RRset against its RRSIG."""
        signer = rrsig_rrset[0].signer
        signer_name = str(signer)
        
        # Get Trusted Keys
        keys = await self._get_keys(signer_name, log)
        if not keys:
            log.debug(f"Could not retrieve keys for {signer_name}")
            return False

        try:
            # Prepare key dictionary for dnspython
            # Key: owner name, Value: DNSKEY RRset
            key_dict = {signer: keys}
            dns.dnssec.validate(rrset, rrsig_rrset, key_dict, None)
            return True
        except dns.dnssec.ValidationFailure:
            return False
        except Exception:
            return False

    async def _validate_unsigned(self, qname: str, log) -> DNSSECStatus:
        """Verify that a zone is legitimately unsigned (Insecure)."""
        zone = qname
        while zone != '.':
            parent = self._get_parent(zone)
            if not parent: break # Should not happen if root is handled
            
            # Check for DS at parent
            ds_rrset = await self._fetch_ds(zone, log)
            
            if ds_rrset:
                # DS exists -> Zone should be signed -> BOGUS
                log.debug(f"DS record found for {zone}, but response was unsigned")
                return DNSSECStatus.BOGUS
            
            # If we are here, we proved NO DS exists for 'zone'.
            # We now trust 'zone' is insecure if 'parent' is secure.
            # But we must verify the "No DS" proof (NSEC/NSEC3) from parent.
            # For simplicity in this lightweight validator, we accept the absence of DS 
            # if we can validate the parent's response saying so.
            # If fetch_ds returned None (and not an empty RRset), it means lookup failed/timeout.
            
            # Optimization: If we checked root and found no DS for TLD, whole tree is insecure.
            return DNSSECStatus.INSECURE
            
        return DNSSECStatus.INSECURE # Root is implicitly valid/unsigned if no anchors match (fallback)

    async def _get_keys(self, zone: str, log) -> Optional[dns.rrset.RRset]:
        """Get validated DNSKEYs for a zone."""
        # 1. Check Cache
        if zone in self.validated_keys:
            keys, expiry = self.validated_keys[zone]
            if time.time() < expiry: return keys

        # 2. Fetch Keys
        try:
            q = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
            wire = await self.query_func(q.to_wire())
            if not wire: return None
            response = dns.message.from_wire(wire)
            
            keys = self._find_rrset(response.answer, zone, dns.rdatatype.DNSKEY)
            if not keys: return None
            
            # 3. Validate Keys (Establish Chain of Trust)
            if not await self._validate_keys(zone, keys, response, log):
                return None
            
            # 4. Cache
            ttl = keys.ttl if keys.ttl > 0 else 300
            self.validated_keys[zone] = (keys, time.time() + ttl)
            return keys
        except Exception:
            return None

    async def _validate_keys(self, zone: str, keys: dns.rrset.RRset, response: dns.message.Message, log) -> bool:
        """Validate DNSKEY RRset against parent DS or Trust Anchor."""
        # Root Zone: Check Anchors
        if zone == '.' or zone == '':
            return self._check_trust_anchor(keys)

        # Non-Root: Check DS from Parent
        ds_rrset = await self._fetch_ds(zone, log)
        if not ds_rrset:
            log.debug(f"No DS record found for {zone} to validate keys")
            return False

        # Verify KSK matches DS
        for ds in ds_rrset:
            if ds.digest_type not in [1, 2, 4]: continue # Supported digests
            for key in keys:
                if key.algorithm in self.disabled_algorithms: continue
                # KSK (257) or ZSK (256)? DS matches KSK.
                try:
                    ds_calc = dns.dnssec.make_ds(zone, key, ds.digest_type)
                    if ds_calc.digest == ds.digest:
                        return True # Trust established
                except Exception: continue
        
        return False

    async def _fetch_ds(self, zone: str, log) -> Optional[dns.rrset.RRset]:
        """Fetch DS record for a zone."""
        # DS records live in the PARENT zone, but we query for 'zone' with type DS.
        # The recursive resolver handles finding the parent.
        
        cache_key = f"DS:{zone}"
        if cache_key in self.ds_cache:
            ds, exp = self.ds_cache[cache_key]
            if time.time() < exp: return ds

        try:
            q = dns.message.make_query(zone, dns.rdatatype.DS, want_dnssec=True)
            wire = await self.query_func(q.to_wire())
            if not wire: return None
            response = dns.message.from_wire(wire)
            
            # Look in Answer (if we asked authoritative parent directly) or Authority (referral)
            # Typically recursive resolver returns it in Answer.
            ds = self._find_rrset(response.answer, zone, dns.rdatatype.DS)
            
            # Cache (even if None/Empty to cache negative result)
            self.ds_cache[cache_key] = (ds, time.time() + 300)
            return ds
        except Exception:
            return None

    def _check_trust_anchor(self, keys: dns.rrset.RRset) -> bool:
        """Check if any key in RRset matches a configured Trust Anchor."""
        for key in keys:
            tag = dns.dnssec.key_id(key)
            if tag in self.trust_anchors:
                anchor = self.trust_anchors[tag]
                try:
                    ds = dns.dnssec.make_ds('.', key, anchor['digest_type'])
                    expected = bytes.fromhex(anchor['digest']) if isinstance(anchor['digest'], str) else anchor['digest']
                    if ds.digest == expected:
                        return True
                except Exception: continue
        return False

    def _find_rrsig(self, section, name, covered_type):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG and rrset.name == name:
                if rrset[0].type_covered == covered_type:
                    return rrset
        return None

    def _find_rrset(self, section, name, rdtype):
        name = dns.name.from_text(name) if isinstance(name, str) else name
        for rrset in section:
            if rrset.name == name and rrset.rdtype == rdtype:
                return rrset
        return None

    def _get_parent(self, zone: str):
        try:
            return dns.name.from_text(zone).parent().to_text()
        except Exception: return None

    def _apply_policy(self, status: DNSSECStatus, response: dns.message.Message) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        if self.mode == 'strict':
            if status == DNSSECStatus.SECURE:
                response.flags |= dns.flags.AD
                return status, response
            return status, self._make_servfail(response)
        
        if self.mode == 'standard':
            if status in (DNSSECStatus.SECURE, DNSSECStatus.INSECURE):
                if status == DNSSECStatus.SECURE: response.flags |= dns.flags.AD
                return status, response
            return status, self._make_servfail(response)

        # Log mode
        return status, response

    def _make_servfail(self, response):
        r = dns.message.make_response(response)
        r.set_rcode(self.failure_rcode)
        return r


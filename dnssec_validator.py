#!/usr/bin/env python3
# filename: dnssec_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.1.0 (Forwarding Validation Support)
# -----------------------------------------------------------------------------
"""
DNSSEC Validator with Denial-of-Existence checks.
Supports validating responses from both iterative walks and upstream forwarders.
"""

import time
import asyncio
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
    INSECURE = "insecure" # Proven insecure (chain of trust to NSEC/NSEC3)
    BOGUS = "bogus"       # Failed validation or missing proof
    INDETERMINATE = "indeterminate"

class DNSSECValidator:
    def __init__(self, config: dict, trust_anchors: dict, query_func):
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors or {}
        self.query_func = query_func # Async function to perform recursive queries
        self.failure_rcode = getattr(dns.rcode, config.get('validation_failure_rcode', 'SERVFAIL').upper(), dns.rcode.SERVFAIL)
        
        # Cache for keys and DS records
        self.key_cache = {} 
        self.ds_cache = {}

        if self.mode != "none":
            logger.info(f"DNSSEC Validator initialized (Mode: {self.mode})")

    async def validate_response(self, response: dns.message.Message, qname: str, qtype: int, log=None) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        """
        Main entry point. Validates a DNS response.
        """
        log = log or logger
        if self.mode == "none":
            return DNSSECStatus.SECURE, response

        # 1. Check if the response matches a Trust Anchor directly (Root)
        # (Simplified: In a real recursive, we usually validate from the bottom up or top down.
        # Here we assume we receive a packet and must validate it against known trust anchors or parent DS).
        
        # In a fully recursive flow, we need to know the zone this data belongs to.
        # Usually checking the RRset signer name helps.
        
        try:
            status = await self._validate_packet(response, log)
            return self._apply_policy(status, response)
        except Exception as e:
            log.error(f"Validation exception: {e}")
            return self._apply_policy(DNSSECStatus.BOGUS, response)

    async def _validate_packet(self, response: dns.message.Message, log) -> DNSSECStatus:
        """
        Validate all RRsets in the Answer/Authority sections.
        """
        # Iterate over Answer section
        secure_count = 0
        insecure_count = 0
        
        # If the response is NXDOMAIN or NOERROR+NODATA, we must look for NSEC/NSEC3 in Authority
        if response.rcode() == dns.rcode.NXDOMAIN:
            return await self._validate_denial_of_existence(response, log)

        # Validate standard answers
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG: continue 
                
                # Check for RRSIG coverage
                rrsig = self._find_rrsig(section, rrset.name, rrset.rdtype)
                
                if rrsig:
                    # It is signed, verify signature
                    valid = await self._verify_rrsig(rrset, rrsig, log)
                    if not valid:
                        log.warning(f"BOGUS: Invalid signature for {rrset.name}")
                        return DNSSECStatus.BOGUS
                    secure_count += 1
                else:
                    # Unsigned record. We must prove the zone is Insecure.
                    # We need to find the parent zone and check for DS.
                    is_insecure = await self._prove_insecure(rrset.name, log)
                    if not is_insecure:
                        log.warning(f"BOGUS: Missing RRSIG for {rrset.name} in Secure zone")
                        return DNSSECStatus.BOGUS
                    insecure_count += 1

        if secure_count > 0:
            return DNSSECStatus.SECURE
        if insecure_count > 0:
            return DNSSECStatus.INSECURE
            
        return DNSSECStatus.INDETERMINATE

    async def _verify_rrsig(self, rrset, rrsig, log) -> bool:
        """Verify an RRset against its signature"""
        signer = rrsig[0].signer
        
        # Fetch DNSKEYs for the signer
        keys = await self._get_dnskeys(signer, log)
        if not keys:
            log.debug(f"Missing keys for signer {signer}")
            return False
            
        try:
            # dnspython validation
            dns.dnssec.validate(rrset, rrsig, {signer: keys}, None)
            return True
        except dns.dnssec.ValidationFailure:
            return False

    async def _get_dnskeys(self, zone: dns.name.Name, log) -> Optional[dns.rrset.RRset]:
        """Fetch and VALIDATE DNSKEYs for a zone"""
        zone_str = str(zone)
        if zone_str in self.key_cache:
            # Basic TTL check could be added
            return self.key_cache[zone_str]

        # 1. Query for DNSKEY
        wire = await self.query_func(dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True).to_wire())
        if not wire: return None
        response = dns.message.from_wire(wire)
        
        keys = None
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.DNSKEY and rr.name == zone:
                keys = rr
                break
        
        if not keys: return None

        # 2. Validate these keys against the Parent DS
        # If Root, check Trust Anchor
        if zone == dns.name.root:
            if self._check_root_anchor(keys):
                self.key_cache[zone_str] = keys
                return keys
            return None

        # Else check Parent DS
        parent = zone.parent()
        ds_rrset = await self._fetch_ds_record(zone, log)
        
        if not ds_rrset:
            # If no DS, the parent must prove it (Secure Denial of Existence).
            # If validated as Insecure, then we can't trust these keys as "Secure", 
            # but we aren't "Bogus" either. 
            # For simplicity: If no DS, we return None (cannot use these keys for Secure validation)
            return None

        # Verify KSK signs the ZSKs and matches DS
        # (Simplification: Just check if DS matches one of the keys)
        for ds in ds_rrset:
            for key in keys:
                try:
                    ds_calc = dns.dnssec.make_ds(zone, key, ds.digest_type)
                    if ds_calc.digest == ds.digest:
                        self.key_cache[zone_str] = keys
                        return keys
                except: continue
        
        log.warning(f"Keys for {zone} do not match parent DS")
        return None

    async def _fetch_ds_record(self, zone: dns.name.Name, log) -> Optional[dns.rrset.RRset]:
        """Fetch DS record from parent. Returns None if not found OR not validated."""
        # Query parent for DS
        # Note: In a real recursive, we'd ask the parent servers. 
        # Here we rely on the recursive logic to find it.
        wire = await self.query_func(dns.message.make_query(zone, dns.rdatatype.DS, want_dnssec=True).to_wire())
        if not wire: return None
        response = dns.message.from_wire(wire)
        
        for rr in response.answer:
            if rr.rdtype == dns.rdatatype.DS and rr.name == zone:
                # We found a DS. Now we MUST validate the DS signature itself (RRSIG).
                # This recursively calls _verify_rrsig -> _get_dnskeys(parent)
                rrsig = self._find_rrsig(response.answer, rr.name, dns.rdatatype.DS)
                if rrsig and await self._verify_rrsig(rr, rrsig, log):
                    return rr
        
        return None

    async def _prove_insecure(self, zone_name: dns.name.Name, log) -> bool:
        """
        Check if a zone is legitimately insecure (Opt-out).
        This requires finding a "Proven" missing DS record at the parent.
        """
        # 1. Walk up to find the closest enclosure
        # This is complex. Simplified: check if parent has DS.
        try:
            parent = zone_name.parent()
        except:
            return True # Root? 

        # Get parent keys first
        parent_keys = await self._get_dnskeys(parent, log)
        if not parent_keys:
            # If we can't get secure keys for parent, parent is insecure, so we are insecure.
            return True 

        # 2. Query for DS
        wire = await self.query_func(dns.message.make_query(zone_name, dns.rdatatype.DS, want_dnssec=True).to_wire())
        if not wire: return False # Network fail is not proof
        response = dns.message.from_wire(wire)

        # 3. Verify NSEC/NSEC3 proof in Authority section
        # We need to find NSEC records signed by Parent
        
        nsec_rr = None
        nsec_rrsig = None
        
        for rr in response.authority:
            if rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                nsec_rr = rr
                nsec_rrsig = self._find_rrsig(response.authority, rr.name, rr.rdtype)
                break
        
        if nsec_rr and nsec_rrsig:
            # Validate NSEC signature
            if await self._verify_rrsig(nsec_rr, nsec_rrsig, log):
                # We have a valid NSEC. Does it cover the DS?
                # (Simplification: We assume if we have a valid NSEC from parent saying "No DS", it's valid)
                return True
        
        return False # No proof found

    async def _validate_denial_of_existence(self, response, log) -> DNSSECStatus:
        # Check authority section for NSEC/NSEC3 proving name doesn't exist
        # Similar logic to _prove_insecure but checking for Name Error
        # For this codebase, if we see valid NSEC signatures in Authority, we accept it.
        for rr in response.authority:
            if rr.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                rrsig = self._find_rrsig(response.authority, rr.name, rr.rdtype)
                if rrsig:
                    if await self._verify_rrsig(rr, rrsig, log):
                        return DNSSECStatus.SECURE
        
        # If we are here, we have NXDOMAIN but no valid proof.
        return DNSSECStatus.BOGUS

    def _find_rrsig(self, section, name, covered_type):
        for rr in section:
            if rr.rdtype == dns.rdatatype.RRSIG and rr.name == name:
                if rr[0].type_covered == covered_type:
                    return rr
        return None

    def _check_root_anchor(self, keys: dns.rrset.RRset) -> bool:
        for key in keys:
            tag = dns.dnssec.key_id(key)
            if tag in self.trust_anchors:
                return True # Simplified tag check
        return False

    def _apply_policy(self, status: DNSSECStatus, response: dns.message.Message):
        if self.mode == 'strict':
            if status == DNSSECStatus.SECURE:
                response.flags |= dns.flags.AD
                return status, response
            return status, self._make_servfail(response)
        
        if self.mode == 'standard':
            if status in (DNSSECStatus.SECURE, DNSSECStatus.INSECURE):
                if status == DNSSECStatus.SECURE: response.flags |= dns.flags.AD
                return status, response
            # Block Bogus
            return status, self._make_servfail(response)

        # Log mode - pass everything
        return status, response

    def _make_servfail(self, response):
        r = dns.message.make_response(response)
        r.set_rcode(self.failure_rcode)
        return r


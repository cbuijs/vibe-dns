#!/usr/bin/env python3
# filename: dnssec_validator.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.1.0 (Audit Fixes: Apex Sig Check & Insecure Delegation Handling)
# -----------------------------------------------------------------------------
"""
DNSSEC Validation with configurable modes.
Correctly handles authenticated insecure delegations and apex signature checks.
"""

import asyncio
import time
from enum import Enum
from typing import Optional, Tuple, Dict, Any

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
    """DNSSEC validation result states"""
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"
    
    def is_valid_for_mode(self, mode: str) -> bool:
        if mode == "none" or mode == "log":
            return True
        elif mode == "standard":
            return self in (DNSSECStatus.SECURE, DNSSECStatus.INSECURE)
        elif mode == "strict":
            return self == DNSSECStatus.SECURE
        return False


class DNSSECValidator:
    """DNSSEC validation logic with cryptographic integrity checks."""
    
    def __init__(self, config: dict, trust_anchors: dict, query_func=None):
        self.mode = config.get('mode', 'none')
        self.trust_anchors = trust_anchors or {}
        self.query_func = query_func
        
        self.failure_rcode = self._parse_rcode(config.get('validation_failure_rcode', 'SERVFAIL'))
        self.unsigned_rcode = self._parse_rcode(config.get('unsigned_zone_rcode', 'SERVFAIL'))
        self.disabled_algorithms = set(config.get('disabled_algorithms', []))
        
        self.validated_keys: Dict[str, Tuple[dns.rrset.RRset, float]] = {}
        self.ds_cache: Dict[str, Tuple[Optional[dns.rrset.RRset], float]] = {}
        self.negative_cache: Dict[str, float] = {}
        
        if self.mode != "none":
            logger.info(f"DNSSEC Validator initialized in mode: {self.mode}")

    def _parse_rcode(self, rcode_str: str) -> dns.rcode.Rcode:
        return getattr(dns.rcode, rcode_str.upper(), dns.rcode.SERVFAIL)

    async def validate_response(self, response: dns.message.Message, qname: str, qtype: int, log=None) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        log = log or logger
        if self.mode == "none":
            return DNSSECStatus.SECURE, response

        qname_norm = qname.lower().rstrip('.') + '.'
        if qname_norm in self.negative_cache and time.time() < self.negative_cache[qname_norm]:
            return self._apply_mode(DNSSECStatus.BOGUS, response, qname, log)

        try:
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for section in (response.answer, response.authority) for rrset in section)
            
            if not has_rrsig:
                status = await self._check_unsigned_zone(qname_norm, log)
            else:
                status = await self._validate_signatures(response, qname_norm, log)
            
            return self._apply_mode(status, response, qname, log)
        except Exception as e:
            log.debug(f"DNSSEC: Validation error for {qname}: {e}")
            return self._apply_mode(DNSSECStatus.INDETERMINATE, response, qname, log)

    async def _check_unsigned_zone(self, qname: str, log) -> DNSSECStatus:
        """
        Walk up the tree to find DS records or proof of insecurity.
        Fix: Correctly handles authenticated insecure delegations to avoid false BOGUS.
        """
        zone = qname
        while zone and zone != '.':
            parent = self._get_parent_zone(zone)
            if not parent: break
            
            cache_key = f"ds:{zone}"
            if cache_key in self.ds_cache:
                ds_rrset, expiry = self.ds_cache[cache_key]
                if time.time() < expiry:
                    # If we have a cached DS, the child MUST be signed
                    if ds_rrset: return DNSSECStatus.BOGUS
            
            ds_response = await self._query_ds(zone, log)
            if ds_response:
                ds_rrset = self._extract_rrset(ds_response, zone, dns.rdatatype.DS)
                if ds_rrset:
                    # Found a DS record for the child. Child response was unsigned -> BOGUS
                    ttl = min((rrset.ttl for rrset in ds_response.answer) if ds_response.answer else [300], default=300)
                    self.ds_cache[cache_key] = (ds_rrset, time.time() + ttl)
                    return DNSSECStatus.BOGUS
                
                # No DS found. Check if the parent response proves the absence (signed denial)
                # If the parent is signed and explicitly says "No DS", delegation is INSECURE.
                has_parent_sig = any(rrset.rdtype == dns.rdatatype.RRSIG for section in (ds_response.answer, ds_response.authority) for rrset in section)
                if has_parent_sig:
                    log.debug(f"DNSSEC: Authenticated insecure delegation found at {zone}")
                    return DNSSECStatus.INSECURE
                
            zone = parent
        return DNSSECStatus.INSECURE

    async def _query_ds(self, zone: str, log) -> Optional[dns.message.Message]:
        if not self.query_func: return None
        try:
            query = dns.message.make_query(dns.name.from_text(zone), dns.rdatatype.DS, want_dnssec=True)
            wire = await self.query_func(query.to_wire())
            return dns.message.from_wire(wire) if wire else None
        except Exception as e:
            log.debug(f"DNSSEC: DS query failed for {zone}: {e}")
            return None

    async def _validate_signatures(self, response: dns.message.Message, qname: str, log) -> DNSSECStatus:
        rrsets_to_validate = []
        rrsigs = {}
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    for rdata in rrset: rrsigs[(rrset.name, rdata.type_covered)] = rrset
                else:
                    rrsets_to_validate.append(rrset)
        
        if not rrsets_to_validate: return DNSSECStatus.SECURE

        for rrset in rrsets_to_validate:
            rrsig_rrset = rrsigs.get((rrset.name, rrset.rdtype))
            if not rrsig_rrset: 
                # If some records are signed and others aren't, it's BOGUS
                return DNSSECStatus.BOGUS
            
            signer = str(rrsig_rrset[0].signer).lower().rstrip('.') + '.'
            dnskey_rrset = await self._get_validated_dnskey(signer, log)
            if not dnskey_rrset: return DNSSECStatus.INDETERMINATE
            
            try:
                dns.dnssec.validate(rrset, rrsig_rrset, {dns.name.from_text(signer): dnskey_rrset})
            except dns.dnssec.ValidationFailure:
                self.negative_cache[qname] = time.time() + 300
                return DNSSECStatus.BOGUS
        return DNSSECStatus.SECURE

    async def _get_validated_dnskey(self, zone: str, log) -> Optional[dns.rrset.RRset]:
        """Establish trust in a DNSKEY RRset and verify its self-signature (Apex Check)."""
        if zone in self.validated_keys:
            dnskey, expiry = self.validated_keys[zone]
            if time.time() < expiry: return dnskey

        if not self.query_func: return None
        try:
            query = dns.message.make_query(dns.name.from_text(zone), dns.rdatatype.DNSKEY, want_dnssec=True)
            wire = await self.query_func(query.to_wire())
            if not wire: return None
            response = dns.message.from_wire(wire)
            
            dnskey_rrset = self._extract_rrset(response, zone, dns.rdatatype.DNSKEY)
            if not dnskey_rrset: return None

            # 1. Establish cryptographic trust in the DNSKEY set via DS chain or Trust Anchor
            if zone == '.' or zone == '':
                if not self._validate_root_dnskey(dnskey_rrset, log): return None
            else:
                if not await self._validate_dnskey_with_ds(zone, dnskey_rrset, response, log): return None
            
            # 2. Apex Signature Check: Ensure the DNSKEY RRset is signed by a valid key in the set
            # This is critical to prevent key substitution attacks.
            rrsig_dnskey = None
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    for rdata in rrset:
                        if rdata.type_covered == dns.rdatatype.DNSKEY:
                            rrsig_dnskey = rrset
                            break
            
            if not rrsig_dnskey:
                log.error(f"DNSSEC: Missing RRSIG for DNSKEY RRset at {zone}")
                return None
            
            try:
                dns.dnssec.validate(dnskey_rrset, rrsig_dnskey, {dns.name.from_text(zone): dnskey_rrset})
            except dns.dnssec.ValidationFailure as e:
                log.error(f"DNSSEC: Apex self-signature validation failed for {zone}: {e}")
                return None
            
            ttl = min((rrset.ttl for rrset in response.answer) if response.answer else [300], default=300)
            self.validated_keys[zone] = (dnskey_rrset, time.time() + ttl)
            return dnskey_rrset
        except Exception as e:
            log.debug(f"DNSSEC: Failed to get DNSKEY for {zone}: {e}")
            return None

    def _validate_root_dnskey(self, dnskey_rrset, log) -> bool:
        for rdata in dnskey_rrset:
            if not (rdata.flags & 0x0001): continue # KSK bit
            key_tag = dns.dnssec.key_id(rdata)
            if key_tag in self.trust_anchors:
                anchor = self.trust_anchors[key_tag]
                computed = dns.dnssec.make_ds(dns.name.root, rdata, anchor['digest_type'])
                expected = anchor['digest']
                if isinstance(expected, str): expected = bytes.fromhex(expected)
                if computed.digest == expected: return True
        return False

    async def _validate_dnskey_with_ds(self, zone, dnskey_rrset, dnskey_response, log) -> bool:
        ds_resp = await self._query_ds(zone, log)
        if not ds_resp: return False
        ds_rrset = self._extract_rrset(ds_resp, zone, dns.rdatatype.DS)
        if not ds_rrset: return False
        
        # Cross-validate: Check if any DS record matches a KSK in the DNSKEY RRset
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                if not (dnskey.flags & 0x0001): continue # Only check KSKs
                if ds.algorithm == dnskey.algorithm and ds.key_tag == dns.dnssec.key_id(dnskey):
                    try:
                        computed = dns.dnssec.make_ds(dns.name.from_text(zone), dnskey, ds.digest_type)
                        if computed.digest == ds.digest: return True
                    except: continue
        return False

    def _extract_rrset(self, response, name, rdtype):
        name_obj = dns.name.from_text(name) if isinstance(name, str) else name
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.name == name_obj and rrset.rdtype == rdtype: return rrset
        return None

    def _get_parent_zone(self, zone: str) -> Optional[str]:
        z = zone.rstrip('.')
        if not z or z == '.': return None
        parts = z.split('.')
        return '.'.join(parts[1:]) + '.' if len(parts) > 1 else '.'

    def _apply_mode(self, status, response, qname, log) -> Tuple[DNSSECStatus, Optional[dns.message.Message]]:
        if self.mode == "none" or self.mode == "log":
            return status, response
        if self.mode == "standard" and status in (DNSSECStatus.BOGUS, DNSSECStatus.INDETERMINATE):
            return status, self._make_err(response, self.failure_rcode)
        if self.mode == "strict" and status != DNSSECStatus.SECURE:
            rcode = self.unsigned_rcode if status == DNSSECStatus.INSECURE else self.failure_rcode
            return status, self._make_err(response, rcode)
        if status == DNSSECStatus.SECURE:
            response.flags |= dns.flags.AD
        return status, response

    def _make_err(self, original, rcode):
        res = dns.message.make_response(original)
        res.set_rcode(rcode)
        res.answer.clear()
        return res

    def get_stats(self) -> dict:
        return {'mode': self.mode, 'keys_cached': len(self.validated_keys)}

    def clear_cache(self):
        self.validated_keys.clear()
        self.ds_cache.clear()
        self.negative_cache.clear()


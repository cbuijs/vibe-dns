#!/usr/bin/env python3
# filename: geoip.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 6.2.1 (Cleanup: Removed unused match_location)
# -----------------------------------------------------------------------------
"""
High-performance GeoIP lookup module with ASN support.
Uses memory-mapped binary files with O(log n) binary search.
Trusts pre-validated compiled database.
"""

import mmap
import struct
import ipaddress
import orjson as json
import logging
from typing import Optional, Tuple
from pathlib import Path
from cctld import CCTLDMapper

logger = logging.getLogger("GeoIP")

class GeoIPLookup:
    def __init__(self, config: dict):
        self.enabled = False
        self.mm = None
        self.f = None
        self.mode = 'binary_mmap'
        
        geoip_cfg = config.get('geoip', {})

        # ALWAYS initialize mapper for Query Blocking
        self.cctld_mode = geoip_cfg.get('cctld_mode', 'geoip_only')
        self.cctld_mapper = CCTLDMapper(enabled=True)

        if not geoip_cfg.get('enabled', False):
            logger.info("GeoIP: DISABLED")
            return

        db_path = geoip_cfg.get('unified_database', 'geoip.vibe')
        if not Path(db_path).exists():
            logger.error(f"GeoIP Database not found at: {db_path}")
            logger.error("Run: python3 geoip_compiler.py --mmdb <path>")
            return

        try:
            self.f = open(db_path, 'rb')
            self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
            
            # Parse Header
            header = struct.unpack_from('!4sHIIIII', self.mm, 0)
            
            if header[0] != b'VIBE':
                raise ValueError("Invalid database magic signature (Expected 'VIBE')")
            
            self.version = header[1]
            self.v4_count = header[2]
            self.v4_offset = header[3]
            self.v6_count = header[4]
            self.v6_offset = header[5]
            self.data_offset = header[6]
            
            self.enabled = True
            self.cctld_mode = geoip_cfg.get('cctld_mode', 'geoip_only')
            self.cctld_mapper = CCTLDMapper(enabled=True)
            
            logger.info(f"GeoIP: ENABLED (Version {self.version})")
            logger.info(f"  - IPv4 Ranges: {self.v4_count}")
            logger.info(f"  - IPv6 Ranges: {self.v6_count}")
            logger.info(f"  - Mode: MMAP + Binary Search")
            logger.info(f"  - IP Hint Mode: {self.cctld_mode}")
            
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
            self.close()

    def lookup(self, ip_str: str) -> Optional[dict]:
        """Lookup GeoIP data - returns raw data from compiled database"""
        if not self.enabled: return None
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        if ip.version == 4:
            return self._lookup_v4(int(ip))
        else:
            return self._lookup_v6(ip.packed)

    def _lookup_v4(self, ip_int: int) -> Optional[dict]:
        if self.v4_count == 0: return None
        low, high = 0, self.v4_count - 1
        record_size = 12
        base_offset = self.v4_offset
        
        while low <= high:
            mid = (low + high) // 2
            offset = base_offset + (mid * record_size)
            start, end, data_ptr = struct.unpack_from('!III', self.mm, offset)
            
            if ip_int < start: high = mid - 1
            elif ip_int > end: low = mid + 1
            else: return self._read_data(data_ptr)
        return None

    def _lookup_v6(self, ip_bytes: bytes) -> Optional[dict]:
        if self.v6_count == 0: return None
        low, high = 0, self.v6_count - 1
        record_size = 36
        base_offset = self.v6_offset
        
        while low <= high:
            mid = (low + high) // 2
            offset = base_offset + (mid * record_size)
            start, end, data_ptr = struct.unpack_from('!16s16sI', self.mm, offset)
            
            if ip_bytes < start: high = mid - 1
            elif ip_bytes > end: low = mid + 1
            else: return self._read_data(data_ptr)
        return None

    def _read_data(self, ptr: int) -> dict:
        """Read and deserialize JSON data - trust it's valid"""
        abs_offset = self.data_offset + ptr
        length = struct.unpack_from('!H', self.mm, abs_offset)[0]
        json_bytes = self.mm[abs_offset+2 : abs_offset+2+length]
        try:
            return json.loads(json_bytes)
        except json.JSONDecodeError:
            return {}

    def lookup_asn(self, ip_str: str) -> Optional[dict]:
        """Lookup ASN - returns raw ASN data from database"""
        if not self.enabled: return None
        result = self.lookup(ip_str)
        if not result: return None
        
        # Return ASN fields if present (compiler guarantees validity)
        asn_data = {}
        if 'asn' in result: 
            asn_data['asn'] = result['asn']
        if 'as_name' in result:
            asn_data['as_name'] = result['as_name']
        
        return asn_data if asn_data else None

    def lookup_with_domain_hint(self, ip_str: str, domain: str = None) -> Tuple[Optional[dict], Optional[str]]:
        """Lookup IP with optional ccTLD domain hint"""
        geo = self.lookup(ip_str)
        cctld = None
        
        if self.cctld_mode != 'geoip_only':
            if domain and self.cctld_mapper.enabled:
                cctld = self.cctld_mapper.get_country_from_domain(domain)
        
        return geo, cctld

    def close(self):
        if self.mm: self.mm.close()
        if self.f: self.f.close()
        self.enabled = False


#!/usr/bin/env python3
# filename: geoip.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.0.0 (GeoNames Integration)
# -----------------------------------------------------------------------------
"""
GeoIP lookup module using MMDB databases and GeoNames mappings.
"""

import ipaddress
import json
import time
import logging
from pathlib import Path
from typing import Optional, Set
from utils import get_logger

logger = get_logger("GeoIP")

class GeoNamesDB:
    """GeoNames compiled database for region/country mappings"""
    
    def __init__(self, db_path: str = "geonames_compiled.json"):
        self.countries = {}
        self.continent_map = {}
        self.region_map = {}
        self.country_name_map = {}
        self.geoname_id_map = {}
        
        logger.info(f"Initializing GeoNames database from: {db_path}")
        
        if Path(db_path).exists():
            logger.debug(f"GeoNames database file found: {db_path}")
            self.load_database(db_path)
        else:
            logger.warning(f"GeoNames database not found: {db_path}")
            logger.info("To enable full GeoNames support, run: python3 geonames_compiler.py --output geonames_compiled.json")
            logger.info("Falling back to basic hardcoded region mappings")
            self._load_fallback_mappings()
    
    def load_database(self, db_path: str):
        """Load compiled GeoNames database"""
        logger.info(f"Loading GeoNames database from: {db_path}")
        start_time = time.time()
        
        try:
            file_size = Path(db_path).stat().st_size / (1024 * 1024)
            logger.debug(f"Database file size: {file_size:.2f} MB")
            
            with open(db_path, 'r', encoding='utf-8') as f:
                db = json.load(f)
            
            parse_time = time.time() - start_time
            logger.debug(f"JSON parsed in {parse_time:.3f}s")
            
            # Load each section with logging
            self.countries = db.get('countries', {})
            logger.debug(f"Loaded {len(self.countries)} countries")
            
            self.continent_map = db.get('continent_map', {})
            continents = [k for k in self.continent_map.keys() if len(k) == 2]  # Codes only
            logger.debug(f"Loaded {len(continents)} continents")
            
            self.region_map = db.get('region_map', {})
            logger.debug(f"Loaded {len(self.region_map)} regions")
            
            self.country_name_map = db.get('country_name_map', {})
            logger.debug(f"Loaded {len(self.country_name_map)} country name mappings")
            
            self.geoname_id_map = db.get('geoname_id_map', {})
            logger.debug(f"Loaded {len(self.geoname_id_map)} GeoNames ID mappings")
            
            total_time = time.time() - start_time
            logger.info(f"✓ GeoNames database loaded successfully in {total_time:.3f}s")
            logger.info(f"  Countries: {len(self.countries)}, Regions: {len(self.region_map)}, Continents: {len(continents)}")
            
            # Log some example mappings at DEBUG level
            if logger.isEnabledFor(logging.DEBUG):
                example_regions = list(self.region_map.keys())[:3]
                for region in example_regions:
                    countries = self.region_map[region].get('countries', [])
                    logger.debug(f"  Example: {region} -> {len(countries)} countries")
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GeoNames JSON database: {e}")
            logger.error(f"Database file may be corrupted. Recompile with: python3 geonames_compiler.py")
            self._load_fallback_mappings()
        except Exception as e:
            logger.error(f"Failed to load GeoNames database: {e}")
            logger.exception("Full traceback:")
            self._load_fallback_mappings()
    
    def _load_fallback_mappings(self):
        """Load minimal fallback mappings if database not available"""
        logger.warning("Loading fallback region mappings (limited functionality)")
        
        self.continent_map = {
            'AF': {'name': 'AFRICA', 'countries': []},
            'AN': {'name': 'ANTARCTICA', 'countries': []},
            'AS': {'name': 'ASIA', 'countries': []},
            'EU': {'name': 'EUROPE', 'countries': []},
            'NA': {'name': 'NORTH_AMERICA', 'countries': []},
            'OC': {'name': 'OCEANIA', 'countries': []},
            'SA': {'name': 'SOUTH_AMERICA', 'countries': []},
        }
        logger.debug(f"Loaded {len(self.continent_map)} fallback continents")
        
        self.region_map = {
            'BALKANS': {'countries': ['AL', 'BA', 'BG', 'HR', 'XK', 'MK', 'ME', 'RO', 'RS', 'SI']},
            'SCANDINAVIA': {'countries': ['DK', 'FI', 'IS', 'NO', 'SE']},
            'BALTICS': {'countries': ['EE', 'LT', 'LV']},
            'BENELUX': {'countries': ['BE', 'LU', 'NL']},
            'MIDDLE_EAST': {'countries': ['AE', 'BH', 'CY', 'EG', 'IL', 'IQ', 'IR', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'YE']},
            'ARABIA': {'countries': ['AE', 'BH', 'KW', 'OM', 'QA', 'SA', 'YE']},
            'INDOCHINA': {'countries': ['KH', 'LA', 'MM', 'TH', 'VN']},
        }
        logger.debug(f"Loaded {len(self.region_map)} fallback regions")
        logger.info(f"✓ Fallback mappings loaded: {len(self.continent_map)} continents, {len(self.region_map)} regions")
        logger.warning("Note: Full country name matching and continent country lists unavailable in fallback mode")
    
    def get_country_by_name(self, name: str) -> Optional[str]:
        """Get ISO2 code by country name"""
        result = self.country_name_map.get(name.upper())
        if result:
            logger.debug(f"GeoNames: Resolved country name '{name}' -> {result}")
        else:
            logger.debug(f"GeoNames: Country name '{name}' not found in mappings")
        return result
    
    def get_region_countries(self, region: str) -> list:
        """Get list of country codes in region"""
        region_data = self.region_map.get(region.upper())
        if region_data:
            countries = region_data.get('countries', [])
            logger.debug(f"GeoNames: Region '{region}' -> {len(countries)} countries: {', '.join(countries[:5])}{'...' if len(countries) > 5 else ''}")
            return countries
        else:
            logger.debug(f"GeoNames: Region '{region}' not found")
        return []
    
    def get_continent_countries(self, continent: str) -> list:
        """Get list of country codes in continent"""
        cont_data = self.continent_map.get(continent.upper())
        if cont_data:
            countries = cont_data.get('countries', [])
            logger.debug(f"GeoNames: Continent '{continent}' -> {len(countries)} countries")
            return countries
        else:
            logger.debug(f"GeoNames: Continent '{continent}' not found")
        return []
    
    def resolve_location_to_countries(self, location: str) -> list:
        """
        Resolve location spec to list of country codes.
        
        Returns list of ISO2 country codes or empty list if not found.
        """
        location_upper = location.upper()
        logger.debug(f"GeoNames: Resolving location '{location}'")
        
        # Direct country code (2 letters)
        if len(location_upper) == 2 and location_upper in self.countries:
            logger.debug(f"GeoNames: Matched as country code: {location_upper}")
            return [location_upper]
        
        # Country name
        country_code = self.get_country_by_name(location_upper)
        if country_code:
            logger.debug(f"GeoNames: Matched as country name: '{location}' -> {country_code}")
            return [country_code]
        
        # Region
        region_countries = self.get_region_countries(location_upper)
        if region_countries:
            logger.debug(f"GeoNames: Matched as region: '{location}' -> {len(region_countries)} countries")
            return region_countries
        
        # Continent
        continent_countries = self.get_continent_countries(location_upper)
        if continent_countries:
            logger.debug(f"GeoNames: Matched as continent: '{location}' -> {len(continent_countries)} countries")
            return continent_countries
        
        logger.debug(f"GeoNames: No match found for location '{location}'")
        return []


class GeoIPLookup:
    """GeoIP lookup using MaxMind/IPInfo MMDB databases with GeoNames integration"""
    
    def __init__(self, config: dict):
        self.enabled = False
        self.reader = None
        self.db_type = None
        self.geonames = None
        
        logger.info("=" * 80)
        logger.info("Initializing GeoIP Lookup System")
        logger.info("=" * 80)
        
        geoip_cfg = config.get('geoip', {})
        if not geoip_cfg.get('enabled', False):
            logger.info("GeoIP status: DISABLED (set geoip.enabled=true to enable)")
            logger.info("=" * 80)
            return
        
        logger.info("GeoIP status: ENABLED")
        
        # Load GeoNames database
        geonames_path = geoip_cfg.get('geonames_database', 'geonames_compiled.json')
        logger.info(f"Loading GeoNames mappings from: {geonames_path}")
        self.geonames = GeoNamesDB(geonames_path)
        
        db_path = geoip_cfg.get('database_path')
        if not db_path:
            logger.error("GeoIP enabled but no database_path configured")
            logger.error("Set geoip.database_path to MaxMind or IPInfo MMDB file")
            logger.info("=" * 80)
            return
        
        logger.info(f"Loading IP-to-Country database: {db_path}")
        
        if not Path(db_path).exists():
            logger.error(f"GeoIP database file not found: {db_path}")
            logger.error("Download from:")
            logger.error("  MaxMind: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            logger.error("  IPInfo:  https://ipinfo.io/developers/database-download")
            logger.info("=" * 80)
            return
        
        try:
            import maxminddb
            
            file_size = Path(db_path).stat().st_size / (1024 * 1024)
            logger.debug(f"Database file size: {file_size:.2f} MB")
            
            logger.info("Opening MMDB database...")
            self.reader = maxminddb.open_database(db_path)
            self.enabled = True
            
            # Detect database type - metadata uses attributes, not dict access
            metadata = self.reader.metadata()
            
            # Get database_type attribute (might be string or bytes)
            db_type_raw = getattr(metadata, 'database_type', '')
            if isinstance(db_type_raw, bytes):
                db_type_raw = db_type_raw.decode('utf-8', errors='ignore')
            db_desc = str(db_type_raw).lower()
            
            # Get build_epoch attribute
            db_build = getattr(metadata, 'build_epoch', 0)
            
            if 'city' in db_desc or 'country' in db_desc:
                self.db_type = 'maxmind'
            elif 'ipinfo' in db_desc or 'standard' in db_desc:
                self.db_type = 'ipinfo'
            else:
                self.db_type = 'unknown'
            
            logger.info(f"✓ GeoIP database opened successfully")
            logger.info(f"  Database type: {self.db_type.upper()}")
            logger.info(f"  Description: {db_type_raw if db_type_raw else 'Unknown'}")
            if db_build:
                from datetime import datetime
                build_date = datetime.fromtimestamp(db_build).strftime('%Y-%m-%d')
                logger.info(f"  Build date: {build_date}")
            
            logger.info("=" * 80)
            logger.info("GeoIP System Ready")
            logger.info(f"  - IP lookups: {self.db_type.upper()} database")
            logger.info(f"  - Region mappings: {'GeoNames' if self.geonames.countries else 'Fallback'}")
            logger.info(f"  - Countries available: {len(self.geonames.countries) if self.geonames.countries else 'Basic'}")
            logger.info(f"  - Regions available: {len(self.geonames.region_map)}")
            logger.info("=" * 80)
            
        except ImportError:
            logger.error("=" * 80)
            logger.error("FATAL: maxminddb library not installed")
            logger.error("Install with: pip install maxminddb")
            logger.error("=" * 80)
        except Exception as e:
            logger.error("=" * 80)
            logger.error(f"Failed to load GeoIP database: {e}")
            logger.exception("Full traceback:")
            logger.error("=" * 80)
    
    def lookup(self, ip_str: str) -> Optional[dict]:
        """
        Lookup IP address and return geographic info.
        
        Returns dict with keys:
        - country_code: ISO 3166-1 alpha-2 (e.g., 'NL')
        - country_name: Full name (e.g., 'Netherlands')
        - continent_code: 2-letter code (e.g., 'EU')
        - continent_name: Full name (e.g., 'Europe')
        - geoname_id: GeoNames ID if available
        """
        if not self.enabled or not self.reader:
            logger.debug(f"GeoIP lookup skipped for {ip_str} (GeoIP disabled)")
            return None
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Skip private/internal IPs
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                logger.debug(f"GeoIP: Skipping lookup for private/internal IP: {ip_str}")
                return None
            
            logger.debug(f"GeoIP: Looking up {ip_str} in {self.db_type} database...")
            data = self.reader.get(str(ip))
            
            if not data:
                logger.debug(f"GeoIP: No data found for {ip_str}")
                return None
            
            result = {}
            
            if self.db_type == 'maxmind':
                country = data.get('country', {})
                continent = data.get('continent', {})
                
                result['country_code'] = country.get('iso_code')
                result['country_name'] = country.get('names', {}).get('en')
                result['continent_code'] = continent.get('code')
                result['continent_name'] = continent.get('names', {}).get('en')
                result['geoname_id'] = country.get('geoname_id')
                
                logger.debug(
                    f"GeoIP: {ip_str} -> {result['country_code']} ({result['country_name']}) "
                    f"in {result['continent_code']} ({result['continent_name']})"
                )
                
            elif self.db_type == 'ipinfo':
                result['country_code'] = data.get('country')
                result['country_name'] = data.get('country_name')
                result['continent_code'] = data.get('continent')
                result['continent_name'] = None
                result['geoname_id'] = None
                
                logger.debug(
                    f"GeoIP: {ip_str} -> {result['country_code']} ({result['country_name']}) "
                    f"in {result['continent_code']}"
                )
                
            else:
                result['country_code'] = (
                    data.get('country', {}).get('iso_code') or 
                    data.get('country')
                )
                result['country_name'] = (
                    data.get('country', {}).get('names', {}).get('en') or
                    data.get('country_name')
                )
                result['continent_code'] = (
                    data.get('continent', {}).get('code') or
                    data.get('continent')
                )
                result['continent_name'] = data.get('continent', {}).get('names', {}).get('en')
                result['geoname_id'] = data.get('country', {}).get('geoname_id')
                
                logger.debug(f"GeoIP: {ip_str} -> {result['country_code']} ({result['country_name']})")
            
            return result
            
        except ValueError as e:
            logger.debug(f"GeoIP: Invalid IP address format: {ip_str}")
            return None
        except Exception as e:
            logger.warning(f"GeoIP lookup error for {ip_str}: {e}")
            return None
    
    def match_location(self, ip_str: str, location_spec: str) -> bool:
        """
        Check if IP matches location specification.
        
        Uses GeoNames database for comprehensive matching:
        - ISO 3166 country code (e.g., 'NL', 'DE')
        - Full country name (e.g., 'NETHERLANDS', 'GERMANY')
        - Continent name (e.g., 'EUROPE', 'ASIA')
        - Region name (e.g., 'BALKANS', 'SCANDINAVIA')
        - GeoNames ID (numeric)
        """
        if not self.enabled:
            logger.debug(f"GeoIP: match_location skipped for {ip_str} (GeoIP disabled)")
            return False
        
        logger.debug(f"GeoIP: Checking if {ip_str} matches location '{location_spec}'")
        
        geo = self.lookup(ip_str)
        if not geo:
            logger.debug(f"GeoIP: No geographic data for {ip_str}, cannot match")
            return False
        
        country_code = geo.get('country_code', '').upper()
        location_upper = location_spec.upper()
        
        logger.debug(f"GeoIP: IP {ip_str} is from {country_code} ({geo.get('country_name', 'Unknown')})")
        
        # Direct country code match
        if len(location_upper) == 2 and country_code == location_upper:
            logger.info(f"✓ GeoIP: {ip_str} matches {location_spec} (direct country code match)")
            return True
        
        # Use GeoNames for advanced matching
        if self.geonames:
            logger.debug(f"GeoIP: Using GeoNames to resolve '{location_spec}'")
            target_countries = self.geonames.resolve_location_to_countries(location_spec)
            if target_countries:
                target_upper = [c.upper() for c in target_countries]
                if country_code in target_upper:
                    logger.info(
                        f"✓ GeoIP: {ip_str} ({country_code}) matches {location_spec} "
                        f"(one of {len(target_countries)} countries in location)"
                    )
                    return True
                else:
                    logger.debug(
                        f"GeoIP: {ip_str} ({country_code}) NOT in {location_spec} "
                        f"(requires one of: {', '.join(target_upper[:5])}{'...' if len(target_upper) > 5 else ''})"
                    )
                    return False
        
        # Fallback: direct name matching
        country_name = geo.get('country_name', '').upper()
        if country_name == location_upper:
            logger.info(f"✓ GeoIP: {ip_str} matches {location_spec} (country name match)")
            return True
        
        continent_name = geo.get('continent_name', '').upper() if geo.get('continent_name') else ''
        if continent_name == location_upper:
            logger.info(f"✓ GeoIP: {ip_str} matches {location_spec} (continent name match)")
            return True
        
        continent_code = geo.get('continent_code', '').upper()
        if continent_code == location_upper:
            logger.info(f"✓ GeoIP: {ip_str} matches {location_spec} (continent code match)")
            return True
        
        logger.debug(f"GeoIP: {ip_str} does NOT match {location_spec}")
        return False
    
    def get_country_code(self, ip_str: str) -> Optional[str]:
        """Get ISO 3166 country code for IP"""
        geo = self.lookup(ip_str)
        code = geo.get('country_code') if geo else None
        if code:
            logger.debug(f"GeoIP: {ip_str} -> country code: {code}")
        return code
    
    def get_country_name(self, ip_str: str) -> Optional[str]:
        """Get full country name for IP"""
        geo = self.lookup(ip_str)
        name = geo.get('country_name') if geo else None
        if name:
            logger.debug(f"GeoIP: {ip_str} -> country name: {name}")
        return name
    
    def get_continent(self, ip_str: str) -> Optional[str]:
        """Get continent code for IP"""
        geo = self.lookup(ip_str)
        continent = geo.get('continent_code') if geo else None
        if continent:
            logger.debug(f"GeoIP: {ip_str} -> continent: {continent}")
        return continent
    
    def close(self):
        """Close database"""
        if self.reader:
            logger.info("Closing GeoIP database")
            self.reader.close()
            self.enabled = False
            logger.debug("GeoIP database closed")


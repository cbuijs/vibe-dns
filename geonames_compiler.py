#!/usr/bin/env python3
# filename: geonames_compiler.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
GeoNames database compiler.

Downloads and compiles GeoNames data into efficient lookup database.
Creates mappings for:
- GeoNames ID -> Country/Region info
- Country names -> ISO codes
- Region names -> Country lists
- Continent codes/names

Data sources:
- countryInfo.txt: Country codes, names, continents
- admin1CodesASCII.txt: Administrative divisions (states/provinces)
- hierarchy.txt: Parent-child relationships
"""

import urllib.request
import json
import os
from pathlib import Path
from typing import Dict, List, Set
from utils import get_logger

logger = get_logger("GeoNamesCompiler")

GEONAMES_BASE_URL = "https://download.geonames.org/export/dump/"

class GeoNamesCompiler:
    """Compiles GeoNames data into optimized lookup database"""
    
    def __init__(self, cache_dir="./geonames_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.countries = {}
        self.geoname_id_map = {}
        self.continent_map = {}
        self.region_map = {}
        self.country_name_map = {}
        
    def download_file(self, filename: str) -> Path:
        """Download GeoNames file if not cached"""
        local_path = self.cache_dir / filename
        
        if local_path.exists():
            logger.info(f"Using cached {filename}")
            return local_path
        
        url = GEONAMES_BASE_URL + filename
        logger.info(f"Downloading {filename} from {url}")
        
        try:
            urllib.request.urlretrieve(url, local_path)
            logger.info(f"Downloaded {filename} ({local_path.stat().st_size} bytes)")
            return local_path
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            raise
    
    def parse_country_info(self) -> Dict:
        """
        Parse countryInfo.txt for country codes, names, continents.
        
        Format (tab-separated):
        ISO  ISO3  ISONumeric  fips  Country  Capital  Area  Population  Continent  tld  
        CurrencyCode  CurrencyName  Phone  PostalCodeFormat  PostalCodeRegex  Languages  
        geonameid  neighbours  EquivalentFipsCode
        """
        path = self.download_file("countryInfo.txt")
        countries = {}
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split('\t')
                if len(parts) < 19:
                    continue
                
                iso2 = parts[0]
                iso3 = parts[1]
                country_name = parts[4]
                continent = parts[8]
                geonameid = parts[16]
                
                countries[iso2] = {
                    'iso2': iso2,
                    'iso3': iso3,
                    'name': country_name,
                    'continent': continent,
                    'geonameid': geonameid
                }
                
                # Map country name variations
                self.country_name_map[country_name.upper()] = iso2
                
                # Map geoname ID
                if geonameid:
                    self.geoname_id_map[geonameid] = {
                        'type': 'country',
                        'iso2': iso2,
                        'name': country_name
                    }
        
        logger.info(f"Parsed {len(countries)} countries")
        return countries
    
    def parse_admin1_codes(self) -> Dict:
        """
        Parse admin1CodesASCII.txt for administrative divisions.
        
        Format (tab-separated):
        code  name  asciiname  geonameid
        
        Example:
        US.CA  California  California  5332921
        NL.07  North Holland  North Holland  2749879
        """
        path = self.download_file("admin1CodesASCII.txt")
        admin_divisions = {}
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('\t')
                if len(parts) < 4:
                    continue
                
                code = parts[0]
                name = parts[1]
                geonameid = parts[3]
                
                # Extract country code
                country_code = code.split('.')[0]
                
                admin_divisions[code] = {
                    'code': code,
                    'name': name,
                    'country': country_code,
                    'geonameid': geonameid
                }
                
                # Map geoname ID
                if geonameid:
                    self.geoname_id_map[geonameid] = {
                        'type': 'admin1',
                        'code': code,
                        'name': name,
                        'country': country_code
                    }
        
        logger.info(f"Parsed {len(admin_divisions)} administrative divisions")
        return admin_divisions
    
    def build_continent_mappings(self) -> Dict:
        """Build continent code to country list mappings"""
        continent_countries = {}
        
        for iso2, data in self.countries.items():
            continent = data['continent']
            if continent not in continent_countries:
                continent_countries[continent] = []
            continent_countries[continent].append(iso2)
        
        # Map continent names
        continent_names = {
            'AF': 'AFRICA',
            'AN': 'ANTARCTICA',
            'AS': 'ASIA',
            'EU': 'EUROPE',
            'NA': 'NORTH_AMERICA',
            'OC': 'OCEANIA',
            'SA': 'SOUTH_AMERICA'
        }
        
        self.continent_map = {}
        for code, name in continent_names.items():
            self.continent_map[code] = {
                'name': name,
                'countries': continent_countries.get(code, [])
            }
            # Also map by name
            self.continent_map[name] = self.continent_map[code]
        
        logger.info(f"Built mappings for {len(continent_names)} continents")
        return self.continent_map
    
    def build_custom_regions(self) -> Dict:
        """Build custom region definitions"""
        regions = {
            'BALKANS': {
                'countries': ['AL', 'BA', 'BG', 'HR', 'XK', 'MK', 'ME', 'RO', 'RS', 'SI'],
                'description': 'Balkan Peninsula countries'
            },
            'SCANDINAVIA': {
                'countries': ['DK', 'FI', 'IS', 'NO', 'SE'],
                'description': 'Nordic countries'
            },
            'BALTICS': {
                'countries': ['EE', 'LT', 'LV'],
                'description': 'Baltic states'
            },
            'BENELUX': {
                'countries': ['BE', 'LU', 'NL'],
                'description': 'Benelux countries'
            },
            'MAGHREB': {
                'countries': ['DZ', 'LY', 'MA', 'MR', 'TN'],
                'description': 'North African Maghreb region'
            },
            'MIDDLE_EAST': {
                'countries': ['AE', 'BH', 'CY', 'EG', 'IL', 'IQ', 'IR', 'JO', 
                             'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'YE'],
                'description': 'Middle East region'
            },
            'ARABIA': {
                'countries': ['AE', 'BH', 'KW', 'OM', 'QA', 'SA', 'YE'],
                'description': 'Arabian Peninsula'
            },
            'INDOCHINA': {
                'countries': ['KH', 'LA', 'MM', 'TH', 'VN'],
                'description': 'Indochina Peninsula'
            },
            'CENTRAL_AMERICA': {
                'countries': ['BZ', 'CR', 'GT', 'HN', 'MX', 'NI', 'PA', 'SV'],
                'description': 'Central America'
            },
            'CARIBBEAN': {
                'countries': ['AG', 'BB', 'BS', 'CU', 'DM', 'DO', 'GD', 'HT', 
                             'JM', 'KN', 'LC', 'TT', 'VC'],
                'description': 'Caribbean islands'
            },
            'CAUCASUS': {
                'countries': ['AM', 'AZ', 'GE'],
                'description': 'Caucasus region'
            },
            'CENTRAL_ASIA': {
                'countries': ['KG', 'KZ', 'TJ', 'TM', 'UZ'],
                'description': 'Central Asian republics'
            },
            'SOUTH_ASIA': {
                'countries': ['AF', 'BD', 'BT', 'IN', 'LK', 'MV', 'NP', 'PK'],
                'description': 'South Asian subcontinent'
            },
            'SOUTHEAST_ASIA': {
                'countries': ['BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN'],
                'description': 'Southeast Asia'
            },
            'EAST_ASIA': {
                'countries': ['CN', 'HK', 'JP', 'KP', 'KR', 'MN', 'MO', 'TW'],
                'description': 'East Asia'
            }
        }
        
        self.region_map = regions
        logger.info(f"Built {len(regions)} custom regions")
        return regions
    
    def compile_database(self, output_file="geonames_compiled.json") -> Path:
        """Compile all data into single JSON database"""
        logger.info("Starting GeoNames compilation...")
        
        # Parse source files
        self.countries = self.parse_country_info()
        self.admin1 = self.parse_admin1_codes()
        self.build_continent_mappings()
        self.build_custom_regions()
        
        # Build complete database
        database = {
            'version': '1.0.0',
            'countries': self.countries,
            'geoname_id_map': self.geoname_id_map,
            'continent_map': self.continent_map,
            'region_map': self.region_map,
            'country_name_map': self.country_name_map,
            'admin1': self.admin1
        }
        
        # Save to file
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(database, f, indent=2, ensure_ascii=False)
        
        size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(f"Compiled database saved to {output_path} ({size_mb:.2f} MB)")
        logger.info(f"  - {len(self.countries)} countries")
        logger.info(f"  - {len(self.continent_map)} continents")
        logger.info(f"  - {len(self.region_map)} regions")
        logger.info(f"  - {len(self.geoname_id_map)} geoname IDs mapped")
        
        return output_path
    
    def verify_database(self, db_path: Path):
        """Verify compiled database integrity"""
        logger.info(f"Verifying database: {db_path}")
        
        with open(db_path, 'r', encoding='utf-8') as f:
            db = json.load(f)
        
        required_keys = ['countries', 'geoname_id_map', 'continent_map', 
                        'region_map', 'country_name_map']
        
        for key in required_keys:
            if key not in db:
                logger.error(f"Missing required key: {key}")
                return False
            logger.info(f"✓ {key}: {len(db[key])} entries")
        
        # Verify continent mappings
        for continent, data in db['continent_map'].items():
            if isinstance(data, dict) and 'countries' in data:
                logger.info(f"✓ {continent}: {len(data['countries'])} countries")
        
        # Verify regions
        for region, data in db['region_map'].items():
            if 'countries' in data:
                logger.info(f"✓ {region}: {len(data['countries'])} countries")
        
        logger.info("Database verification complete ✓")
        return True


def main():
    """Compile GeoNames database"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Compile GeoNames database")
    parser.add_argument("--output", default="geonames_compiled.json", 
                       help="Output file path")
    parser.add_argument("--cache-dir", default="./geonames_cache",
                       help="Cache directory for downloaded files")
    parser.add_argument("--verify", action="store_true",
                       help="Verify database after compilation")
    
    args = parser.parse_args()
    
    compiler = GeoNamesCompiler(cache_dir=args.cache_dir)
    
    try:
        db_path = compiler.compile_database(output_file=args.output)
        
        if args.verify:
            compiler.verify_database(db_path)
        
        print(f"\n✓ Database compiled successfully: {db_path}")
        print(f"  Use this file with: geoip.database_path")
        
    except Exception as e:
        logger.error(f"Compilation failed: {e}")
        raise


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
# filename: cctld.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.4.0 (Unified Region Definitions)
# -----------------------------------------------------------------------------
"""
CCTLD (Country Code Top-Level Domain) mapping for geographic hints.
Includes Continent and Region mapping for query-based blocking.
"""

from typing import Optional, List, Dict
from utils import get_logger

from geo_regions import (
    REGION_DEFINITIONS, COUNTRY_TO_CONTINENT,
    get_country_continent, get_country_regions
)

logger = get_logger("CCTLD")

# Standard CCTLD to Country mapping
CCTLD_TO_COUNTRY = {
    'ad': 'AD', 'al': 'AL', 'at': 'AT', 'ax': 'AX', 'ba': 'BA', 'be': 'BE',
    'bg': 'BG', 'by': 'BY', 'ch': 'CH', 'cy': 'CY', 'cz': 'CZ', 'de': 'DE',
    'dk': 'DK', 'ee': 'EE', 'es': 'ES', 'fi': 'FI', 'fo': 'FO', 'fr': 'FR',
    'gb': 'GB', 'gg': 'GG', 'gi': 'GI', 'gr': 'GR', 'hr': 'HR', 'hu': 'HU',
    'ie': 'IE', 'im': 'IM', 'is': 'IS', 'it': 'IT', 'je': 'JE', 'li': 'LI',
    'lt': 'LT', 'lu': 'LU', 'lv': 'LV', 'mc': 'MC', 'md': 'MD', 'me': 'ME',
    'mk': 'MK', 'mt': 'MT', 'nl': 'NL', 'no': 'NO', 'pl': 'PL', 'pt': 'PT',
    'ro': 'RO', 'rs': 'RS', 'ru': 'RU', 'se': 'SE', 'si': 'SI', 'sk': 'SK',
    'sm': 'SM', 'tr': 'TR', 'ua': 'UA', 'uk': 'GB', 'va': 'VA', 'xk': 'XK',
    'ae': 'AE', 'af': 'AF', 'am': 'AM', 'az': 'AZ', 'bd': 'BD', 'bh': 'BH',
    'bn': 'BN', 'bt': 'BT', 'cn': 'CN', 'ge': 'GE', 'hk': 'HK', 'id': 'ID',
    'il': 'IL', 'in': 'IN', 'iq': 'IQ', 'ir': 'IR', 'jo': 'JO', 'jp': 'JP',
    'kg': 'KG', 'kh': 'KH', 'kp': 'KP', 'kr': 'KR', 'kw': 'KW', 'kz': 'KZ',
    'la': 'LA', 'lb': 'LB', 'lk': 'LK', 'mm': 'MM', 'mn': 'MN', 'mo': 'MO',
    'mv': 'MV', 'my': 'MY', 'np': 'NP', 'om': 'OM', 'ph': 'PH', 'pk': 'PK',
    'ps': 'PS', 'qa': 'QA', 'sa': 'SA', 'sg': 'SG', 'sy': 'SY', 'th': 'TH',
    'tj': 'TJ', 'tl': 'TL', 'tm': 'TM', 'tw': 'TW', 'uz': 'UZ', 'vn': 'VN',
    'ye': 'YE',
    'ao': 'AO', 'bj': 'BJ', 'bw': 'BW', 'bf': 'BF', 'bi': 'BI', 'cm': 'CM',
    'cv': 'CV', 'cf': 'CF', 'td': 'TD', 'km': 'KM', 'cg': 'CG', 'cd': 'CD',
    'ci': 'CI', 'dj': 'DJ', 'eg': 'EG', 'gq': 'GQ', 'er': 'ER', 'et': 'ET',
    'ga': 'GA', 'gm': 'GM', 'gh': 'GH', 'gn': 'GN', 'gw': 'GW', 'ke': 'KE',
    'ls': 'LS', 'lr': 'LR', 'ly': 'LY', 'mg': 'MG', 'mw': 'MW', 'ml': 'ML',
    'mr': 'MR', 'mu': 'MU', 'yt': 'YT', 'ma': 'MA', 'mz': 'MZ', 'na': 'NA',
    'ne': 'NE', 'ng': 'NG', 're': 'RE', 'rw': 'RW', 'sh': 'SH', 'st': 'ST',
    'sn': 'SN', 'sc': 'SC', 'sl': 'SL', 'so': 'SO', 'za': 'ZA', 'ss': 'SS',
    'sd': 'SD', 'sz': 'SZ', 'tz': 'TZ', 'tg': 'TG', 'tn': 'TN', 'ug': 'UG',
    'eh': 'EH', 'zm': 'ZM', 'zw': 'ZW',
    'ca': 'CA', 'us': 'US', 'mx': 'MX', 'bz': 'BZ', 'cr': 'CR', 'sv': 'SV',
    'gt': 'GT', 'hn': 'HN', 'ni': 'NI', 'pa': 'PA', 'pm': 'PM',
    'ar': 'AR', 'bo': 'BO', 'br': 'BR', 'cl': 'CL', 'co': 'CO', 'ec': 'EC',
    'fk': 'FK', 'gf': 'GF', 'gy': 'GY', 'py': 'PY', 'pe': 'PE', 'sr': 'SR',
    'uy': 'UY', 've': 'VE',
    'ag': 'AG', 'ai': 'AI', 'aw': 'AW', 'bb': 'BB', 'bm': 'BM', 'bq': 'BQ',
    'bs': 'BS', 'cu': 'CU', 'cw': 'CW', 'dm': 'DM', 'do': 'DO', 'gd': 'GD',
    'gp': 'GP', 'ht': 'HT', 'jm': 'JM', 'kn': 'KN', 'ky': 'KY', 'lc': 'LC',
    'mf': 'MF', 'mq': 'MQ', 'ms': 'MS', 'pr': 'PR', 'bl': 'BL', 'sx': 'SX',
    'tc': 'TC', 'tt': 'TT', 'vc': 'VC', 'vg': 'VG', 'vi': 'VI',
    'as': 'AS', 'au': 'AU', 'ck': 'CK', 'fj': 'FJ', 'fm': 'FM', 'gu': 'GU',
    'ki': 'KI', 'mh': 'MH', 'mp': 'MP', 'nc': 'NC', 'nf': 'NF', 'nr': 'NR',
    'nu': 'NU', 'nz': 'NZ', 'pf': 'PF', 'pg': 'PG', 'pn': 'PN', 'pw': 'PW',
    'sb': 'SB', 'tk': 'TK', 'to': 'TO', 'tv': 'TV', 'um': 'UM', 'vu': 'VU',
    'wf': 'WF', 'ws': 'WS',
}

COUNTRY_TO_CCTLD = {}
for cctld, country in CCTLD_TO_COUNTRY.items():
    if country not in COUNTRY_TO_CCTLD:
        COUNTRY_TO_CCTLD[country] = []
    COUNTRY_TO_CCTLD[country].append(cctld)

class CCTLDMapper:
    """Maps domain names to country codes via CCTLD"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.country_to_regions = {}
        
        if self.enabled:
            self._invert_regions()
            logger.info(f"CCTLD Mapper initialized: {len(CCTLD_TO_COUNTRY)} TLDs mapped")
        else:
            logger.debug("CCTLD Mapper initialized (disabled)")

    def _invert_regions(self):
        """Pre-compute Country -> [Regions] map for fast lookup"""
        for region, region_data in REGION_DEFINITIONS.items():
            countries = region_data.get('countries', [])
            for country in countries:
                if country not in self.country_to_regions:
                    self.country_to_regions[country] = []
                self.country_to_regions[country].append(region)

    def get_country_from_domain(self, domain: str) -> Optional[str]:
        """Extract country code from domain's CCTLD"""
        if not self.enabled:
            return None
        
        if not domain:
            return None
        
        domain = domain.lower().rstrip('.')
        parts = domain.split('.')
        if len(parts) < 2:
            return None
        
        tld = parts[-1]
        country = CCTLD_TO_COUNTRY.get(tld)
        
        return country
    
    def get_cctlds_for_country(self, country_code: str) -> list:
        """Get all CCTLDs for a country code"""
        return COUNTRY_TO_CCTLD.get(country_code.upper(), [])

    def get_continent_from_country(self, country_code: str) -> Optional[str]:
        """Get continent code for a country code"""
        return get_country_continent(country_code)
    
    def get_regions_from_country(self, country_code: str) -> List[str]:
        """Get list of regions a country belongs to"""
        if not country_code: 
            return []
        return get_country_regions(country_code)


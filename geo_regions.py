#!/usr/bin/env python3
# filename: geo_regions.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.2 (Cleanup: Removed unused helper)
# -----------------------------------------------------------------------------
"""
Unified geographic region definitions.
Single source of truth for continent, region, and country mappings.
"""

from typing import Optional, List

# Continent definitions
CONTINENTS = {
    'AF': {'name': 'AFRICA', 'code': 'AF'},
    'AN': {'name': 'ANTARCTICA', 'code': 'AN'},
    'AS': {'name': 'ASIA', 'code': 'AS'},
    'EU': {'name': 'EUROPE', 'code': 'EU'},
    'NA': {'name': 'NORTH_AMERICA', 'code': 'NA'},
    'OC': {'name': 'OCEANIA', 'code': 'OC'},
    'SA': {'name': 'SOUTH_AMERICA', 'code': 'SA'}
}

# Country -> Continent mapping
COUNTRY_TO_CONTINENT = {
    'AD': 'EU', 'AL': 'EU', 'AT': 'EU', 'AX': 'EU', 'BA': 'EU', 'BE': 'EU', 'BG': 'EU', 'BY': 'EU',
    'CH': 'EU', 'CY': 'EU', 'CZ': 'EU', 'DE': 'EU', 'DK': 'EU', 'EE': 'EU', 'ES': 'EU', 'FI': 'EU',
    'FO': 'EU', 'FR': 'EU', 'GB': 'EU', 'GG': 'EU', 'GI': 'EU', 'GR': 'EU', 'HR': 'EU', 'HU': 'EU',
    'IE': 'EU', 'IM': 'EU', 'IS': 'EU', 'IT': 'EU', 'JE': 'EU', 'LI': 'EU', 'LT': 'EU', 'LU': 'EU',
    'LV': 'EU', 'MC': 'EU', 'MD': 'EU', 'ME': 'EU', 'MK': 'EU', 'MT': 'EU', 'NL': 'EU', 'NO': 'EU',
    'PL': 'EU', 'PT': 'EU', 'RO': 'EU', 'RS': 'EU', 'RU': 'EU', 'SE': 'EU', 'SI': 'EU', 'SK': 'EU',
    'SM': 'EU', 'TR': 'AS', 'UA': 'EU', 'VA': 'EU', 'XK': 'EU',
    'AE': 'AS', 'AF': 'AS', 'AM': 'AS', 'AZ': 'AS', 'BD': 'AS', 'BH': 'AS', 'BN': 'AS', 'BT': 'AS',
    'CN': 'AS', 'GE': 'AS', 'HK': 'AS', 'ID': 'AS', 'IL': 'AS', 'IN': 'AS', 'IQ': 'AS', 'IR': 'AS',
    'JO': 'AS', 'JP': 'AS', 'KG': 'AS', 'KH': 'AS', 'KP': 'AS', 'KR': 'AS', 'KW': 'AS', 'KZ': 'AS',
    'LA': 'AS', 'LB': 'AS', 'LK': 'AS', 'MM': 'AS', 'MN': 'AS', 'MO': 'AS', 'MV': 'AS', 'MY': 'AS',
    'NP': 'AS', 'OM': 'AS', 'PH': 'AS', 'PK': 'AS', 'PS': 'AS', 'QA': 'AS', 'SA': 'AS', 'SG': 'AS',
    'SY': 'AS', 'TH': 'AS', 'TJ': 'AS', 'TL': 'AS', 'TM': 'AS', 'TW': 'AS', 'UZ': 'AS', 'VN': 'AS',
    'YE': 'AS',
    'AO': 'AF', 'BF': 'AF', 'BI': 'AF', 'BJ': 'AF', 'BW': 'AF', 'CD': 'AF', 'CF': 'AF', 'CG': 'AF',
    'CI': 'AF', 'CM': 'AF', 'CV': 'AF', 'DJ': 'AF', 'DZ': 'AF', 'EG': 'AF', 'EH': 'AF', 'ER': 'AF',
    'ET': 'AF', 'GA': 'AF', 'GH': 'AF', 'GM': 'AF', 'GN': 'AF', 'GQ': 'AF', 'GW': 'AF', 'KE': 'AF',
    'KM': 'AF', 'LR': 'AF', 'LS': 'AF', 'LY': 'AF', 'MA': 'AF', 'MG': 'AF', 'ML': 'AF', 'MR': 'AF',
    'MU': 'AF', 'MW': 'AF', 'MZ': 'AF', 'NA': 'AF', 'NE': 'AF', 'NG': 'AF', 'RE': 'AF', 'RW': 'AF',
    'SC': 'AF', 'SD': 'AF', 'SH': 'AF', 'SL': 'AF', 'SN': 'AF', 'SO': 'AF', 'SS': 'AF', 'ST': 'AF',
    'SZ': 'AF', 'TD': 'AF', 'TG': 'AF', 'TN': 'AF', 'TZ': 'AF', 'UG': 'AF', 'YT': 'AF', 'ZA': 'AF',
    'ZM': 'AF', 'ZW': 'AF',
    'AG': 'NA', 'AI': 'NA', 'AW': 'NA', 'BB': 'NA', 'BL': 'NA', 'BM': 'NA', 'BQ': 'NA', 'BS': 'NA',
    'BZ': 'NA', 'CA': 'NA', 'CR': 'NA', 'CU': 'NA', 'CW': 'NA', 'DM': 'NA', 'DO': 'NA', 'GD': 'NA',
    'GL': 'NA', 'GP': 'NA', 'GT': 'NA', 'HN': 'NA', 'HT': 'NA', 'JM': 'NA', 'KN': 'NA', 'KY': 'NA',
    'LC': 'NA', 'MF': 'NA', 'MQ': 'NA', 'MS': 'NA', 'MX': 'NA', 'NI': 'NA', 'PA': 'NA', 'PM': 'NA',
    'PR': 'NA', 'SV': 'NA', 'SX': 'NA', 'TC': 'NA', 'TT': 'NA', 'US': 'NA', 'VC': 'NA', 'VG': 'NA',
    'VI': 'NA',
    'AR': 'SA', 'BO': 'SA', 'BR': 'SA', 'CL': 'SA', 'CO': 'SA', 'EC': 'SA', 'FK': 'SA', 'GF': 'SA',
    'GY': 'SA', 'PE': 'SA', 'PY': 'SA', 'SR': 'SA', 'UY': 'SA', 'VE': 'SA',
    'AS': 'OC', 'AU': 'OC', 'CK': 'OC', 'FJ': 'OC', 'FM': 'OC', 'GU': 'OC', 'KI': 'OC', 'MH': 'OC',
    'MP': 'OC', 'NC': 'OC', 'NF': 'OC', 'NR': 'OC', 'NU': 'OC', 'NZ': 'OC', 'PF': 'OC', 'PG': 'OC',
    'PN': 'OC', 'PW': 'OC', 'SB': 'OC', 'TK': 'OC', 'TO': 'OC', 'TV': 'OC', 'UM': 'OC', 'VU': 'OC',
    'WF': 'OC', 'WS': 'OC',
    'AQ': 'AN', 'BV': 'AN', 'GS': 'AN', 'HM': 'AN', 'TF': 'AN'
}

# Regional definitions
REGION_DEFINITIONS = {
    'AFRICA': {
        'countries': ['AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'DZ', 'EG', 
                     'EH', 'ER', 'ET', 'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'KE', 'KM', 'LR', 'LS', 'LY', 
                     'MA', 'MG', 'ML', 'MR', 'MU', 'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SD', 
                     'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 'SZ', 'TD', 'TG', 'TN', 'TZ', 'UG', 'YT', 'ZA', 
                     'ZM', 'ZW']
    },
    'AL_MAGHRIB': {
        'countries': ['DZ', 'LY', 'MA', 'MR', 'TN', 'EH']
    },
    'AMERICA': {
        'countries': ['BM', 'CA', 'GL', 'PM', 'US', 'BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'AI', 'AG', 
                     'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 
                     'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI', 'AR', 'BO', 
                     'BR', 'CL', 'CO', 'EC', 'FK', 'GF', 'GY', 'PY', 'PE', 'SR', 'UY', 'VE']
    },
    'ARAB_GULF_COUNTRIES': {
        'countries': ['BH', 'KW', 'OM', 'QA', 'SA', 'AE']
    },
    'ARABIA': {
        'countries': ['SA', 'YE', 'OM', 'AE', 'QA', 'BH', 'KW', 'IQ', 'JO']
    },
    'ARCTIC': {
        'countries': ['CA', 'DK', 'FI', 'IS', 'NO', 'RU', 'SE', 'US']
    },
    'ASIA': {
        'countries': ['AE', 'AF', 'AM', 'AZ', 'BD', 'BH', 'BN', 'BT', 'CN', 'CY', 'GE', 'HK', 'ID', 'IL', 
                     'IN', 'IQ', 'IR', 'JO', 'JP', 'KG', 'KH', 'KP', 'KR', 'KW', 'KZ', 'LA', 'LB', 'LK', 
                     'MM', 'MN', 'MO', 'MV', 'MY', 'NP', 'OM', 'PH', 'PK', 'PS', 'QA', 'SA', 'SG', 'SY', 
                     'TH', 'TJ', 'TL', 'TM', 'TR', 'TW', 'UZ', 'VN', 'YE']
    },
    'ASEAN': {
        'countries': ['BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN']
    },
    'AUSTRALASIA': {
        'countries': ['AU', 'NZ']
    },
    'AUSTRALIA_AND_NEW_ZEALAND': {
        'countries': ['AU', 'NZ']
    },
    'BALKANS': {
        'countries': ['AL', 'BA', 'BG', 'HR', 'GR', 'ME', 'MK', 'RO', 'RS', 'SI', 'TR', 'XK']
    },
    'BALTIC_REGION': {
        'countries': ['EE', 'LV', 'LT', 'FI', 'SE', 'DK', 'DE', 'PL', 'RU']
    },
    'BALTIC_STATES': {
        'countries': ['EE', 'LV', 'LT']
    },
    'BENELUX': {
        'countries': ['BE', 'LU', 'NL']
    },
    'BRICS': {
        'countries': ['BR', 'RU', 'IN', 'CN', 'ZA', 'EG', 'ET', 'IR', 'AE']
    },
    'CARIBBEAN': {
        'countries': ['AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 
                     'HT', 'JM', 'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI']
    },
    'CAUCASUS_REGION': {
        'countries': ['AM', 'AZ', 'GE', 'RU']
    },
    'CENTRAL_AFRICA': {
        'countries': ['AO', 'CM', 'CF', 'TD', 'CG', 'CD', 'GQ', 'GA', 'ST']
    },
    'CENTRAL_AMERICA': {
        'countries': ['BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA']
    },
    'CENTRAL_ASIA': {
        'countries': ['KZ', 'KG', 'TJ', 'TM', 'UZ']
    },
    'CENTRAL_EUROPE': {
        'countries': ['AT', 'CZ', 'DE', 'HU', 'LI', 'PL', 'SK', 'SI', 'CH']
    },
    'CHINA': {
        'countries': ['CN', 'HK', 'MO','TW']
    },
    'DENAKIL': {
        'countries': ['ER', 'ET', 'DJ']
    },
    'EASTERN_AFRICA': {
        'countries': ['BI', 'KM', 'DJ', 'ER', 'ET', 'KE', 'MG', 'MW', 'MU', 'YT', 'MZ', 'RE', 'RW', 'SC', 
                     'SO', 'SS', 'TZ', 'UG', 'ZM', 'ZW']
    },
    'EASTERN_ASIA': {
        'countries': ['CN', 'HK', 'MO', 'JP', 'KP', 'KR', 'MN', 'TW']
    },
    'EASTERN_EUROPE': {
        'countries': ['BY', 'BG', 'CZ', 'HU', 'MD', 'PL', 'RO', 'RU', 'SK', 'UA']
    },
    'EU_MEMBERS': {
        'countries': ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 
                     'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'],
        'description': 'European Union member states'
    },
    'EUROPEAN_UNION': {
        'countries': ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 
                     'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'],
        'description': 'European Union member states'
    },
    'EUROPE': {
        'countries': ['AD', 'AL', 'AT', 'AX', 'BA', 'BE', 'BG', 'BY', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 
                     'FI', 'FO', 'FR', 'GB', 'GG', 'GI', 'GR', 'HR', 'HU', 'IE', 'IM', 'IS', 'IT', 'JE', 
                     'LI', 'LT', 'LU', 'LV', 'MC', 'MD', 'ME', 'MK', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 
                     'RS', 'RU', 'SE', 'SI', 'SJ', 'SK', 'SM', 'UA', 'VA']
    },
    'EEA': {
        'countries': ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 
                     'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'IS', 
                     'LI', 'NO']
    },
    'FIVE_EYES': {
        'countries': ['AU', 'CA', 'NZ', 'GB', 'US']
    },
    'G5_SAHEL': {
        'countries': ['BF', 'TD', 'ML', 'MR', 'NE']
    },
    'G7': {
        'countries': ['CA', 'FR', 'DE', 'IT', 'JP', 'GB', 'US']
    },
    'GCC': {
        'countries': ['BH', 'KW', 'OM', 'QA', 'SA', 'AE']
    },
    'HORN_OF_AFRICA': {
        'countries': ['DJ', 'ER', 'ET', 'SO']
    },
    'INDOCHINA': {
        'countries': ['KH', 'LA', 'VN', 'MM', 'TH', 'MY']
    },
    'LATIN_AMERICA': {
        'countries': ['AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'FK', 'GF', 'GY', 'PY', 'PE', 'SR', 'UY', 'VE', 
                     'BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'MX', 'DO', 'HT', 'CU']
    },
    'LEVANT': {
        'countries': ['CY', 'IL', 'JO', 'LB', 'PS', 'SY']
    },
    'MELANESIA': {
        'countries': ['FJ', 'NC', 'PG', 'SB', 'VU']
    },
    'MICRONESIA': {
        'countries': ['FM', 'GU', 'KI', 'MH', 'NR', 'MP', 'PW']
    },
    'MIDDLE_AMERICA': {
        'countries': ['BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 
                     'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'MQ', 'MS', 'MX', 'PR', 'BL', 
                     'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI']
    },
    'MIDDLE_EAST': {
        'countries': ['BH', 'CY', 'EG', 'IR', 'IQ', 'IL', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 
                     'TR', 'AE', 'YE']
    },
    'MOSQUITIA': {
        'countries': ['HN', 'NI']
    },
    'NATO': {
        'countries': ['AL', 'BE', 'BG', 'CA', 'HR', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 
                     'IT', 'LV', 'LT', 'LU', 'ME', 'NL', 'MK', 'NO', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 
                     'SE', 'TR', 'GB', 'US']
    },
    'NORDIC': {
        'countries': ['DK', 'FI', 'IS', 'NO', 'SE', 'FO', 'AX', 'GL', 'SJ']
    },
    'NORTHEAST_AFRICA': {
        'countries': ['EG', 'SD', 'SS']
    },
    'NORTHERN_AFRICA': {
        'countries': ['DZ', 'EG', 'LY', 'MA', 'SD', 'TN', 'EH']
    },
    'NORTHERN_AMERICA': {
        'countries': ['BM', 'CA', 'GL', 'PM', 'US']
    },
    'NORTHERN_EUROPE': {
        'countries': ['AX', 'DK', 'EE', 'FO', 'FI', 'GG', 'IS', 'IE', 'IM', 'JE', 'LV', 'LT', 'NO', 'SJ', 
                     'SE', 'GB']
    },
    'OFAC': {
        'countries': ['BA', 'BI', 'BY', 'CD', 'CF', 'CG', 'CI', 'CN', 'CU', 'CY', 'ER', 'ET', 'HK', 'HT', 
                     'IQ', 'IR', 'IT', 'KP', 'LB', 'LK', 'LR', 'LY', 'MK', 'MM', 'NI', 'RO', 'RU', 'SD', 
                     'SO', 'SS', 'SY', 'UA', 'VE', 'VN', 'XK', 'YE', 'ZW']
    },
    'POLYNESIA': {
        'countries': ['AS', 'CK', 'NU', 'PF', 'PN', 'TO', 'TV', 'WF', 'WS']
    },
    'RUSSIA': {
        'countries': ['AM', 'AZ', 'BY', 'EE', 'GE', 'KZ', 'KG', 'LV', 'LT', 'MD', 'RU', 'SU', 'TJ', 'TM', 'UA', 'UZ']
    },
    'SAHEL': {
        'countries': ['BF', 'TD', 'GM', 'ML', 'MR', 'NE', 'NG', 'SN', 'SD']
    },
    'SCANDINAVIA': {
        'countries': ['DK', 'NO', 'SE']
    },
    'SCHENGEN': {
        'countries': ['AT', 'BE', 'BG', 'HR', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IT', 
                     'LV', 'LI', 'LT', 'LU', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'CH']
    },
    'SOUTH_EASTERN_ASIA': {
        'countries': ['BN', 'KH', 'ID', 'LA', 'MY', 'MM', 'PH', 'SG', 'TH', 'TL', 'VN']
    },
    'SOUTHERN_AFRICA': {
        'countries': ['BW', 'SZ', 'LS', 'NA', 'ZA']
    },
    'SOUTHERN_ASIA': {
        'countries': ['AF', 'BD', 'BT', 'IN', 'IR', 'MV', 'NP', 'PK', 'LK']
    },
    'SOUTHERN_EUROPE': {
        'countries': ['AL', 'AD', 'BA', 'HR', 'GI', 'GR', 'VA', 'IT', 'MT', 'ME', 'MK', 'PT', 'SM', 'RS', 
                     'SI', 'ES']
    },
    'SUB_SAHARAN_AFRICA': {
        'countries': ['AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'ER', 'ET', 
                     'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'KE', 'KM', 'LR', 'LS', 'MG', 'ML', 'MR', 'MU', 
                     'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 
                     'SZ', 'TD', 'TG', 'TZ', 'UG', 'YT', 'ZA', 'ZM', 'ZW']
    },
    'WESTERN_AFRICA': {
        'countries': ['BJ', 'BF', 'CV', 'CI', 'GM', 'GH', 'GN', 'GW', 'LR', 'ML', 'MR', 'NE', 'NG', 'SH', 
                     'SN', 'SL', 'TG']
    },
    'WESTERN_ASIA': {
        'countries': ['AM', 'AZ', 'BH', 'CY', 'GE', 'IQ', 'IL', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 
                     'SY', 'TR', 'AE', 'YE']
    },
    'WESTERN_EUROPE': {
        'countries': ['AT', 'BE', 'FR', 'DE', 'LI', 'LU', 'MC', 'NL', 'CH']
    },
    'WEST_INDIES': {
        'countries': ['AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 
                     'HT', 'JM', 'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI']
    }
}

def get_continent_name(code: str) -> Optional[str]:
    """Get continent full name from 2-letter code"""
    return CONTINENTS.get(code.upper(), {}).get('name')

def get_country_continent(country_code: str) -> Optional[str]:
    """Get continent code for country"""
    return COUNTRY_TO_CONTINENT.get(country_code.upper())

def get_country_regions(country_code: str) -> List[str]:
    """Get all regions a country belongs to"""
    cc = country_code.upper()
    regions = []
    for region_name, region_data in REGION_DEFINITIONS.items():
        if cc in region_data.get('countries', []):
            regions.append(region_name)
    return regions

def get_region_countries(region_name: str) -> List[str]:
    """Get all countries in a region"""
    region_data = REGION_DEFINITIONS.get(region_name.upper())
    if region_data:
        return region_data.get('countries', [])
    return []


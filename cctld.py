#!/usr/bin/env python3
# filename: cctld.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.3.0 (Regions Support)
# -----------------------------------------------------------------------------
"""
CCTLD (Country Code Top-Level Domain) mapping for geographic hints.
Includes Continent and Region mapping for query-based blocking.
"""

from typing import Optional, List, Dict
from utils import get_logger

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

# Mapping for query-based blocking (Country -> Continent)
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

# Regional Definitions (Aligned with geoip_compiler.py)
REGION_DEFINITIONS = {
    'AFRICA': ['AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'DZ', 'EG', 'EH', 'ER', 'ET', 'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'KE', 'KM', 'LR', 'LS', 'LY', 'MA', 'MG', 'ML', 'MR', 'MU', 'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SD', 'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 'SZ', 'TD', 'TG', 'TN', 'TZ', 'UG', 'YT', 'ZA', 'ZM', 'ZW'],
    'AL_MAGHRIB': ['DZ', 'LY', 'MA', 'MR', 'TN', 'EH'],
    'AMERICA': ['BM', 'CA', 'GL', 'PM', 'US', 'BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI', 'AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'FK', 'GF', 'GY', 'PY', 'PE', 'SR', 'UY', 'VE'],
    'ARAB_GULF_COUNTRIES': ['BH', 'KW', 'OM', 'QA', 'SA', 'AE'],
    'ARABIA': ['SA', 'YE', 'OM', 'AE', 'QA', 'BH', 'KW', 'IQ', 'JO'],
    'ARCTIC': ['CA', 'DK', 'FI', 'IS', 'NO', 'RU', 'SE', 'US'],
    'ASIA': ['AE', 'AF', 'AM', 'AZ', 'BD', 'BH', 'BN', 'BT', 'CN', 'CY', 'GE', 'HK', 'ID', 'IL', 'IN', 'IQ', 'IR', 'JO', 'JP', 'KG', 'KH', 'KP', 'KR', 'KW', 'KZ', 'LA', 'LB', 'LK', 'MM', 'MN', 'MO', 'MV', 'MY', 'NP', 'OM', 'PH', 'PK', 'PS', 'QA', 'SA', 'SG', 'SY', 'TH', 'TJ', 'TL', 'TM', 'TR', 'TW', 'UZ', 'VN', 'YE'],
    'ASEAN': ['BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN'],
    'AUSTRALASIA': ['AU', 'NZ'],
    'AUSTRALIA_AND_NEW_ZEALAND': ['AU', 'NZ'],
    'BALKANS': ['AL', 'BA', 'BG', 'HR', 'GR', 'ME', 'MK', 'RO', 'RS', 'SI', 'TR', 'XK'],
    'BALTIC_REGION': ['EE', 'LV', 'LT', 'FI', 'SE', 'DK', 'DE', 'PL', 'RU'],
    'BALTIC_STATES': ['EE', 'LV', 'LT'],
    'BENELUX': ['BE', 'LU', 'NL'],
    'BRICS': ['BR', 'RU', 'IN', 'CN', 'ZA', 'EG', 'ET', 'IR', 'AE'],
    'CARIBBEAN': ['AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI'],
    'CAUCASUS_REGION': ['AM', 'AZ', 'GE', 'RU'],
    'CENTRAL_AFRICA': ['AO', 'CM', 'CF', 'TD', 'CG', 'CD', 'GQ', 'GA', 'ST'],
    'CENTRAL_AMERICA': ['BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA'],
    'CENTRAL_ASIA': ['KZ', 'KG', 'TJ', 'TM', 'UZ'],
    'CENTRAL_EUROPE': ['AT', 'CZ', 'DE', 'HU', 'LI', 'PL', 'SK', 'SI', 'CH'],
    'DENAKIL': ['ER', 'ET', 'DJ'],
    'EASTERN_AFRICA': ['BI', 'KM', 'DJ', 'ER', 'ET', 'KE', 'MG', 'MW', 'MU', 'YT', 'MZ', 'RE', 'RW', 'SC', 'SO', 'SS', 'TZ', 'UG', 'ZM', 'ZW'],
    'EASTERN_ASIA': ['CN', 'HK', 'MO', 'JP', 'KP', 'KR', 'MN', 'TW'],
    'EASTERN_EUROPE': ['BY', 'BG', 'CZ', 'HU', 'MD', 'PL', 'RO', 'RU', 'SK', 'UA'],
    'EU_MEMBERS': ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'],
    'EUROPE': ['AD', 'AL', 'AT', 'AX', 'BA', 'BE', 'BG', 'BY', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FO', 'FR', 'GB', 'GG', 'GI', 'GR', 'HR', 'HU', 'IE', 'IM', 'IS', 'IT', 'JE', 'LI', 'LT', 'LU', 'LV', 'MC', 'MD', 'ME', 'MK', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'RS', 'RU', 'SE', 'SI', 'SJ', 'SK', 'SM', 'UA', 'VA'],
    'EEA': ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'IS', 'LI', 'NO'],
    'FIVE_EYES': ['AU', 'CA', 'NZ', 'GB', 'US'],
    'G5_SAHEL': ['BF', 'TD', 'ML', 'MR', 'NE'],
    'G7': ['CA', 'FR', 'DE', 'IT', 'JP', 'GB', 'US'],
    'GCC': ['BH', 'KW', 'OM', 'QA', 'SA', 'AE'],
    'HORN_OF_AFRICA': ['DJ', 'ER', 'ET', 'SO'],
    'INDOCHINA': ['KH', 'LA', 'VN', 'MM', 'TH', 'MY'],
    'LATIN_AMERICA': ['AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'FK', 'GF', 'GY', 'PY', 'PE', 'SR', 'UY', 'VE', 'BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'MX', 'DO', 'HT', 'CU'],
    'LEVANT': ['CY', 'IL', 'JO', 'LB', 'PS', 'SY'],
    'MELANESIA': ['FJ', 'NC', 'PG', 'SB', 'VU'],
    'MICRONESIA': ['FM', 'GU', 'KI', 'MH', 'NR', 'MP', 'PW'],
    'MIDDLE_AMERICA': ['BZ', 'CR', 'SV', 'GT', 'HN', 'NI', 'PA', 'AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'MQ', 'MS', 'MX', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI'],
    'MIDDLE_EAST': ['BH', 'CY', 'EG', 'IR', 'IQ', 'IL', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'AE', 'YE'],
    'MOSQUITIA': ['HN', 'NI'],
    'NATO': ['AL', 'BE', 'BG', 'CA', 'HR', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IT', 'LV', 'LT', 'LU', 'ME', 'NL', 'MK', 'NO', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'TR', 'GB', 'US'],
    'NORDIC': ['DK', 'FI', 'IS', 'NO', 'SE', 'FO', 'AX', 'GL', 'SJ'],
    'NORTHEAST_AFRICA': ['EG', 'SD', 'SS'],
    'NORTHERN_AFRICA': ['DZ', 'EG', 'LY', 'MA', 'SD', 'TN', 'EH'],
    'NORTHERN_AMERICA': ['BM', 'CA', 'GL', 'PM', 'US'],
    'NORTHERN_EUROPE': ['AX', 'DK', 'EE', 'FO', 'FI', 'GG', 'IS', 'IE', 'IM', 'JE', 'LV', 'LT', 'NO', 'SJ', 'SE', 'GB'],
    'OFAC': ['BA', 'BI', 'BY', 'CD', 'CF', 'CG', 'CI', 'CN', 'CU', 'CY', 'ER', 'ET', 'HK', 'HT', 'IQ', 'IR', 'IT', 'KP', 'LB', 'LK', 'LR', 'LY', 'MK', 'MM', 'NI', 'RO', 'RU', 'SD', 'SO', 'SS', 'SY', 'UA', 'VE', 'VN', 'XK', 'YE', 'ZW'],
    'POLYNESIA': ['AS', 'CK', 'NU', 'PF', 'PN', 'TO', 'TV', 'WF', 'WS'],
    'SAHEL': ['BF', 'TD', 'GM', 'ML', 'MR', 'NE', 'NG', 'SN', 'SD'],
    'SCANDINAVIA': ['DK', 'NO', 'SE'],
    'SCHENGEN': ['AT', 'BE', 'BG', 'HR', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IT', 'LV', 'LI', 'LT', 'LU', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'CH'],
    'SOUTH_EASTERN_ASIA': ['BN', 'KH', 'ID', 'LA', 'MY', 'MM', 'PH', 'SG', 'TH', 'TL', 'VN'],
    'SOUTHERN_AFRICA': ['BW', 'SZ', 'LS', 'NA', 'ZA'],
    'SOUTHERN_ASIA': ['AF', 'BD', 'BT', 'IN', 'IR', 'MV', 'NP', 'PK', 'LK'],
    'SOUTHERN_EUROPE': ['AL', 'AD', 'BA', 'HR', 'GI', 'GR', 'VA', 'IT', 'MT', 'ME', 'MK', 'PT', 'SM', 'RS', 'SI', 'ES'],
    'SUB_SAHARAN_AFRICA': ['AO', 'BF', 'BI', 'BJ', 'BW', 'CD', 'CF', 'CG', 'CI', 'CM', 'CV', 'DJ', 'ER', 'ET', 'GA', 'GH', 'GM', 'GN', 'GQ', 'GW', 'KE', 'KM', 'LR', 'LS', 'MG', 'ML', 'MR', 'MU', 'MW', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'SC', 'SH', 'SL', 'SN', 'SO', 'SS', 'ST', 'SZ', 'TD', 'TG', 'TZ', 'UG', 'YT', 'ZA', 'ZM', 'ZW'],
    'WESTERN_AFRICA': ['BJ', 'BF', 'CV', 'CI', 'GM', 'GH', 'GN', 'GW', 'LR', 'ML', 'MR', 'NE', 'NG', 'SH', 'SN', 'SL', 'TG'],
    'WESTERN_ASIA': ['AM', 'AZ', 'BH', 'CY', 'GE', 'IQ', 'IL', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'AE', 'YE'],
    'WESTERN_EUROPE': ['AT', 'BE', 'FR', 'DE', 'LI', 'LU', 'MC', 'NL', 'CH'],
    'WEST_INDIES': ['AI', 'AG', 'AW', 'BS', 'BB', 'BQ', 'VG', 'KY', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'MQ', 'MS', 'PR', 'BL', 'KN', 'LC', 'MF', 'VC', 'SX', 'TT', 'TC', 'VI']
}

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
        for region, countries in REGION_DEFINITIONS.items():
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
        return COUNTRY_TO_CONTINENT.get(country_code.upper())
    
    def get_regions_from_country(self, country_code: str) -> List[str]:
        """Get list of regions a country belongs to"""
        if not country_code: return []
        return self.country_to_regions.get(country_code.upper(), [])


#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 9.5.0 (Fix cctld_mode logic)
# -----------------------------------------------------------------------------
"""
Filtering Engine with strict rule ordering and action prioritization.
Includes extended debug logging for deep inspection of filtering logic.
Flows:
  Query:  Domains -> GeoIP/ccTLD -> Regex
  Answer: Domains -> ASN -> GeoIP -> IPs/CIDRs -> Regex
Priority:
  ALLOW > BLOCK > DROP
"""

import sys
import regex
import ipaddress
import orjson as json
import dns.rdatatype
import logging
from collections import defaultdict
from utils import get_logger
from validation import is_valid_domain

try:
    from intervaltree import IntervalTree
except ImportError:
    print("FATAL: 'intervaltree' required. Install: pip install intervaltree")
    sys.exit(1)

logger = get_logger("Filtering")

class DomainTrie:
    __slots__ = ('root',)
    
    def __init__(self): 
        self.root = {} 

    def insert(self, domain_rule, action='BLOCK', rule_data=None, list_name="Unknown"):
        is_inclusive = domain_rule.startswith('.')
        is_exclusive = domain_rule.startswith('*.')
        
        clean_domain = domain_rule.lstrip('.*')
        
        if not is_valid_domain(clean_domain, allow_underscores=False):
            logger.warning(f"Invalid domain format, skipping: {domain_rule}")
            return
        
        parts = clean_domain.split('.')[::-1]
        
        node = self.root
        for part in parts:
            if part not in node: 
                node[part] = {}
            node = node[part]
        
        original_rule = rule_data if rule_data else domain_rule
        data = {'action': action, 'rule': original_rule, 'list': list_name}
        
        if is_exclusive: 
            node['_wild'] = data 
        elif is_inclusive:
            node['_end'] = data 
            node['_wild'] = data 
        else: 
            node['_end'] = data 

    def match(self, domain_norm: str):
        parts = domain_norm.split('.')[::-1]
        node = self.root
        
        for i, part in enumerate(parts):
            if part not in node: 
                if '_wild' in node: 
                    return node['_wild']
                return None
            node = node[part]
        
        if '_end' in node: 
            return node['_end']
        if '_wild' in node: 
            return node['_wild']
        return None


class DomainCategorizer:
    def __init__(self, categories_file='categories.json'):
        self.categories = {}
        self.regex_cache = {}
        
        try:
            logger.info(f"Loading categories from {categories_file}...")
            with open(categories_file, 'rb') as f:
                self.categories = json.loads(f.read())
            
            logger.info(f"Found {len(self.categories)} categories")
            
            for category, data in self.categories.items():
                if 'regex' in data and data['regex']:
                    self.regex_cache[category] = []
                    for pattern in data['regex']:
                        clean_pattern = pattern.strip('/')
                        try:
                            compiled = regex.compile(clean_pattern, regex.IGNORECASE)
                            self.regex_cache[category].append(compiled)
                        except Exception as e:
                            logger.warning(f"Category '{category}': Failed to compile regex '{pattern}': {e}")
                            
        except FileNotFoundError:
            logger.warning(f"Categories file not found: {categories_file}")
        except Exception as e:
            logger.error(f"Error loading categories: {e}")

    def classify(self, domain_norm: str) -> dict:
        results = {}
        parts = domain_norm.split('.')
        tld = parts[-1] if parts else ""
    
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Categorizing domain: {domain_norm}")

        for category, data in self.categories.items():
            score = 0
            
            if 'tlds' in data and tld in data['tlds']:
                score = max(score, 90)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"  - Category '{category}': TLD match ({tld}) -> 90%")
            
            if category in self.regex_cache:
                for pattern in self.regex_cache[category]:
                    if pattern.search(domain_norm):
                        score = max(score, 100)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"  - Category '{category}': Regex match -> 100%")
                        break
        
            if 'keywords' in data:
                for kw in data['keywords']:
                    if kw in parts:
                        score = max(score, 95)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"  - Category '{category}': Keyword part match ({kw}) -> 95%")
                        break
                    elif kw in domain_norm:
                        score = max(score, 80)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"  - Category '{category}': Keyword string match ({kw}) -> 80%")
        
            if score > 0:
                results[category] = score
    
        return results


def _make_action_dict():
    # Helper to create prioritized lists
    return {'ALLOW': [], 'BLOCK': [], 'DROP': []}

def _make_answer_action_dict():
    return {'ALLOW': [], 'BLOCK': [], 'DROP': []}

class RuleEngine:
    def __init__(self):
        self.query_rules = {
            'domain': DomainTrie(),
            # Regex separated by action for strict priority checking
            'regex': {'ALLOW': [], 'BLOCK': [], 'DROP': []},
            'geoip': defaultdict(_make_action_dict)
        }
        
        self.answer_rules = {
            'domain': DomainTrie(),
            'regex': {'ALLOW': [], 'BLOCK': [], 'DROP': []},
            'ip': IntervalTree(),
            'geoip': defaultdict(_make_action_dict),
            'asn': defaultdict(_make_action_dict)
        }
        
        self.allowed_types = set()
        self.blocked_types = set()
        self.dropped_types = set()
        self.categorizer = None 
        self.category_rules = {}
        
        self._regex_cache = {}

    def set_type_filters(self, allowed: list[str], blocked: list[str], dropped: list[str] = None):
        if allowed:
            for t in allowed:
                try: self.allowed_types.add(dns.rdatatype.from_text(t.upper()))
                except: pass
        if blocked:
            for t in blocked:
                try: self.blocked_types.add(dns.rdatatype.from_text(t.upper()))
                except: pass
        if dropped:
            for t in dropped:
                try: self.dropped_types.add(dns.rdatatype.from_text(t.upper()))
                except: pass

    def set_category_rules(self, rules_config):
        self.category_rules = rules_config or {}

    def check_type(self, qtype: int):
        qtype_name = dns.rdatatype.to_text(qtype)
        if self.allowed_types:
            if qtype not in self.allowed_types: 
                return "BLOCK", f"Type {qtype_name} NOT in allowed list", "PolicyTypeFilter"
        if self.dropped_types and qtype in self.dropped_types:
            return "DROP", f"Type {qtype_name} IS in dropped list", "PolicyTypeFilter"
        if self.blocked_types and qtype in self.blocked_types:
            return "BLOCK", f"Type {qtype_name} IS in blocked list", "PolicyTypeFilter"
        return "PASS", None, None

    def add_rule(self, rule_text, action='BLOCK', list_name="Unknown"):
        """
        Add rule with specified action.
        Supports ALLOW, BLOCK, DROP across all rule types.
        """
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        if action not in ['ALLOW', 'BLOCK', 'DROP']:
            logger.warning(f"Invalid action '{action}', defaulting to BLOCK")
            action = 'BLOCK'
        
        is_answer_only = rule_text.startswith('@') and not rule_text.startswith('@@')
        clean_rule_text = rule_text[1:] if (is_answer_only or rule_text.startswith('@@')) else rule_text
        
        # --- IP/CIDR (IntervalTree) ---
        if is_answer_only or not rule_text.startswith('@'):
            try:
                net = ipaddress.ip_network(clean_rule_text, strict=False)
                start_int = int(net.network_address)
                end_int = int(net.broadcast_address) + 1  
                
                data = {'action': action, 'rule': rule_text, 'list': list_name}
                self.answer_rules['ip'].addi(start_int, end_int, data)
                
                return "cidr" if '/' in clean_rule_text else "ip"
            except ValueError: 
                pass 
        
        # --- GeoIP/ASN Rules ---
        if rule_text.startswith('@@'):
            # GeoIP Query + Answer
            location_spec = rule_text[2:].upper()
            data = (rule_text, list_name)
            
            self.query_rules['geoip'][location_spec][action].append(data)
            self.answer_rules['geoip'][location_spec][action].append(data)
            logger.debug(f"Added GEO-IP (Query+Answer) rule: {rule_text} -> {action}")
            return "geoip"
        
        elif rule_text.startswith('@AS'):
            # ASN Answer
            asn_spec = rule_text[1:].upper()
            if not asn_spec.startswith('AS'):
                asn_spec = 'AS' + asn_spec
            
            data = (rule_text, list_name)
            self.answer_rules['asn'][asn_spec][action].append(data)
            logger.debug(f"Added ASN rule: {rule_text} -> {action}")
            return "asn"
        
        elif rule_text.startswith('@'):
            # GeoIP Query Only
            location_spec = rule_text[1:].upper()
            data = (rule_text, list_name)
            
            self.query_rules['geoip'][location_spec][action].append(data)
            logger.debug(f"Added GEO-IP (Query Only) rule: {rule_text} -> {action}")
            return "geoip"
        
        # --- Regex Rules ---
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            pattern_str = clean_rule_text[1:-1]
            if pattern_str not in self._regex_cache:
                try:
                    self._regex_cache[pattern_str] = regex.compile(pattern_str, regex.IGNORECASE)
                except Exception as e:
                    logger.warning(f"Invalid regex: {rule_text} - {e}")
                    return "ignored"
            
            pattern = self._regex_cache[pattern_str]
            data = (pattern, rule_text, list_name)
            
            target = self.answer_rules if is_answer_only else self.query_rules
            # Store in prioritized buckets
            target['regex'][action].append(data)
            logger.debug(f"Added Regex rule: {rule_text} -> {action}")
            return "regex"

        # --- Domain Rules (Trie) ---
        from domain_utils import normalize_domain
        clean_normalized = normalize_domain(clean_rule_text)
        
        if clean_rule_text.startswith('.'):
            clean_normalized = '.' + clean_normalized
        elif clean_rule_text.startswith('*.'):
            clean_normalized = '*.' + clean_normalized
        
        target = self.answer_rules if is_answer_only else self.query_rules
        target['domain'].insert(clean_normalized, action=action, rule_data=rule_text, list_name=list_name)
        # logger.debug(f"Added Domain rule: {clean_normalized} -> {action}")
        return "domain"

    def is_blocked(self, qname_norm: str, geoip_lookup=None):
        """
        Check Query Rules.
        Order: Domains -> GeoIP/ccTLD -> Regex
        Priority: ALLOW > BLOCK > DROP (Implicit in ordering/checks)
        """
        
        # 1. Domains (Trie)
        # Note: ListManager compiles policies by adding ALLOW rules LAST, 
        # so the Trie inherently respects ALLOW > BLOCK > DROP override logic.
        match = self.query_rules['domain'].match(qname_norm)
        if match:
            logger.debug(f"Query Domain Match: {qname_norm} -> {match['action']} (Rule: {match['rule']})")
            return match['action'], match['rule'], match['list']

        # 2. GeoIP/ccTLD
        if geoip_lookup and geoip_lookup.cctld_mapper and geoip_lookup.cctld_mapper.enabled:
            # Respect configuration: Only check ccTLD if mode is explicitly 'cctld_first'.
            # 'geoip_only' = Ignore TLDs (Answer only).
            # 'cctld_geoip' = Hint only (Answer only).
            
            cctld_mode = getattr(geoip_lookup, 'cctld_mode', 'geoip_only')
            
            if cctld_mode == 'cctld_first':
                cctld_country = geoip_lookup.cctld_mapper.get_country_from_domain(qname_norm)
                
                if cctld_country:
                    locations = geoip_lookup.cctld_mapper.expand_locations(cctld_country)
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Query GeoIP Check: {qname_norm} -> {cctld_country} -> Locations: {locations}")
                    
                    # Priority: ALLOW > BLOCK > DROP
                    for action in ['ALLOW', 'BLOCK', 'DROP']:
                        for loc in locations:
                            if loc in self.query_rules['geoip']:
                                if self.query_rules['geoip'][loc][action]:
                                    rule, list_name = self.query_rules['geoip'][loc][action][0]
                                    logger.info(f"{'🔇' if action == 'DROP' else ('⛔' if action == 'BLOCK' else '✓')} GEO-IP {action} (Query ccTLD) | Domain: {qname_norm} | TLD: .{qname_norm.split('.')[-1]} | Country: {cctld_country} | Matched: {loc} | Rule: '{rule}' | List: '{list_name}'")
                                    return action, rule, list_name

        # 3. Regex
        # Priority: ALLOW > BLOCK > DROP
        for action in ['ALLOW', 'BLOCK', 'DROP']:
            for pattern, rule, list_name in self.query_rules['regex'][action]:
                if pattern.search(qname_norm):
                    logger.debug(f"Query Regex Match: {qname_norm} -> {action} (Rule: {rule})")
                    return action, rule, list_name

        return "PASS", None, None

    def check_answer(self, qname_norm=None, ip_str=None, geoip_lookup=None, domain_hint=None, check_query_rules=False):
        """
        Check Answer Rules.
        Order: Domains -> ASN -> GeoIP -> IPs/CIDRs -> Regex
        Priority: ALLOW > BLOCK > DROP
        """
        
        # 1. Domains (Trie) - Checked if domain hint provided (CNAME target, etc)
        if qname_norm:
            # Check explicit answer rules first
            match = self.answer_rules['domain'].match(qname_norm)
            
            # If enabled, check standard query rules (Blocklists) against the Answer domain (CNAME target)
            if not match and check_query_rules:
                match = self.query_rules['domain'].match(qname_norm)
            
            if match:
                logger.debug(f"Answer Domain Match: {qname_norm} -> {match['action']} (Rule: {match['rule']})")
                return match['action'], match['rule'], match['list']

        # 2. ASN
        if ip_str and geoip_lookup and geoip_lookup.enabled:
            asn_data = geoip_lookup.lookup_asn(ip_str)
            if asn_data and 'asn' in asn_data:
                asn = asn_data['asn'].upper()
                as_name = asn_data.get('as_name', 'Unknown')
                for action in ['ALLOW', 'BLOCK', 'DROP']:
                    if asn in self.answer_rules['asn']:
                        if self.answer_rules['asn'][asn][action]:
                            rule, list_name = self.answer_rules['asn'][asn][action][0]
                            logger.info(f"{'🔇' if action == 'DROP' else ('⛔' if action == 'BLOCK' else '✓')} ASN {action} | IP: {ip_str} | ASN: {asn} | Holder: {as_name} | Rule: '{rule}' | List: '{list_name}'")
                            return action, rule, list_name

        # 3. GeoIP
        if ip_str and geoip_lookup and geoip_lookup.enabled:
            # Use domain_hint to support 'cctld_geoip' mode (disambiguate IP location using TLD)
            geo_data, _ = geoip_lookup.lookup_with_domain_hint(ip_str, domain_hint)
            
            if geo_data:
                applicable_locations = set()
                if geo_data.get('country_code'): applicable_locations.add(geo_data['country_code'].upper())
                if geo_data.get('country_name'): applicable_locations.add(geo_data['country_name'].upper())
                if geo_data.get('continent_code'): applicable_locations.add(geo_data['continent_code'].upper())
                if geo_data.get('continent_name'): applicable_locations.add(geo_data['continent_name'].upper())
                for r in geo_data.get('regions', []): applicable_locations.add(r.upper())
                
                trigger_info = f"{geo_data.get('country_code', '??')} ({geo_data.get('country_name', 'Unknown')})"
                
                for action in ['ALLOW', 'BLOCK', 'DROP']:
                    for loc in applicable_locations:
                        if loc in self.answer_rules['geoip']:
                            if self.answer_rules['geoip'][loc][action]:
                                rule, list_name = self.answer_rules['geoip'][loc][action][0]
                                logger.info(f"{'🔇' if action == 'DROP' else ('⛔' if action == 'BLOCK' else '✓')} GEO-IP {action} (Answer IP) | Target: {ip_str} | Loc: {loc} | Rule: '{rule}' | Trigger: {trigger_info}")
                                return action, rule, list_name

        # 4. IPs/CIDRs (IntervalTree)
        if ip_str:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_int = int(ip_obj)
                
                # IntervalTree returns a set of all matching intervals
                matches = self.answer_rules['ip'][ip_int]
                if matches:
                    # Scan for highest priority action in all matches
                    found_actions = {iv.data['action']: iv.data for iv in matches}
                    
                    if 'ALLOW' in found_actions:
                        m = found_actions['ALLOW']
                        logger.debug(f"Answer IP Match: {ip_str} -> ALLOW (Rule: {m['rule']})")
                        return 'ALLOW', m['rule'], m['list']
                    if 'BLOCK' in found_actions:
                        m = found_actions['BLOCK']
                        logger.debug(f"Answer IP Match: {ip_str} -> BLOCK (Rule: {m['rule']})")
                        return 'BLOCK', m['rule'], m['list']
                    if 'DROP' in found_actions:
                        m = found_actions['DROP']
                        logger.debug(f"Answer IP Match: {ip_str} -> DROP (Rule: {m['rule']})")
                        return 'DROP', m['rule'], m['list']
            except ValueError: 
                pass 
        
        # 5. Regex
        if qname_norm:
            for action in ['ALLOW', 'BLOCK', 'DROP']:
                for pattern, rule, list_name in self.answer_rules['regex'][action]:
                    if pattern.search(qname_norm):
                        logger.debug(f"Answer Regex Match: {qname_norm} -> {action} (Rule: {rule})")
                        return action, rule, list_name
        
        return "PASS", None, None
    
    def has_answer_only_rules(self):
        return bool(
            any(any(l.values()) for l in self.answer_rules['geoip'].values()) or
            any(any(l.values()) for l in self.answer_rules['asn'].values()) or
            len(self.answer_rules['ip']) > 0 or
            self.answer_rules['domain'].root or
            any(len(l) > 0 for l in self.answer_rules['regex'].values())
        )

    def get_stats(self) -> dict:
        query_block_geo = sum(len(self.query_rules['geoip'][loc]['BLOCK']) for loc in self.query_rules['geoip'])
        query_drop_geo = sum(len(self.query_rules['geoip'][loc]['DROP']) for loc in self.query_rules['geoip'])
        answer_block_geo = sum(len(self.answer_rules['geoip'][loc]['BLOCK']) for loc in self.answer_rules['geoip'])
        answer_drop_geo = sum(len(self.answer_rules['geoip'][loc]['DROP']) for loc in self.answer_rules['geoip'])
        
        answer_block_asn = sum(len(self.answer_rules['asn'][asn]['BLOCK']) for asn in self.answer_rules['asn'])
        answer_drop_asn = sum(len(self.answer_rules['asn'][asn]['DROP']) for asn in self.answer_rules['asn'])
        
        return {
            'allow_domains': len(self.query_rules['domain'].root),
            'block_domains': len(self.query_rules['domain'].root),
            'drop_domains': len(self.query_rules['domain'].root),
            'query_block_geo': query_block_geo,
            'query_drop_geo': query_drop_geo,
            'answer_block_geo': answer_block_geo,
            'answer_drop_geo': answer_drop_geo,
            'answer_block_asn': answer_block_asn,
            'answer_drop_asn': answer_drop_asn,
            'answer_ips': len(self.answer_rules['ip']),
        }


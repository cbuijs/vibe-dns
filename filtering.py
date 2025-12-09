#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 7.0.0 (Consolidated Action Handling)
# -----------------------------------------------------------------------------
"""
Filtering Engine with consolidated action handling.
All actions (ALLOW/BLOCK/DROP) use unified data structures.
"""

import regex
import ipaddress
import orjson as json
import dns.rdatatype
from collections import defaultdict
from utils import get_logger
from validation import is_valid_domain

# Try importing IntervalTree, warn if missing
try:
    from intervaltree import IntervalTree
except ImportError:
    print("WARNING: 'intervaltree' module not found. Please install via 'pip install intervaltree'.")
    class IntervalTree:
        def __init__(self): self.tree = set()
        def __len__(self): return 0
        def overlaps(self, start, end): return False
        def add(self, start, end, data): pass
        def __getitem__(self, point): return set()

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
            with open(categories_file, 'rb') as f:
                self.categories = json.loads(f.read())
            
            for category, data in self.categories.items():
                if 'patterns' in data:
                    self.regex_cache[category] = [
                        regex.compile(pattern, regex.IGNORECASE)
                        for pattern in data['patterns']
                    ]
            
            logger.info(f"Loaded {len(self.categories)} categories from {categories_file}")
            logger.debug(f"Pre-compiled {sum(len(v) for v in self.regex_cache.values())} regex patterns")
        except FileNotFoundError:
            logger.warning(f"Categories file not found: {categories_file}")
        except Exception as e:
            logger.error(f"Error loading categories: {e}")

    def classify(self, domain_norm: str) -> dict:
        results = {}
        parts = domain_norm.split('.')
        tld = parts[-1] if parts else ""
        
        for category, data in self.categories.items():
            score = 0
            
            if 'tlds' in data and tld in data['tlds']: 
                score = max(score, 90)
            
            if category in self.regex_cache:
                for pattern in self.regex_cache[category]:
                    if pattern.search(domain_norm):
                        score = max(score, 100)
                        break
            
            if 'keywords' in data:
                for kw in data['keywords']:
                    if kw in parts:
                        score = max(score, 95)
                    elif kw in domain_norm:
                        score = max(score, 70)
            
            if score > 0: 
                results[category] = score
        
        return results

class RuleEngine:
    def __init__(self):
        # Consolidated structures
        self.query_rules = {
            'domain': DomainTrie(),
            'regex': [],  # [(pattern, action, rule, list), ...]
            'geoip': defaultdict(lambda: {'ALLOW': [], 'BLOCK': [], 'DROP': []})
        }
        
        self.answer_rules = {
            'domain': DomainTrie(),
            'regex': [],
            'ip': IntervalTree(),
            'geoip': defaultdict(lambda: {'BLOCK': [], 'DROP': []})
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
                try: 
                    self.allowed_types.add(dns.rdatatype.from_text(t.upper()))
                except Exception: 
                    logger.warning(f"Unknown QTYPE: {t}")
        if blocked:
            for t in blocked:
                try: 
                    self.blocked_types.add(dns.rdatatype.from_text(t.upper()))
                except Exception: 
                    logger.warning(f"Unknown QTYPE: {t}")
        if dropped:
            for t in dropped:
                try:
                    self.dropped_types.add(dns.rdatatype.from_text(t.upper()))
                except Exception:
                    logger.warning(f"Unknown QTYPE: {t}")

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
        
        Args:
            rule_text: Rule string (domain, IP, regex, geoip tag)
            action: 'ALLOW', 'BLOCK', or 'DROP'
            list_name: Source list name for logging
            
        Returns:
            Rule type: "domain", "regex", "ip", "cidr", "geoip", or "ignored"
        """
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        # Validate action
        if action not in ['ALLOW', 'BLOCK', 'DROP']:
            logger.warning(f"Invalid action '{action}', defaulting to BLOCK")
            action = 'BLOCK'
        
        # --- GeoIP Rules ---
        if rule_text.startswith('@@'):
            # BOTH query (ccTLD) AND answer (IP)
            location_spec = rule_text[2:].upper()
            data = (rule_text, list_name)
            
            if action == 'ALLOW':
                logger.warning(f"GEO-IP ALLOW not supported: {rule_text} | List: '{list_name}'")
                return "ignored"
            
            self.query_rules['geoip'][location_spec][action].append(data)
            self.answer_rules['geoip'][location_spec][action].append(data)
            
            logger.info(
                f"✓ Added GEO-IP rule (Query+Answer): {rule_text} | "
                f"Location: {location_spec} | "
                f"Action: {action} | "
                f"List: '{list_name}'"
            )
            return "geoip"
        
        elif rule_text.startswith('@') and not rule_text.startswith('@@'):
            # QUERY ONLY (ccTLD-based)
            location_spec = rule_text[1:].upper()
            data = (rule_text, list_name)
            
            if action == 'ALLOW':
                logger.warning(f"GEO-IP ALLOW not supported: {rule_text} | List: '{list_name}'")
                return "ignored"
            
            self.query_rules['geoip'][location_spec][action].append(data)
            
            logger.info(
                f"✓ Added GEO-IP rule (Query ONLY): {rule_text} | "
                f"Location: {location_spec} | "
                f"Action: {action} | "
                f"List: '{list_name}'"
            )
            return "geoip"
        
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

        # --- Regex Rules ---
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            pattern_str = clean_rule_text[1:-1]
            if pattern_str not in self._regex_cache:
                try:
                    self._regex_cache[pattern_str] = regex.compile(pattern_str, regex.IGNORECASE)
                except Exception as e:
                    logger.warning(f"Invalid regex rule: {rule_text} - {e}")
                    return "ignored"
            
            pattern = self._regex_cache[pattern_str]
            data = (pattern, action, rule_text, list_name)
            
            target = self.answer_rules if is_answer_only else self.query_rules
            target['regex'].append(data)
            return "regex"

        # --- IP/CIDR Rules (Using IntervalTree) ---
        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            start_int = int(net.network_address)
            end_int = int(net.broadcast_address) + 1  
            
            data = {'action': action, 'rule': rule_text, 'list': list_name}
            
            # IP rules always go to answer section
            self.answer_rules['ip'].add(start_int, end_int, data)
                
            return "cidr" if '/' in clean_rule_text else "ip"
        except ValueError: 
            pass

        # --- Domain Rules ---
        from domain_utils import normalize_domain
        clean_normalized = normalize_domain(clean_rule_text)
        
        if clean_rule_text.startswith('.'):
            clean_normalized = '.' + clean_normalized
        elif clean_rule_text.startswith('*.'):
            clean_normalized = '*.' + clean_normalized
        
        target = self.answer_rules if is_answer_only else self.query_rules
        target['domain'].insert(clean_normalized, action=action, rule_data=rule_text, list_name=list_name)
        return "domain"

    def _expand_geoip_locations(self, country_code, geoip_lookup):
        """Build set of applicable location tags from country code"""
        locations = set()
        locations.add(country_code.upper())
        
        # Add continent
        cont = geoip_lookup.cctld_mapper.get_continent_from_country(country_code)
        if cont:
            locations.add(cont.upper())
        
        # Add regions
        regs = geoip_lookup.cctld_mapper.get_regions_from_country(country_code)
        for r in regs:
            locations.add(r.upper())
        
        return locations

    def is_blocked(self, qname_norm: str, geoip_lookup=None):
        """
        Check if query is blocked.
        Returns (action, rule, list_name).
        Action is ALLOW/BLOCK/DROP/PASS.
        """
        # 1. Domain trie (priority: ALLOW > DROP > BLOCK)
        match = self.query_rules['domain'].match(qname_norm)
        if match:
            if match.get('action') == 'ALLOW':
                return "ALLOW", match['rule'], match['list']
            elif match.get('action') == 'DROP':
                return "DROP", match['rule'], match['list']
            elif match.get('action') == 'BLOCK':
                return "BLOCK", match['rule'], match['list']
        
        # 2. Regex (check in priority order)
        for pattern, action, rule, list_name in self.query_rules['regex']:
            if pattern.search(qname_norm):
                if action == 'ALLOW':
                    return "ALLOW", rule, list_name
        
        for pattern, action, rule, list_name in self.query_rules['regex']:
            if pattern.search(qname_norm):
                if action == 'DROP':
                    return "DROP", rule, list_name
        
        for pattern, action, rule, list_name in self.query_rules['regex']:
            if pattern.search(qname_norm):
                if action == 'BLOCK':
                    return "BLOCK", rule, list_name
        
        # 3. GeoIP Query Blocking (ccTLD check)
        if geoip_lookup and geoip_lookup.cctld_mapper and geoip_lookup.cctld_mapper.enabled:
            logger.debug(f"🌍 Query GeoIP Check: Analyzing domain '{qname_norm}'")
            
            cctld_country = geoip_lookup.cctld_mapper.get_country_from_domain(qname_norm)
            
            if cctld_country:
                logger.debug(f"  ✓ ccTLD Detected: .{qname_norm.split('.')[-1]} → Country: {cctld_country}")
                
                locations = self._expand_geoip_locations(cctld_country, geoip_lookup)
                logger.debug(f"  → Checking against {len(locations)} location tags: {', '.join(sorted(locations))}")
                
                # Check DROP first, then BLOCK
                for action in ['DROP', 'BLOCK']:
                    for loc in locations:
                        if loc in self.query_rules['geoip']:
                            if self.query_rules['geoip'][loc][action]:
                                rule, list_name = self.query_rules['geoip'][loc][action][0]
                                logger.info(
                                    f"{'🔇' if action == 'DROP' else '⛔'} GEO-IP {action} (Query ccTLD) | "
                                    f"Domain: {qname_norm} | "
                                    f"TLD: .{qname_norm.split('.')[-1]} | "
                                    f"Country: {cctld_country} | "
                                    f"Matched: {loc} | "
                                    f"Rule: '{rule}' | "
                                    f"List: '{list_name}'"
                                )
                                return action, rule, list_name
                
                logger.debug(f"  ✓ No GeoIP rules matched for {qname_norm}")
            else:
                logger.debug(f"  ✗ No ccTLD country mapping for domain '{qname_norm}'")
        
        return "PASS", None, None

    def check_answer(self, qname_norm, ip_str, geoip_lookup=None, domain_hint=None):
        """
        Check answer records.
        
        Args:
            qname_norm: Normalized query name (for domain blocking)
            ip_str: IP address string (for IP blocking)
            geoip_lookup: GeoIPLookup instance
            domain_hint: Domain name for CCTLD hint in IP lookup
            
        Returns:
            (action, rule, list_name)
        """
        
        # 1. GeoIP Checks (IP-based)
        applicable_locations = set()
        trigger_info = None

        if ip_str and geoip_lookup and geoip_lookup.enabled:
            geo_data, cctld_country = geoip_lookup.lookup_with_domain_hint(ip_str, domain_hint)
            
            if geo_data:
                cc = geo_data.get('country_code', '??').upper()
                cn = geo_data.get('country_name', 'Unknown')
                trigger_info = f"{cc} ({cn})"
                
                if geo_data.get('country_code'): 
                    applicable_locations.add(geo_data['country_code'].upper())
                if geo_data.get('country_name'): 
                    applicable_locations.add(geo_data['country_name'].upper())
                if geo_data.get('continent_code'): 
                    applicable_locations.add(geo_data['continent_code'].upper())
                if geo_data.get('continent_name'): 
                    applicable_locations.add(geo_data['continent_name'].upper())
                for r in geo_data.get('regions', []): 
                    applicable_locations.add(r.upper())
            
            if cctld_country:
                applicable_locations.add(cctld_country.upper())

        # Check GeoIP rules
        if applicable_locations:
            for action in ['DROP', 'BLOCK']:
                for loc in applicable_locations:
                    if loc in self.answer_rules['geoip']:
                        if self.answer_rules['geoip'][loc][action]:
                            rule, list_name = self.answer_rules['geoip'][loc][action][0]
                            logger.info(
                                f"{'🔇' if action == 'DROP' else '⛔'} GEO-IP {action} | "
                                f"Target: {ip_str} | Loc: {loc} | Rule: '{rule}' | Trigger: {trigger_info}"
                            )
                            return action, rule, list_name
        
        # 2. IP Checks (IntervalTree)
        if ip_str:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_int = int(ip_obj)
                
                matches = self.answer_rules['ip'][ip_int]
                if matches:
                    match = matches.pop().data
                    return match['action'], match['rule'], match['list']
            except ValueError: 
                pass 
        
        # 3. Domain Checks
        if qname_norm:
            # Regex (check DROP first, then BLOCK)
            for pattern, action, rule, list_name in self.answer_rules['regex']:
                if pattern.search(qname_norm):
                    if action == 'DROP':
                        return "DROP", rule, list_name
            
            for pattern, action, rule, list_name in self.answer_rules['regex']:
                if pattern.search(qname_norm):
                    if action == 'BLOCK':
                        return "BLOCK", rule, list_name
            
            # Trie
            match = self.answer_rules['domain'].match(qname_norm)
            if match:
                if match.get('action') in ['DROP', 'BLOCK']:
                    return match['action'], match['rule'], match['list']
        
        return "PASS", None, None
    
    def has_answer_only_rules(self):
        return bool(
            any(self.answer_rules['geoip'].values()) or
            len(self.answer_rules['ip']) > 0 or
            self.answer_rules['domain'].root or
            self.answer_rules['regex']
        )

    def get_stats(self) -> dict:
        # Count geoip rules
        query_block_geo = sum(len(self.query_rules['geoip'][loc]['BLOCK']) for loc in self.query_rules['geoip'])
        query_drop_geo = sum(len(self.query_rules['geoip'][loc]['DROP']) for loc in self.query_rules['geoip'])
        answer_block_geo = sum(len(self.answer_rules['geoip'][loc]['BLOCK']) for loc in self.answer_rules['geoip'])
        answer_drop_geo = sum(len(self.answer_rules['geoip'][loc]['DROP']) for loc in self.answer_rules['geoip'])
        
        return {
            'allow_domains': len(self.query_rules['domain'].root),
            'block_domains': len(self.query_rules['domain'].root),
            'drop_domains': len(self.query_rules['domain'].root),
            'query_block_geoip': query_block_geo,
            'query_drop_geoip': query_drop_geo,
            'answer_block_geoip': answer_block_geo,
            'answer_drop_geoip': answer_drop_geo,
            'answer_block_ips': len(self.answer_rules['ip']),
            'answer_drop_ips': len(self.answer_rules['ip']),
        }


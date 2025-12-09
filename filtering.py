#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 6.8.1 (Query-only GeoIP Support)
# -----------------------------------------------------------------------------
"""
Filtering Engine with IntervalTree for ranges and Map-based GeoIP.
Requires: pip install intervaltree

Changes:
- Single @ rules (@ASIA) apply ONLY to queries (ccTLD)
- Double @@ rules (@@ASIA) apply to BOTH queries (ccTLD) AND answers (IP)
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

logger = get_logger("Filtering")

class DomainTrie:
    __slots__ = ('root',)
    def __init__(self): 
        self.root = {} 

    def insert(self, domain_rule, rule_data=None, list_name="Unknown"):
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
        data = {'rule': original_rule, 'list': list_name}
        
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
        self.allow_trie = DomainTrie()
        self.block_trie = DomainTrie()
        self.drop_trie = DomainTrie()
        
        self.allow_regex = []
        self.block_regex = []
        self.drop_regex = []
        
        self.allow_ips = IntervalTree()
        self.block_ips = IntervalTree()
        self.drop_ips = IntervalTree()
        
        self.answer_block_trie = DomainTrie()
        self.answer_block_ips = IntervalTree()
        self.answer_block_regex = []
        
        # Query-only GeoIP rules (ccTLD-based, single @)
        self.query_block_geoip = defaultdict(list)
        self.query_drop_geoip = defaultdict(list)
        
        # Answer-only GeoIP rules (IP-based, double @@)
        self.answer_block_geoip = defaultdict(list)
        self.answer_drop_geoip = defaultdict(list)
        
        self.answer_drop_trie = DomainTrie()
        self.answer_drop_ips = IntervalTree()
        self.answer_drop_regex = []
        
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

    def add_rule(self, rule_text, list_type='block', list_name="Unknown"):
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        # --- GeoIP Rules ---
        if rule_text.startswith('@@'):
            # BOTH query (ccTLD) AND answer (IP)
            location_spec = rule_text[2:].upper()
            data = (rule_text, list_name)
            
            if list_type == 'drop':
                self.answer_drop_geoip[location_spec].append(data)
                self.query_drop_geoip[location_spec].append(data)
            elif list_type == 'block':
                self.answer_block_geoip[location_spec].append(data)
                self.query_block_geoip[location_spec].append(data)
            else:
                logger.warning(
                    f"⚠ GEO-IP rule only works in block/drop lists: {rule_text} | "
                    f"List: '{list_name}' | Type: '{list_type}'"
                )
                return "ignored"
            
            logger.info(
                f"✓ Added GEO-IP rule (Query+Answer): {rule_text} | "
                f"Location: {location_spec} | "
                f"Action: {list_type.upper()} | "
                f"List: '{list_name}'"
            )
            return "geoip"
        
        elif rule_text.startswith('@') and not rule_text.startswith('@@'):
            # QUERY ONLY (ccTLD-based)
            location_spec = rule_text[1:].upper()
            data = (rule_text, list_name)
            
            if list_type == 'drop':
                self.query_drop_geoip[location_spec].append(data)
            elif list_type == 'block':
                self.query_block_geoip[location_spec].append(data)
            else:
                logger.warning(
                    f"⚠ GEO-IP rule only works in block/drop lists: {rule_text} | "
                    f"List: '{list_name}' | Type: '{list_type}'"
                )
                return "ignored"
            
            logger.info(
                f"✓ Added GEO-IP rule (Query ONLY): {rule_text} | "
                f"Location: {location_spec} | "
                f"Action: {list_type.upper()} | "
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
            data = (pattern, rule_text, list_name)
            
            if is_answer_only:
                if list_type == 'drop': self.answer_drop_regex.append(data)
                else: self.answer_block_regex.append(data)
            else:
                if list_type == 'drop': self.drop_regex.append(data)
                elif list_type == 'block': self.block_regex.append(data)
                else: self.allow_regex.append(data)
            return "regex"

        # --- IP/CIDR Rules (Using IntervalTree) ---
        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            start_int = int(net.network_address)
            end_int = int(net.broadcast_address) + 1  
            
            data = {'rule': rule_text, 'list': list_name}
            
            if is_answer_only:
                if list_type == 'drop': self.answer_drop_ips.add(start_int, end_int, data)
                else: self.answer_block_ips.add(start_int, end_int, data)
            else:
                if list_type == 'drop': self.drop_ips.add(start_int, end_int, data)
                elif list_type == 'block': self.block_ips.add(start_int, end_int, data)
                else: self.allow_ips.add(start_int, end_int, data)
                
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
        
        if is_answer_only:
            target = self.answer_drop_trie if list_type == 'drop' else self.answer_block_trie
        else:
            target = (
                self.drop_trie if list_type == 'drop' else
                self.block_trie if list_type == 'block' else
                self.allow_trie
            )
        
        target.insert(clean_normalized, rule_data=rule_text, list_name=list_name)
        return "domain"

    def is_blocked(self, qname_norm: str, geoip_lookup=None):
        """
        Check if query is blocked.
        Returns (action, rule, list_name).
        Action is ALLOW/BLOCK/DROP/PASS.
        
        Supports GeoIP Query Blocking via ccTLD (Regions & Continents).
        """
        match = self.allow_trie.match(qname_norm)
        if match: 
            return "ALLOW", match['rule'], match['list']
        
        match = self.drop_trie.match(qname_norm)
        if match:
            return "DROP", match['rule'], match['list']
        
        match = self.block_trie.match(qname_norm)
        if match: 
            return "BLOCK", match['rule'], match['list']
            
        # --- GeoIP Query Blocking (ccTLD check) ---
        if geoip_lookup and geoip_lookup.cctld_mapper and geoip_lookup.cctld_mapper.enabled:
            logger.debug(f"🌍 Query GeoIP Check: Analyzing domain '{qname_norm}'")
            
            cctld_country = geoip_lookup.cctld_mapper.get_country_from_domain(qname_norm)
            
            if cctld_country:
                logger.debug(f"  ✓ ccTLD Detected: .{qname_norm.split('.')[-1]} → Country: {cctld_country}")
                
                applicable_locations = set()
                applicable_locations.add(cctld_country.upper())
                
                # Add continent
                cont = geoip_lookup.cctld_mapper.get_continent_from_country(cctld_country)
                if cont:
                    applicable_locations.add(cont.upper())
                    logger.debug(f"  ✓ Continent Mapped: {cctld_country} → {cont}")
                
                # Add regions
                regs = geoip_lookup.cctld_mapper.get_regions_from_country(cctld_country)
                if regs:
                    for r in regs:
                        applicable_locations.add(r.upper())
                    logger.debug(f"  ✓ Regions Mapped: {cctld_country} → {', '.join(regs)}")
                
                logger.debug(f"  → Checking against {len(applicable_locations)} location tags: {', '.join(sorted(applicable_locations))}")
                
                # Check DROP
                for loc in applicable_locations:
                    if loc in self.query_drop_geoip:
                        rule, list_name = self.query_drop_geoip[loc][0]
                        logger.info(
                            f"🔇 GEO-IP DROP (Query ccTLD) | "
                            f"Domain: {qname_norm} | "
                            f"TLD: .{qname_norm.split('.')[-1]} | "
                            f"Country: {cctld_country} | "
                            f"Matched: {loc} | "
                            f"Rule: '{rule}' | "
                            f"List: '{list_name}'"
                        )
                        return "DROP", rule, list_name
                
                # Check BLOCK
                for loc in applicable_locations:
                    if loc in self.query_block_geoip:
                        rule, list_name = self.query_block_geoip[loc][0]
                        logger.info(
                            f"⛔ GEO-IP BLOCK (Query ccTLD) | "
                            f"Domain: {qname_norm} | "
                            f"TLD: .{qname_norm.split('.')[-1]} | "
                            f"Country: {cctld_country} | "
                            f"Matched: {loc} | "
                            f"Rule: '{rule}' | "
                            f"List: '{list_name}'"
                        )
                        return "BLOCK", rule, list_name
                
                logger.debug(f"  ✓ No GeoIP rules matched for {qname_norm} (Country: {cctld_country}, Locations: {', '.join(sorted(applicable_locations))})")
            else:
                logger.debug(f"  ✗ No ccTLD country mapping for domain '{qname_norm}' (TLD: .{qname_norm.split('.')[-1]})")
        else:
            if not geoip_lookup:
                logger.debug(f"🌍 Query GeoIP Check: Skipped (geoip_lookup=None)")
            elif not geoip_lookup.cctld_mapper:
                logger.debug(f"🌍 Query GeoIP Check: Skipped (cctld_mapper not initialized)")
            elif not geoip_lookup.cctld_mapper.enabled:
                logger.debug(f"🌍 Query GeoIP Check: Skipped (cctld_mapper disabled)")
        
        return "PASS", None, None

    def check_answer(self, qname_norm, ip_str, geoip_lookup=None, domain_hint=None, country_override=None):
        """
        Check answer records with O(1) GeoIP and O(log n) IP range support.
        
        Args:
            qname_norm: Normalized query name (for domain blocking)
            ip_str: IP address string (for IP blocking)
            geoip_lookup: GeoIPLookup instance
            domain_hint: Domain name for CCTLD hint in IP lookup
            country_override: Force check against this country code (e.g. for Query ccTLD blocking)
            
        Returns:
            (action, rule, list_name)
        """
        
        # 1. GeoIP Checks (Optimized with Detail Logging)
        applicable_locations = set()
        trigger_info = None

        # Case A: IP-based Lookup
        if ip_str and geoip_lookup and geoip_lookup.enabled:
            geo_data, cctld_country = geoip_lookup.lookup_with_domain_hint(ip_str, domain_hint)
            
            if geo_data:
                cc = geo_data.get('country_code', '??').upper()
                cn = geo_data.get('country_name', 'Unknown')
                
                # Capture trigger info for logging
                trigger_info = f"{cc} ({cn})"
                
                if geo_data.get('country_code'): applicable_locations.add(geo_data['country_code'].upper())
                if geo_data.get('country_name'): applicable_locations.add(geo_data['country_name'].upper())
                if geo_data.get('continent_code'): applicable_locations.add(geo_data['continent_code'].upper())
                if geo_data.get('continent_name'): applicable_locations.add(geo_data['continent_name'].upper())
                for r in geo_data.get('regions', []): applicable_locations.add(r.upper())
            
            if cctld_country:
                 applicable_locations.add(cctld_country.upper())

        # Case B: Country Override (Query Blocking via ccTLD)
        elif country_override and geoip_lookup and geoip_lookup.cctld_mapper:
            cc = country_override.upper()
            trigger_info = f"{cc} (Query ccTLD)"
            
            applicable_locations.add(cc)
            
            # Map Country -> Continent for blocking (e.g., .cn matches @@ASIA)
            cont = geoip_lookup.cctld_mapper.get_continent_from_country(cc)
            if cont:
                applicable_locations.add(cont.upper())
            
            # Map Country -> Regions for blocking (e.g., .nl matches @@BENELUX)
            regs = geoip_lookup.cctld_mapper.get_regions_from_country(cc)
            for r in regs:
                applicable_locations.add(r.upper())

        # Perform GeoIP Rule Matching
        if applicable_locations:
            # Check DROP
            for loc in applicable_locations:
                if loc in self.answer_drop_geoip:
                    rule, list_name = self.answer_drop_geoip[loc][0]
                    # Enhanced Logging: Show Trigger Country
                    log_target = ip_str if ip_str else f"Query: {country_override}"
                    logger.info(f"🔇 GEO-IP DROP | Target: {log_target} | Loc: {loc} | Rule: '{rule}' | Trigger: {trigger_info}")
                    return "DROP", rule, list_name

            # Check BLOCK
            for loc in applicable_locations:
                if loc in self.answer_block_geoip:
                    rule, list_name = self.answer_block_geoip[loc][0]
                    # Enhanced Logging: Show Trigger Country
                    log_target = ip_str if ip_str else f"Query: {country_override}"
                    logger.info(f"⛔ GEO-IP BLOCK | Target: {log_target} | Loc: {loc} | Rule: '{rule}' | Trigger: {trigger_info}")
                    return "BLOCK", rule, list_name
        
        # 2. IP Checks (Optimized with IntervalTree)
        if ip_str:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_int = int(ip_obj)
                
                drops = self.answer_drop_ips[ip_int]
                if drops:
                    match = drops.pop().data 
                    return "DROP", match['rule'], match['list']
                
                blocks = self.answer_block_ips[ip_int]
                if blocks:
                    match = blocks.pop().data
                    return "BLOCK", match['rule'], match['list']
            except ValueError: 
                pass 
        
        # 3. Domain Checks
        if qname_norm:
            for pat, original_rule, list_name in self.answer_drop_regex:
                if pat.search(qname_norm):
                    return "DROP", original_rule, list_name
            
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname_norm): 
                    return "BLOCK", original_rule, list_name
            
            match = self.answer_drop_trie.match(qname_norm)
            if match:
                return "DROP", match['rule'], match['list']
            
            match = self.answer_block_trie.match(qname_norm)
            if match: 
                return "BLOCK", match['rule'], match['list']
        
        return "PASS", None, None
    
    def has_answer_only_rules(self):
        return bool(
            self.answer_block_geoip or self.answer_drop_geoip or
            len(self.answer_block_ips) > 0 or len(self.answer_drop_ips) > 0 or
            self.answer_block_trie.root or self.answer_drop_trie.root or
            self.answer_block_regex or self.answer_drop_regex
        )

    def get_stats(self) -> dict:
        return {
            'allow_domains': len(self.allow_trie.root),
            'block_domains': len(self.block_trie.root),
            'drop_domains': len(self.drop_trie.root),
            'query_block_geoip': len(self.query_block_geoip),
            'query_drop_geoip': len(self.query_drop_geoip),
            'answer_block_geoip': len(self.answer_block_geoip),
            'answer_drop_geoip': len(self.answer_drop_geoip),
            'answer_block_ips': len(self.answer_block_ips),
            'answer_drop_ips': len(self.answer_drop_ips),
        }


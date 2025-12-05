#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 6.1.0 (Enhanced GeoIP Logging)
# -----------------------------------------------------------------------------
"""
Filtering Engine with GeoIP support and DROP action.

Updates (v6.1.0):
- Enhanced GeoIP logging with detailed country information
- Improved check_answer() with comprehensive GeoIP tracking
- Better rule loading feedback

Updates (v6.0.0):
- GeoIP-based filtering for client identification and answer blocking
- DROP action (silent drop with no response)
- Rules with @ prefix support GeoIP location specs (@NL, @EUROPE, etc.)

Updates (v5.0.0):
- Regex pattern caching: Patterns compiled once and reused
- DomainCategorizer pre-compiles all patterns during __init__
- RuleEngine caches regex patterns to avoid recompilation
- Added get_stats() method for monitoring
"""

import regex
import ipaddress
import json
import dns.rdatatype
from utils import get_logger
from validation import is_valid_domain

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
            with open(categories_file, 'r') as f:
                self.categories = json.load(f)
            
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
        self.allow_ips = []
        self.block_ips = []
        self.drop_ips = []
        self.answer_block_trie = DomainTrie()
        self.answer_block_ips = [] 
        self.answer_block_regex = []
        self.answer_block_geoip = []
        self.answer_drop_trie = DomainTrie()
        self.answer_drop_ips = []
        self.answer_drop_regex = []
        self.answer_drop_geoip = []
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
        
        # GeoIP Rule FIRST (@@COUNTRY, @@CONTINENT, @@REGION)
        if rule_text.startswith('@@'):
            location_spec = rule_text[2:].upper()
            
            if list_type == 'drop':
                target = self.answer_drop_geoip
            elif list_type == 'block':
                target = self.answer_block_geoip
            else:
                logger.warning(
                    f"⚠ GEO-IP rule only works in block/drop lists: {rule_text} | "
                    f"List: '{list_name}' | Type: '{list_type}'"
                )
                return "ignored"
            
            target.append((location_spec, rule_text, list_name))
            logger.info(
                f"✓ Added GEO-IP rule: {rule_text} | "
                f"Location: {location_spec} | "
                f"Action: {list_type.upper()} | "
                f"List: '{list_name}' | "
                f"Total {list_type.upper()} rules: {len(target)}"
            )
            return "geoip"
        
        # Regular answer-only rules (@domain, @ip)
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

        # Regex Rule
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            pattern_str = clean_rule_text[1:-1]
            
            if pattern_str not in self._regex_cache:
                try:
                    self._regex_cache[pattern_str] = regex.compile(pattern_str, regex.IGNORECASE)
                except Exception as e:
                    logger.warning(f"Invalid regex rule: {rule_text} - {e}")
                    return "ignored"
            
            pattern = self._regex_cache[pattern_str]
            
            if is_answer_only:
                target = self.answer_drop_regex if list_type == 'drop' else self.answer_block_regex
            else:
                target = (
                    self.drop_regex if list_type == 'drop' else
                    self.block_regex if list_type == 'block' else
                    self.allow_regex
                )
            
            target.append((pattern, rule_text, list_name)) 
            return "regex"

        # IP/CIDR Rule
        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            
            if is_answer_only:
                target = self.answer_drop_ips if list_type == 'drop' else self.answer_block_ips
            else:
                target = (
                    self.drop_ips if list_type == 'drop' else
                    self.block_ips if list_type == 'block' else
                    self.allow_ips
                )
            
            target.append((net, rule_text, list_name))
            return "cidr" if '/' in clean_rule_text else "ip"
        except ValueError: 
            pass

        # Domain Rule
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

    def is_blocked(self, qname_norm: str):
        """Returns (action, rule, list_name) where action is ALLOW/BLOCK/DROP/PASS"""
        match = self.allow_trie.match(qname_norm)
        if match: 
            return "ALLOW", match['rule'], match['list']
        
        match = self.drop_trie.match(qname_norm)
        if match:
            return "DROP", match['rule'], match['list']
        
        match = self.block_trie.match(qname_norm)
        if match: 
            return "BLOCK", match['rule'], match['list']
        
        return "PASS", None, None

    def check_answer(self, qname_norm, ip_str, geoip_lookup=None):
        """
        Check answer records.
        Returns (action, rule, list_name) where action is BLOCK/DROP/PASS
        """
        # GeoIP check for answer IPs - ENHANCED LOGGING
        if ip_str and geoip_lookup:
            if not geoip_lookup.enabled:
                logger.debug(f"⚠ GEO-IP disabled, skipping check for IP {ip_str}")
            else:
                # Perform lookup FIRST to get geo info for logging
                geo_info = geoip_lookup.lookup(ip_str)
                if geo_info:
                    logger.info(
                        f"🌍 GEO-IP lookup | IP: {ip_str} | "
                        f"Country: {geo_info.get('country_code')} ({geo_info.get('country_name')}) | "
                        f"Continent: {geo_info.get('continent_code')} | "
                        f"Testing {len(self.answer_drop_geoip) + len(self.answer_block_geoip)} GEO-IP rules"
                    )
                else:
                    logger.debug(f"GEO-IP lookup failed for {ip_str} (private/invalid IP?)")
                
                # DROP rules
                for location_spec, rule, list_name in self.answer_drop_geoip:
                    logger.debug(f"  → Testing DROP rule: {rule} (location: {location_spec})")
                    if geoip_lookup.match_location(ip_str, location_spec):
                        logger.warning(
                            f"🔇 GEO-IP DROP TRIGGERED | "
                            f"IP: {ip_str} | "
                            f"Location: {location_spec} | "
                            f"Rule: '{rule}' | "
                            f"List: '{list_name}' | "
                            f"Country: {geo_info.get('country_code') if geo_info else 'Unknown'}"
                        )
                        return "DROP", rule, list_name
                    else:
                        logger.debug(f"    ✗ No match for {location_spec}")
                
                # BLOCK rules
                for location_spec, rule, list_name in self.answer_block_geoip:
                    logger.debug(f"  → Testing BLOCK rule: {rule} (location: {location_spec})")
                    if geoip_lookup.match_location(ip_str, location_spec):
                        logger.warning(
                            f"⛔ GEO-IP BLOCK TRIGGERED | "
                            f"IP: {ip_str} | "
                            f"Location: {location_spec} | "
                            f"Rule: '{rule}' | "
                            f"List: '{list_name}' | "
                            f"Country: {geo_info.get('country_code') if geo_info else 'Unknown'}"
                        )
                        return "BLOCK", rule, list_name
                    else:
                        logger.debug(f"    ✗ No match for {location_spec}")
                
                logger.debug(f"  ✓ GEO-IP check passed for {ip_str}, no matches")
        
        # IP check
        if ip_str:
            try:
                ip = ipaddress.ip_address(ip_str)
                
                for net, rule, list_name in self.answer_drop_ips:
                    if ip in net:
                        logger.debug(f"Answer IP {ip_str} matched DROP rule: {rule}")
                        return "DROP", rule, list_name
                
                for net, rule, list_name in self.answer_block_ips:
                    if ip in net: 
                        logger.debug(f"Answer IP {ip_str} matched BLOCK rule: {rule}")
                        return "BLOCK", rule, list_name
            except ValueError: 
                pass 
        
        # Domain check
        if qname_norm:
            for pat, original_rule, list_name in self.answer_drop_regex:
                if pat.search(qname_norm):
                    logger.debug(f"Answer domain {qname_norm} matched DROP regex: {original_rule}")
                    return "DROP", original_rule, list_name
            
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname_norm): 
                    logger.debug(f"Answer domain {qname_norm} matched BLOCK regex: {original_rule}")
                    return "BLOCK", original_rule, list_name
            
            match = self.answer_drop_trie.match(qname_norm)
            if match:
                logger.debug(f"Answer domain {qname_norm} matched DROP rule: {match['rule']}")
                return "DROP", match['rule'], match['list']
            
            match = self.answer_block_trie.match(qname_norm)
            if match: 
                logger.debug(f"Answer domain {qname_norm} matched BLOCK rule: {match['rule']}")
                return "BLOCK", match['rule'], match['list']
        
        return "PASS", None, None
    
    def get_stats(self) -> dict:
        stats = {
            'allow_domains': len(self.allow_trie.root),
            'block_domains': len(self.block_trie.root),
            'drop_domains': len(self.drop_trie.root),
            'allow_regex': len(self.allow_regex),
            'block_regex': len(self.block_regex),
            'drop_regex': len(self.drop_regex),
            'allow_ips': len(self.allow_ips),
            'block_ips': len(self.block_ips),
            'drop_ips': len(self.drop_ips),
            'answer_block_domains': len(self.answer_block_trie.root),
            'answer_block_regex': len(self.answer_block_regex),
            'answer_block_ips': len(self.answer_block_ips),
            'answer_block_geoip': len(self.answer_block_geoip),
            'answer_drop_domains': len(self.answer_drop_trie.root),
            'answer_drop_regex': len(self.answer_drop_regex),
            'answer_drop_ips': len(self.answer_drop_ips),
            'answer_drop_geoip': len(self.answer_drop_geoip),
            'regex_patterns_cached': len(self._regex_cache),
            'allowed_types': len(self.allowed_types),
            'blocked_types': len(self.blocked_types),
            'dropped_types': len(self.dropped_types),
            'category_rules': len(self.category_rules)
        }
        
        # Enhanced GeoIP rules logging
        if stats['answer_block_geoip'] > 0 or stats['answer_drop_geoip'] > 0:
            logger.info(
                f"🌍 GEO-IP rules active: "
                f"{stats['answer_block_geoip']} BLOCK, "
                f"{stats['answer_drop_geoip']} DROP"
            )
            
            # Log individual rules for debugging
            if stats['answer_block_geoip'] > 0:
                logger.debug(f"  BLOCK GEO-IP rules:")
                for location_spec, rule, list_name in self.answer_block_geoip:
                    logger.debug(f"    - {rule} (location: {location_spec}, list: {list_name})")
            
            if stats['answer_drop_geoip'] > 0:
                logger.debug(f"  DROP GEO-IP rules:")
                for location_spec, rule, list_name in self.answer_drop_geoip:
                    logger.debug(f"    - {rule} (location: {location_spec}, list: {list_name})")
        else:
            logger.debug("No GEO-IP rules loaded")
        
        return stats

    def check_category(self, qname_norm: str):
        if not self.categorizer or not self.category_rules: 
            return "PASS", None, None
        
        categories = self.categorizer.classify(qname_norm)
        
        for cat, score in categories.items():
            if cat in self.category_rules:
                rule = self.category_rules[cat]
                action = rule.get('action', 'PASS').upper()
                threshold = rule.get('threshold', 80)
                
                if score >= threshold:
                    logger.debug(
                        f"Category '{cat}' matched with score {score} "
                        f"(threshold: {threshold}), action: {action}"
                    )
                    return action, f"Category:{cat}(score={score})", "CategoryFilter"
        
        return "PASS", None, None


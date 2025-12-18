#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 10.1.0 (Fix: Respect Global Categorization Flag)
# -----------------------------------------------------------------------------
"""
Filtering Engine with Global Priority Logic (ALLOW > BLOCK > DROP).
Updates:
  - Explicitly check 'categorization_enabled' config before running categorizer.
  - Performance optimization: Skips Regex/GeoIP checks early if possible.
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
from heuristics import DomainHeuristics

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
    return {'LOG': [], 'ALLOW': [], 'BLOCK': [], 'DROP': []}

class RuleEngine:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.categorization_enabled = self.config.get('categorization_enabled', True)
        
        self.query_rules = {
            'domain': DomainTrie(),
            'regex': {'LOG': [], 'ALLOW': [], 'BLOCK': [], 'DROP': []},
            'geoip': defaultdict(_make_action_dict)
        }
        
        self.answer_rules = {
            'domain': DomainTrie(),
            'regex': {'LOG': [], 'ALLOW': [], 'BLOCK': [], 'DROP': []},
            'ip': IntervalTree(),
            'geoip': defaultdict(_make_action_dict),
            'asn': defaultdict(_make_action_dict)
        }
        
        self.allowed_types = set()
        self.blocked_types = set()
        self.dropped_types = set()
        self.logged_types = set()
        self.categorizer = None 
        self.category_rules = {}
        
        self._regex_cache = {}

        heuristics_config = self.config.get('heuristics', {}) if self.config else {}
        self.heuristics = DomainHeuristics(heuristics_config)

    def enable_categorization(self, categories_file='categories.json'):
        if self.categorization_enabled:
            self.categorizer = DomainCategorizer(categories_file)
        else:
            logger.info("Categorization disabled by config.")

    def set_type_filters(self, allowed: list[str], blocked: list[str], dropped: list[str] = None, logged: list[str] = None):
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
        if logged:
            for t in logged:
                try: self.logged_types.add(dns.rdatatype.from_text(t.upper()))
                except: pass

    def set_category_rules(self, rules_config):
        self.category_rules = rules_config or {}

    def check_type(self, qtype: int):
        qtype_name = dns.rdatatype.to_text(qtype)
        
        if self.logged_types and qtype in self.logged_types:
            logger.info(f"📋 LOG | Type: Query Type | QType: {qtype_name} | Rule: 'logged_types' | List: 'PolicyTypeFilter'")
        
        if self.allowed_types:
            if qtype not in self.allowed_types: 
                return "BLOCK", f"Type {qtype_name} NOT in allowed list", "PolicyTypeFilter"
        if self.dropped_types and qtype in self.dropped_types:
            return "DROP", f"Type {qtype_name} IS in dropped list", "PolicyTypeFilter"
        if self.blocked_types and qtype in self.blocked_types:
            return "BLOCK", f"Type {qtype_name} IS in blocked list", "PolicyTypeFilter"
        return "PASS", None, None

    def check_heuristics(self, qname_norm: str, qtype: int = None) -> tuple:
        if not self.heuristics.enabled:
            return "PASS", None, 0
    
        qtype_str = None
        if qtype is not None:
            try: qtype_str = dns.rdatatype.to_text(qtype)
            except: pass
        
        score, reasons = self.heuristics.analyze(qname_norm, qtype_str)
        reason_str = ", ".join(reasons) if reasons else "Clean"
    
        if score >= self.heuristics.block_threshold:
            return "BLOCK", reason_str, score
        
        return "PASS", reason_str, score

    def add_rule(self, rule_text, action='BLOCK', list_name="Unknown"):
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        if action not in ['LOG', 'ALLOW', 'BLOCK', 'DROP']:
            logger.warning(f"Invalid action '{action}', defaulting to BLOCK")
            action = 'BLOCK'
        
        is_answer_only = rule_text.startswith('@') and not rule_text.startswith('@@')
        clean_rule_text = rule_text[1:] if (is_answer_only or rule_text.startswith('@@')) else rule_text
        
        # IP/CIDR (IntervalTree)
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
        
        # GeoIP/ASN Rules
        if rule_text.startswith('@@'):
            location_spec = rule_text[2:].upper()
            data = (rule_text, list_name)
            self.query_rules['geoip'][location_spec][action].append(data)
            self.answer_rules['geoip'][location_spec][action].append(data)
            return "geoip"
        
        elif rule_text.startswith('@AS'):
            asn_spec = rule_text[1:].upper()
            if not asn_spec.startswith('AS'): asn_spec = 'AS' + asn_spec
            data = (rule_text, list_name)
            self.answer_rules['asn'][asn_spec][action].append(data)
            return "asn"
        
        elif rule_text.startswith('@'):
            location_spec = rule_text[1:].upper()
            data = (rule_text, list_name)
            self.query_rules['geoip'][location_spec][action].append(data)
            return "geoip"
        
        # Regex Rules
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            pattern_str = clean_rule_text[1:-1]
            if pattern_str not in self._regex_cache:
                try:
                    self._regex_cache[pattern_str] = regex.compile(pattern_str, regex.IGNORECASE)
                except Exception:
                    return "ignored"
            
            pattern = self._regex_cache[pattern_str]
            data = (pattern, rule_text, list_name)
            target = self.answer_rules if is_answer_only else self.query_rules
            target['regex'][action].append(data)
            return "regex"

        # Domain Rules (Trie)
        from domain_utils import normalize_domain
        clean_normalized = normalize_domain(clean_rule_text)
        
        if clean_rule_text.startswith('.'):
            clean_normalized = '.' + clean_normalized
        elif clean_rule_text.startswith('*.'):
            clean_normalized = '*.' + clean_normalized
        
        target = self.answer_rules if is_answer_only else self.query_rules
        target['domain'].insert(clean_normalized, action=action, rule_data=rule_text, list_name=list_name)
        return "domain"

    def is_blocked(self, qname_norm: str, geoip_lookup=None):
        """
        Check Query Rules.
        CRITICAL: Checks ALL mechanisms and applies Global Priority.
        Priority: ALLOW > BLOCK > DROP
        """
        matches = [] # List of {'action': ..., 'rule': ..., 'list': ..., 'source': ..., 'details': ...}

        # 1. Domains (Trie)
        trie_match = self.query_rules['domain'].match(qname_norm)
        if trie_match:
            matches.append({
                'action': trie_match['action'],
                'rule': trie_match['rule'],
                'list': trie_match['list'],
                'source': 'Domain',
                'details': f"Rule: {trie_match['rule']}"
            })

        # 2. GeoIP/ccTLD
        if geoip_lookup and geoip_lookup.cctld_mapper and geoip_lookup.cctld_mapper.enabled:
            # Check if using cctld_first OR if the user configured a rule for the TLD
            cctld_country = geoip_lookup.cctld_mapper.get_country_from_domain(qname_norm)
            
            if cctld_country:
                locations = geoip_lookup.cctld_mapper.expand_locations(cctld_country)
                
                # Check for rules on these locations
                for loc in locations:
                    if loc in self.query_rules['geoip']:
                        for action, rules in self.query_rules['geoip'][loc].items():
                            if rules:
                                # Found a rule for this location
                                matches.append({
                                    'action': action,
                                    'rule': rules[0][0],
                                    'list': rules[0][1],
                                    'source': f'GeoIP ({loc})',
                                    'details': f"Country: {cctld_country} -> Matches: {loc}"
                                })

        # 3. Categories (Categorizer)
        # OPTIMIZATION: Only run expensive regex classification if enabled AND rules exist
        if self.categorization_enabled and self.categorizer and self.category_rules:
            cats = self.categorizer.classify(qname_norm)
            for cat, score in cats.items():
                if cat in self.category_rules:
                    rule = self.category_rules[cat]
                    # Check confidence/threshold if exists
                    min_conf = rule.get('min_confidence', 0)
                    if score >= min_conf:
                        action = rule.get('action', 'BLOCK')
                        matches.append({
                            'action': action,
                            'rule': f"Category:{cat}",
                            'list': 'PolicyCategorization',
                            'source': 'Category',
                            'details': f"Matched: {cat} (Score: {score})"
                        })

        # 4. Regex
        for action in ['LOG', 'ALLOW', 'BLOCK', 'DROP']:
            for pattern, rule, list_name in self.query_rules['regex'][action]:
                if pattern.search(qname_norm):
                    matches.append({
                        'action': action,
                        'rule': rule,
                        'list': list_name,
                        'source': 'Regex',
                        'details': f"Pattern: {rule}"
                    })

        # --- Resolve Priorities ---
        final_action = "PASS"
        
        # Process LOGs first (non-terminal)
        for m in matches:
            if m['action'] == 'LOG':
                logger.info(f"📋 LOG | Type: Query {m['source']} | Domain: {qname_norm} | {m['details']} | List: '{m['list']}'")

        # Check ALLOW (Highest Priority)
        allow_match = next((m for m in matches if m['action'] == 'ALLOW'), None)
        if allow_match:
            logger.info(f"✓ ALLOWED | Reason: {allow_match['source']} Allowlist | Domain: {qname_norm} | {allow_match['details']} | List: '{allow_match['list']}'")
            return 'ALLOW', allow_match['rule'], allow_match['list']

        # Check BLOCK
        block_match = next((m for m in matches if m['action'] == 'BLOCK'), None)
        if block_match:
            logger.debug(f"Query Block Match: {qname_norm} -> {block_match['details']}")
            return 'BLOCK', block_match['rule'], block_match['list']

        # Check DROP
        drop_match = next((m for m in matches if m['action'] == 'DROP'), None)
        if drop_match:
            return 'DROP', drop_match['rule'], drop_match['list']

        return "PASS", None, None

    def check_answer(self, qname_norm=None, ip_str=None, geoip_lookup=None, domain_hint=None, check_query_rules=False):
        """
        Check Answer Rules.
        CRITICAL: Checks ALL mechanisms and applies Global Priority.
        Priority: ALLOW > BLOCK > DROP
        """
        matches = []

        # 1. Domains (Trie) - Usually checking CNAME targets here
        if qname_norm:
            trie_match = self.answer_rules['domain'].match(qname_norm)
            if not trie_match and check_query_rules:
                trie_match = self.query_rules['domain'].match(qname_norm)
            
            if trie_match:
                matches.append({
                    'action': trie_match['action'],
                    'rule': trie_match['rule'],
                    'list': trie_match['list'],
                    'source': 'Domain',
                    'details': f"Rule: {trie_match['rule']}"
                })

        # 2. ASN
        if ip_str and geoip_lookup and geoip_lookup.enabled:
            asn_data = geoip_lookup.lookup_asn(ip_str)
            if asn_data and 'asn' in asn_data:
                asn = asn_data['asn'].upper()
                as_name = asn_data.get('as_name', 'Unknown')
                if asn in self.answer_rules['asn']:
                    for action, rules in self.answer_rules['asn'][asn].items():
                        if rules:
                            matches.append({
                                'action': action,
                                'rule': rules[0][0],
                                'list': rules[0][1],
                                'source': f'ASN ({asn})',
                                'details': f"Holder: {as_name}"
                            })

        # 3. GeoIP
        if ip_str and geoip_lookup and geoip_lookup.enabled:
            geo_data, _ = geoip_lookup.lookup_with_domain_hint(ip_str, domain_hint)
            if geo_data:
                locs = set()
                if geo_data.get('country_code'): locs.add(geo_data['country_code'].upper())
                if geo_data.get('continent_code'): locs.add(geo_data['continent_code'].upper())
                for r in geo_data.get('regions', []): locs.add(r.upper())
                
                trigger_info = f"{geo_data.get('country_code', '??')} ({geo_data.get('country_name', 'Unknown')})"
                
                for loc in locs:
                    if loc in self.answer_rules['geoip']:
                        for action, rules in self.answer_rules['geoip'][loc].items():
                            if rules:
                                matches.append({
                                    'action': action,
                                    'rule': rules[0][0],
                                    'list': rules[0][1],
                                    'source': f'GeoIP ({loc})',
                                    'details': f"Trigger: {trigger_info}"
                                })

        # 4. IPs/CIDRs (IntervalTree)
        if ip_str:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_int = int(ip_obj)
                
                found = self.answer_rules['ip'][ip_int]
                for iv in found:
                    matches.append({
                        'action': iv.data['action'],
                        'rule': iv.data['rule'],
                        'list': iv.data['list'],
                        'source': 'IP/CIDR',
                        'details': f"Matched IP: {ip_str}"
                    })
            except ValueError: 
                pass 
        
        # 5. Regex
        if qname_norm:
            for action in ['LOG', 'ALLOW', 'BLOCK', 'DROP']:
                for pattern, rule, list_name in self.answer_rules['regex'][action]:
                    if pattern.search(qname_norm):
                        matches.append({
                            'action': action,
                            'rule': rule,
                            'list': list_name,
                            'source': 'Regex',
                            'details': f"Pattern: {rule}"
                        })

        # --- Resolve Priorities ---
        
        # Process LOGs
        for m in matches:
            if m['action'] == 'LOG':
                target = ip_str if ip_str else qname_norm
                logger.info(f"📋 LOG | Type: Answer {m['source']} | Target: {target} | {m['details']} | List: '{m['list']}'")

        # Check ALLOW (Wins all)
        allow_match = next((m for m in matches if m['action'] == 'ALLOW'), None)
        if allow_match:
            return 'ALLOW', allow_match['rule'], allow_match['list']

        # Check BLOCK
        block_match = next((m for m in matches if m['action'] == 'BLOCK'), None)
        if block_match:
            # Restore rich logging for Block actions
            logger.info(f"⛔ BLOCKED (Answer {block_match['source']}) | Rule: '{block_match['rule']}' | {block_match['details']}")
            return 'BLOCK', block_match['rule'], block_match['list']

        # Check DROP
        drop_match = next((m for m in matches if m['action'] == 'DROP'), None)
        if drop_match:
            logger.info(f"🔇 DROPPED (Answer {drop_match['source']}) | Rule: '{drop_match['rule']}' | {drop_match['details']}")
            return 'DROP', drop_match['rule'], drop_match['list']
        
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
        return {
            'rules_domain': "N/A", # Trie traversal needed for count
            'rules_ip': len(self.answer_rules['ip']),
        }


#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 3.5.3 (Fix: Rule Reporting) + OPTIMIZED
# -----------------------------------------------------------------------------
"""
Filtering Engine.

Updates:
- Fixed rule reporting to show the actual matched rule, not a reconstructed one
- When inserting rules, we now store the original rule text
- When matching, we return the exact rule that was inserted
- OPTIMIZED: Uses validation module instead of duplicate _is_valid_domain
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
        
        # Ensure domain stored in Trie is always lowercase
        clean_domain = domain_rule.lstrip('.*').lower()
        
        # Validate domain format - OPTIMIZED: Uses validation module
        if not is_valid_domain(clean_domain, allow_underscores=False):
            logger.warning(f"Invalid domain format, skipping: {domain_rule}")
            return
        
        parts = clean_domain.split('.')[::-1]
        
        node = self.root
        for part in parts:
            if part not in node: 
                node[part] = {}
            node = node[part]
        
        # IMPORTANT: Store the ORIGINAL rule text (e.g., ".doubleclick.net")
        # not the queried domain
        original_rule = rule_data if rule_data else domain_rule
        data = {'rule': original_rule, 'list': list_name}
        
        if is_exclusive: 
            node['_wild'] = data 
        elif is_inclusive:
            node['_end'] = data 
            node['_wild'] = data 
        else: 
            node['_end'] = data 

    def match(self, domain_str: str):
        """
        Match domain and return the rule data.
        Input is automatically lowercased.
        Returns the data dict with 'rule' and 'list' keys, where 'rule' is the
        ORIGINAL rule that was inserted (e.g., ".doubleclick.net")
        """
        clean = domain_str.rstrip('.').lower()
        parts = clean.split('.')[::-1]
        node = self.root
        last_wildcard_data = None

        for part in parts:
            if '_wild' in node: 
                last_wildcard_data = node['_wild']
            if part in node: 
                node = node[part]
            else: 
                return last_wildcard_data
        
        if '_end' in node: 
            return node['_end']
        if '_wild' in node: 
            return node['_wild']
        return last_wildcard_data

class DomainCategorizer:
    def __init__(self, categories_file="categories.json"):
        self.categories = {}
        self.regex_cache = {}
        try:
            with open(categories_file, 'r') as f:
                self.categories = json.load(f)
            
            for cat, data in self.categories.items():
                if 'regex' in data:
                    self.regex_cache[cat] = []
                    for r_str in data['regex']:
                        try: 
                            self.regex_cache[cat].append(regex.compile(r_str, regex.IGNORECASE))
                        except Exception as e:
                            logger.warning(f"Failed to compile regex for {cat}: {e}")
        except FileNotFoundError:
            logger.warning(f"Categories file not found: {categories_file}")
        except Exception as e:
            logger.error(f"Error loading categories: {e}")

    def categorize(self, domain: str) -> dict:
        """Categorize domain. Input is automatically lowercased."""
        results = {}
        domain_lower = domain.lower().rstrip('.')
        parts = domain_lower.replace('-', '.').split('.')
        tld = parts[-1] if parts else ""
        
        for category, data in self.categories.items():
            score = 0
            
            # TLD matching
            if 'tlds' in data and tld in data['tlds']: 
                score = max(score, 90)
            
            # Regex matching
            if category in self.regex_cache:
                for pattern in self.regex_cache[category]:
                    if pattern.search(domain_lower):
                        score = max(score, 100)
                        break
            
            # Keyword matching (FIXED)
            if 'keywords' in data:
                for kw in data['keywords']:
                    kw_lower = kw.lower()
                    if kw_lower in parts:
                        score = max(score, 95)
                    elif kw_lower in domain_lower:
                        score = max(score, 70)  # Lower score for substring match
            
            if score > 0: 
                results[category] = score
        
        return results

class RuleEngine:
    def __init__(self):
        self.allow_trie = DomainTrie()
        self.block_trie = DomainTrie()
        self.allow_regex = []
        self.block_regex = []
        self.allow_ips = []
        self.block_ips = []
        self.answer_block_trie = DomainTrie()
        self.answer_block_ips = [] 
        self.answer_block_regex = []
        self.allowed_types = set()
        self.blocked_types = set()
        self.categorizer = None 
        self.category_rules = {}

    def set_type_filters(self, allowed: list[str], blocked: list[str]):
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

    def set_category_rules(self, rules_config):
        self.category_rules = rules_config or {}

    def check_type(self, qtype: int):
        qtype_name = dns.rdatatype.to_text(qtype)
        if self.allowed_types:
            if qtype not in self.allowed_types: 
                return True, f"Type {qtype_name} NOT in allowed list", "PolicyTypeFilter"
            return False, None, None
        if self.blocked_types:
            if qtype in self.blocked_types: 
                return True, f"Type {qtype_name} IS in blocked list", "PolicyTypeFilter"
        return False, None, None

    def add_rule(self, rule_text, list_type='block', list_name="Unknown"):
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

        # Regex Rule
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            try:
                pattern = regex.compile(clean_rule_text[1:-1], regex.IGNORECASE)
                target = self.answer_block_regex if is_answer_only else (
                    self.block_regex if list_type == 'block' else self.allow_regex
                )
                target.append((pattern, rule_text, list_name)) 
                return "regex"
            except Exception as e:
                logger.warning(f"Invalid regex rule: {rule_text} - {e}")
                return "ignored"

        # IP/CIDR Rule
        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            target = self.answer_block_ips if is_answer_only else (
                self.block_ips if list_type == 'block' else self.allow_ips
            )
            target.append((net, rule_text, list_name))
            return "cidr" if '/' in clean_rule_text else "ip"
        except ValueError: 
            pass

        # Domain Rule
        # IMPORTANT: Pass the original rule_text as rule_data so it's stored in the trie
        target = self.answer_block_trie if is_answer_only else (
            self.block_trie if list_type == 'block' else self.allow_trie
        )
        target.insert(clean_rule_text, rule_data=rule_text, list_name=list_name)
        return "domain"

    def is_blocked(self, qname: str):
        """Check if domain is blocked. Input is automatically lowercased."""
        # Ensure lowercase at entry point
        qname_lower = qname.lower().rstrip('.')
        
        match = self.allow_trie.match(qname_lower)
        if match: 
            return "ALLOW", match['rule'], match['list']
        
        match = self.block_trie.match(qname_lower)
        if match: 
            return "BLOCK", match['rule'], match['list']
        
        return "PASS", None, None

    def check_answer(self, qname_str, ip_str):
        """Check answer records. Inputs are automatically lowercased/normalized."""
        if ip_str:
            try:
                ip = ipaddress.ip_address(ip_str)
                for net, rule, list_name in self.answer_block_ips:
                    if ip in net: 
                        return True, rule, list_name
            except ValueError: 
                pass 
        
        if qname_str:
            qname = str(qname_str).lower().rstrip('.')
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname): 
                    return True, original_rule, list_name
            match = self.answer_block_trie.match(qname)
            if match: 
                return True, match['rule'], match['list']
        
        return False, None, None


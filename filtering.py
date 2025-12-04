#!/usr/bin/env python3
# filename: filtering.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 5.0.0 (Optimized - Regex Caching)
# -----------------------------------------------------------------------------
"""
Filtering Engine.

Updates (v5.0.0):
- Regex pattern caching: Patterns compiled once and reused
- DomainCategorizer pre-compiles all patterns during __init__
- RuleEngine caches regex patterns to avoid recompilation
- Added get_stats() method for monitoring

Updates (v4.0.0):
- All methods now expect PRE-NORMALIZED domain names (lowercase, no trailing dot)
- Removed redundant .lower() and .rstrip('.') calls throughout
- Domain normalization happens once at entry point (resolver.py)
- Improved performance by eliminating duplicate string operations
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
        """
        Insert rule into trie.
        
        Args:
            domain_rule: Domain rule (can have . or *. prefix)
            rule_data: Original rule text to store
            list_name: List name for tracking
            
        Note: Expects normalized input (lowercase, no trailing dot)
        """
        is_inclusive = domain_rule.startswith('.')
        is_exclusive = domain_rule.startswith('*.')
        
        clean_domain = domain_rule.lstrip('.*')
        
        # Validate domain format
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
        """
        Match domain and return the rule data.
        
        Args:
            domain_norm: PRE-NORMALIZED domain (lowercase, no trailing dot)
            
        Returns:
            Data dict with 'rule' and 'list' keys, or None
        """
        parts = domain_norm.split('.')[::-1]
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
            
            # Pre-compile ALL regex patterns during initialization
            total_patterns = 0
            failed_patterns = 0
            
            for cat, data in self.categories.items():
                if 'regex' in data and data['regex']:
                    self.regex_cache[cat] = []
                    for r_str in data['regex']:
                        try:
                            compiled_pattern = regex.compile(r_str, regex.IGNORECASE)
                            self.regex_cache[cat].append(compiled_pattern)
                            total_patterns += 1
                        except Exception as e:
                            logger.warning(f"Failed to compile regex for category '{cat}': {r_str} - {e}")
                            failed_patterns += 1
            
            if total_patterns > 0:
                logger.info(
                    f"DomainCategorizer: Pre-compiled {total_patterns} regex patterns "
                    f"across {len(self.regex_cache)} categories"
                    f"{f' ({failed_patterns} failed)' if failed_patterns > 0 else ''}"
                )
            
        except FileNotFoundError:
            logger.warning(f"Categories file not found: {categories_file}")
        except Exception as e:
            logger.error(f"Error loading categories: {e}")

    def categorize(self, domain_norm: str) -> dict:
        """
        Categorize domain.
        
        Args:
            domain_norm: PRE-NORMALIZED domain (lowercase, no trailing dot)
            
        Returns:
            Dict of {category: confidence_score}
        """
        results = {}
        parts = domain_norm.replace('-', '.').split('.')
        tld = parts[-1] if parts else ""
        
        for category, data in self.categories.items():
            score = 0
            
            # TLD matching
            if 'tlds' in data and tld in data['tlds']: 
                score = max(score, 90)
            
            # Regex matching
            if category in self.regex_cache:
                for pattern in self.regex_cache[category]:
                    if pattern.search(domain_norm):
                        score = max(score, 100)
                        break
            
            # Keyword matching
            if 'keywords' in data:
                for kw in data['keywords']:
                    # Keywords in categories.json are already lowercase
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
        
        # Regex pattern cache - prevents recompilation
        self._regex_cache = {}

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
        """
        Add a filtering rule.
        
        Args:
            rule_text: Rule text (will be normalized)
            list_type: 'allow' or 'block'
            list_name: Source list name
            
        Returns:
            Rule type: 'domain', 'regex', 'ip', 'cidr', or 'ignored'
        """
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): 
            return "ignored"
        
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

        # Regex Rule - with pattern caching
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            pattern_str = clean_rule_text[1:-1]
            
            # Check cache first
            if pattern_str not in self._regex_cache:
                try:
                    self._regex_cache[pattern_str] = regex.compile(pattern_str, regex.IGNORECASE)
                except Exception as e:
                    logger.warning(f"Invalid regex rule: {rule_text} - {e}")
                    return "ignored"
            
            pattern = self._regex_cache[pattern_str]
            target = self.answer_block_regex if is_answer_only else (
                self.block_regex if list_type == 'block' else self.allow_regex
            )
            target.append((pattern, rule_text, list_name)) 
            return "regex"

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

        # Domain Rule - normalize before insertion
        from domain_utils import normalize_domain
        clean_normalized = normalize_domain(clean_rule_text)
        
        # Preserve prefix for rule matching
        if clean_rule_text.startswith('.'):
            clean_normalized = '.' + clean_normalized
        elif clean_rule_text.startswith('*.'):
            clean_normalized = '*.' + clean_normalized
        
        target = self.answer_block_trie if is_answer_only else (
            self.block_trie if list_type == 'block' else self.allow_trie
        )
        target.insert(clean_normalized, rule_data=rule_text, list_name=list_name)
        return "domain"

    def is_blocked(self, qname_norm: str):
        """
        Check if domain is blocked.
        
        Args:
            qname_norm: PRE-NORMALIZED domain (lowercase, no trailing dot)
            
        Returns:
            (action, rule, list_name) tuple where action is ALLOW/BLOCK/PASS
        """
        match = self.allow_trie.match(qname_norm)
        if match: 
            return "ALLOW", match['rule'], match['list']
        
        match = self.block_trie.match(qname_norm)
        if match: 
            return "BLOCK", match['rule'], match['list']
        
        return "PASS", None, None

    def check_answer(self, qname_norm, ip_str):
        """
        Check answer records.
        
        Args:
            qname_norm: PRE-NORMALIZED domain (lowercase, no trailing dot) or None
            ip_str: IP address string or None
            
        Returns:
            (is_blocked, rule, list_name) tuple
        """
        if ip_str:
            try:
                ip = ipaddress.ip_address(ip_str)
                for net, rule, list_name in self.answer_block_ips:
                    if ip in net: 
                        return True, rule, list_name
            except ValueError: 
                pass 
        
        if qname_norm:
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname_norm): 
                    return True, original_rule, list_name
            match = self.answer_block_trie.match(qname_norm)
            if match: 
                return True, match['rule'], match['list']
        
        return False, None, None
    
    def get_stats(self) -> dict:
        """
        Get filtering engine statistics.
        
        Returns:
            Dict with rule counts and cache stats
        """
        return {
            'allow_domains': len(self.allow_trie.root),
            'block_domains': len(self.block_trie.root),
            'allow_regex': len(self.allow_regex),
            'block_regex': len(self.block_regex),
            'allow_ips': len(self.allow_ips),
            'block_ips': len(self.block_ips),
            'answer_block_domains': len(self.answer_block_trie.root),
            'answer_block_regex': len(self.answer_block_regex),
            'answer_block_ips': len(self.answer_block_ips),
            'regex_patterns_cached': len(self._regex_cache),
            'allowed_types': len(self.allowed_types),
            'blocked_types': len(self.blocked_types),
            'category_rules': len(self.category_rules)
        }


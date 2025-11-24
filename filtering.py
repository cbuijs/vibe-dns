#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# Updated: 2025-11-24 14:20:00
# -----------------------------------------------------------------------------

import regex
import aiohttp
import asyncio
import os
import time
import hashlib
import logging
from urllib.parse import urlparse
import ipaddress
from dnslib import QTYPE

from utils import logger

# -----------------------------------------------------------------------------
# Domain Trie Data Structure
# -----------------------------------------------------------------------------
# This Trie (Prefix Tree) is optimized for matching domain names.
# Instead of matching "google.com" left-to-right, we split it into labels
# ["com", "google"] and match from the TLD down. This lets us easily support:
# - Exact matches: "example.com"
# - Wildcards: "*.example.com" (subdomains only)
# - Zone matches: ".example.com" (domain + subdomains)
# -----------------------------------------------------------------------------
class DomainTrie:
    __slots__ = ('root',)

    def __init__(self):
        self.root = {} 

    def insert(self, domain_rule, rule_data=None, list_name="Unknown"):
        # Check for special prefixes
        is_inclusive = domain_rule.startswith('.') # Matches .google.com (google.com + subs)
        is_exclusive = domain_rule.startswith('*.') # Matches *.google.com (only subs)
        
        # Remove markers to get raw domain parts
        clean_domain = domain_rule.lstrip('.*')
        parts = clean_domain.split('.')[::-1] # Reverse: com -> google
        
        node = self.root
        for part in parts:
            if part not in node:
                node[part] = {}
            node = node[part]
        
        # Store the rule and source list at the node
        data = {'rule': rule_data or domain_rule, 'list': list_name}

        if is_exclusive:
            node['_wild'] = data # Only matches children
        elif is_inclusive:
            node['_end'] = data # Matches this node
            node['_wild'] = data # AND matches children
        else:
            node['_end'] = data # Exact match only

    def match(self, domain):
        """
        Walks the Trie to find if the domain matches any stored rule.
        Returns the rule data if found, else None.
        """
        parts = domain.rstrip('.').split('.')[::-1]
        node = self.root
        
        # We keep track of the last wildcard rule we saw while walking down.
        # This handles cases like: Rule "*.com", Query "google.com".
        last_wildcard_data = None

        for part in parts:
            if '_wild' in node:
                last_wildcard_data = node['_wild']
            
            if part in node:
                node = node[part]
            else:
                # Path ended. Did we see a wildcard higher up?
                return last_wildcard_data
        
        # We matched the full domain. Is there an exact match or wildcard here?
        if '_end' in node: return node['_end']
        if '_wild' in node: return node['_wild']
        
        return last_wildcard_data

# -----------------------------------------------------------------------------
# Rule Engine
# -----------------------------------------------------------------------------
# This class holds all the filtering logic for a single Policy (e.g., "StrictPolicy").
# It contains separate storage for:
# - Domains (Trie)
# - Regexes (List)
# - IP Addresses (List)
# It also separates "Query Rules" (what you ask for) from "Answer Rules" (what you get back).
# -----------------------------------------------------------------------------
class RuleEngine:
    def __init__(self):
        self.allow_trie = DomainTrie()
        self.block_trie = DomainTrie()
        
        # Regex lists store tuples: (compiled_pattern, original_rule_string, list_name)
        self.allow_regex = []
        self.block_regex = []
        
        # IP lists store tuples: (ip_network_object, original_rule_string, list_name)
        self.allow_ips = []
        self.block_ips = []
        
        # Storage for Answer-only rules (starting with @)
        self.answer_block_trie = DomainTrie()
        self.answer_block_ips = [] 
        self.answer_block_regex = []

        # Sets for RR-Type filtering (e.g., Block TXT records)
        self.allowed_types = set()
        self.blocked_types = set()

    def set_type_filters(self, allowed, blocked):
        """Converts config string types (A, AAAA) to DNSRib QTYPE integers."""
        if allowed:
            for t in allowed:
                try: self.allowed_types.add(getattr(QTYPE, t.upper()))
                except AttributeError: logger.warning(f"Unknown QTYPE in allowed list: {t}")
        if blocked:
            for t in blocked:
                try: self.blocked_types.add(getattr(QTYPE, t.upper()))
                except AttributeError: logger.warning(f"Unknown QTYPE in blocked list: {t}")

    def check_type(self, qtype):
        """Validates if the query type is allowed."""
        if self.allowed_types:
            if qtype not in self.allowed_types:
                return True, f"Type {QTYPE[qtype]} NOT in allowed list", "PolicyTypeFilter"
            return False, None, None

        if self.blocked_types:
            if qtype in self.blocked_types:
                return True, f"Type {QTYPE[qtype]} IS in blocked list", "PolicyTypeFilter"
        
        return False, None, None

    def add_rule(self, rule_text, list_type='block', list_name="Unknown"):
        """
        Parses a raw rule string (e.g., from a blocklist file) and adds it
        to the correct internal structure based on its syntax (Regex vs IP vs Domain).
        Returns the type of rule added ('regex', 'ip', 'domain') for stats.
        """
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): return "ignored"

        # '@' prefix means this rule applies to Answers, not Queries.
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

        # 1. Check for Regex: /pattern/
        if clean_rule_text.startswith('/') and clean_rule_text.endswith('/'):
            try:
                pattern = regex.compile(clean_rule_text[1:-1])
                
                if is_answer_only:
                     target = self.answer_block_regex
                     rtype = "ans_regex"
                else:
                     target = self.block_regex if list_type == 'block' else self.allow_regex
                     rtype = "regex"
                
                target.append((pattern, rule_text, list_name)) 
                return rtype
            except Exception as e:
                logger.warning(f"Invalid regex rule {rule_text}: {e}")
                return "ignored"

        # 2. Check for IP / CIDR
        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            target = self.answer_block_ips if list_type == 'block' else self.allow_ips
            target.append((net, rule_text, list_name))
            
            if '/' in clean_rule_text: return "cidr"
            return "ip"
        except ValueError:
            pass

        # 3. Default: Treat as Domain
        if is_answer_only:
             target = self.answer_block_trie
             rtype = "ans_domain"
        else:
             target = self.block_trie if list_type == 'block' else self.allow_trie
             rtype = "domain"
             
        target.insert(clean_rule_text, rule_data=rule_text, list_name=list_name)
        return rtype

    def is_blocked(self, qname):
        """
        Checks a Query Name against all loaded rules.
        Priority: Allow Lists (Regex -> Trie) THEN Block Lists (Regex -> Trie).
        """
        qname = qname.lower().rstrip('.')
        
        # Check Allow Lists
        for pat, original_rule, list_name in self.allow_regex:
            if pat.search(qname): 
                return "ALLOW", original_rule, list_name
        
        match = self.allow_trie.match(qname)
        if match: 
            return "ALLOW", match['rule'], match['list']
        
        # Check Block Lists
        for pat, original_rule, list_name in self.block_regex:
            if pat.search(qname): 
                return "BLOCK", original_rule, list_name

        match = self.block_trie.match(qname)
        if match: 
            return "BLOCK", match['rule'], match['list']
                
        return "PASS", None, None

    def check_answer(self, qname, ip_str):
        """
        Checks items in the DNS Response (Answer Section).
        Matches IP addresses (A/AAAA) or Domains (CNAME/MX/etc).
        """
        # Check IP against IP blocklists
        if ip_str:
            try:
                ip = ipaddress.ip_address(ip_str)
                for net, rule, list_name in self.answer_block_ips:
                    if ip in net: 
                        return True, rule, list_name
            except ValueError: pass 
        
        # Check Domain against Answer-Only (@) blocklists
        if qname:
            qname = str(qname).lower().rstrip('.')
            
            # Check Regexes
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname): 
                    return True, original_rule, list_name

            # Check Trie
            match = self.answer_block_trie.match(qname)
            if match: 
                return True, match['rule'], match['list']
            
        return False, None, None

# -----------------------------------------------------------------------------
# List Manager
# -----------------------------------------------------------------------------
# Handles downloading blocklists from URLs, caching them locally to disk,
# and refreshing them periodically.
# -----------------------------------------------------------------------------
class ListManager:
    def __init__(self, cache_dir="./list_cache", refresh_interval=86400):
        self.lists_data = {} 
        self.cache_dir = cache_dir
        self.refresh_interval = refresh_interval
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    def _get_cache_path(self, source_url):
        # Hash the URL to create a safe filename
        hash_name = hashlib.md5(source_url.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, hash_name + ".txt")

    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path): return False
        mtime = os.path.getmtime(cache_path)
        # Return True only if file is younger than refresh interval
        if time.time() - mtime > self.refresh_interval: return False
        return True

    async def update_lists(self, list_config):
        """
        Iterates through all lists in config, fetches content (from net or cache),
        and parses rules.
        """
        for name, sources in list_config.items():
            rules = set()
            
            for source in sources:
                content = ""
                cache_path = ""
                
                try:
                    if source.startswith(('http://', 'https://')):
                        cache_path = self._get_cache_path(source)
                        
                        # Use cache if valid, otherwise download
                        if self._is_cache_valid(cache_path):
                            logger.info(f"Loading cached list '{name}': {source}")
                            with open(cache_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                        else:
                            logger.info(f"Fetching list '{name}': {source}")
                            async with aiohttp.ClientSession() as session:
                                async with session.get(source, timeout=15) as resp:
                                    if resp.status == 200:
                                        content = await resp.text()
                                        with open(cache_path, 'w', encoding='utf-8') as f:
                                            f.write(content)
                                    else:
                                        logger.warning(f"Failed to fetch {source}: {resp.status}")
                                        # If fetch fails, try to use stale cache as backup
                                        if os.path.exists(cache_path):
                                            logger.warning(f"Using stale cache for {source}")
                                            with open(cache_path, 'r', encoding='utf-8') as f:
                                                content = f.read()
                    else:
                        # Local File Path
                        if os.path.exists(source):
                            with open(source, 'r', encoding='utf-8') as f: content = f.read()
                        else:
                            logger.warning(f"File not found: {source}")
                    
                    if content:
                        parsed_rules = self._parse_content(content)
                        
                        # Only calculate detailed stats if DEBUG logging is on (for speed)
                        if logger.isEnabledFor(logging.DEBUG):
                            type_counts = {
                                'domain': 0, 'ip': 0, 'cidr': 0, 'regex': 0,
                                'ans_domain': 0, 'ans_regex': 0
                            }
                            for r in parsed_rules:
                                is_ans = r.startswith('@')
                                clean = r[1:] if is_ans else r
                                
                                if clean.startswith('/') and clean.endswith('/'):
                                    if is_ans: type_counts['ans_regex'] += 1
                                    else: type_counts['regex'] += 1
                                elif self._is_ip_or_cidr(clean):
                                    if '/' in clean: type_counts['cidr'] += 1
                                    else: type_counts['ip'] += 1
                                else:
                                    if is_ans: type_counts['ans_domain'] += 1
                                    else: type_counts['domain'] += 1
                            
                            stats_msg = (
                                f"Source '{source}' parsed: "
                                f"{type_counts['domain']} Domains, "
                                f"{type_counts['ip']} IPs, "
                                f"{type_counts['cidr']} CIDRs, "
                                f"{type_counts['regex']} Regex, "
                                f"{type_counts['ans_domain']} Ans-Dom, "
                                f"{type_counts['ans_regex']} Ans-Reg"
                            )
                            logger.debug(stats_msg)
                        
                        rules.update(parsed_rules)

                except Exception as e:
                    logger.error(f"Error loading source {source}: {e}")
                    if cache_path and os.path.exists(cache_path):
                         with open(cache_path, 'r', encoding='utf-8') as f:
                             parsed = self._parse_content(f.read())
                             rules.update(parsed)
            
            self.lists_data[name] = rules
            logger.info(f"List '{name}' consolidated with {len(rules)} unique rules.")

    def _is_ip_or_cidr(self, text):
        try:
            ipaddress.ip_network(text, strict=False)
            return True
        except ValueError:
            return False

    def _parse_content(self, text):
        valid_rules = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'): continue
            
            clean_check = line[1:] if line.startswith('@') else line
            # Preserve regexes with spaces
            if clean_check.startswith('/') and clean_check.endswith('/'):
                valid_rules.add(line)
                continue
            
            if '#' in line: line = line.split('#')[0].strip()
            
            parts = line.split()
            if not parts: continue

            # Handle standard HOSTS format
            if parts[0] in ['0.0.0.0', '127.0.0.1', '::']:
                if len(parts) >= 2: valid_rules.add(parts[1])
            elif len(parts) == 1:
                valid_rules.add(parts[0])
            else:
                 valid_rules.add(parts[0])
        return valid_rules

    def compile_policy(self, policy_name, policy_config):
        """
        Converts the consolidated lists into a RuleEngine instance for fast lookup.
        """
        engine = RuleEngine()
        
        count_stats = logger.isEnabledFor(logging.DEBUG)
        counts = {'domain': 0, 'ip': 0, 'cidr': 0, 'regex': 0, 'ans_domain': 0, 'ans_regex': 0, 'ignored': 0}

        def apply_rules(list_names, mode):
            for lname in list_names:
                for r in self.lists_data.get(lname, set()): 
                    r_type = engine.add_rule(r, mode, list_name=lname)
                    if count_stats:
                        counts[r_type] = counts.get(r_type, 0) + 1

        if 'allow' in policy_config:
            apply_rules(policy_config['allow'], 'allow')
        if 'block' in policy_config:
            apply_rules(policy_config['block'], 'block')
        
        engine.set_type_filters(policy_config.get('allowed_types', []), policy_config.get('blocked_types', []))
        
        if count_stats:
            logger.debug(f"Policy '{policy_name}' Loaded: {counts['domain']} Domains, {counts['ip']} IPs, {counts['cidr']} CIDRs, {counts['regex']} Regex, {counts['ans_domain']} Ans-Dom, {counts['ans_regex']} Ans-Reg")
        else:
            logger.info(f"Policy '{policy_name}' compiled.")
            
        return engine



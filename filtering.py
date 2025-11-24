#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.1
# Updated: 2025-11-25 08:00:00
# -----------------------------------------------------------------------------

import regex
import aiohttp
import asyncio
import os
import time
import hashlib
import logging
import ipaddress
import json
from urllib.parse import urlparse
from dnslib import QTYPE
from utils import logger

# -----------------------------------------------------------------------------
# Domain Trie Data Structure
# -----------------------------------------------------------------------------
class DomainTrie:
    __slots__ = ('root',)
    def __init__(self): self.root = {} 

    def insert(self, domain_rule, rule_data=None, list_name="Unknown"):
        is_inclusive = domain_rule.startswith('.')
        is_exclusive = domain_rule.startswith('*.')
        clean_domain = domain_rule.lstrip('.*')
        parts = clean_domain.split('.')[::-1]
        
        node = self.root
        for part in parts:
            if part not in node: node[part] = {}
            node = node[part]
        
        data = {'rule': rule_data or domain_rule, 'list': list_name}
        if is_exclusive: node['_wild'] = data 
        elif is_inclusive:
            node['_end'] = data 
            node['_wild'] = data 
        else: node['_end'] = data 

    def match(self, domain):
        parts = domain.rstrip('.').split('.')[::-1]
        node = self.root
        last_wildcard_data = None

        for part in parts:
            if '_wild' in node: last_wildcard_data = node['_wild']
            if part in node: node = node[part]
            else: return last_wildcard_data
        
        if '_end' in node: return node['_end']
        if '_wild' in node: return node['_wild']
        return last_wildcard_data

# -----------------------------------------------------------------------------
# Domain Categorization
# -----------------------------------------------------------------------------
class DomainCategorizer:
    def __init__(self, categories_file="categories.json"):
        self.categories = {}
        self.regex_cache = {}
        
        if os.path.exists(categories_file):
            try:
                with open(categories_file, 'r') as f:
                    self.categories = json.load(f)
                
                for cat, data in self.categories.items():
                    if 'regex' in data:
                        self.regex_cache[cat] = []
                        for r_str in data['regex']:
                            try: self.regex_cache[cat].append(regex.compile(r_str))
                            except Exception as e: logger.warning(f"Invalid regex in category '{cat}': {e}")
                
                logger.info(f"Loaded {len(self.categories)} categories from {categories_file}")
            except Exception as e: logger.error(f"Failed to load categories file: {e}")
        else: logger.warning(f"Categories file not found: {categories_file}")

    def categorize(self, domain):
        results = {}
        domain_lower = domain.lower().rstrip('.')
        parts = domain_lower.replace('-', '.').split('.')
        tld = parts[-1] if parts else ""
        
        for category, data in self.categories.items():
            score = 0
            if 'tlds' in data and tld in data['tlds']: score = max(score, 90)

            if category in self.regex_cache:
                for pattern in self.regex_cache[category]:
                    if pattern.search(domain_lower):
                        score = max(score, 100)
                        break
            
            if 'keywords' in data:
                for kw in data['keywords']:
                    kw_lower = kw.lower()
                    if kw_lower in parts: score = max(score, 95)
                    elif kw_lower in domain_lower: pass

            if score > 0: results[category] = score
        return results

# -----------------------------------------------------------------------------
# Rules & Parsing
# -----------------------------------------------------------------------------
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

    def set_type_filters(self, allowed, blocked):
        if allowed:
            for t in allowed:
                try: self.allowed_types.add(getattr(QTYPE, t.upper()))
                except AttributeError: logger.warning(f"Unknown QTYPE in allowed list: {t}")
        if blocked:
            for t in blocked:
                try: self.blocked_types.add(getattr(QTYPE, t.upper()))
                except AttributeError: logger.warning(f"Unknown QTYPE in blocked list: {t}")

    def set_category_rules(self, rules_config):
        if not rules_config: return
        self.category_rules = rules_config

    def check_type(self, qtype):
        if self.allowed_types:
            if qtype not in self.allowed_types: return True, f"Type {QTYPE[qtype]} NOT in allowed list", "PolicyTypeFilter"
            return False, None, None
        if self.blocked_types:
            if qtype in self.blocked_types: return True, f"Type {QTYPE[qtype]} IS in blocked list", "PolicyTypeFilter"
        return False, None, None

    def add_rule(self, rule_text, list_type='block', list_name="Unknown"):
        rule_text = rule_text.strip()
        if not rule_text or rule_text.startswith('#'): return "ignored"
        is_answer_only = rule_text.startswith('@')
        clean_rule_text = rule_text[1:] if is_answer_only else rule_text

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
            except Exception as e: logger.warning(f"Invalid regex rule {rule_text}: {e}")
            return "ignored"

        try:
            net = ipaddress.ip_network(clean_rule_text, strict=False)
            target = self.answer_block_ips if list_type == 'block' else self.allow_ips
            target.append((net, rule_text, list_name))
            if '/' in clean_rule_text: return "cidr"
            return "ip"
        except ValueError: pass

        if is_answer_only:
             target = self.answer_block_trie
             rtype = "ans_domain"
        else:
             target = self.block_trie if list_type == 'block' else self.allow_trie
             rtype = "domain"
        target.insert(clean_rule_text, rule_data=rule_text, list_name=list_name)
        return rtype

    def is_blocked(self, qname):
        qname = qname.lower().rstrip('.')
        
        if self.category_rules and self.categorizer:
            scores = self.categorizer.categorize(qname)
            for cat, score in scores.items():
                if cat in self.category_rules:
                    rule = self.category_rules[cat]
                    threshold = rule.get('min_confidence', 0)
                    action = rule.get('action', 'ALLOW')
                    if score >= threshold:
                        return action, f"Cat: {cat}, Score: {score}%", f"min_confidence: {threshold}"

        for pat, original_rule, list_name in self.allow_regex:
            if pat.search(qname): return "ALLOW", original_rule, list_name
        
        match = self.allow_trie.match(qname)
        if match: return "ALLOW", match['rule'], match['list']
        
        for pat, original_rule, list_name in self.block_regex:
            if pat.search(qname): return "BLOCK", original_rule, list_name

        match = self.block_trie.match(qname)
        if match: return "BLOCK", match['rule'], match['list']
        return "PASS", None, None

    def check_answer(self, qname, ip_str):
        if ip_str:
            try:
                ip = ipaddress.ip_address(ip_str)
                for net, rule, list_name in self.answer_block_ips:
                    if ip in net: return True, rule, list_name
            except ValueError: pass 
        
        if qname:
            qname = str(qname).lower().rstrip('.')
            for pat, original_rule, list_name in self.answer_block_regex:
                if pat.search(qname): return True, original_rule, list_name
            
            match = self.answer_block_trie.match(qname)
            if match: return True, match['rule'], match['list']
        return False, None, None

class ListManager:
    def __init__(self, cache_dir="./list_cache", refresh_interval=86400, categories_file="categories.json"):
        self.lists_data = {} 
        self.cache_dir = cache_dir
        self.refresh_interval = refresh_interval
        self.categories_file = categories_file
        if not os.path.exists(self.cache_dir): os.makedirs(self.cache_dir)

    def _get_cache_path(self, source_url):
        hash_name = hashlib.md5(source_url.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, hash_name + ".txt")

    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path): return False
        if time.time() - os.path.getmtime(cache_path) > self.refresh_interval: return False
        return True

    async def update_lists(self, list_config):
        for name, sources in list_config.items():
            rules = set()
            for source in sources:
                if isinstance(source, dict):
                    source_url = source.get('source')
                    domain_type = source.get('hosts_domain_type', 'exact')
                else:
                    source_url = source
                    domain_type = 'exact'
                
                content = ""
                cache_path = ""
                try:
                    if source_url.startswith(('http://', 'https://')):
                        cache_path = self._get_cache_path(source_url)
                        if self._is_cache_valid(cache_path):
                            logger.info(f"Loading cached list '{name}': {source_url}")
                            with open(cache_path, 'r', encoding='utf-8') as f: content = f.read()
                        else:
                            logger.info(f"Fetching list '{name}': {source_url}")
                            async with aiohttp.ClientSession() as session:
                                async with session.get(source_url, timeout=15) as resp:
                                    if resp.status == 200:
                                        content = await resp.text()
                                        with open(cache_path, 'w', encoding='utf-8') as f: f.write(content)
                                    else:
                                        logger.warning(f"Failed to fetch {source_url}: {resp.status}")
                                        if os.path.exists(cache_path):
                                            logger.warning(f"Using stale cache for {source_url}")
                                            with open(cache_path, 'r', encoding='utf-8') as f: content = f.read()
                    else:
                        if os.path.exists(source_url):
                            with open(source_url, 'r', encoding='utf-8') as f: content = f.read()
                        else: logger.warning(f"File not found: {source_url}")
                    
                    if content:
                        parsed_rules = self._parse_content(content, domain_type)
                        if logger.isEnabledFor(logging.DEBUG):
                            type_counts = {'domain': 0, 'ip': 0, 'cidr': 0, 'regex': 0, 'ans_domain': 0, 'ans_regex': 0}
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
                            stats_msg = (f"Source '{source_url}' parsed: {type_counts['domain']} Domains, {type_counts['ip']} IPs, "
                                         f"{type_counts['cidr']} CIDRs, {type_counts['regex']} Regex, "
                                         f"{type_counts['ans_domain']} Ans-Dom, {type_counts['ans_regex']} Ans-Reg")
                            logger.debug(stats_msg)
                        rules.update(parsed_rules)
                except Exception as e:
                    logger.error(f"Error loading source {source_url}: {e}")
                    if cache_path and os.path.exists(cache_path):
                         with open(cache_path, 'r', encoding='utf-8') as f:
                             parsed = self._parse_content(f.read(), domain_type)
                             rules.update(parsed)
            self.lists_data[name] = rules
            logger.info(f"List '{name}' consolidated with {len(rules)} unique rules.")

    def _is_ip_or_cidr(self, text):
        try:
            ipaddress.ip_network(text, strict=False)
            return True
        except ValueError: return False

    def _parse_content(self, text, hosts_domain_type='exact'):
        valid_rules = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'): continue
            clean_check = line[1:] if line.startswith('@') else line
            if clean_check.startswith('/') and clean_check.endswith('/'):
                valid_rules.add(line)
                continue
            if '#' in line: line = line.split('#')[0].strip()
            parts = line.split()
            if not parts: continue
            if parts[0] in ['0.0.0.0', '127.0.0.1', '::']:
                if len(parts) >= 2: 
                    domain = parts[1]
                    if hosts_domain_type == 'inclusive': domain = '.' + domain.lstrip('.')
                    elif hosts_domain_type == 'exclusive': domain = '*.' + domain.lstrip('.')
                    valid_rules.add(domain)
            elif len(parts) == 1: valid_rules.add(parts[0])
            else: valid_rules.add(parts[0])
        return valid_rules

    def compile_policy(self, policy_name, policy_config):
        engine = RuleEngine()
        engine.categorizer = DomainCategorizer(self.categories_file)
        count_stats = logger.isEnabledFor(logging.DEBUG)
        counts = {'domain': 0, 'ip': 0, 'cidr': 0, 'regex': 0, 'ans_domain': 0, 'ans_regex': 0, 'ignored': 0}

        def apply_rules(list_names, mode):
            for lname in list_names:
                for r in self.lists_data.get(lname, set()): 
                    r_type = engine.add_rule(r, mode, list_name=lname)
                    if count_stats: counts[r_type] = counts.get(r_type, 0) + 1

        if 'allow' in policy_config: apply_rules(policy_config['allow'], 'allow')
        if 'block' in policy_config: apply_rules(policy_config['block'], 'block')
        engine.set_type_filters(policy_config.get('allowed_types', []), policy_config.get('blocked_types', []))
        if 'category_rules' in policy_config:
            engine.set_category_rules(policy_config['category_rules'])

        if count_stats:
            logger.debug(f"Policy '{policy_name}' Loaded: {counts['domain']} Domains, {counts['ip']} IPs, {counts['cidr']} CIDRs, "
                         f"{counts['regex']} Regex, {counts['ans_domain']} Ans-Dom, {counts['ans_regex']} Ans-Reg")
        else:
            logger.info(f"Policy '{policy_name}' compiled.")
        return engine


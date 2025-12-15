#!/usr/bin/env python3
# filename: list_manager.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 5.3.1 (Extended Logging)
# -----------------------------------------------------------------------------
"""
List Management with prioritized compilation order.
Ensures ALLOW > BLOCK > DROP priority by applying rules in specific sequence.
Includes extended logging for rule compilation.
"""

import os
import time
import hashlib
import ipaddress
import pickle
import urllib.request
from utils import get_logger
from validation import is_valid_domain

logger = get_logger("ListManager")

class ListManager:
    def __init__(self, cache_dir="./list_cache", refresh_interval=86400, categories_file="categories.json"):
        self.lists_data = {} 
        self.cache_dir = cache_dir
        self.refresh_interval = refresh_interval if refresh_interval else 86400
        self.categories_file = categories_file
        if not os.path.exists(self.cache_dir): 
            os.makedirs(self.cache_dir)
        logger.info(f"ListManager initialized. Cache: {os.path.abspath(self.cache_dir)}")

    def _get_cache_path(self, source_url, ext=".pkl"):
        hash_name = hashlib.md5(source_url.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, hash_name + ext)

    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path): 
            return False
        age = time.time() - os.path.getmtime(cache_path)
        if age > self.refresh_interval: 
            return False
        return True

    def _load_processed_cache(self, cache_path):
        try:
            with open(cache_path, 'rb') as f:
                return pickle.load(f)
        except Exception:
            return None

    def _save_processed_cache(self, cache_path, rules_set):
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(rules_set, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.error(f"Failed to save processed cache: {e}")

    async def _fetch_url(self, url):
        import asyncio
        loop = asyncio.get_running_loop()
        try:
            content = await loop.run_in_executor(None, self._fetch_sync, url)
            return content
        except Exception as e:
            logger.warning(f"Fetch failed: {e}")
            return None

    def _fetch_sync(self, url):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
        except Exception:
            pass
        return None

    async def update_lists(self, list_config):
        if not list_config:
            return

        logger.info(f"Starting update for {len(list_config)} lists...")

        for name, sources in list_config.items():
            rules = set()
            
            for source in sources:
                if isinstance(source, dict):
                    source_url = source.get('source')
                    domain_type = source.get('hosts_domain_type', 'exact')
                else:
                    source_url = source
                    domain_type = 'exact'
                
                content = None
                cache_path_raw = ""
                
                try:
                    if source_url.startswith(('http://', 'https://')):
                        cache_path_pkl = self._get_cache_path(source_url, '.pkl')
                        cache_path_raw = self._get_cache_path(source_url, '.txt')
                        
                        if self._is_cache_valid(cache_path_pkl):
                            parsed_rules = self._load_processed_cache(cache_path_pkl)
                            if parsed_rules:
                                rules.update(parsed_rules)
                                logger.debug(f"Loaded processed cache for {source_url} ({len(parsed_rules)} rules)")
                                continue
                        
                        if self._is_cache_valid(cache_path_raw):
                            with open(cache_path_raw, 'r', encoding='utf-8') as f: 
                                content = f.read()
                            logger.debug(f"Loaded raw cache for {source_url}")
                        else:
                            logger.info(f"Downloading: {source_url}")
                            content = await self._fetch_url(source_url)
                            if content:
                                with open(cache_path_raw, 'w', encoding='utf-8') as f: 
                                    f.write(content)
                            elif os.path.exists(cache_path_raw):
                                logger.warning(f"Download failed for {source_url}, using stale cache")
                                with open(cache_path_raw, 'r', encoding='utf-8') as f: 
                                    content = f.read()
                        
                        if content:
                            parsed_rules = self._parse_content(content, domain_type)
                            rules.update(parsed_rules)
                            self._save_processed_cache(cache_path_pkl, parsed_rules)
                            logger.debug(f"Parsed {len(parsed_rules)} rules from {source_url}")
                        
                    else:
                        if os.path.exists(source_url):
                            cache_path_pkl = self._get_cache_path(source_url, '.pkl')
                            if os.path.exists(cache_path_pkl) and os.path.getmtime(cache_path_pkl) > os.path.getmtime(source_url):
                                parsed_rules = self._load_processed_cache(cache_path_pkl)
                                if parsed_rules:
                                    rules.update(parsed_rules)
                                    logger.debug(f"Loaded local processed cache for {source_url} ({len(parsed_rules)} rules)")
                                    continue
                            
                            logger.info(f"Loading local file: {source_url}")
                            with open(source_url, 'r', encoding='utf-8') as f: 
                                content = f.read()
                            parsed_rules = self._parse_content(content, domain_type)
                            rules.update(parsed_rules)
                            self._save_processed_cache(cache_path_pkl, parsed_rules)
                            logger.debug(f"Parsed {len(parsed_rules)} rules from {source_url}")
                        else:
                            logger.warning(f"Local file not found: {source_url}")

                except Exception as e:
                    logger.error(f"Error processing {source_url}: {e}")
            
            self.lists_data[name] = rules
            logger.info(f"Loaded list '{name}': {len(rules)} unique rules")

    def _parse_content(self, text, hosts_domain_type='exact'):
        valid_rules = set()
        lines = text.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '!')):
                continue
            
            if '#' in line:
                line = line.split('#')[0].strip()
                if not line: continue
            
            if line.startswith('@') or (line.startswith('/') and line.endswith('/')):
                valid_rules.add(line)
                continue
            
            parts = line.split()
            domain = parts[1] if (len(parts) >= 2 and parts[0] in ('127.0.0.1', '0.0.0.0', '::1', '::')) else parts[0]
            domain = domain.lower().strip('.')
            
            try:
                ipaddress.ip_address(domain)
                continue 
            except ValueError:
                pass
            
            if is_valid_domain(domain):
                if hosts_domain_type == 'inclusive':
                    domain = '.' + domain
                elif hosts_domain_type == 'exclusive':
                    domain = '*.' + domain
                valid_rules.add(domain)
        
        return valid_rules

    def compile_policy(self, policy_name, policy_config):
        """
        Compile policy by applying rules in strict priority order.
        Order of Application: DROP -> BLOCK -> ALLOW
        This ensures that ALLOW rules (applied last) overwrite BLOCK/DROP rules in Trie/IntervalTree.
        """
        from filtering import RuleEngine, DomainCategorizer
        
        engine = RuleEngine()
        engine.categorizer = DomainCategorizer(self.categories_file)

        logger.info(f"Compiling Policy: {policy_name}")

        def apply_rules(list_names, action):
            count = 0
            for lname in list_names:
                if lname not in self.lists_data:
                    logger.warning(f"  - List '{lname}' not found")
                    continue
                rules_set = self.lists_data[lname]
                for r in rules_set:
                    engine.add_rule(r, action=action, list_name=lname)
                    count += 1
            if count > 0:
                logger.info(f"  + Applied {action}: {count} rules from {list_names}")
            else:
                logger.debug(f"  + Applied {action}: 0 rules")

        allow_lists = policy_config.get('allow', [])
        block_lists = policy_config.get('block', [])
        drop_lists = policy_config.get('drop', [])

        # Priority Strategy: Last Write Wins
        # 1. Apply DROP (Lowest priority overwrite)
        if drop_lists:
            apply_rules(drop_lists, 'DROP')
            
        # 2. Apply BLOCK (Overwrites DROP)
        if block_lists:
            apply_rules(block_lists, 'BLOCK')
            
        # 3. Apply ALLOW (Highest priority - Overwrites BLOCK & DROP)
        if allow_lists:
            apply_rules(allow_lists, 'ALLOW')

        category_rules = policy_config.get('category_rules', {})
        if category_rules:
            logger.info(f"  + Configuring {len(category_rules)} category rules")
            engine.set_category_rules(category_rules)
        
        return engine

    def get_list_rules(self, list_name):
        return self.lists_data.get(list_name, set())


#!/usr/bin/env python3
# filename: list_manager.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 5.2.0 (Binary Cache + GeoIP Cache)
# -----------------------------------------------------------------------------
"""
List Management with pre-processed binary cache for instant loading.
Caches both blocklists and compiled policy engines.
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
        logger.info(f"ListManager initialized. Cache: {os.path.abspath(self.cache_dir)}, Refresh: {self.refresh_interval}s")

    def _get_cache_path(self, source_url, ext=".pkl"):
        hash_name = hashlib.md5(source_url.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, hash_name + ext)

    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path): 
            return False
        age = time.time() - os.path.getmtime(cache_path)
        if age > self.refresh_interval: 
            logger.debug(f"Cache expired: {cache_path} (Age: {age:.1f}s)")
            return False
        return True

    def _load_processed_cache(self, cache_path):
        """Load pre-processed set from binary cache"""
        try:
            with open(cache_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"Failed to load processed cache: {e}")
            return None

    def _save_processed_cache(self, cache_path, rules_set):
        """Save pre-processed set to binary cache"""
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump(rules_set, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.error(f"Failed to save processed cache: {e}")

    async def _fetch_url(self, url):
        import asyncio
        loop = asyncio.get_running_loop()
        try:
            start_time = time.time()
            content = await loop.run_in_executor(None, self._fetch_sync, url)
            duration = time.time() - start_time
            if content:
                logger.info(f"Downloaded {len(content)} bytes in {duration:.2f}s")
            return content
        except Exception as e:
            logger.warning(f"Fetch failed: {e}")
            return None

    def _fetch_sync(self, url):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
                else:
                    logger.warning(f"HTTP {response.status}")
        except Exception as e:
            logger.warning(f"HTTP Exception: {e}")
        return None

    async def update_lists(self, list_config):
        if not list_config:
            logger.info("No lists configured.")
            return

        logger.info(f"Starting update for {len(list_config)} lists...")

        for name, sources in list_config.items():
            rules = set()
            logger.debug(f"Processing '{name}' ({len(sources)} sources)")
            
            for source in sources:
                if isinstance(source, dict):
                    source_url = source.get('source')
                    domain_type = source.get('hosts_domain_type', 'exact')
                else:
                    source_url = source
                    domain_type = 'exact'
                
                content = None
                cache_path = ""
                
                try:
                    if source_url.startswith(('http://', 'https://')):
                        cache_path_pkl = self._get_cache_path(source_url, '.pkl')
                        cache_path_raw = self._get_cache_path(source_url, '.txt')
                        
                        # Try pre-processed cache first
                        if self._is_cache_valid(cache_path_pkl):
                            logger.info(f"Loading processed cache: {source_url}")
                            parsed_rules = self._load_processed_cache(cache_path_pkl)
                            if parsed_rules:
                                rules.update(parsed_rules)
                                logger.debug(f"Loaded {len(parsed_rules)} rules")
                                continue
                        
                        # Check raw cache
                        if self._is_cache_valid(cache_path_raw):
                            logger.info(f"Loading raw cache: {source_url}")
                            with open(cache_path_raw, 'r', encoding='utf-8') as f: 
                                content = f.read()
                        else:
                            logger.info(f"Downloading: {source_url}")
                            content = await self._fetch_url(source_url)
                            if content:
                                with open(cache_path_raw, 'w', encoding='utf-8') as f: 
                                    f.write(content)
                            elif os.path.exists(cache_path_raw):
                                logger.warning(f"Download failed, using stale cache")
                                with open(cache_path_raw, 'r', encoding='utf-8') as f: 
                                    content = f.read()
                        
                        if content:
                            parsed_rules = self._parse_content(content, domain_type)
                            rules.update(parsed_rules)
                            self._save_processed_cache(cache_path_pkl, parsed_rules)
                            logger.debug(f"Parsed {len(parsed_rules)} rules")
                        
                    else:
                        # Local file
                        if os.path.exists(source_url):
                            cache_path_pkl = self._get_cache_path(source_url, '.pkl')
                            
                            # Use processed cache if newer than source
                            if os.path.exists(cache_path_pkl):
                                if os.path.getmtime(cache_path_pkl) > os.path.getmtime(source_url):
                                    logger.info(f"Loading local cache: {source_url}")
                                    parsed_rules = self._load_processed_cache(cache_path_pkl)
                                    if parsed_rules:
                                        rules.update(parsed_rules)
                                        continue
                            
                            logger.info(f"Loading: {os.path.abspath(source_url)}")
                            with open(source_url, 'r', encoding='utf-8') as f: 
                                content = f.read()
                            parsed_rules = self._parse_content(content, domain_type)
                            rules.update(parsed_rules)
                            self._save_processed_cache(cache_path_pkl, parsed_rules)
                        else:
                            logger.warning(f"Not found: {source_url}")

                except Exception as e:
                    logger.error(f"Error processing {source_url}: {e}")
                    # Fallback to stale cache
                    if cache_path and os.path.exists(cache_path):
                        logger.info(f"Fallback to stale cache")
                        try:
                            with open(cache_path, 'r', encoding='utf-8') as f:
                                parsed = self._parse_content(f.read(), domain_type)
                                rules.update(parsed)
                        except Exception as fb_err:
                            logger.error(f"Fallback failed: {fb_err}")
            
            self.lists_data[name] = rules
            logger.info(f"'{name}': {len(rules)} unique rules")

    def _parse_content(self, text, hosts_domain_type='exact'):
        valid_rules = set()
        invalid_count = 0
        lines = text.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '!')):
                continue
            
            # Remove inline comments
            if '#' in line and not line.startswith('#'):
                line = line.split('#')[0].strip()
                if not line:
                    continue
            
            # GeoIP tags (@TAG, @@TAG, @AS123)
            if line.startswith('@'):
                valid_rules.add(line)
                continue
            
            # Regex patterns
            if line.startswith('/') and line.endswith('/'):
                valid_rules.add(line)
                continue
            
            # Extract domain from various formats
            parts = line.split()
            if len(parts) >= 2:
                # hosts file format: IP domain
                domain = parts[1] if parts[0] in ('127.0.0.1', '0.0.0.0', '::1', '::') else parts[0]
            else:
                domain = parts[0]
            
            domain = domain.lower().strip('.')
            
            # Skip if it's an IP address
            try:
                ipaddress.ip_address(domain)
                continue  # Skip IPs in domain column
            except ValueError:
                pass  # Not an IP, continue
            
            # Validate domain
            if is_valid_domain(domain):
                # Apply domain type prefix
                if hosts_domain_type == 'inclusive':
                    domain = '.' + domain
                elif hosts_domain_type == 'exclusive':
                    domain = '*.' + domain
                valid_rules.add(domain)
            else:
                invalid_count += 1
        
        if invalid_count > 0:
            logger.warning(f"Skipped {invalid_count} invalid entries")
        
        return valid_rules

    def compile_policy(self, policy_name, policy_config):
        """Compile policy with consolidated action handling - uses cache when possible"""
        from filtering import RuleEngine, DomainCategorizer
        
        # Generate cache hash from policy config + lists content
        import json
        config_str = json.dumps(policy_config, sort_keys=True)
        lists_hash = hashlib.md5()
        
        # Include list names and their sizes in hash
        for action in ['allow', 'block', 'drop']:
            for list_name in policy_config.get(action, []):
                if list_name in self.lists_data:
                    lists_hash.update(f"{list_name}:{len(self.lists_data[list_name])}".encode())
        
        combined_hash = hashlib.md5(
            (config_str + lists_hash.hexdigest()).encode()
        ).hexdigest()
        
        cache_path = os.path.join(self.cache_dir, f"policy_{policy_name}_{combined_hash}.engine")
        
        # Try loading cached engine
        if os.path.exists(cache_path):
            try:
                logger.info(f"Loading cached policy: {policy_name}")
                with open(cache_path, 'rb') as f:
                    engine = pickle.load(f)
                # Restore categorizer reference (not pickled)
                engine.categorizer = DomainCategorizer(self.categories_file)
                logger.info(f"✓ Loaded compiled policy '{policy_name}' from cache")
                return engine
            except Exception as e:
                logger.warning(f"Failed to load policy cache: {e}, recompiling...")
        
        # Compile fresh engine
        engine = RuleEngine()
        engine.categorizer = DomainCategorizer(self.categories_file)

        logger.info(f"Compiling Policy: {policy_name}")

        def apply_rules(list_names, action):
            """Apply rules with specified action"""
            count = 0
            geoip_query_count = 0
            geoip_answer_count = 0
        
            for lname in list_names:
                if lname not in self.lists_data:
                    logger.warning(f"  - List '{lname}' not found")
                    continue
                
                rules_set = self.lists_data[lname]
                logger.debug(f"  - '{lname}' ({len(rules_set)} rules) → {action}")
            
                for r in rules_set:
                    result = engine.add_rule(r, action=action, list_name=lname)
                    if result == 'geoip':
                        if r.startswith('@@'):
                            geoip_answer_count += 1
                        elif r.startswith('@'):
                            geoip_query_count += 1
                        else:
                            count += 1
                    else:
                        count += 1
        
            if count > 0:
                logger.info(f"  ✓ {action}: {count:,} domain rules")
            if geoip_query_count > 0:
                logger.info(f"  ✓ {action}: {geoip_query_count:,} GeoIP query rules")
            if geoip_answer_count > 0:
                logger.info(f"  ✓ {action}: {geoip_answer_count:,} GeoIP answer rules")

        # Apply policy lists
        allow_lists = policy_config.get('allow', [])
        block_lists = policy_config.get('block', [])
        drop_lists = policy_config.get('drop', [])

        if allow_lists:
            apply_rules(allow_lists, 'ALLOW')
        if block_lists:
            apply_rules(block_lists, 'BLOCK')
        if drop_lists:
            apply_rules(drop_lists, 'DROP')

        # Category rules
        category_rules = policy_config.get('category_rules', {})
        if category_rules:
            logger.info(f"  Category rules: {len(category_rules)}")
            engine.set_category_rules(category_rules)
        
        # Save compiled engine to cache
        try:
            # Temporarily remove categorizer before pickling (can't pickle it)
            categorizer = engine.categorizer
            engine.categorizer = None
            with open(cache_path, 'wb') as f:
                pickle.dump(engine, f, protocol=pickle.HIGHEST_PROTOCOL)
            engine.categorizer = categorizer
            logger.debug(f"Saved policy cache: {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save policy cache: {e}")

        return engine

    def get_list_rules(self, list_name):
        return self.lists_data.get(list_name, set())


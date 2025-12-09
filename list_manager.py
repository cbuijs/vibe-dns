#!/usr/bin/env python3
# filename: list_manager.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 5.0.0 (Consolidated Action Handling)
# -----------------------------------------------------------------------------
"""
List Management Module with consolidated action handling.
"""

import os
import time
import hashlib
import ipaddress
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
        logger.info(f"ListManager initialized. Cache Dir: {os.path.abspath(self.cache_dir)}, Refresh Interval: {self.refresh_interval}s")

    def _get_cache_path(self, source_url):
        hash_name = hashlib.md5(source_url.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, hash_name + ".txt")

    def _is_cache_valid(self, cache_path):
        if not os.path.exists(cache_path): 
            logger.debug(f"Cache miss (not found): {cache_path}")
            return False
        age = time.time() - os.path.getmtime(cache_path)
        if age > self.refresh_interval: 
            logger.debug(f"Cache expired: {cache_path} (Age: {age:.1f}s > {self.refresh_interval}s)")
            return False
        logger.debug(f"Cache hit: {cache_path} (Age: {age:.1f}s)")
        return True

    async def _fetch_url(self, url):
        import asyncio
        loop = asyncio.get_running_loop()
        try:
            logger.debug(f"Fetching URL: {url}")
            start_time = time.time()
            content = await loop.run_in_executor(None, self._fetch_sync, url)
            duration = time.time() - start_time
            if content:
                logger.info(f"Downloaded {len(content)} bytes from {url} in {duration:.2f}s")
            return content
        except Exception as e:
            logger.warning(f"Fetch failed for {url}: {e}")
            return None

    def _fetch_sync(self, url):
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
                else:
                    logger.warning(f"HTTP Error {response.status} fetching {url}")
        except Exception as e:
            logger.warning(f"HTTP Exception fetching {url}: {e}")
        return None

    async def update_lists(self, list_config):
        if not list_config:
            logger.info("No lists configured.")
            return

        total_lists = len(list_config)
        logger.info(f"Starting update for {total_lists} lists...")

        for name, sources in list_config.items():
            rules = set()
            logger.debug(f"Processing list group: '{name}' with {len(sources)} sources")
            
            for source in sources:
                if isinstance(source, dict):
                    source_url = source.get('source')
                    domain_type = source.get('hosts_domain_type', 'exact')
                else:
                    source_url = source
                    domain_type = 'exact'
                
                logger.debug(f" - Source: {source_url} (Type: {domain_type})")
                
                content = None
                cache_path = ""
                try:
                    if source_url.startswith(('http://', 'https://')):
                        cache_path = self._get_cache_path(source_url)
                        if self._is_cache_valid(cache_path):
                            logger.info(f"Loading cached: {source_url}")
                            with open(cache_path, 'r', encoding='utf-8') as f: 
                                content = f.read()
                        else:
                            logger.info(f"Downloading: {source_url}")
                            content = await self._fetch_url(source_url)
                            if content:
                                with open(cache_path, 'w', encoding='utf-8') as f: 
                                    f.write(content)
                                logger.debug(f"Saved to cache: {cache_path}")
                            elif os.path.exists(cache_path):
                                logger.warning(f"Download failed, using stale cache for {source_url}")
                                with open(cache_path, 'r', encoding='utf-8') as f: 
                                    content = f.read()
                    else:
                        if os.path.exists(source_url):
                            abs_path = os.path.abspath(source_url)
                            logger.info(f"Loading local file: {abs_path}")
                            with open(source_url, 'r', encoding='utf-8') as f: 
                                content = f.read()
                        else: 
                            logger.warning(f"File not found: {source_url}")
                    
                    if content:
                        parsed_rules = self._parse_content(content, domain_type)
                        rules.update(parsed_rules)
                        logger.debug(f"Parsed {len(parsed_rules)} rules from {source_url}")
                    else:
                        logger.warning(f"No content loaded for {source_url}")

                except Exception as e:
                    logger.error(f"Error processing source {source_url}: {e}")
                    if cache_path and os.path.exists(cache_path):
                         logger.info(f"Fallback: Loading stale cache for {source_url}")
                         try:
                             with open(cache_path, 'r', encoding='utf-8') as f:
                                 parsed = self._parse_content(f.read(), domain_type)
                                 rules.update(parsed)
                         except Exception as fallback_error:
                             logger.error(f"Fallback also failed: {fallback_error}")
            
            self.lists_data[name] = rules
            logger.info(f"List '{name}' consolidated: {len(rules)} unique rules.")

    def _parse_content(self, text, hosts_domain_type='exact'):
        valid_rules = set()
        invalid_count = 0
        lines = text.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('!'): 
                continue
            
            # Keep original @ or @@ prefix
            clean_check = line
            if line.startswith('@@'):
                clean_check = line[2:]
            elif line.startswith('@'):
                clean_check = line[1:]
            
            # GeoIP rules: @@COUNTRY (both), @COUNTRY (query only)
            if line.startswith('@@') or (line.startswith('@') and not line.startswith('@@')):
                if clean_check:
                    valid_rules.add(line)
                    continue
            
            # Regex rules
            if clean_check.startswith('/') and clean_check.endswith('/'):
                valid_rules.add(line)
                continue
            
            if '#' in line: 
                line = line.split('#')[0].strip()
            
            parts = line.split()
            if not parts: 
                continue
            
            domain = None
            
            if parts[0] in ['0.0.0.0', '127.0.0.1', '::', '::1']:
                if len(parts) >= 2: 
                    domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
            else:
                domain = parts[0] 

            if domain:
                domain = domain.lower().strip()
                
                try:
                    ipaddress.ip_address(domain)
                    continue
                except ValueError:
                    pass
                
                if not is_valid_domain(domain, allow_underscores=False):
                    invalid_count += 1
                    if invalid_count <= 10:
                        logger.debug(f"Invalid domain on line {line_num}: {domain}")
                    continue
                
                if hosts_domain_type == 'inclusive' and not domain.startswith('.'):
                    domain = '.' + domain
                elif hosts_domain_type == 'exclusive' and not domain.startswith('*.'):
                    domain = '*.' + domain
                
                valid_rules.add(domain)
        
        if invalid_count > 0:
            logger.warning(f"Skipped {invalid_count} invalid domain entries")
                
        return valid_rules

    def compile_policy(self, policy_name, policy_config):
        """Compile policy with consolidated action handling"""
        from filtering import RuleEngine, DomainCategorizer
        engine = RuleEngine()
        engine.categorizer = DomainCategorizer(self.categories_file)
    
        logger.info(f"Compiling Policy: {policy_name}")

        def apply_rules(list_names, action):
            """Apply rules with specified action"""
            count = 0
            geoip_query_count = 0
            geoip_answer_count = 0
            
            for lname in list_names:
                rules_set = self.lists_data.get(lname, set())
                logger.debug(f"  - Applying list '{lname}' ({len(rules_set)} rules) as {action}")
                
                for r in rules_set:
                    result = engine.add_rule(r, action=action, list_name=lname)
                    if result == 'geoip':
                        if r.startswith('@@'):
                            geoip_answer_count += 1
                        elif r.startswith('@'):
                            geoip_query_count += 1
                
                count += len(rules_set)
            
            return count, geoip_query_count, geoip_answer_count

        a_count = 0
        b_count = 0
        d_count = 0
        total_geoip_query = 0
        total_geoip_answer = 0
    
        if 'allow' in policy_config: 
            logger.debug(f"Processing Allow lists for {policy_name}: {policy_config['allow']}")
            a_count, _, _ = apply_rules(policy_config['allow'], 'ALLOW')
    
        if 'block' in policy_config: 
            logger.debug(f"Processing Block lists for {policy_name}: {policy_config['block']}")
            b_count, block_query_geo, block_answer_geo = apply_rules(policy_config['block'], 'BLOCK')
            total_geoip_query += block_query_geo
            total_geoip_answer += block_answer_geo
    
        if 'drop' in policy_config:
            logger.debug(f"Processing Drop lists for {policy_name}: {policy_config['drop']}")
            d_count, drop_query_geo, drop_answer_geo = apply_rules(policy_config['drop'], 'DROP')
            total_geoip_query += drop_query_geo
            total_geoip_answer += drop_answer_geo
    
        allowed_types = policy_config.get('allowed_types', [])
        blocked_types = policy_config.get('blocked_types', [])
        dropped_types = policy_config.get('dropped_types', [])
    
        engine.set_type_filters(allowed_types, blocked_types, dropped_types)
    
        if allowed_types: 
            logger.debug(f"  - Allowed QTypes: {allowed_types}")
        if blocked_types: 
            logger.debug(f"  - Blocked QTypes: {blocked_types}")
        if dropped_types:
            logger.debug(f"  - Dropped QTypes: {dropped_types}")

        if 'category_rules' in policy_config:
            engine.set_category_rules(policy_config['category_rules'])
            logger.debug(f"  - Category Rules: {list(policy_config['category_rules'].keys())}")

        # Enhanced summary with GEO-IP stats
        summary = f"Policy '{policy_name}' Ready: {b_count} Block, {d_count} Drop, {a_count} Allow rules"
        total_geoip = total_geoip_query + total_geoip_answer
        if total_geoip > 0:
            summary += f" | 🌍 {total_geoip} GEO-IP rules ({total_geoip_query} query-only, {total_geoip_answer} answer-only)"
        
        logger.info(f"✓ {summary}")
        
        # Detailed GEO-IP logging
        stats = engine.get_stats()
        if stats.get('query_block_geoip', 0) > 0 or stats.get('query_drop_geoip', 0) > 0:
            logger.info(
                f"  → Query GeoIP: {stats.get('query_block_geoip', 0)} BLOCK, "
                f"{stats.get('query_drop_geoip', 0)} DROP (ccTLD-based, single @)"
            )
        if stats.get('answer_block_geoip', 0) > 0 or stats.get('answer_drop_geoip', 0) > 0:
            logger.info(
                f"  → Answer GeoIP: {stats.get('answer_block_geoip', 0)} BLOCK, "
                f"{stats.get('answer_drop_geoip', 0)} DROP (IP-based, double @@)"
            )
    
        return engine


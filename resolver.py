#!/usr/bin/env python3
# filename: resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 4.0.0 (Major Improvements)
# -----------------------------------------------------------------------------
"""
Core DNS Resolution & Processing Logic.

Major Changes:
- LRU (Least Recently Used) cache eviction strategy
- Enhanced CNAME loop detection with depth limits
- Better error handling and validation
- Improved cache management
"""

import asyncio
import time
import random
import ipaddress
import logging
from typing import Any, Optional
from collections import OrderedDict

# dnspython imports
import dns.message
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.rdata
import dns.edns
import dns.flags
import dns.name

from utils import get_logger, ContextAdapter, is_ip_in_network
from upstream_manager import UpstreamManager

logger = get_logger("Resolver")

class RateLimiter:
    """Tracks request rates per client IP/Subnet to prevent abuse"""
    def __init__(self, config: dict | None):
        config = config or {}
        self.enabled = config.get('enabled', True)
        self.window = config.get('window_seconds', 60)
        self.udp_thresh = config.get('udp_threshold', 100)
        self.total_thresh = config.get('total_threshold', 200)
        self.ipv4_mask = config.get('ipv4_mask', 32)
        self.ipv6_mask = config.get('ipv6_mask', 128)
        self.clients: dict[str, dict] = {}
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(self.window * 2)
            now = time.time()
            expired = [k for k, v in self.clients.items() if now - v['start'] > (self.window * 2)]
            for k in expired: del self.clients[k]

    def get_subnet_key(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                if self.ipv4_mask < 32: return str(ipaddress.IPv4Network((ip, self.ipv4_mask), strict=False))
            elif ip.version == 6:
                if self.ipv6_mask < 128: return str(ipaddress.IPv6Network((ip, self.ipv6_mask), strict=False))
            return str(ip)
        except Exception: return ip_str

    def check(self, ip: str, proto: str) -> str:
        if not self.enabled: return "ALLOW"
        subnet_key = self.get_subnet_key(ip)
        now = time.time()
        
        if subnet_key not in self.clients: self.clients[subnet_key] = {'start': now, 'udp': 0, 'total': 0}
        entry = self.clients[subnet_key]
        
        if now - entry['start'] > self.window:
            entry['start'], entry['udp'], entry['total'] = now, 0, 0
            
        entry['total'] += 1
        if proto == 'udp': entry['udp'] += 1
            
        if entry['total'] > self.total_thresh: return "DROP"
        if proto == 'udp' and entry['udp'] > self.udp_thresh: return "TC"
        return "ALLOW"

class RequestDeduplicator:
    """Coalesces identical concurrent requests"""
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.pending: dict[tuple, asyncio.Future] = {}

    async def get_or_process(self, key: tuple, worker_coroutine):
        if not self.enabled: return await worker_coroutine()
        
        if key in self.pending:
            return await self.pending[key]
            
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending[key] = future
        try:
            result = await worker_coroutine()
            if not future.done(): future.set_result(result)
            return result
        except Exception as e:
            if not future.done(): future.set_exception(e)
            raise e
        finally:
            if key in self.pending: del self.pending[key]

class DNSCache:
    """
    In-memory DNS cache with LRU eviction.
    Keys are: (qname, qtype, group, scope) to ensure group isolation.
    """
    def __init__(self, size, ttl_margin, negative_ttl, gc_interval=300, prefetch_min_hits=3):
        # Use OrderedDict for LRU tracking
        self.cache: OrderedDict[tuple, tuple[bytes, float, int]] = OrderedDict()
        self.size = size or 10000
        self.margin = ttl_margin or 0
        self.negative_ttl = negative_ttl or 60
        self.gc_interval = gc_interval
        self.prefetch_min_hits = prefetch_min_hits
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'writes': 0
        }
        
        asyncio.create_task(self.gc_loop())
        logger.info(f"DNS Cache initialized: size={self.size}, LRU eviction enabled")

    async def gc_loop(self):
        """Periodic cleanup of expired entries"""
        while True:
            await asyncio.sleep(self.gc_interval)
            now = time.time()
            
            # Find expired entries
            expired = []
            for k, v in list(self.cache.items()):
                if v[1] < now:
                    expired.append(k)
            
            # Remove expired
            if expired:
                for k in expired: 
                    del self.cache[k]
                self.stats['expirations'] += len(expired)
                logger.debug(f"Cache GC: Removed {len(expired)} expired entries. Total: {len(self.cache)}/{self.size}")

    def get(self, qname: str, qtype: int, group: str = "default", scope: str = "DEFAULT") -> tuple[dns.message.Message | None, float, int]:
        key = (qname, qtype, group, scope)
        
        if key in self.cache:
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            
            record_bytes, expire_time, hits = self.cache[key]
            now = time.time()
            ttl_remain = expire_time - now
            
            if ttl_remain > 0:
                try:
                    new_hits = hits + 1
                    # Update hit count
                    self.cache[key] = (record_bytes, expire_time, new_hits)
                    
                    msg = dns.message.from_wire(record_bytes)
                    for section in (msg.answer, msg.authority, msg.additional):
                        for rrset in section:
                            rrset.ttl = int(ttl_remain)
                    
                    self.stats['hits'] += 1
                    return msg, ttl_remain, new_hits
                except Exception as e:
                    logger.warning(f"Cache entry corrupted: {e}")
                    del self.cache[key]
            else:
                del self.cache[key]
                self.stats['expirations'] += 1
        
        self.stats['misses'] += 1
        return None, 0, 0

    def put(self, message: dns.message.Message, group: str = "default", scope: str = "DEFAULT", forced_ttl: int | None = None, req_logger=logger):
        """
        Store DNS response in cache with LRU eviction.
        """
        if self.size == 0: return
        
        # Check if we need to evict (LRU strategy)
        if len(self.cache) >= self.size:
            # Remove least recently used entry
            evicted_key = next(iter(self.cache))
            del self.cache[evicted_key]
            self.stats['evictions'] += 1
            req_logger.debug(f"Cache LRU eviction: {evicted_key[0]} (size limit reached)")
            
        if not message.question: return
        qname = str(message.question[0].name)
        qtype = message.question[0].rdtype
        
        if forced_ttl is not None:
            min_ttl = forced_ttl
        else:
            ttls = []
            for section in (message.answer, message.authority, message.additional):
                for rrset in section:
                    ttls.append(rrset.ttl)
            min_ttl = min(ttls) if ttls else self.negative_ttl
        
        expire_time = time.time() + min_ttl
        key = (qname, qtype, group, scope)
        
        # Add to cache (OrderedDict keeps insertion order)
        self.cache[key] = (message.to_wire(), expire_time, 0)
        self.stats['writes'] += 1
        
        req_logger.debug(f"Cache Write [{group}/{scope}]: {qname} TTL={int(min_ttl)}s (Total: {len(self.cache)}/{self.size})")
    
    def get_stats(self) -> dict:
        """Return cache statistics"""
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'size': len(self.cache),
            'max_size': self.size,
            'hits': self.stats['hits'],
            'misses': self.stats['misses'],
            'hit_rate': f"{hit_rate:.1f}%",
            'evictions': self.stats['evictions'],
            'expirations': self.stats['expirations'],
            'writes': self.stats['writes']
        }

class DNSHandler:
    # Maximum CNAME chain depth to prevent loops
    MAX_CNAME_DEPTH = 16
    
    def __init__(self, config, policy_map, default_policy, rule_engines, groups, mac_mapper, upstream, cache):
        self.config = config or {}
        self.policy_map = policy_map or {}
        self.rule_engines = rule_engines or {}
        self.groups = groups or {}
        self.mac_mapper = mac_mapper
        self.upstream = upstream
        self.cache = cache
        self.schedules = self.config.get('schedules') or {}
        
        response_cfg = self.config.get('response') or {}
        self.block_rcode = getattr(dns.rcode, response_cfg.get('block_rcode', 'REFUSED'))
        self.block_ip_opt = response_cfg.get('block_ip', None)
        self.block_ttl = response_cfg.get('block_ttl', 60)
        self.ip_block_mode = response_cfg.get('ip_block_mode', 'filter')
        self.round_robin = response_cfg.get('round_robin_enabled', False)
        self.match_answers_globally = response_cfg.get('match_answers_globally', False)
        
        self.rate_limiter = RateLimiter(self.config.get('rate_limit', {}))
        dedup_cfg = self.config.get('deduplication') or {}
        self.deduplicator = RequestDeduplicator(dedup_cfg.get('enabled', True))
        self.DEFAULT_POLICY_SCOPE = "DEFAULT_CACHE"
        
        self.prefetch_margin = self.config.get('cache', {}).get('prefetch_margin', 0)
        self.prefetch_min_hits = self.config.get('cache', {}).get('prefetch_min_hits', 3)
        
        server_cfg = self.config.get('server') or {}
        self.categorization_enabled = self.config.get('categorization_enabled', True)
        self.forward_ecs_mode = server_cfg.get('forward_ecs_mode', 'none').lower()
        self.forward_mac_mode = server_cfg.get('forward_mac_mode', 'none').lower()
        
        logger.info(f"DNSHandler Ready. BlockMode: {self.ip_block_mode}, AnswerMatching: {self.match_answers_globally}")

    def identify_client(self, addr, meta, req_logger) -> str | None:
        source_ip = addr[0]
        match_ip = source_ip
        mac = None
        
        srv_ip = (meta.get('server_ip') or '').lower()
        srv_port = str(meta.get('server_port', ''))

        if meta.get('ecs_ip'):
            match_ip = meta['ecs_ip']
        
        if meta.get('mac_override'):
            mac = meta['mac_override']

        if not mac:
             mac = self.mac_mapper.get_mac(source_ip)
        
        req_logger.debug(f"ID Params: IP={match_ip}, MAC={mac}, Port={srv_port}")

        for gname, identifiers in self.groups.items():
            if not identifiers: continue
            for ident in identifiers:
                ident = ident.lower()
                if ident.startswith('server_ip:') and srv_ip == ident[10:]:
                    req_logger.info(f"Client identified as group '{gname}'. Reason: Matched Listening IP '{srv_ip}'")
                    return gname
                if ident.startswith('server_port:') and srv_port == ident[12:]:
                    req_logger.info(f"Client identified as group '{gname}'. Reason: Matched Listening Port '{srv_port}'")
                    return gname
                if mac and ident == mac.lower():
                    req_logger.info(f"Client identified as group '{gname}'. Reason: Matched MAC '{mac}'")
                    return gname
                if ident == match_ip:
                    req_logger.info(f"Client identified as group '{gname}'. Reason: Matched IP '{match_ip}'")
                    return gname
                if '/' in ident and not ident.startswith('path:') and is_ip_in_network(match_ip, ident):
                    req_logger.info(f"Client identified as group '{gname}'. Reason: IP '{match_ip}' is in Subnet '{ident}'")
                    return gname
        
        return None

    def is_schedule_active(self, schedule_name):
        if not schedule_name or schedule_name not in self.schedules: return False
        schedule_list = self.schedules[schedule_name]
        if isinstance(schedule_list, dict): schedule_list = [schedule_list]
        from datetime import datetime
        now = datetime.now()
        current_hm = now.strftime("%H:%M")
        for block in schedule_list:
            if "days" in block and now.strftime("%a") not in block["days"]: continue
            start, end = block.get("start"), block.get("end")
            if not start or not end: continue
            if start <= end:
                if start <= current_hm < end: return True
            else:
                if current_hm >= start or current_hm < end: return True
        return False

    def get_active_policy(self, group, req_logger):
        if not group or group not in self.policy_map: return self.DEFAULT_POLICY_SCOPE
        assignment = self.policy_map[group]
        default_policy = assignment.get('policy', self.DEFAULT_POLICY_SCOPE)
        schedule_name = assignment.get('schedule')
        if self.is_schedule_active(schedule_name):
            sched_policy = assignment.get('schedule_policy')
            req_logger.info(f"Schedule '{schedule_name}' is ACTIVE. Overriding policy {default_policy} -> {sched_policy}")
            return sched_policy
        return default_policy

    def create_block_response(self, request: dns.message.Message, qname_obj, qtype) -> dns.message.Message:
        reply = dns.message.make_response(request)
        reply.set_rcode(self.block_rcode)
        
        inject_ip = None
        if self.block_ip_opt and qtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            if self.block_ip_opt == "NULL":
                if qtype == dns.rdatatype.A: inject_ip = "0.0.0.0"
                elif qtype == dns.rdatatype.AAAA: inject_ip = "::"
            else:
                try:
                    ip_obj = ipaddress.ip_address(self.block_ip_opt)
                    if qtype == dns.rdatatype.A and ip_obj.version == 4: inject_ip = self.block_ip_opt
                    elif qtype == dns.rdatatype.AAAA and ip_obj.version == 6: inject_ip = self.block_ip_opt
                except ValueError: pass

        if inject_ip:
            reply.set_rcode(dns.rcode.NOERROR)
            rdata = dns.rdata.from_text(dns.rdataclass.IN, qtype, inject_ip)
            rrset = dns.rrset.from_rdata(qname_obj, self.block_ttl, rdata)
            reply.answer.append(rrset)
            
        return reply

    def collapse_cnames(self, response: dns.message.Message, req_logger):
        """
        Collapse CNAME chains with enhanced loop detection.
        Implements depth limit and cycle detection.
        """
        response_cfg = self.config.get('response') or {}
        if not response_cfg.get('cname_collapse', True): 
            return
        
        if not response.question: 
            return
        qname = response.question[0].name
        
        # Find all CNAME records
        cname_rrsets = []
        final_rrsets = []  # A/AAAA/other records to keep
        
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname_rrsets.append(rrset)
            else:
                final_rrsets.append(rrset)
        
        if not cname_rrsets:
            return  # No CNAMEs to collapse
        
        # Build CNAME chain with depth limit
        cname_chain = {}
        for rrset in cname_rrsets:
            cname_chain[rrset.name] = rrset[0].target
        
        # Find the final target with loop detection
        current = qname
        visited = set()
        depth = 0
        
        while current in cname_chain and depth < self.MAX_CNAME_DEPTH:
            if current in visited:
                req_logger.warning(f"CNAME loop detected at depth {depth}: {current}")
                return  # Don't collapse, keep original response
            
            visited.add(current)
            current = cname_chain[current]
            depth += 1
        
        if depth >= self.MAX_CNAME_DEPTH:
            req_logger.warning(f"CNAME chain exceeded maximum depth ({self.MAX_CNAME_DEPTH})")
            return  # Don't collapse, keep original response
        
        final_target = current
        
        # Rewrite all final records (A/AAAA/etc) to use the original qname
        modified = False
        for rrset in final_rrsets:
            if rrset.name == final_target:
                # This record points to the final CNAME target
                # Create new RRset with original qname but keep ALL rdatas
                new_rrset = dns.rrset.RRset(qname, rrset.rdclass, rrset.rdtype)
                new_rrset.ttl = rrset.ttl
                
                # Copy ALL records (not just the first one)
                for rdata in rrset:
                    new_rrset.add(rdata)
                
                # Replace the old rrset
                final_rrsets.remove(rrset)
                final_rrsets.append(new_rrset)
                modified = True
                break
        
        if modified:
            # Remove all CNAME records and replace answer section
            response.answer.clear()
            response.answer.extend(final_rrsets)
            
            if cname_rrsets:
                req_logger.debug(
                    f"CNAME Flattened: Removed {len(cname_rrsets)} CNAME(s) "
                    f"(depth: {depth}), kept {sum(len(r) for r in final_rrsets)} record(s)"
                )

    def minimize_response(self, response: dns.message.Message):
        if self.config.get('response', {}).get('minimize_response', False):
            if response.authority or response.additional:
                response.authority.clear()
                response.additional.clear()

    def modify_ttls(self, response: dns.message.Message, req_logger):
        response_cfg = self.config.get('response') or {}
        min_ttl = response_cfg.get('min_ttl', 0)
        max_ttl = response_cfg.get('max_ttl', 86400)
        sync_mode = response_cfg.get('ttl_sync_mode', 'none').lower()
        
        target_ttl = None
        if sync_mode != 'none' and response.answer:
            ttls = [rrset.ttl for rrset in response.answer]
            if ttls:
                if sync_mode == 'first': target_ttl = ttls[0]
                elif sync_mode == 'last': target_ttl = ttls[-1]
                elif sync_mode == 'highest': target_ttl = max(ttls)
                elif sync_mode == 'lowest': target_ttl = min(ttls)
                elif sync_mode == 'average': target_ttl = int(sum(ttls) / len(ttls))
                req_logger.debug(f"TTL Sync ({sync_mode}): Input={ttls} -> Target={target_ttl}s")

        for section_name, section in [('Answer', response.answer), ('Auth', response.authority), ('Addl', response.additional)]:
            for rrset in section:
                if target_ttl is not None and section_name == 'Answer':
                    rrset.ttl = int(target_ttl)
                
                if rrset.ttl < min_ttl: rrset.ttl = int(min_ttl)
                elif rrset.ttl > max_ttl: rrset.ttl = int(max_ttl)

    def round_robin_answers(self, response: dns.message.Message, req_logger=None):
        if not self.round_robin: return
        
        shuffled = False
        for rrset in response.answer:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                items = list(rrset)
                if len(items) > 1:
                    random.shuffle(items)
                    rrset.clear()
                    for item in items:
                        rrset.add(item)
                    shuffled = True
        
        if shuffled and req_logger:
            req_logger.debug("Round Robin: Shuffled A/AAAA answer records")

    async def process_query(self, data, client_addr, meta=None):
        try:
            request = dns.message.from_wire(data)
        except Exception as e:
            logger.warning(f"Failed to parse DNS packet from {client_addr}: {e}")
            return None

        if not request.question: return None
        q = request.question[0]
        qname = q.name
        qname_str = str(qname)
        qtype = q.rdtype
        qid = request.id
        client_ip = client_addr[0]
        if meta is None: meta = {}

        # --- EDNS Parsing & Filtering ---
        ecs_ip = None
        edns_mac = None
        
        # Filter EDNS options - keep only ECS (8), Cookies (10), and MAC (65001)
        allowed_option_codes = {8, 10, 65001}  # ECS, Cookies, MAC
        filtered_options = []
        
        for opt in request.options:
            # ECS Option (8)
            if isinstance(opt, dns.edns.ECSOption):
                try: ecs_ip = str(opt.address)
                except: pass
                meta['ecs_ip'] = ecs_ip
                filtered_options.append(opt)
            
            # Generic options
            elif isinstance(opt, dns.edns.GenericOption):
                # MAC Option (65001)
                if opt.otype == 65001:
                    try:
                        mac_bytes = opt.data
                        mac_str = ":".join(f"{b:02x}" for b in mac_bytes).upper()
                        meta['mac_override'] = mac_str
                        edns_mac = mac_str
                    except: pass
                    filtered_options.append(opt)
                # Cookie Option (10)
                elif opt.otype == 10:
                    filtered_options.append(opt)
                # Drop all other generic options
            
            # Keep standard Cookie option if it's not GenericOption
            elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                filtered_options.append(opt)
        
        # Replace options with filtered list using use_edns()
        if request.edns >= 0:
            edns_ver = request.edns
            payload = request.payload if request.payload >= 512 else 1232
            request.use_edns(edns=edns_ver, ednsflags=request.ednsflags, options=filtered_options, payload=payload)
        elif filtered_options:
            # No EDNS present but we have options to add (shouldn't happen but handle it)
            request.use_edns(edns=0, ednsflags=0, options=filtered_options, payload=1232)

        log_ip = ecs_ip if ecs_ip else client_ip
        log_mac = edns_mac if edns_mac else self.mac_mapper.get_mac(client_ip)
        
        ctx = {
            'id': qid,
            'ip': f"{log_ip}{' (ECS)' if ecs_ip else ''}",
            'mac': f"{log_mac or 'Unk'}{' (EDNS)' if edns_mac else ''}",
            'proto': meta.get('proto', 'udp').upper()
        }
        req_logger = ContextAdapter(logger, ctx)
        req_logger.info(f"QUERY: {qname_str} [{dns.rdatatype.to_text(qtype)}]")

        group = self.identify_client(client_addr, meta, req_logger)
        group_key = group if group else "default"
        policy_name = self.get_active_policy(group, req_logger)
        
        # --- Cache Check ---
        cached_msg, ttl_remain, hits = self.cache.get(qname_str, qtype, group=group_key, scope=policy_name)
        if cached_msg:
            req_logger.info(f"CACHE HIT [{group_key}/{policy_name}]: TTL={int(ttl_remain)}s")
            cached_msg.id = qid
            
            # Filter EDNS options in cached response
            if cached_msg.edns >= 0:
                allowed_option_codes = {8, 10, 65001}
                filtered_options = []
                for opt in cached_msg.options:
                    if isinstance(opt, dns.edns.ECSOption):
                        filtered_options.append(opt)
                    elif isinstance(opt, dns.edns.GenericOption):
                        if opt.otype in allowed_option_codes:
                            filtered_options.append(opt)
                    elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                        filtered_options.append(opt)
                
                edns_ver = cached_msg.edns
                payload = cached_msg.payload if cached_msg.payload >= 512 else 1232
                cached_msg.use_edns(edns=edns_ver, ednsflags=cached_msg.ednsflags, options=filtered_options, payload=payload)
            
            if self.prefetch_margin > 0 and ttl_remain < self.prefetch_margin and hits >= self.prefetch_min_hits:
                req_logger.debug(f"Prefetching {qname_str} (Hits: {hits})")
                asyncio.create_task(self._resolve_upstream(qname_str, qtype, data, qid, None, policy_name, request, client_ip, req_logger, group_key))
            self.round_robin_answers(cached_msg, req_logger)
            return cached_msg.to_wire()
        else:
            req_logger.debug(f"CACHE MISS [{group_key}/{policy_name}]: {qname_str}")

        # --- Rate Limit Check ---
        limit_action = self.rate_limiter.check(log_ip, meta.get('proto', 'udp'))
        if limit_action == "DROP": 
            req_logger.warning("Rate Limit Exceeded: Dropping query")
            return None
        if limit_action == "TC":
            req_logger.warning("Rate Limit Exceeded: Forcing TCP")
            reply = dns.message.make_response(request)
            reply.flags |= dns.flags.TC
            return reply.to_wire()

        # --- Policy Check (Phase 1: Domain/Type) ---
        if policy_name == "BLOCK":
            req_logger.info(f"⛔ BLOCKED | Reason: Schedule Policy | Schedule: {group} | Policy: BLOCK")
            return self.create_block_response(request, qname, qtype).to_wire()

        engine = self.rule_engines.get(policy_name)
        if engine:
            # Categorization
            if self.categorization_enabled and engine.categorizer:
                 cat_results = engine.categorizer.categorize(qname_str)
                 for cat, score in cat_results.items():
                     if engine.category_rules and cat in engine.category_rules:
                         rule = engine.category_rules[cat]
                         if score >= rule.get('min_confidence', 0):
                             action = rule.get('action', 'ALLOW')
                             if action == 'BLOCK':
                                 req_logger.info(
                                     f"⛔ BLOCKED | Reason: Category Match | "
                                     f"Category: '{cat}' | Confidence: {score}% | "
                                     f"Policy: '{policy_name}' | Min: {rule.get('min_confidence', 0)}%"
                                 )
                                 return self.create_block_response(request, qname, qtype).to_wire()
                             elif action == 'ALLOW':
                                 req_logger.info(
                                     f"✓ ALLOWED | Reason: Category Match | "
                                     f"Category: '{cat}' | Confidence: {score}% | "
                                     f"Policy: '{policy_name}'"
                                 )
                     else:
                         # Just informational - category detected but no rule
                         req_logger.debug(f"Category: '{cat}' (Confidence: {score}%)")
            
            blocked_type, reason, _ = engine.check_type(qtype)
            if blocked_type: 
                req_logger.info(
                    f"⛔ BLOCKED | Reason: Query Type Filter | "
                    f"Type: {dns.rdatatype.to_text(qtype)} | "
                    f"Policy: '{policy_name}' | Details: {reason}"
                )
                return self.create_block_response(request, qname, qtype).to_wire()

            action, rule, list_name = engine.is_blocked(qname_str)
            if action == "BLOCK":
                req_logger.info(
                    f"⛔ BLOCKED | Reason: Domain Rule | "
                    f"Domain: {qname_str} | "
                    f"Rule: '{rule}' | "
                    f"List: '{list_name}' | "
                    f"Policy: '{policy_name}'"
                )
                return self.create_block_response(request, qname, qtype).to_wire()
            elif action == "ALLOW":
                req_logger.info(
                    f"✓ ALLOWED | Reason: Domain Allowlist | "
                    f"Domain: {qname_str} | "
                    f"Rule: '{rule}' | "
                    f"List: '{list_name}' | "
                    f"Policy: '{policy_name}'"
                )

        # --- Upstream Resolution ---
        dedup_key = (qname_str, qtype, policy_name, group_key)
        final_msg = await self.deduplicator.get_or_process(dedup_key, 
            lambda: self._resolve_upstream(qname_str, qtype, data, qid, engine, policy_name, request, client_ip, req_logger, group_key))
        
        self.round_robin_answers(final_msg, req_logger)
        final_msg.id = qid
        
        # Final EDNS filtering before returning
        if final_msg.edns >= 0:
            allowed_option_codes = {8, 10, 65001}
            filtered_final_options = []
            for opt in final_msg.options:
                if isinstance(opt, dns.edns.ECSOption):
                    filtered_final_options.append(opt)
                elif isinstance(opt, dns.edns.GenericOption):
                    if opt.otype in allowed_option_codes:
                        filtered_final_options.append(opt)
                elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                    filtered_final_options.append(opt)
            
            edns_ver = final_msg.edns
            payload = final_msg.payload if final_msg.payload >= 512 else 1232
            final_msg.use_edns(edns=edns_ver, ednsflags=final_msg.ednsflags, options=filtered_final_options, payload=payload)
        
        return final_msg.to_wire()

    async def _resolve_upstream(self, qname_str, qtype, data, qid, engine, policy_name, request, client_ip, req_logger, group_key="default"):
        upstream_group = "Default"
        policies = self.config.get('policies') or {}
        if policy_name in policies:
             upstream_group = policies[policy_name].get('upstream_group', "Default")
        
        # --- Native EDNS Forwarding Logic ---
        opts_to_keep = []
        for opt in request.options:
            if isinstance(opt, dns.edns.ECSOption):
                 if self.forward_ecs_mode == 'preserve': opts_to_keep.append(opt)
            elif isinstance(opt, dns.edns.GenericOption) and opt.otype == 65001:
                 if self.forward_mac_mode == 'preserve': opts_to_keep.append(opt)
            else:
                 opts_to_keep.append(opt)

        if self.forward_ecs_mode == 'add':
             try:
                ip = ipaddress.ip_address(client_ip)
                src_len = 32 if ip.version == 4 else 128
                opts_to_keep.append(dns.edns.ECSOption(ip, src_len))
                req_logger.debug(f"Added ECS: {client_ip}")
             except Exception: pass

        if self.forward_mac_mode == 'add':
            mac = self.mac_mapper.get_mac(client_ip)
            if mac:
                try:
                    mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
                    opts_to_keep.append(dns.edns.GenericOption(65001, mac_bytes))
                    req_logger.debug(f"Added MAC: {mac}")
                except Exception: pass
        
        # Apply EDNS Options
        edns_ver = request.edns if request.edns >= 0 else 0
        payload = request.payload if request.payload >= 512 else 1232
        request.use_edns(edns=edns_ver, ednsflags=request.ednsflags, options=opts_to_keep, payload=payload)
        
        try:
            upstream_query_data = request.to_wire()
        except:
            upstream_query_data = data

        req_logger.debug(f"Forwarding to Upstream Group: {upstream_group}")
        upstream_data = await self.upstream.forward_query(upstream_query_data, qid=qid, client_ip=client_ip, upstream_group=upstream_group, req_logger=req_logger)
        
        if not upstream_data:
            req_logger.warning("Upstream Resolution Failed (SERVFAIL or Timeout)")
            reply = dns.message.make_response(request)
            reply.set_rcode(dns.rcode.SERVFAIL)
            return reply

        try:
            response = dns.message.from_wire(upstream_data)
        except Exception as e:
             req_logger.warning(f"Upstream sent invalid DNS data: {e}")
             reply = dns.message.make_response(request)
             reply.set_rcode(dns.rcode.SERVFAIL)
             return reply
        
        # --- Policy Check (Phase 2: Answers/IPs) ---
        if engine and self.match_answers_globally:
            for section in (response.answer, response.authority, response.additional):
                safe_rrsets = []
                for rrset in section:
                    is_bad = False
                    matched_rule = None
                    matched_list = None
                    matched_target = None
                    
                    if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                        for rdata in rrset:
                             is_bad, rule, lst = engine.check_answer(None, rdata.to_text())
                             if is_bad:
                                 matched_rule = rule
                                 matched_list = lst
                                 matched_target = rdata.to_text()
                                 req_logger.info(
                                     f"⛔ BLOCKED | Reason: Answer IP Match | "
                                     f"IP: {matched_target} | "
                                     f"Rule: '{matched_rule}' | "
                                     f"List: '{matched_list}' | "
                                     f"Policy: '{policy_name}' | "
                                     f"Type: {dns.rdatatype.to_text(rrset.rdtype)}"
                                 )
                                 break
                    elif rrset.rdtype in [dns.rdatatype.CNAME, dns.rdatatype.MX, dns.rdatatype.PTR]:
                        for rdata in rrset:
                            is_bad, rule, lst = engine.check_answer(str(rdata.target), None)
                            if is_bad:
                                matched_rule = rule
                                matched_list = lst
                                matched_target = str(rdata.target)
                                req_logger.info(
                                    f"⛔ BLOCKED | Reason: Answer Domain Match | "
                                    f"Domain: {matched_target} | "
                                    f"Rule: '{matched_rule}' | "
                                    f"List: '{matched_list}' | "
                                    f"Policy: '{policy_name}' | "
                                    f"Type: {dns.rdatatype.to_text(rrset.rdtype)}"
                                )
                                break
                    
                    if is_bad:
                         if self.ip_block_mode == 'block':
                             req_logger.info(
                                 f"⛔ BLOCKED | Reason: Answer Match - Full Response Blocked | "
                                 f"Trigger: {matched_target} | "
                                 f"Rule: '{matched_rule}' | "
                                 f"List: '{matched_list}' | "
                                 f"Policy: '{policy_name}' | "
                                 f"Mode: block (entire response)"
                             )
                             block_resp = self.create_block_response(request, request.question[0].name, qtype)
                             return block_resp
                         # If mode is 'filter', we just skip adding this rrset
                    else:
                        safe_rrsets.append(rrset)
                
                section.clear()
                section.extend(safe_rrsets)

        self.collapse_cnames(response, req_logger)
        self.minimize_response(response)
        self.modify_ttls(response, req_logger)
        
        # --- Filter EDNS options in response ---
        # Keep only ECS (8), Cookies (10), and MAC (65001)
        if response.edns >= 0:
            allowed_option_codes = {8, 10, 65001}
            filtered_response_options = []
            
            for opt in response.options:
                if isinstance(opt, dns.edns.ECSOption):
                    filtered_response_options.append(opt)
                elif isinstance(opt, dns.edns.GenericOption):
                    if opt.otype in allowed_option_codes:
                        filtered_response_options.append(opt)
                elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                    filtered_response_options.append(opt)
            
            edns_ver = response.edns
            payload = response.payload if response.payload >= 512 else 1232
            response.use_edns(edns=edns_ver, ednsflags=response.ednsflags, options=filtered_response_options, payload=payload)
        
        self.cache.put(response, group=group_key, scope=policy_name, req_logger=req_logger)
        return response


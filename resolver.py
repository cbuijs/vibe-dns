#!/usr/bin/env python3
# filename: resolver.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 7.8.0 (Short-Circuit Logic + PTR Check + CNAME Fix)
# -----------------------------------------------------------------------------
"""
Core DNS Resolution logic.
Matches filtering flow: Query Checks -> Upstream -> Answer Checks.
Implements 'filter' mode to strip specific blocked IPs from responses.
Enforces strict short-circuiting: Once an Action (BLOCK/DROP/ALLOW) is hit, 
processing stops immediately.
"""

import asyncio
import time
import random
import ipaddress
import logging
from typing import Any, Optional, Dict, List, Tuple

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
from cache_stats import LRUCache
from domain_utils import normalize_domain

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

class DecisionCache(LRUCache):
    def __init__(self, size=50000, ttl=300):
        super().__init__(max_size=size, default_ttl=ttl)
    
    def get_decision(self, qname_norm: str, qtype: int, group: str, policy: str) -> Optional[dict]:
        key = (qname_norm, qtype, group, policy)
        return self.get(key)
    
    def put_decision(self, qname_norm: str, qtype: int, group: str, policy: str, decision: dict):
        key = (qname_norm, qtype, group, policy)
        self.put(key, decision)

class DNSCache(LRUCache):
    def __init__(self, size, ttl_margin, negative_ttl, gc_interval=300, prefetch_min_hits=3):
        super().__init__(max_size=size, default_ttl=negative_ttl)
        self.margin = ttl_margin or 0
        self.negative_ttl = negative_ttl or 60
        self.gc_interval = gc_interval
        self.prefetch_min_hits = prefetch_min_hits
        self.hit_counts: dict[tuple, int] = {}
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(self.gc_interval)
            self.cleanup_expired()

    def get_dns(self, qname_norm: str, qtype: int, group: str = "default", scope: str = "DEFAULT") -> tuple[dns.message.Message | None, float, int]:
        key = (qname_norm, qtype, group, scope)
        if key not in self.cache:
            self.stats.record_miss()
            return None, 0, 0
        self.cache.move_to_end(key)
        record_bytes, expires = self.cache[key]
        now = time.time()
        ttl_remain = expires - now
        if ttl_remain <= 0:
            del self.cache[key]
            self.stats.record_expiration()
            self.stats.record_miss()
            return None, 0, 0
        self.hit_counts[key] = self.hit_counts.get(key, 0) + 1
        hits = self.hit_counts[key]
        self.stats.record_hit()
        try:
            msg = dns.message.from_wire(record_bytes)
            for section in (msg.answer, msg.authority, msg.additional):
                for rrset in section:
                    rrset.ttl = int(ttl_remain)
            return msg, ttl_remain, hits
        except Exception:
            del self.cache[key]
            return None, 0, 0

    def put_dns(self, message: dns.message.Message, qname_norm: str, qtype: int, group: str = "default", 
                scope: str = "DEFAULT", forced_ttl: int | None = None, req_logger=logger):
        if self.max_size == 0: return
        if forced_ttl is not None:
            min_ttl = forced_ttl
        else:
            ttls = []
            for section in (message.answer, message.authority, message.additional):
                for rrset in section:
                    ttls.append(rrset.ttl)
            min_ttl = min(ttls) if ttls else self.negative_ttl
        key = (qname_norm, qtype, group, scope)
        wire = message.to_wire()
        self.put(key, wire, ttl=min_ttl)
    
    def should_prefetch(self, key: tuple, ttl_remain: float) -> bool:
        if self.margin <= 0: return False
        if ttl_remain >= self.margin: return False
        hits = self.hit_counts.get(key, 0)
        return hits >= self.prefetch_min_hits

class DNSHandler:
    MAX_CNAME_DEPTH = 16
    
    def __init__(self, config, policy_map, default_policy, rule_engines, groups, mac_mapper, upstream, cache, geoip=None):
        self.config = config or {}
        self.policy_map = policy_map or {}
        self.rule_engines = rule_engines or {}
        self.mac_mapper = mac_mapper
        self.upstream = upstream
        self.cache = cache
        self.geoip = geoip
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
        
        self.decision_cache = DecisionCache(
            size=self.config.get('decision_cache', {}).get('size', 50000),
            ttl=self.config.get('decision_cache', {}).get('ttl', 300)
        )
        
        server_cfg = self.config.get('server') or {}
        self.categorization_enabled = self.config.get('categorization_enabled', True)
        self.forward_ecs_mode = server_cfg.get('forward_ecs_mode', 'none').lower()
        self.forward_mac_mode = server_cfg.get('forward_mac_mode', 'none').lower()
        
        self.ecs_ipv4_mask = server_cfg.get('ecs_ipv4_mask', 24)
        self.ecs_ipv6_mask = server_cfg.get('ecs_ipv6_mask', 56)
        self.ecs_override_ipv4 = server_cfg.get('ecs_override_ipv4')
        self.ecs_override_ipv6 = server_cfg.get('ecs_override_ipv6')
        
        # PTR Check Configuration
        self.ptr_check_mode = self.config.get('filtering', {}).get('ptr_check', 'none').lower()
        if self.ptr_check_mode not in ['strict', 'none']:
            logger.warning(f"Invalid ptr_check mode '{self.ptr_check_mode}', defaulting to 'none'")
            self.ptr_check_mode = 'none'
        
        self.group_ip_map: Dict[str, str] = {}
        self.group_mac_map: Dict[str, str] = {}
        self.group_srv_ip_map: Dict[str, str] = {}
        self.group_srv_port_map: Dict[str, str] = {}
        self.group_cidr_list: List[Tuple[str, str]] = []
        self.group_geoip_list: List[Tuple[str, str]] = []
        self.group_default_actions: Dict[str, str] = {}

        self._build_client_maps(groups or {})
        
        logger.info(f"DNSHandler Ready. BlockMode: {self.ip_block_mode}, PTR Check: {self.ptr_check_mode}")

    def _build_client_maps(self, groups: Dict[str, list]):
        for gname, identifiers in groups.items():
            if not identifiers: continue
            default_action = None
            start_idx = 0
            if identifiers and isinstance(identifiers[0], dict):
                if 'default_action' in identifiers[0]:
                    default_action = identifiers[0]['default_action'].upper()
                    if default_action in ['ALLOW', 'BLOCK', 'DROP']:
                        self.group_default_actions[gname] = default_action
                        start_idx = 1
            for ident in identifiers[start_idx:]:
                ident_lower = ident.lower().strip()
                if ident_lower.startswith('server_ip:'):
                    self.group_srv_ip_map[ident_lower[10:]] = gname
                    continue
                if ident_lower.startswith('server_port:'):
                    self.group_srv_port_map[ident_lower[12:]] = gname
                    continue
                if ident_lower.startswith('geoip:'):
                    self.group_geoip_list.append((ident_lower[6:], gname))
                    continue
                if '/' in ident_lower and not ident_lower.startswith('path:'):
                    self.group_cidr_list.append((ident_lower, gname))
                    continue
                try:
                    ipaddress.ip_address(ident_lower)
                    self.group_ip_map[ident_lower] = gname
                    continue
                except ValueError:
                    pass
                self.group_mac_map[ident_lower] = gname

    def _process_edns_options(self, message, keep_ecs=True, keep_mac=True):
        if message.edns < 0: return []
        allowed_codes = {8, 10, 65001}
        filtered = []
        for opt in message.options:
            if isinstance(opt, dns.edns.ECSOption):
                if keep_ecs: filtered.append(opt)
            elif isinstance(opt, dns.edns.GenericOption):
                if opt.otype == 65001:
                    if keep_mac: filtered.append(opt)
                elif opt.otype in allowed_codes: filtered.append(opt)
            elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                filtered.append(opt)
        return filtered
    
    def _apply_edns_options(self, message, options):
        if message.edns >= 0 or options:
            edns_ver = message.edns if message.edns >= 0 else 0
            payload = message.payload if message.payload >= 512 else 1232
            message.use_edns(edns=edns_ver, ednsflags=message.ednsflags, options=options, payload=payload)

    def _extract_ip_from_ptr(self, qname_str: str) -> Optional[str]:
        qname_lower = qname_str.lower().rstrip('.')
        if qname_lower.endswith('.in-addr.arpa'):
            base = qname_lower[:-13]
            parts = base.split('.')
            if len(parts) == 4:
                try:
                    for part in parts:
                        if not 0 <= int(part) <= 255:
                            return None
                    return ".".join(parts[::-1])
                except ValueError:
                    return None
        elif qname_lower.endswith('.ip6.arpa'):
            base = qname_lower[:-9]
            parts = base.split('.')
            if len(parts) == 32:
                try:
                    for part in parts: int(part, 16)
                    nibbles = parts[::-1]
                    hex_str = "".join(nibbles)
                    ip = ":".join(hex_str[i:i+4] for i in range(0, 32, 4))
                    ipaddress.IPv6Address(ip)
                    return ip
                except ValueError:
                    return None
        return None

    def _apply_mask(self, ip_str: str, mask: int) -> Tuple[str, int]:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                m = min(max(mask, 0), 32)
                net = ipaddress.IPv4Network(f"{ip_str}/{m}", strict=False)
                return str(net.network_address), m
            elif ip.version == 6:
                m = min(max(mask, 0), 128)
                net = ipaddress.IPv6Network(f"{ip_str}/{m}", strict=False)
                return str(net.network_address), m
        except Exception:
            return ip_str, 0

    def identify_client(self, addr, meta, req_logger) -> str | None:
        srv_ip = (meta.get('server_ip') or '').lower()
        srv_port = str(meta.get('server_port', ''))

        if srv_ip in self.group_srv_ip_map:
            gname = self.group_srv_ip_map[srv_ip]
            req_logger.info(f"Client identified as group '{gname}'. Reason: Matched Listening IP '{srv_ip}'")
            return gname
        
        if srv_port in self.group_srv_port_map:
            gname = self.group_srv_port_map[srv_port]
            req_logger.info(f"Client identified as group '{gname}'. Reason: Matched Listening Port '{srv_port}'")
            return gname

        source_ip = addr[0]
        match_ip = meta.get('ecs_ip') or source_ip
        match_ip_lower = match_ip.lower()
        
        mac = meta.get('mac_override') or self.mac_mapper.get_mac(source_ip)
        if mac:
            mac_lower = mac.lower()
            if mac_lower in self.group_mac_map:
                gname = self.group_mac_map[mac_lower]
                req_logger.info(f"Client identified as group '{gname}'. Reason: Matched MAC '{mac}'")
                return gname

        if match_ip_lower in self.group_ip_map:
            gname = self.group_ip_map[match_ip_lower]
            req_logger.info(f"Client identified as group '{gname}'. Reason: Matched IP '{match_ip}'")
            return gname

        for cidr, gname in self.group_cidr_list:
            if is_ip_in_network(match_ip, cidr):
                req_logger.info(f"Client identified as group '{gname}'. Reason: IP '{match_ip}' is in Subnet '{cidr}'")
                return gname

        if self.geoip and self.geoip.enabled and self.group_geoip_list:
            for location, gname in self.group_geoip_list:
                if self.geoip.match_location(match_ip, location):
                    req_logger.info(f"✓ Client identified as group '{gname}' | Reason: GeoIP Match | IP: {match_ip} | Location: {location}")
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

    def get_active_policy(self, group, req_logger) -> Tuple[str, str]:
        if group and group in self.group_default_actions:
            action = self.group_default_actions[group]
            return action, "Group Default Action"

        if not group or group not in self.policy_map: 
            return self.DEFAULT_POLICY_SCOPE, "Default Policy"

        assignment = self.policy_map[group]
        default_policy = assignment.get('policy', self.DEFAULT_POLICY_SCOPE)
        
        schedule_name = assignment.get('schedule')
        if self.is_schedule_active(schedule_name):
            sched_policy = assignment.get('schedule_policy')
            if sched_policy:
                req_logger.info(f"Schedule '{schedule_name}' is ACTIVE. Overriding policy {default_policy} -> {sched_policy}")
                return sched_policy, f"Schedule '{schedule_name}'"
        
        return default_policy, "Policy Assignment"

    def create_block_response(self, request: dns.message.Message, qname_obj, qtype, force_rcode=None) -> dns.message.Message:
        reply = dns.message.make_response(request)
        
        if force_rcode is not None:
            reply.set_rcode(force_rcode)
            return reply
        else:
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
        response_cfg = self.config.get('response') or {}
        if not response_cfg.get('cname_collapse', True): return
        
        if not response.question: return
        qname = response.question[0].name
        
        cname_rrsets = []
        other_rrsets = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME: cname_rrsets.append(rrset)
            else: other_rrsets.append(rrset)
        
        if not cname_rrsets: return

        cname_chain = {}
        for rrset in cname_rrsets: cname_chain[rrset.name] = rrset[0].target
        
        current = qname
        visited = set()
        depth = 0
        
        while current in cname_chain and depth < self.MAX_CNAME_DEPTH:
            if current in visited:
                req_logger.warning(f"CNAME loop detected at depth {depth}: {current}")
                return
            visited.add(current)
            current = cname_chain[current]
            depth += 1
        
        if depth >= self.MAX_CNAME_DEPTH:
            req_logger.warning(f"CNAME chain exceeded maximum depth ({self.MAX_CNAME_DEPTH})")
            return
        
        final_target = current
        new_answer = []
        for rrset in other_rrsets:
            if rrset.name == final_target:
                new_rrset = dns.rrset.RRset(qname, rrset.rdclass, rrset.rdtype)
                new_rrset.ttl = rrset.ttl
                for rdata in rrset: new_rrset.add(rdata)
                new_answer.append(new_rrset)
        
        response.answer.clear()
        response.answer.extend(new_answer)
        
        if not response.answer:
            empty_rcode_str = response_cfg.get('cname_empty_rcode', 'NXDOMAIN').upper()
            if empty_rcode_str == 'NOERROR': response.set_rcode(dns.rcode.NOERROR)
            else: response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            if cname_rrsets:
                req_logger.debug(f"CNAME Flattened: Removed {len(cname_rrsets)} CNAME(s) (depth: {depth}), kept {sum(len(r) for r in new_answer)} record(s)")

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
        
        all_rrsets = list(response.answer) + list(response.authority) + list(response.additional)
        if not all_rrsets: return
        
        target_ttl = None
        if sync_mode != 'none' and response.answer:
            answer_ttls = [rrset.ttl for rrset in response.answer]
            if answer_ttls:
                if sync_mode == 'first': target_ttl = answer_ttls[0]
                elif sync_mode == 'last': target_ttl = answer_ttls[-1]
                elif sync_mode == 'highest': target_ttl = max(answer_ttls)
                elif sync_mode == 'lowest': target_ttl = min(answer_ttls)
                elif sync_mode == 'average': target_ttl = int(sum(answer_ttls) / len(answer_ttls))
        
        for rrset in all_rrsets:
            if target_ttl is not None and rrset in response.answer: rrset.ttl = int(target_ttl)
            if rrset.ttl < min_ttl: rrset.ttl = int(min_ttl)
            elif rrset.ttl > max_ttl: rrset.ttl = int(max_ttl)

    def round_robin_answers(self, response: dns.message.Message, req_logger=None):
        if not self.round_robin: return
        for rrset in response.answer:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                items = list(rrset)
                if len(items) > 1:
                    random.shuffle(items)
                    rrset.clear()
                    for item in items: rrset.add(item)

    def _log_response(self, response: dns.message.Message, req_logger):
        if not req_logger.isEnabledFor(logging.DEBUG): return
        rcode = dns.rcode.to_text(response.rcode())
        answer_count = len(response.answer)
        req_logger.debug(f"RESPONSE: RCODE={rcode} | Answers={answer_count}")
        if answer_count > 0:
            for rrset in response.answer:
                req_logger.debug(f"  - {rrset.name} {rrset.ttl} {dns.rdatatype.to_text(rrset.rdtype)}: {', '.join([r.to_text() for r in rrset])}")

    async def process_query(self, data, client_addr, meta=None):
        try:
            request = dns.message.from_wire(data)
        except Exception as e:
            logger.warning(f"Failed to parse DNS packet from {client_addr}: {e}")
            return None

        if not request.question: return None
        q = request.question[0]
        qname_str = str(q.name)
        qtype = q.rdtype
        qid = request.id
        client_ip = client_addr[0]
        if meta is None: meta = {}
        qname_norm = normalize_domain(qname_str)
        
        ecs_ip = None
        edns_mac = None
        filtered_options = []
        for opt in request.options:
            if isinstance(opt, dns.edns.ECSOption):
                try: ecs_ip = str(opt.address)
                except: pass
                meta['ecs_ip'] = ecs_ip
                filtered_options.append(opt)
            elif isinstance(opt, dns.edns.GenericOption):
                if opt.otype == 65001:
                    try: edns_mac = ":".join(f"{b:02x}" for b in opt.data).upper()
                    except: pass
                    meta['mac_override'] = edns_mac
                    filtered_options.append(opt)
                elif opt.otype == 10: filtered_options.append(opt)
            elif hasattr(dns.edns, 'CookieOption') and isinstance(opt, dns.edns.CookieOption):
                filtered_options.append(opt)
        self._apply_edns_options(request, filtered_options)

        log_ip = ecs_ip if ecs_ip else client_ip
        ctx = {'id': qid, 'ip': log_ip, 'proto': meta.get('proto', 'udp').upper()}
        req_logger = ContextAdapter(logger, ctx)
        req_logger.info(f"QUERY: {qname_norm} [{dns.rdatatype.to_text(qtype)}]")

        # --- PTR Strict Check ---
        if qtype == dns.rdatatype.PTR and self.ptr_check_mode == 'strict':
            is_reverse = qname_norm.endswith('.in-addr.arpa') or qname_norm.endswith('.ip6.arpa')
            if is_reverse:
                extracted_ip = self._extract_ip_from_ptr(qname_str)
                if not extracted_ip:
                    req_logger.info(f"⛔ BLOCKED | Reason: Invalid PTR Syntax | Domain: {qname_norm} | Mode: ptr_check=strict")
                    return self.create_block_response(request, q.name, qtype).to_wire()
                else:
                    req_logger.debug(f"PTR Check OK: {qname_norm} -> {extracted_ip}")

        group = self.identify_client(client_addr, meta, req_logger)
        group_key = group if group else "default"
        policy_name, policy_source = self.get_active_policy(group, req_logger)
        
        req_logger.debug(f"DECISION: Client Group: '{group_key}' -> Policy: '{policy_name}' (Source: {policy_source})")

        cached_decision = self.decision_cache.get_decision(qname_norm, qtype, group_key, policy_name)
        is_explicit_allow = False
        
        if cached_decision:
            action = cached_decision['action']
            reason = cached_decision.get('reason', 'Unknown')
            rule = cached_decision.get('rule', 'N/A')
            list_name = cached_decision.get('list', 'N/A')
            
            if action == 'BLOCK':
                req_logger.info(f"⛔ BLOCKED (Decision Cache Hit) | Reason: {reason} | Rule: '{rule}' | List: '{list_name}'")
                return self.create_block_response(request, q.name, qtype).to_wire()
            elif action == 'DROP':
                req_logger.info(f"🔇 DROPPED (Decision Cache Hit) | Reason: {reason} | Rule: '{rule}' | List: '{list_name}'")
                return None
            elif action == 'ALLOW':
                req_logger.info(f"✓ ALLOWED (Decision Cache Hit) | Reason: {reason} | Rule: '{rule}' | List: '{list_name}'")
                is_explicit_allow = True
        
        if not cached_decision:
            cache_key = (qname_norm, qtype, group_key, policy_name)
            cached_msg, ttl_remain, hits = self.cache.get_dns(qname_norm, qtype, group=group_key, scope=policy_name)
            if cached_msg:
                req_logger.info(f"CACHE HIT [{group_key}/{policy_name}]: TTL={int(ttl_remain)}s")
                cached_msg.id = qid
                self._apply_edns_options(cached_msg, self._process_edns_options(cached_msg, keep_ecs=True, keep_mac=True))
                if self.cache.should_prefetch(cache_key, ttl_remain):
                    asyncio.create_task(self._resolve_upstream(qname_norm, qtype, data, qid, None, policy_name, request, client_ip, req_logger, group_key, is_explicit_allow))
                self.round_robin_answers(cached_msg, req_logger)
                self._log_response(cached_msg, req_logger)
                return cached_msg.to_wire()
            else:
                req_logger.debug(f"CACHE MISS [{group_key}/{policy_name}]: {qname_norm}")

        limit_action = self.rate_limiter.check(log_ip, meta.get('proto', 'udp'))
        if limit_action == "DROP": 
            req_logger.warning("Rate Limit Exceeded: Dropping query")
            return None
        if limit_action == "TC":
            req_logger.warning("Rate Limit Exceeded: Forcing TCP")
            reply = dns.message.make_response(request)
            reply.flags |= dns.flags.TC
            return reply.to_wire()

        if policy_name == "BLOCK":
            req_logger.info(f"⛔ BLOCKED | Reason: {policy_source} | Group: {group_key} | Policy: BLOCK")
            self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'BLOCK', 'reason': policy_source, 'rule': 'N/A', 'list': policy_source})
            return self.create_block_response(request, q.name, qtype).to_wire()
        elif policy_name == "DROP":
            req_logger.info(f"🔇 DROPPED | Reason: {policy_source} | Group: {group_key} | Policy: DROP")
            self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'DROP', 'reason': 'Category Match', 'rule': 'N/A', 'list': policy_source})
            return None
        elif policy_name == "ALLOW":
            req_logger.info(f"✓ ALLOWED | Reason: {policy_source} | Group: {group_key} | Policy: ALLOW")
            is_explicit_allow = True
            self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'ALLOW', 'reason': policy_source, 'rule': 'N/A', 'list': policy_source})

        engine = self.rule_engines.get(policy_name)
        if engine and not is_explicit_allow:
            # 1. Check PTR IP
            if qtype == dns.rdatatype.PTR:
                target_ip = self._extract_ip_from_ptr(qname_str)
                if target_ip:
                    m_action, m_rule, m_list = engine.check_answer(None, target_ip, self.geoip)
                    if m_action == 'BLOCK':
                        req_logger.info(f"⛔ BLOCKED | Reason: PTR GeoIP/Range Match | Target IP: {target_ip} | Rule: '{m_rule}' | List: '{m_list}'")
                        return self.create_block_response(request, q.name, qtype).to_wire()
                    elif m_action == 'DROP':
                        req_logger.info(f"🔇 DROPPED | Reason: PTR GeoIP/Range Match | Target IP: {target_ip} | Rule: '{m_rule}' | List: '{m_list}'")
                        return None

            # 2. Categorization
            if self.categorization_enabled and engine.categorizer and engine.category_rules:
                 cat_results = engine.categorizer.classify(qname_norm)
                 for cat, score in cat_results.items():
                     if cat in engine.category_rules:
                         rule = engine.category_rules[cat]
                         if score >= rule.get('min_confidence', 0):
                             action = rule.get('action', 'ALLOW')
                             req_logger.debug(f"DEBUG: Category '{cat}' match ({score}%) -> Rule Action: {action}")
                             
                             if action == 'BLOCK':
                                 req_logger.info(f"⛔ BLOCKED | Reason: Category Match | Category: '{cat}' | Confidence: {score}% | Policy: '{policy_name}'")
                                 self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'BLOCK', 'reason': 'Category Match', 'rule': f"Category: {cat}", 'list': policy_name})
                                 return self.create_block_response(request, q.name, qtype).to_wire()
                             elif action == 'DROP':
                                 req_logger.info(f"🔇 DROPPED | Reason: Category Match | Category: '{cat}' | Confidence: {score}% | Policy: '{policy_name}'")
                                 self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'DROP', 'reason': 'Category Match', 'rule': f"Category: {cat}", 'list': policy_name})
                                 return None
                             elif action == 'ALLOW':
                                 req_logger.info(f"✓ ALLOWED | Reason: Category Match | Category: '{cat}' | Confidence: {score}% | Policy: '{policy_name}'")
                                 is_explicit_allow = True
                                 self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'ALLOW', 'reason': 'Category Match', 'rule': f"Category: {cat}", 'list': policy_name})
                                 break # Stop category loop, and due to flag set, will skip next checks
                         else:
                             req_logger.debug(f"DEBUG: Category '{cat}' match ({score}%) -> Below Min Confidence ({rule.get('min_confidence', 0)}%)")

            if not is_explicit_allow:
                h_action, h_reason, h_score = engine.check_heuristics(qname_norm)
                if h_action == "BLOCK":
                    req_logger.info(f"⛔ BLOCKED | Reason: Heuristics | Domain: {qname_norm} | Score: {h_score}/5 | Details: {h_reason}")
                    self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'BLOCK', 'reason': 'Heuristics', 'rule': f"Score {h_score}", 'list': 'Heuristics'})
                    return self.create_block_response(request, q.name, qtype).to_wire()
                elif h_score > 0:
                    req_logger.debug(f"Heuristics Monitor: {qname_norm} | score={h_score}/{engine.heuristics.block_threshold} | Detects: [{h_reason}]")

            # 3. Query Type
            if not is_explicit_allow:
                action_type, reason, _ = engine.check_type(qtype)
                if action_type == "BLOCK":
                    req_logger.info(f"⛔ BLOCKED | Reason: Query Type Filter | Type: {dns.rdatatype.to_text(qtype)} | Details: {reason}")
                    
                    # Custom Logic: AAAA = NOERROR (Empty), Others = NXDOMAIN
                    target_rcode = dns.rcode.NXDOMAIN
                    if qtype == dns.rdatatype.AAAA:
                        target_rcode = dns.rcode.NOERROR
                        
                    return self.create_block_response(request, q.name, qtype, force_rcode=target_rcode).to_wire()
                elif action_type == "DROP":
                    req_logger.info(f"🔇 DROPPED | Reason: Query Type Filter | Type: {dns.rdatatype.to_text(qtype)} | Details: {reason}")
                    return None

            # 4. Standard Blocking (Domains -> GeoIP -> Regex)
            if not is_explicit_allow:
                action, rule, list_name = engine.is_blocked(qname_norm, geoip_lookup=self.geoip)
                if action:
                    req_logger.debug(f"DEBUG: Domain/GeoIP Rule Match -> Action: {action} | Rule: '{rule}' | List: '{list_name}'")
                
                if action == "BLOCK":
                    req_logger.info(f"⛔ BLOCKED | Reason: Domain Rule | Domain: {qname_norm} | Rule: '{rule}' | List: '{list_name}' | Policy: '{policy_name}'")
                    self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'BLOCK', 'reason': 'Domain Rule', 'rule': rule, 'list': list_name})
                    return self.create_block_response(request, q.name, qtype).to_wire()
                elif action == "DROP":
                    req_logger.info(f"🔇 DROPPED | Reason: Domain Rule | Domain: {qname_norm} | Rule: '{rule}' | List: '{list_name}' | Policy: '{policy_name}'")
                    self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'DROP', 'reason': 'Domain Rule', 'rule': rule, 'list': list_name})
                    return None
                elif action == "ALLOW":
                    req_logger.info(f"✓ ALLOWED | Reason: Domain Allowlist | Domain: {qname_norm} | Rule: '{rule}' | List: '{list_name}' | Policy: '{policy_name}'")
                    is_explicit_allow = True
                    self.decision_cache.put_decision(qname_norm, qtype, group_key, policy_name, {'action': 'ALLOW', 'reason': 'Domain Allowlist', 'rule': rule, 'list': list_name})

        dedup_key = (qname_norm, qtype, policy_name, group_key)
        final_msg = await self.deduplicator.get_or_process(dedup_key, 
            lambda: self._resolve_upstream(qname_norm, qtype, data, qid, engine, policy_name, request, client_ip, req_logger, group_key, is_explicit_allow))
        
        if final_msg is None: return None
        
        self.round_robin_answers(final_msg, req_logger)
        final_msg.id = qid
        self._apply_edns_options(final_msg, self._process_edns_options(final_msg, keep_ecs=True, keep_mac=True))
        self._log_response(final_msg, req_logger)
        return final_msg.to_wire()

    async def _resolve_upstream(self, qname_norm, qtype, data, qid, engine, policy_name, request, client_ip, req_logger, group_key="default", is_explicit_allow=False):
        upstream_group = "Default"
        policies = self.config.get('policies') or {}
        if policy_name in policies: upstream_group = policies[policy_name].get('upstream_group', "Default")
        
        # ECS Logic
        incoming_ecs = next((o for o in request.options if isinstance(o, dns.edns.ECSOption)), None)
        keep_ecs = (self.forward_ecs_mode in ['preserve', 'privacy'])
        keep_mac = (self.forward_mac_mode == 'preserve')
        opts_to_keep = self._process_edns_options(request, keep_ecs=keep_ecs, keep_mac=keep_mac)
        
        if incoming_ecs:
             if not keep_ecs and self.forward_ecs_mode != 'privacy':
                 req_logger.debug(f"[ECS] Stripping client ECS: {incoming_ecs.address}")
             elif self.forward_ecs_mode == 'preserve':
                 req_logger.debug(f"[ECS] Preserving client ECS: {incoming_ecs.address}")

        if self.forward_ecs_mode == 'privacy':
            new_opts = []
            has_ecs = False
            for opt in opts_to_keep:
                if isinstance(opt, dns.edns.ECSOption):
                    has_ecs = True
                    try:
                        mask = self.ecs_ipv4_mask if ipaddress.ip_address(opt.address).version == 4 else self.ecs_ipv6_mask
                        masked_ip, applied_mask = self._apply_mask(str(opt.address), mask)
                        new_opts.append(dns.edns.ECSOption(masked_ip, applied_mask))
                        req_logger.debug(f"[ECS] Privacy Truncation: {opt.address} -> {masked_ip}/{applied_mask}")
                    except: pass
                else: new_opts.append(opt)
            opts_to_keep = new_opts
        else: has_ecs = any(isinstance(o, dns.edns.ECSOption) for o in opts_to_keep)

        if self.forward_ecs_mode == 'override':
            if self.ecs_override_ipv4:
                opts_to_keep.append(dns.edns.ECSOption(self.ecs_override_ipv4, 32))
                req_logger.debug(f"[ECS] Override (IPv4): Forced {self.ecs_override_ipv4}/32")
            if self.ecs_override_ipv6:
                opts_to_keep.append(dns.edns.ECSOption(self.ecs_override_ipv6, 128))
                req_logger.debug(f"[ECS] Override (IPv6): Forced {self.ecs_override_ipv6}/128")
        elif self.forward_ecs_mode == 'add' or (self.forward_ecs_mode == 'privacy' and not has_ecs):
             try:
                ip = ipaddress.ip_address(client_ip)
                if self.forward_ecs_mode == 'privacy':
                    mask = self.ecs_ipv4_mask if ip.version == 4 else self.ecs_ipv6_mask
                    masked_ip, src_len = self._apply_mask(str(ip), mask)
                    opts_to_keep.append(dns.edns.ECSOption(masked_ip, src_len))
                    req_logger.debug(f"[ECS] Added Privacy ECS: {masked_ip}/{src_len} (from {client_ip})")
                else:
                    src_len = 32 if ip.version == 4 else 128
                    opts_to_keep.append(dns.edns.ECSOption(str(ip), src_len))
                    req_logger.debug(f"[ECS] Added ECS: {client_ip}/{src_len}")
             except: pass

        if self.forward_mac_mode == 'add':
            mac = self.mac_mapper.get_mac(client_ip)
            if mac:
                try:
                    opts_to_keep.append(dns.edns.GenericOption(65001, bytes.fromhex(mac.replace(':', '').replace('-', ''))))
                    req_logger.debug(f"Added MAC: {mac}")
                except: pass
        
        self._apply_edns_options(request, opts_to_keep)
        try: upstream_query_data = request.to_wire()
        except: upstream_query_data = data

        req_logger.debug(f"Forwarding to Upstream Group: {upstream_group}")
        upstream_data = await self.upstream.forward_query(upstream_query_data, qid=qid, client_ip=client_ip, upstream_group=upstream_group, req_logger=req_logger)
        
        if not upstream_data:
            req_logger.warning("Upstream Resolution Failed (SERVFAIL or Timeout)")
            reply = dns.message.make_response(request)
            reply.set_rcode(dns.rcode.SERVFAIL)
            return reply

        try: response = dns.message.from_wire(upstream_data)
        except Exception as e:
             req_logger.warning(f"Upstream sent invalid DNS data: {e}")
             return None
        
        # --- Answer Filtering ---
        # Flow: Domains -> ASN -> GeoIP -> IPs/CIDRs -> Regex
        if not is_explicit_allow and engine and (self.match_answers_globally or engine.has_answer_only_rules()):
            matched_action = None
            
            for section in (response.answer, response.authority, response.additional):
                safe_rrsets = []
                for rrset in section:
                    rrset_action = "PASS"
                    target_text = ""
                    matched_rule = ""
                    matched_list = ""
                    
                    if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                        for rdata in rrset:
                            ip_text = rdata.to_text()
                            # Priority checked inside check_answer
                            rrset_action, rrset_rule, rrset_list = engine.check_answer(
                                None, ip_text, self.geoip, domain_hint=qname_norm, check_query_rules=self.match_answers_globally
                            )
                            
                            if rrset_action != "PASS":
                                req_logger.debug(f"DEBUG: Answer Match (IP) -> Action: {rrset_action} | IP: {ip_text} | Rule: '{rrset_rule}'")

                            if rrset_action in ['BLOCK', 'DROP']:
                                target_text = ip_text
                                matched_rule = rrset_rule
                                matched_list = rrset_list
                                break
                    elif rrset.rdtype in [dns.rdatatype.CNAME, dns.rdatatype.MX, dns.rdatatype.PTR]:
                        for rdata in rrset:
                            target_norm = normalize_domain(str(rdata.target))
                            rrset_action, rrset_rule, rrset_list = engine.check_answer(
                                target_norm, None, self.geoip, check_query_rules=self.match_answers_globally
                            )
                            
                            if rrset_action != "PASS":
                                req_logger.debug(f"DEBUG: Answer Match (Domain) -> Action: {rrset_action} | Domain: {target_norm} | Rule: '{rrset_rule}'")

                            if rrset_action in ['BLOCK', 'DROP']:
                                target_text = target_norm
                                matched_rule = rrset_rule
                                matched_list = rrset_list
                                break
                    
                    if rrset_action == "DROP":
                        req_logger.info(f"🔇 DROPPED (Answer Match) | Target: {target_text} | Rule: '{matched_rule}' | List: '{matched_list}'")
                        return None
                    elif rrset_action == "BLOCK":
                        # If filtering is ON, we exclude this RRSET and continue.
                        # If blocking is 'block', we return the full block response.
                        if self.ip_block_mode == 'block':
                            req_logger.info(f"⛔ BLOCKED (Answer Match) | Target: {target_text} | Rule: '{matched_rule}' | List: '{matched_list}' | Mode: block (entire response)")
                            return self.create_block_response(request, request.question[0].name, qtype)
                        else:
                            matched_action = "BLOCK"
                            req_logger.info(f"⛔ BLOCKED (Answer Filter) | Stripping record: {target_text} | Rule: '{matched_rule}' | List: '{matched_list}'")
                            # Continue loop effectively filters this RRSET by not adding it to safe_rrsets
                            continue
                    
                    safe_rrsets.append(rrset)
                
                section.clear()
                section.extend(safe_rrsets)

            # If all IPs were filtered out (empty response), invoke standard block action
            has_ips = False
            for rrset in response.answer:
                if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                    has_ips = True
                    break
            
            if matched_action == "BLOCK" and not has_ips:
                 req_logger.info(f"⛔ BLOCKED (Filtered Empty) | All records removed")
                 return self.create_block_response(request, request.question[0].name, qtype)

        self.collapse_cnames(response, req_logger)
        self.minimize_response(response)
        self.modify_ttls(response, req_logger)
        
        self.cache.put_dns(response, qname_norm, qtype, group=group_key, scope=policy_name, req_logger=req_logger)
        return response


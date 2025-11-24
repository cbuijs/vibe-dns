#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# Updated: 2025-11-24 14:20:00
# -----------------------------------------------------------------------------

import asyncio
import time
import random
import ipaddress
import ssl
import logging
from datetime import datetime
from urllib.parse import urlparse
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, AAAA, DNSHeader
import aiohttp

from utils import logger, is_ip_in_network

# -----------------------------------------------------------------------------
# Rate Limiter
# -----------------------------------------------------------------------------
# Manages request floods. It tracks the number of queries per subnet (IPv4 /24, IPv6 /64)
# within a time window.
# - UDP floods get "TC" (Truncated) to force TCP retry (harder to spoof).
# - Total floods get silently dropped.
# It has a built-in Garbage Collector (GC) to remove old client entries.
# -----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, config):
        self.enabled = config.get('enabled', True)
        self.window = config.get('window_seconds', 60)
        self.udp_thresh = config.get('udp_threshold', 100)
        self.total_thresh = config.get('total_threshold', 200)
        self.ipv4_mask = config.get('ipv4_mask', 32)
        self.ipv6_mask = config.get('ipv6_mask', 128)
        self.clients = {}
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(self.window * 2)
            now = time.time()
            expired = [k for k, v in self.clients.items() if now - v['start'] > (self.window * 2)]
            for k in expired: del self.clients[k]

    def get_subnet_key(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                if self.ipv4_mask < 32:
                    return str(ipaddress.IPv4Network((ip, self.ipv4_mask), strict=False))
                return str(ip)
            elif ip.version == 6:
                if self.ipv6_mask < 128:
                    return str(ipaddress.IPv6Network((ip, self.ipv6_mask), strict=False))
                return str(ip)
        except Exception:
            pass
        return ip_str 

    def check(self, ip, proto):
        if not self.enabled: return "ALLOW"
        subnet_key = self.get_subnet_key(ip)
        now = time.time()
        
        if subnet_key not in self.clients:
            self.clients[subnet_key] = {'start': now, 'udp': 0, 'total': 0}
        
        entry = self.clients[subnet_key]
        if now - entry['start'] > self.window:
            entry['start'] = now
            entry['udp'] = 0
            entry['total'] = 0
            
        entry['total'] += 1
        if proto == 'udp': entry['udp'] += 1
            
        if entry['total'] > self.total_thresh:
            # We let the caller handle the logging to include query ID context
            return "DROP"
        
        if proto == 'udp' and entry['udp'] > self.udp_thresh:
            return "TC"
            
        return "ALLOW"

# -----------------------------------------------------------------------------
# Request Deduplicator
# -----------------------------------------------------------------------------
# Prevents "Cache Stampedes". If 50 clients ask for "google.com" at the exact
# same millisecond, we only send 1 query upstream and answer all 50 with the result.
# -----------------------------------------------------------------------------
class RequestDeduplicator:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.pending = {}

    async def get_or_process(self, qname, qtype, scope, worker_coroutine):
        if not self.enabled:
            return await worker_coroutine()

        key = (qname, qtype, scope)
        if key in self.pending:
            logger.debug(f"MATCH DEDUPLICATION: Joining in-flight query for {qname} [{scope}]")
            return await self.pending[key]
        
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.pending[key] = future
        
        try:
            result = await worker_coroutine()
            if not future.done():
                future.set_result(result)
            return result
        except Exception as e:
            if not future.done():
                future.set_exception(e)
            raise e
        finally:
            if key in self.pending:
                del self.pending[key]

# -----------------------------------------------------------------------------
# DNS Cache
# -----------------------------------------------------------------------------
# Stores DNS responses in RAM.
# It automatically updates the TTL of cached records before serving them, so
# clients always see the remaining time, not the original time.
# -----------------------------------------------------------------------------
class DNSCache:
    def __init__(self, size, ttl_margin, negative_ttl, gc_interval=300):
        self.cache = {} 
        self.size = size
        self.margin = ttl_margin
        self.negative_ttl = negative_ttl
        self.max_size = size
        self.DEFAULT_SCOPE = "DEFAULT_CACHE"
        self.gc_interval = gc_interval
        # Background task to remove expired entries
        asyncio.create_task(self.gc_loop())

    async def gc_loop(self):
        while True:
            await asyncio.sleep(self.gc_interval)
            now = time.time()
            expired = [k for k, v in self.cache.items() if v[1] < now]
            for k in expired: del self.cache[k]
            if expired: logger.info(f"CACHE GC: Flushed {len(expired)} items.")

    def get(self, qname, qtype, scope=None):
        if scope is None: scope = self.DEFAULT_SCOPE
        key = (str(qname), qtype, scope)
        
        if key in self.cache:
            record_bytes, expire_time = self.cache[key]
            now = time.time()
            ttl_remain = expire_time - now
            
            if ttl_remain > 0:
                try:
                    record = DNSRecord.parse(record_bytes)
                    # Update TTLs in the record to reflect remaining time
                    for rr in record.rr: rr.ttl = int(ttl_remain)
                    for rr in record.ar: rr.ttl = int(ttl_remain)
                    for rr in record.auth: rr.ttl = int(ttl_remain)
                    return record, ttl_remain
                except Exception:
                    del self.cache[key]
            else:
                logger.debug(f"CACHE EXPIRED: {qname} [{QTYPE[qtype]}]")
                del self.cache[key]
        return None, 0

    def put(self, record, scope=None, forced_ttl=None):
        if self.max_size == 0: return
        if scope is None: scope = self.DEFAULT_SCOPE

        if len(self.cache) >= self.max_size:
            keys = list(self.cache.keys())
            if keys:
                del self.cache[random.choice(keys)]
                logger.debug("CACHE GC: Evicted random entry")

        qname = str(record.q.qname)
        qtype = record.q.qtype
        
        if forced_ttl is not None:
            min_ttl = forced_ttl
        else:
            ttls = [rr.ttl for rr in record.rr] + [rr.ttl for rr in record.ar] + [rr.ttl for rr in record.auth]
            min_ttl = min(ttls) if ttls else self.negative_ttl
        
        expire_time = time.time() + min_ttl
        key = (qname, qtype, scope)
        
        self.cache[key] = (record.pack(), expire_time)
        logger.info(f"CACHE WRITE [{scope}]: {qname} [{QTYPE[qtype]}] Stored TTL: {int(min_ttl)}s")

# -----------------------------------------------------------------------------
# Upstream Management
# -----------------------------------------------------------------------------
# Manages the pool of upstream servers (e.g., Cloudflare, Quad9).
# Periodically checks latency and sorts them so the fastest one is used.
# -----------------------------------------------------------------------------
class UpstreamManager:
    def __init__(self, config):
        self.servers = [] 
        self.parse_config(config)
        self.monitor_interval = config.get('monitor_interval', 60)
        self.monitor_on_query = config.get('monitor_on_query', False)
        self.test_domain = config.get('test_domain', 'www.google.com')
        self.loop = asyncio.get_event_loop()
        self.session = None 
        self.last_monitor_time = 0

    async def get_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    def parse_config(self, config):
        raw_servers = config.get('servers', [])
        for s in raw_servers:
            forced_ip = None
            if '#' in s: s, forced_ip = s.split('#')
            if '://' in s: proto, rest = s.split('://')
            else: proto, rest = 'udp', s
            
            path = "/dns-query"
            if proto in ['https', 'doh'] and '/' in rest:
                parts = rest.split('/', 1)
                rest, path = parts[0], '/' + parts[1]
            
            if ':' in rest and not rest.endswith(']'): 
                host, port = rest.split(':')
                port = int(port)
            else:
                host, port = rest, 53 if proto in ['udp','tcp'] else 853 if proto == 'tls' else 443

            self.servers.append({
                'proto': proto, 'host': host, 'ip': forced_ip or host, 
                'port': port, 'path': path, 'latency': 999
            })

    async def start_monitor(self):
        await self.check_latencies()
        while True:
            await asyncio.sleep(self.monitor_interval)
            if not self.monitor_on_query:
                 await self.check_latencies()

    async def check_latencies_if_needed(self):
        if self.monitor_on_query:
            if time.time() - self.last_monitor_time > self.monitor_interval:
                asyncio.create_task(self.check_latencies())

    async def check_latencies(self):
        logger.debug("UPSTREAM MONITOR: Starting latency check...")
        self.last_monitor_time = time.time()
        
        tasks = [self._measure_latency(s) for s in self.servers]
        results = await asyncio.gather(*tasks)
        
        # Log latencies for debug
        for i, lat in enumerate(results):
            self.servers[i]['latency'] = lat
            logger.debug(f"UPSTREAM MONITOR: {self.servers[i]['host']} -> {lat:.3f}s")

        old_fastest = self.servers[0] if self.servers else None
        self.servers.sort(key=lambda x: x['latency'])
        new_fastest = self.servers[0] if self.servers else None

        if old_fastest and new_fastest and old_fastest['host'] != new_fastest['host']:
            logger.info(f"UPSTREAM SWITCH: {old_fastest['host']} ({old_fastest['latency']:.3f}s) -> {new_fastest['host']} ({new_fastest['latency']:.3f}s)")

    async def _measure_latency(self, server):
        start = time.time()
        try:
            q = DNSRecord.question(self.test_domain)
            pkt = q.pack()
            timeout = 2.0 
            
            if server['proto'] == 'udp':
                await self._udp_query(server['ip'], server['port'], pkt, timeout=timeout)
            elif server['proto'] == 'tcp':
                 await self._tcp_query(server['ip'], server['port'], pkt, timeout=timeout)
            elif server['proto'] == 'tls':
                 await self._tcp_query(server['ip'], server['port'], pkt, timeout=timeout, tls=True, hostname=server['host'])
            elif server['proto'] in ['https', 'doh']:
                 await self._doh_query(server['ip'], server['port'], server['host'], server['path'], pkt, timeout=timeout)
            
            return time.time() - start
        except Exception as e:
            return 999.0 # High penalty on failure

    async def forward_query(self, query_data, qid=0, client_ip="Unknown"):
        await self.check_latencies_if_needed()

        for server in self.servers[:3]:
            try:
                logger.info(f"[ID:{qid}] [IP:{client_ip}] FORWARDING: to {server['host']} ({server['proto']}://{server['ip']}:{server['port']})")
                if server['proto'] == 'udp':
                    return await self._udp_query(server['ip'], server['port'], query_data)
                elif server['proto'] == 'tcp':
                    return await self._tcp_query(server['ip'], server['port'], query_data)
                elif server['proto'] == 'tls':
                    return await self._tcp_query(server['ip'], server['port'], query_data, tls=True, hostname=server['host'])
                elif server['proto'] in ['https', 'doh']:
                    return await self._doh_query(server['ip'], server['port'], server['host'], server['path'], query_data)
            except Exception as e:
                logger.warning(f"[ID:{qid}] [IP:{client_ip}] UPSTREAM FAILED {server['host']}: {e}")
                continue
        return None

    async def _udp_query(self, ip, port, data, timeout=5):
        import socket
        sock_family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(sock_family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        await self.loop.sock_connect(sock, (ip, port))
        await self.loop.sock_sendall(sock, data)
        response = await asyncio.wait_for(self.loop.sock_recv(sock, 65535), timeout)
        sock.close()
        return response

    async def _tcp_query(self, ip, port, data, timeout=5, tls=False, hostname=None):
        ssl_ctx = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            if hostname: ssl_ctx.check_hostname = True
            else: ssl_ctx.check_hostname, ssl_ctx.verify_mode = False, ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=hostname if tls else None)
        try:
            writer.write(len(data).to_bytes(2, 'big') + data)
            await writer.drain()
            len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
            resp_len = int.from_bytes(len_bytes, 'big')
            return await asyncio.wait_for(reader.readexactly(resp_len), timeout)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _doh_query(self, ip, port, hostname, path, data, timeout=5):
        session = await self.get_session()
        url = f"https://{hostname}:{port}{path}"
        headers = {'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'}
        async with session.post(url, data=data, headers=headers, timeout=timeout) as resp:
            if resp.status == 200: return await resp.read()
            raise Exception(f"DoH status {resp.status}")

# -----------------------------------------------------------------------------
# DNS Request Handler
# -----------------------------------------------------------------------------
# This is the core logic class.
# 1. Identifies the client (IP/MAC/SNI).
# 2. Checks caches.
# 3. Enforces Rate Limits.
# 4. Enforces Block/Allow Policies.
# 5. Forwards to upstream if allowed.
# 6. Filters and Modifies responses (CNAME collapse, TTLs, Round Robin).
# -----------------------------------------------------------------------------
class DNSHandler:
    def __init__(self, config, policy_map, default_policy, rule_engines, groups, mac_mapper, upstream, cache):
        self.config = config
        self.policy_map = policy_map
        self.rule_engines = rule_engines
        self.groups = groups
        self.mac_mapper = mac_mapper
        self.upstream = upstream
        self.cache = cache
        self.schedules = config.get('schedules', {})
        
        self.block_rcode = getattr(RCODE, config['response'].get('block_rcode', 'REFUSED'))
        self.block_ip_opt = config['response'].get('block_ip', None)
        self.block_ttl = config['response'].get('block_ttl', 60)
        
        self.rate_limiter = RateLimiter(config.get('rate_limit', {}))
        self.deduplicator = RequestDeduplicator(config.get('deduplication', {}).get('enabled', True))
        self.DEFAULT_POLICY_SCOPE = "DEFAULT_CACHE"
        
        self.prefetch_margin = config['cache'].get('prefetch_margin', 0)
        self.round_robin = config['response'].get('round_robin_enabled', False)

    def identify_client(self, addr, meta=None):
        ip = addr[0]
        mac = self.mac_mapper.get_mac(ip)
        meta = meta or {}
        sni, path = meta.get('sni', '').lower(), meta.get('path', '').lower()
        
        for gname, identifiers in self.groups.items():
            for ident in identifiers:
                ident = ident.lower()
                
                if ident == ip:
                    logger.info(f"MATCH CLIENT: IP {ip} -> Group '{gname}' (Exact IP)")
                    return gname
                
                if '/' in ident and not ident.startswith('path:') and is_ip_in_network(ip, ident):
                    logger.info(f"MATCH CLIENT: IP {ip} -> Group '{gname}' (CIDR {ident})")
                    return gname
                
                if mac and ident == mac.lower():
                    logger.info(f"MATCH CLIENT: MAC {mac} (IP: {ip}) -> Group '{gname}'")
                    return gname
                
                if ident.startswith('sni:') and sni and sni == ident[4:]:
                    logger.info(f"MATCH CLIENT: SNI {sni} (IP: {ip}) -> Group '{gname}'")
                    return gname
                
                if ident.startswith('path:') and path and path == ident[5:]:
                    logger.info(f"MATCH CLIENT: PATH {path} (IP: {ip}) -> Group '{gname}'")
                    return gname
        return None

    def is_schedule_active(self, schedule_name):
        if not schedule_name or schedule_name not in self.schedules: return False
        schedule = self.schedules[schedule_name]
        now = datetime.now()
        current_day = now.strftime("%a")
        current_hm = now.strftime("%H:%M")
        
        if "days" in schedule and current_day not in schedule["days"]: return False
        slots = schedule.get("slots", [])
        if "start" in schedule and "end" in schedule:
            slots.append({"start": schedule["start"], "end": schedule["end"]})
            
        for slot in slots:
            start = slot.get("start")
            end = slot.get("end")
            if not start or not end: continue
            
            # Handle overnight slots (e.g. 22:00 to 06:00)
            if start <= end:
                if start <= current_hm < end: return True
            else:
                if current_hm >= start or current_hm < end: return True
        return False

    def get_active_policy(self, group):
        if not group or group not in self.policy_map: return self.DEFAULT_POLICY_SCOPE
        assignment = self.policy_map[group]
        default_policy = assignment.get('policy', self.DEFAULT_POLICY_SCOPE)
        schedule_name = assignment.get('schedule')
        
        if self.is_schedule_active(schedule_name):
            sched_policy = assignment.get('schedule_policy')
            if sched_policy:
                logger.info(f"MATCH SCHEDULE: '{schedule_name}' is ACTIVE. Override Policy: {default_policy} -> {sched_policy}")
                return sched_policy
        return default_policy

    def create_block_response(self, request, qname, qtype):
        reply = request.reply()
        inject_ip = None
        
        if self.block_ip_opt:
            if self.block_ip_opt == "NULL":
                if qtype == QTYPE.A: inject_ip = "0.0.0.0"
                elif qtype == QTYPE.AAAA: inject_ip = "::"
            else:
                try:
                    ip_obj = ipaddress.ip_address(self.block_ip_opt)
                    if qtype == QTYPE.A and ip_obj.version == 4:
                        inject_ip = self.block_ip_opt
                    elif qtype == QTYPE.AAAA and ip_obj.version == 6:
                        inject_ip = self.block_ip_opt
                except ValueError: pass

        if inject_ip:
            try:
                if qtype == QTYPE.A: 
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(inject_ip), ttl=self.block_ttl))
                    reply.header.rcode = RCODE.NOERROR
                elif qtype == QTYPE.AAAA: 
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(inject_ip), ttl=self.block_ttl))
                    reply.header.rcode = RCODE.NOERROR
            except Exception as e:
                logger.error(f"Failed to inject block IP {inject_ip}: {e}")
                reply.header.rcode = self.block_rcode
        else:
            reply.header.rcode = self.block_rcode
        return reply

    def collapse_cnames(self, response, qid=0, client_ip="Unknown"):
        if not self.config['response'].get('cname_collapse', True): return
        max_iterations = 10
        qname = response.q.qname
        cnames_removed = 0
        records_hoisted = 0
        
        for _ in range(max_iterations):
            qname_str = str(qname).lower()
            cname_rr = None
            for rr in response.rr:
                if rr.rtype == QTYPE.CNAME and str(rr.rname).lower() == qname_str:
                    cname_rr = rr
                    break
            
            if not cname_rr: break
            target_str = str(cname_rr.rdata).lower()
            target_rrs = [rr for rr in response.rr if str(rr.rname).lower() == target_str and rr is not cname_rr]
            
            if not target_rrs: break
            
            cnames_removed += 1
            for rr in target_rrs: 
                records_hoisted += 1
                rr.rname = cname_rr.rname
                # TTL of hoisted record should not exceed the CNAME's TTL
                if cname_rr.ttl < rr.ttl:
                    rr.ttl = cname_rr.ttl

            response.rr = [rr for rr in response.rr if rr is not cname_rr]
        
        if cnames_removed > 0:
            logger.info(f"[ID:{qid}] [IP:{client_ip}] CNAME COLLAPSE: Flattened {cnames_removed} CNAMEs, hoisted {records_hoisted} records.")

    def minimize_response(self, response, qid=0, client_ip="Unknown"):
        if self.config['response'].get('minimize_response', False):
            if response.ar or response.auth:
                count_removed = len(response.ar) + len(response.auth)
                response.ar = []
                response.auth = []
                logger.info(f"[ID:{qid}] [IP:{client_ip}] RESPONSE MINIMIZED: Stripped {count_removed} records.")

    def modify_ttls(self, response, qid=0, client_ip="Unknown"):
        min_ttl = self.config['response'].get('min_ttl', 0)
        max_ttl = self.config['response'].get('max_ttl', 86400)
        sync_mode = self.config['response'].get('ttl_sync_mode', 'none')
        
        if not response.rr: return

        ttls = [rr.ttl for rr in response.rr]
        new_ttl = None
        if sync_mode != 'none':
            if sync_mode == 'first': new_ttl = ttls[0]
            elif sync_mode == 'last': new_ttl = ttls[-1]
            elif sync_mode == 'highest': new_ttl = max(ttls)
            elif sync_mode == 'lowest': new_ttl = min(ttls)
            elif sync_mode == 'average': new_ttl = int(sum(ttls) / len(ttls))
            logger.info(f"[ID:{qid}] [IP:{client_ip}] TTL SYNC: Mode '{sync_mode}' set all TTLs to {new_ttl}s")

        for rr in response.rr:
            if new_ttl is not None: rr.ttl = new_ttl
            
            if rr.ttl < min_ttl: 
                rr.ttl = min_ttl
                logger.debug(f"[ID:{qid}] [IP:{client_ip}] TTL CLAMP: Boosted {rr.ttl}s -> {min_ttl}s")
            elif rr.ttl > max_ttl: 
                rr.ttl = max_ttl
                logger.debug(f"[ID:{qid}] [IP:{client_ip}] TTL CLAMP: Capped {rr.ttl}s -> {max_ttl}s")

    def round_robin_answers(self, response, qid=0, client_ip="Unknown"):
        if not self.round_robin or not response.rr: return
        
        a_records = [rr for rr in response.rr if rr.rtype == QTYPE.A]
        aaaa_records = [rr for rr in response.rr if rr.rtype == QTYPE.AAAA]
        other_records = [rr for rr in response.rr if rr.rtype not in [QTYPE.A, QTYPE.AAAA]]
        
        shuffled_types = []
        if len(a_records) > 1:
            random.shuffle(a_records)
            shuffled_types.append("A")
            
        if len(aaaa_records) > 1:
            random.shuffle(aaaa_records)
            shuffled_types.append("AAAA")
            
        if shuffled_types:
            response.rr = other_records + a_records + aaaa_records
            logger.info(f"[ID:{qid}] [IP:{client_ip}] ROUND ROBIN: Shuffled {', '.join(shuffled_types)} records.")

    def log_answer_records(self, response, qid, client_ip):
        if logger.isEnabledFor(logging.DEBUG):
             for rr in response.rr:
                 logger.debug(f"[ID:{qid}] [IP:{client_ip}] ANSWER: {rr.rname} {QTYPE[rr.rtype]} TTL={rr.ttl} DATA={rr.rdata}")

    async def process_query(self, data, client_addr, meta=None):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = request.q.qtype
            qid = request.header.id
            client_ip = client_addr[0]
            
            # 1. Identify Client & Policy FIRST
            group = self.identify_client(client_addr, meta)
            policy_name = self.get_active_policy(group)
            engine = self.rule_engines.get(policy_name)

            # 2. CHECK CACHE (High Priority)
            cached_record, ttl_remain = self.cache.get(qname, qtype, scope=policy_name)
            if cached_record:
                logger.info(f"[ID:{qid}] [IP:{client_ip}] CACHE HIT [{policy_name}]: {qname} TTL: {int(ttl_remain)}s")
                reply = cached_record
                reply.header.id = qid 
                
                # Prefetch?
                if self.prefetch_margin > 0 and ttl_remain < self.prefetch_margin:
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] PREFETCH INITIATED: {qname} (TTL: {int(ttl_remain)}s < Margin: {self.prefetch_margin}s)")
                    async def prefetch_worker():
                        await self._resolve_upstream(qname, qtype, data, qid, engine, policy_name, request, client_ip)
                    asyncio.create_task(prefetch_worker())

                self.round_robin_answers(reply, qid, client_ip)
                self.log_answer_records(reply, qid, client_ip)
                return reply.pack()

            # 3. Rate Limiting
            limit_action = self.rate_limiter.check(client_ip, meta.get('proto', 'udp'))
            if limit_action == "DROP": 
                logger.warning(f"[ID:{qid}] [IP:{client_ip}] RATE LIMIT DROP: {client_ip}")
                return None
            if limit_action == "TC":
                reply = request.reply()
                reply.header.tc = 1
                return reply.pack()

            # 4. Schedule Blocking
            if policy_name == "BLOCK":
                logger.info(f"[ID:{qid}] [IP:{client_ip}] MATCH SCHEDULE BLOCK (QUERY): {qname}")
                block_resp = self.create_block_response(request, qname, qtype)
                self.cache.put(block_resp, scope=policy_name, forced_ttl=60)
                return block_resp.pack()
            elif policy_name == "ALLOW":
                engine = None
            
            logger.info(f"[ID:{qid}] [IP:{client_ip}] QUERY: {client_ip} -> {qname} [{QTYPE[qtype]}] Policy: {policy_name}")

            # 5. Policy Check
            if engine:
                blocked_type, type_reason, type_list = engine.check_type(qtype)
                if blocked_type:
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] BLOCK TYPE: {qname} Reason: {type_reason} (List: {type_list})")
                    reply = request.reply()
                    reply.header.rcode = self.block_rcode
                    self.cache.put(reply, scope=policy_name, forced_ttl=60)
                    return reply.pack()

                action, rule, list_name = engine.is_blocked(qname)
                if action == "BLOCK":
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] BLOCK DOMAIN: {qname} Rule: '{rule}' (List: {list_name})")
                    block_resp = self.create_block_response(request, qname, qtype)
                    self.cache.put(block_resp, scope=policy_name, forced_ttl=300)
                    return block_resp.pack()
                elif action == "ALLOW":
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] ALLOW DOMAIN: {qname} Rule: '{rule}' (List: {list_name})")

            # 6. Upstream
            async def resolve_worker():
                return await self._resolve_upstream(qname, qtype, data, qid, engine, policy_name, request, client_ip)

            final_record = await self.deduplicator.get_or_process(qname, qtype, policy_name, resolve_worker)
            self.round_robin_answers(final_record, qid, client_ip)
            final_record.header.id = qid
            self.log_answer_records(final_record, qid, client_ip)
            return final_record.pack()

        except Exception as e:
            logger.error(f"HANDLER ERROR: {e}", exc_info=True)
            return None

    async def _resolve_upstream(self, qname, qtype, data, qid, engine, policy_name, request, client_ip="Unknown"):
        logger.info(f"[ID:{qid}] [IP:{client_ip}] CACHE MISS [{policy_name}]: {qname} - Forwarding...")
        
        upstream_data = await self.upstream.forward_query(data, qid=qid, client_ip=client_ip)
        if not upstream_data:
            fail_reply = request.reply()
            fail_reply.header.rcode = RCODE.SERVFAIL
            return fail_reply

        response = DNSRecord.parse(upstream_data)
        logger.info(f"[ID:{qid}] [IP:{client_ip}] UPSTREAM RESPONSE: {qname} RCODE: {RCODE[response.header.rcode]}")
        
        # Filter answers (Before modification)
        if engine:
            filtered_rrs = []
            for rr in response.rr:
                is_bad = False
                bad_rule, bad_list = "", ""
                if rr.rtype in [QTYPE.A, QTYPE.AAAA]: 
                    is_bad, bad_rule, bad_list = engine.check_answer(None, str(rr.rdata))
                elif rr.rtype in [QTYPE.CNAME, QTYPE.MX, QTYPE.NS, QTYPE.PTR, QTYPE.SRV]: 
                    is_bad, bad_rule, bad_list = engine.check_answer(str(rr.rdata), None)
                
                if is_bad: 
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] RESPONSE FILTER (ANSWER): Removed {rr.rdata}. Rule: '{bad_rule}' ({bad_list})")
                    if rr.rtype not in [QTYPE.A, QTYPE.AAAA]:
                        logger.info(f"[ID:{qid}] [IP:{client_ip}] STRICT BLOCK: Blocked domain in answer. Blocking full response.")
                        block_resp = self.create_block_response(request, qname, qtype)
                        self.cache.put(block_resp, scope=policy_name, forced_ttl=60)
                        return block_resp
                else: filtered_rrs.append(rr)
            
            response.rr = filtered_rrs
            if not response.rr and request.q.qtype in [QTYPE.A, QTYPE.AAAA]:
                    logger.info(f"[ID:{qid}] [IP:{client_ip}] RESPONSE FILTER (ANSWER): All IPs removed. Blocking.")
                    block_resp = self.create_block_response(request, qname, qtype)
                    self.cache.put(block_resp, scope=policy_name, forced_ttl=60)
                    return block_resp

        self.collapse_cnames(response, qid=qid, client_ip=client_ip)
        self.minimize_response(response, qid=qid, client_ip=client_ip)
        self.modify_ttls(response, qid=qid, client_ip=client_ip)
        self.cache.put(response, scope=policy_name)
        return response



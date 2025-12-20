#!/usr/bin/env python3
# filename: server.py
# Version: 5.1.0 (Recursive Resolver with Fallback Group)
"""
Main Server Module with DoH/DoT support and recursive resolution.
"""

import asyncio
import yaml
import sys
import os
import argparse
import logging
import signal
import random
from typing import Any, Optional

import dns.message
import dns.rdatatype

from list_manager import ListManager         
from upstream_manager import UpstreamManager 
from resolver import DNSHandler, DNSCache    
from utils import setup_logger, MacMapper, get_server_ips, get_logger, GroupFileLoader, merge_groups
from config_validator import validate_config
from defaults import merge_with_defaults
from geoip import GeoIPLookup
from secure_dns_listeners import DoTServer, DoHServer, create_ssl_context

logger = get_logger("Server")


class UDPServer:
    """AsyncIO Datagram Protocol for DNS UDP with Concurrency Limit"""
    def __init__(self, handler, host, port, max_concurrent=1000):
        self.handler = handler
        self.host = host
        self.port = port
        self.transport = None
        self.sem = asyncio.Semaphore(max_concurrent)

    def connection_made(self, transport):
        self.transport = transport
        logger.debug(f"UDP Transport bound to {self.host}:{self.port}")

    def datagram_received(self, data, addr):
        if self.sem.locked():
            logger.warning(f"UDP Overload: Dropping packet from {addr}")
            return
        asyncio.create_task(self.handle_safe(data, addr))

    async def handle_safe(self, data, addr):
        async with self.sem:
            await self.handle(data, addr)

    async def handle(self, data, addr):
        try:
            meta = {
                'proto': 'udp',
                'server_ip': self.host,
                'server_port': self.port
            }
            resp = await self.handler.process_query(data, addr, meta)
            if resp and self.transport:
                self.transport.sendto(resp, addr)
        except Exception as e:
            logger.exception(f"Error handling UDP packet from {addr}: {e}")


class TCPServer:
    """AsyncIO Stream Handler for DNS TCP"""
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.debug(f"TCP Connection from {addr} on {self.host}:{self.port}")
        
        meta = {
            'proto': 'tcp', 
            'server_ip': self.host,
            'server_port': self.port
        }
        
        try:
            len_bytes = await reader.readexactly(2)
            length = int.from_bytes(len_bytes, 'big')
            data = await reader.readexactly(length)
            
            resp = await self.handler.process_query(data, addr, meta)
            
            if resp:
                writer.write(len(resp).to_bytes(2, 'big') + resp)
                await writer.drain()
                
        except asyncio.IncompleteReadError:
            logger.debug(f"TCP Connection closed prematurely by {addr}")
        except Exception as e:
            logger.exception(f"TCP Error {addr}: {e}")
        finally:
            writer.close()


async def shutdown(sig: signal.Signals, stop_event: asyncio.Event) -> None:
    logger.info(f"Received exit signal {sig.name}...")
    stop_event.set()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filtering DNS Server")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config file")
    parser.add_argument("--validate-only", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--skip-validation", action="store_true", help="Skip configuration validation on startup")
    return parser.parse_args()


async def init_recursive_resolver(config: dict, upstream_manager: UpstreamManager):
    """Initialize recursive resolver if enabled"""
    recursive_cfg = config.get('upstream', {}).get('recursive', {})
    
    if not recursive_cfg.get('enabled', False):
        logger.info("Recursive resolution: DISABLED (using forwarding)")
        return None
    
    try:
        from recursive_resolver import RecursiveResolver
        
        logger.info(">>> Initializing Recursive Resolver")
        # Pass upstream_manager to resolver for fallback support
        resolver = RecursiveResolver(recursive_cfg, upstream_manager)
        
        if not await resolver.initialize():
            logger.error("Failed to initialize recursive resolver")
            return None
        
        dnssec_mode = recursive_cfg.get('dnssec', {}).get('mode', 'none')
        fallback_msg = f", Fallback: {recursive_cfg.get('fallback_group', 'None')}" if recursive_cfg.get('fallback_enabled') else ""
        logger.info(f"Recursive resolution: ENABLED (DNSSEC mode: {dnssec_mode}{fallback_msg})")
        
        return resolver
        
    except ImportError as e:
        logger.error(f"Recursive resolver module not found: {e}")
        logger.error("Make sure recursive_resolver.py, dnssec_validator.py, and root_hints.py are available")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize recursive resolver: {e}")
        return None


async def main() -> None:
    args = parse_arguments()
    config: dict[str, Any] = {}
    
    logger.info(">>> Phase 1: Configuration Loading")
    if os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {args.config}")
            
            config = merge_with_defaults(config)
            logger.debug("Applied default configuration values")
            
        except Exception as e:
            print(f"FATAL: Error loading config file: {e}")
            sys.exit(1)
    else:
        print(f"Config not found at {args.config}")
        if not args.validate_only:
            print("Using internal defaults")
        else:
            sys.exit(1)

    # Configuration validation
    if args.validate_only:
        logger.info(">>> Phase 1.5: Configuration Validation")
        is_valid, errors, warnings = validate_config(config)
        if errors:
            logger.error("Configuration validation failed!")
            sys.exit(1)
        print("\n✅ Configuration validation PASSED")
        sys.exit(0)
    elif not args.skip_validation:
        logger.info(">>> Phase 1.5: Configuration Validation")
        is_valid, errors, warnings = validate_config(config)
        if errors:
            logger.error("Configuration validation failed!")
            sys.exit(1)
    else:
        logger.warning("Configuration validation SKIPPED (--skip-validation)")

    if not config.get('server', {}).get('bind_ip') and not config.get('server', {}).get('bind_interfaces'):
        logger.info("No explicit bind_ip configured. Defaulting to ALL interfaces")
        config.setdefault('server', {})['bind_ip'] = ["0.0.0.0", "::"]

    setup_logger(config)
    logger.info("Starting DNS Filter Server v5.1.0")
    
    logger.info(">>> Phase 2: Component Initialization")
    
    listen_ips = get_server_ips(config)
    mac_mapper = MacMapper(config.get('mac_cache_refresh_interval', 300))
    
    group_file_loader = None
    if 'group_files' in config:
        group_file_loader = GroupFileLoader(config)
    
    merged_groups = merge_groups(config.get('groups', {}), group_file_loader)
    
    list_manager = ListManager(
        cache_dir="./list_cache", 
        refresh_interval=config.get('list_refresh_interval', 86400),
        categories_file=config.get('categories_file', 'categories.json')
    )
    await list_manager.update_lists(config.get('lists', {}))
    
    rule_engines = {}
    for pol_name, pol_cfg in config.get('policies', {}).items():
        rule_engines[pol_name] = list_manager.compile_policy(pol_name, pol_cfg, global_config=config)

    upstream = UpstreamManager(config.get('upstream', {}))
    monitor_task = asyncio.create_task(upstream.start_monitor())
    
    if config.get('upstream', {}).get('startup_check_enabled', True):
        logger.info("Performing startup upstream health check...")
        await asyncio.sleep(1)
    
    geoip_lookup = GeoIPLookup(config)
    
    # Initialize recursive resolver (if enabled) - PASS upstream manager now
    recursive_resolver = await init_recursive_resolver(config, upstream)
    
    cache_cfg = config.get('cache', {})
    cache = DNSCache(
        size=cache_cfg.get('size', 10000),
        ttl_margin=cache_cfg.get('prefetch_margin', 0),
        negative_ttl=cache_cfg.get('negative_ttl', 60),
        gc_interval=cache_cfg.get('gc_interval', 300),
        prefetch_min_hits=cache_cfg.get('prefetch_min_hits', 3)
    )

    handler = DNSHandler(
        config=config, 
        policy_map=config.get('assignments', {}), 
        default_policy="ALLOW", 
        rule_engines=rule_engines,
        groups=merged_groups, 
        mac_mapper=mac_mapper, 
        upstream=upstream, 
        cache=cache,
        geoip=geoip_lookup,
        recursive_resolver=recursive_resolver
    )

    logger.info(">>> Phase 3: Starting Listeners")
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    
    servers = []     
    transports = []  

    def get_ports(key: str, default: list[int]) -> list[int]:
        val = config.get('server', {}).get(key, default)
        return val if isinstance(val, list) else [val]

    udp_ports = get_ports('port_udp', [53])
    tcp_ports = get_ports('port_tcp', [53])
    
    # DoT/DoH ports from TLS context
    tls_cfg = config.get('server', {}).get('tls', {})
    dot_ports_val = tls_cfg.get('port_dot', [853])
    doh_ports_val = tls_cfg.get('port_doh', [443])
    dot_ports = dot_ports_val if isinstance(dot_ports_val, list) else [dot_ports_val]
    doh_ports = doh_ports_val if isinstance(doh_ports_val, list) else [doh_ports_val]

    udp_concurrency = config.get('server', {}).get('udp_concurrency', 1000)

    # Standard UDP/TCP listeners
    for ip in listen_ips:
        for port in udp_ports:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda h=ip, p=port: UDPServer(handler, h, p, max_concurrent=udp_concurrency),
                    local_addr=(ip, port)
                )
                transports.append(transport)
                logger.info(f"✓ UDP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"✗ UDP Bind Error {ip}:{port}: {e}")

        for port in tcp_ports:
            try:
                server = await asyncio.start_server(
                    TCPServer(handler, ip, port).handle_client,
                    ip, port
                )
                servers.append(server)
                logger.info(f"✓ TCP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"✗ TCP Bind Error {ip}:{port}: {e}")

    # DoT/DoH listeners (require SSL config)
    tls_cfg = config.get('server', {}).get('tls', {})
    if tls_cfg.get('enabled', False):
        logger.info(">>> Phase 3.5: Initializing Secure DNS (DoH/DoT)")
        
        cert_file = tls_cfg.get('cert_file')
        key_file = tls_cfg.get('key_file')
        ca_file = tls_cfg.get('ca_file')
        
        logger.info(f"TLS Configuration:")
        logger.info(f"  Certificate: {cert_file}")
        logger.info(f"  Key: {key_file}")
        if ca_file:
            logger.info(f"  CA: {ca_file}")
        
        if cert_file and key_file:
            try:
                ssl_context = create_ssl_context(cert_file, key_file, ca_file)
                
                # DoT Listeners
                if tls_cfg.get('enable_dot', True):
                    dot_count = 0
                    for ip in listen_ips:
                        for port in dot_ports:
                            try:
                                dot_server = DoTServer(handler, ip, port)
                                server = await asyncio.start_server(
                                    dot_server.handle_client,
                                    ip, port,
                                    ssl=ssl_context
                                )
                                servers.append(server)
                                dot_count += 1
                                logger.info(f"✓ DoT Listening on {ip}:{port}")
                            except Exception as e:
                                logger.error(f"✗ DoT Bind Error {ip}:{port}: {e}")
                    
                    if dot_count > 0:
                        logger.info(f"✓ DoT service started on {dot_count} endpoint(s)")
                else:
                    logger.info("DoT disabled in configuration")
                
                # DoH Listeners
                if tls_cfg.get('enable_doh', True):
                    doh_paths = tls_cfg.get('doh_paths', ['/dns-query'])
                    doh_strict = tls_cfg.get('doh_strict_paths', False)
                    
                    logger.info(f"  DoH Paths: {doh_paths}")
                    logger.info(f"  Strict Path Mode: {doh_strict}")
                    
                    doh_count = 0
                    for ip in listen_ips:
                        for port in doh_ports:
                            try:
                                doh_server = DoHServer(handler, ip, port, doh_paths, doh_strict)
                                server = await asyncio.start_server(
                                    doh_server.handle_client,
                                    ip, port,
                                    ssl=ssl_context
                                )
                                servers.append(server)
                                doh_count += 1
                                logger.info(f"✓ DoH Listening on {ip}:{port} (RFC 8484)")
                            except Exception as e:
                                logger.error(f"✗ DoH Bind Error {ip}:{port}: {e}")
                    
                    if doh_count > 0:
                        logger.info(f"✓ DoH service started on {doh_count} endpoint(s)")
                        for path in doh_paths:
                            logger.info(f"  Client URL: https://{listen_ips[0]}:{doh_ports[0]}{path}")
                    else:
                        logger.warning("⚠ DoH enabled but no listeners started")
                else:
                    logger.info("DoH disabled in configuration")
                    
            except Exception as e:
                logger.error(f"✗ Failed to initialize secure DNS: {e}")
                logger.error("Continuing with standard DNS only (UDP/TCP)")
        else:
            logger.warning("⚠ TLS enabled but cert_file/key_file not configured - skipping DoH/DoT")
    else:
        logger.info("TLS disabled - DoH/DoT not available (set server.tls.enabled: true to enable)")

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, stop_event)))

    logger.info("Server Ready. Press Ctrl+C to stop.")
    await stop_event.wait()
    
    # Shutdown
    logger.info("Shutting down...")
    if geoip_lookup: 
        geoip_lookup.close()
    monitor_task.cancel()
    for t in transports: 
        t.close()
    for s in servers:
        s.close()
        await s.wait_closed()
    await upstream.close()
    logger.info("Server stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


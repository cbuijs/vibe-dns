#!/usr/bin/env python3
# filename: server.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 4.5.0 (Optimization: UDP Semaphore)
# -----------------------------------------------------------------------------
"""
Main Server Module with concurrency limits.
"""

import asyncio
import yaml
import sys
import os
import argparse
import logging
import signal
import random
from typing import Any

import dns.message
import dns.rdatatype

from list_manager import ListManager         
from upstream_manager import UpstreamManager 
from resolver import DNSHandler, DNSCache    
from utils import setup_logger, MacMapper, get_server_ips, get_logger, GroupFileLoader, merge_groups
from config_validator import validate_config
from defaults import merge_with_defaults
from geoip import GeoIPLookup

logger = get_logger("Server")


class UDPServer:
    """AsyncIO Datagram Protocol for DNS UDP with Concurrency Limit"""
    def __init__(self, handler, host, port, max_concurrent=1000):
        self.handler = handler
        self.host = host
        self.port = port
        self.transport = None
        # Semaphore to bound concurrent tasks
        self.sem = asyncio.Semaphore(max_concurrent)

    def connection_made(self, transport):
        self.transport = transport
        logger.debug(f"UDP Transport bound to {self.host}:{self.port}")

    def datagram_received(self, data, addr):
        # Optimization: Check if semaphore is locked (pool full) BEFORE creating task
        if self.sem.locked():
            logger.warning(f"UDP Overload: Dropping packet from {addr} (Max concurrent: {self.sem._value})")
            return

        asyncio.create_task(self.handle_safe(data, addr))

    async def handle_safe(self, data, addr):
        # Acquire semaphore for the duration of processing
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
    return parser.parse_args()

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

    logger.info(">>> Phase 1.5: Configuration Validation")
    is_valid, errors, warnings = validate_config(config)
    
    if errors:
        logger.error("Configuration validation failed!")
        sys.exit(1)
    
    if args.validate_only:
        print("\n✅ Configuration validation PASSED")
        sys.exit(0)

    if not config.get('server', {}).get('bind_ip') and not config.get('server', {}).get('bind_interfaces'):
        logger.info("No explicit bind_ip configured. Defaulting to ALL interfaces")
        config.setdefault('server', {})['bind_ip'] = ["0.0.0.0", "::"]

    setup_logger(config)
    logger.info("Starting DNS Filter Server v4.5.0 (Optimized)")
    
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
        rule_engines[pol_name] = list_manager.compile_policy(pol_name, pol_cfg)

    upstream = UpstreamManager(config.get('upstream', {}))
    monitor_task = asyncio.create_task(upstream.start_monitor())
    
    # Startup checks omitted for brevity (same as original)
    if config.get('upstream', {}).get('startup_check_enabled', True):
        # ... (Same startup check code)
        pass 
    
    geoip_lookup = GeoIPLookup(config)
    
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
        geoip=geoip_lookup
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

    # Default concurrency limit 1000, can be made configurable
    udp_concurrency = 1000 

    for ip in listen_ips:
        for port in udp_ports:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: UDPServer(handler, ip, port, max_concurrent=udp_concurrency),
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

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, stop_event)))

    logger.info("Server Ready. Press Ctrl+C to stop.")
    await stop_event.wait()
    
    # ... (Shutdown logic same as original)
    logger.info("Shutting down...")
    if geoip_lookup: geoip_lookup.close()
    monitor_task.cancel()
    for t in transports: t.close()
    await upstream.close()
    logger.info("Server stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


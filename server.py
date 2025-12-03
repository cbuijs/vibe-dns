#!/usr/bin/env python3
# filename: server.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 3.4.0 (Enhanced Logging)
# -----------------------------------------------------------------------------
"""
Main Server Module.

Updates:
- Added detailed logging for configuration loading, interface binding, and component initialization.
- Structured logging to clearly separate startup phases.
"""

import asyncio
import yaml
import sys
import os
import argparse
import logging
import signal
from typing import Any

# Internal Project Modules
from list_manager import ListManager         
from upstream_manager import UpstreamManager 
from resolver import DNSHandler, DNSCache    
from utils import setup_logger, MacMapper, get_server_ips, get_logger
from startup import perform_startup_checks

# Initialize Module Logger
logger = get_logger("Server")

# -----------------------------------------------------------------------------
# Network Protocols
# -----------------------------------------------------------------------------

class UDPServer:
    """AsyncIO Datagram Protocol for DNS UDP."""
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.debug(f"UDP Transport bound to {self.host}:{self.port}")

    def datagram_received(self, data, addr):
        # Fire and forget processing
        asyncio.create_task(self.handle(data, addr))

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
            # Catch all errors so they are logged to file/console instead of stderr
            logger.exception(f"Error handling UDP packet from {addr}: {e}")

class TCPServer:
    """AsyncIO Stream Handler for DNS TCP."""
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

# -----------------------------------------------------------------------------
# Main Application
# -----------------------------------------------------------------------------

async def shutdown(sig: signal.Signals, stop_event: asyncio.Event) -> None:
    logger.info(f"Received exit signal {sig.name}...")
    stop_event.set()

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filtering DNS Server")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config file.")
    return parser.parse_args()

async def main() -> None:
    args = parse_arguments()
    config: dict[str, Any] = {}
    
    # 1. Load Config
    logger.info(">>> Phase 1: Configuration Loading")
    if os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            print(f"Error loading config file: {e}")
    else:
        print(f"Config not found at {args.config}, using internal defaults.")

    # 2. Defaults
    config.setdefault('upstream', {})
    config.setdefault('cache', {'size': 10000})
    config.setdefault('lists', {})
    config.setdefault('policies', {})
    
    server_cfg = config.setdefault('server', {})
    if not server_cfg.get('bind_ip') and not server_cfg.get('bind_interfaces'):
        logger.info("No explicit bind_ip configured. Defaulting to ALL interfaces.")
        server_cfg['bind_ip'] = ["0.0.0.0", "::"]

    # 3. Setup Logging
    setup_logger(config)
    logger.info("Starting DNS Filter Server (Engine: dnspython)")
    
    # 4. Initialize Components
    logger.info(">>> Phase 2: Component Initialization")
    
    listen_ips = get_server_ips(config)
    logger.info(f"Resolved Listen IPs: {listen_ips}")
    
    mac_mapper = MacMapper(config.get('mac_cache_refresh_interval', 300))
    
    logger.info("Initializing List Manager...")
    list_manager = ListManager(
        cache_dir="./list_cache", 
        refresh_interval=config.get('list_refresh_interval', 86400),
        categories_file=config.get('categories_file', 'categories.json')
    )
    await list_manager.update_lists(config['lists'])
    
    logger.info("Compiling Policy Rules...")
    rule_engines = {}
    for pol_name, pol_cfg in config['policies'].items():
        rule_engines[pol_name] = list_manager.compile_policy(pol_name, pol_cfg)
    logger.info(f"Compiled {len(rule_engines)} policies.")

    logger.info("Initializing Upstream Manager...")
    upstream = UpstreamManager(config['upstream'])
    monitor_task = asyncio.create_task(upstream.start_monitor())
    
    # Startup Health Check
    if config['upstream'].get('startup_check_enabled', True):
        logger.info("Performing startup connectivity checks...")
        await asyncio.sleep(0.5) 
        if not await perform_startup_checks(upstream, config['upstream'].get('test_domain', 'www.google.com')):
            logger.critical("Server startup aborted: Unable to reach upstream.")
            monitor_task.cancel()
            await upstream.close()
            return
        logger.info("Startup checks passed.")
    
    logger.info("Initializing DNS Cache & Resolver...")
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
        groups=config.get('groups', {}), 
        mac_mapper=mac_mapper, 
        upstream=upstream, 
        cache=cache
    )

    # 5. Listeners
    logger.info(">>> Phase 3: Starting Listeners")
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    
    servers = []     
    transports = []  

    def get_ports(key: str, default: list[int]) -> list[int]:
        val = config['server'].get(key, default)
        return val if isinstance(val, list) else [val]

    udp_ports = get_ports('port_udp', [53])
    tcp_ports = get_ports('port_tcp', [53])

    if not listen_ips:
        logger.warning("No IPs resolved for binding. Server may not be accessible.")

    for ip in listen_ips:
        for port in udp_ports:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: UDPServer(handler, ip, port),
                    local_addr=(ip, port)
                )
                transports.append(transport)
                logger.info(f"UDP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"UDP Bind Error {ip}:{port}: {e}")

        for port in tcp_ports:
            try:
                server = await asyncio.start_server(
                    TCPServer(handler, ip, port).handle_client,
                    ip, port
                )
                servers.append(server)
                logger.info(f"TCP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"TCP Bind Error {ip}:{port}: {e}")

    # 6. Loop & Signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, stop_event)))

    logger.info(">>> Server is Ready & Running. Press Ctrl+C to stop.")
    await stop_event.wait()
    
    # 7. Shutdown
    logger.info("Shutdown signal received...")
    monitor_task.cancel()
    
    if sys.version_info >= (3, 11):
        try:
            async with asyncio.TaskGroup() as tg:
                for s in servers:
                    s.close()
                    tg.create_task(s.wait_closed())
        except Exception: pass
    else:
        for s in servers:
            s.close()
            await s.wait_closed()
    
    for t in transports: 
        t.close()
    
    await upstream.close()
    logger.info("Server stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


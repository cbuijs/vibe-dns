#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.2.0 (Pure UDP/TCP)
# Updated: 2025-11-25 11:45:00
# -----------------------------------------------------------------------------

import asyncio
import yaml
import sys
import os
import argparse
import logging
import signal

from filtering import ListManager
from resolver import UpstreamManager, DNSHandler, DNSCache
from utils import setup_logger, MacMapper, get_server_ips, logger

# -----------------------------------------------------------------------------
# UDP & TCP Listeners
# -----------------------------------------------------------------------------
class UDPServer:
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle(data, addr))

    async def handle(self, data, addr):
        meta = {
            'proto': 'udp',
            'server_ip': self.host,
            'server_port': self.port
        }
        resp = await self.handler.process_query(data, addr, meta)
        if resp:
            self.transport.sendto(resp, addr)

class TCPServer:
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        
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
        except asyncio.IncompleteReadError: pass
        except Exception as e:
            logger.debug(f"TCP Error {addr}: {e}")
        finally:
            writer.close()

# -----------------------------------------------------------------------------
# Shutdown
# -----------------------------------------------------------------------------
async def shutdown(signal, stop_event):
    logger.info(f"Received exit signal {signal.name}...")
    stop_event.set()

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(description="Filtering DNS Server")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to YAML config.")
    return parser.parse_args()

async def main():
    args = parse_arguments()
    if not os.path.exists(args.config):
        print(f"Error: Config not found at {args.config}")
        return

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    
    setup_logger(config)
    log_level_str = config.get('logging', {}).get('level', 'INFO').upper()
    logger.info(f"Log level set to: {log_level_str}")
    logger.info(f"Starting DNS Filter Server (Pure UDP/TCP)...")

    listen_ips = get_server_ips(config)
    mac_mapper = MacMapper(config.get('mac_cache_refresh_interval', 300))
    list_manager = ListManager(
        cache_dir="./list_cache", 
        refresh_interval=config.get('list_refresh_interval', 86400),
        categories_file=config.get('categories_file', 'categories.json')
    )
    await list_manager.update_lists(config['lists'])
    
    rule_engines = {}
    for pol_name, pol_cfg in config['policies'].items():
        rule_engines[pol_name] = list_manager.compile_policy(pol_name, pol_cfg)

    upstream = UpstreamManager(config['upstream'])
    asyncio.create_task(upstream.start_monitor())
    
    cache = DNSCache(
        config['cache']['size'],
        config['cache'].get('prefetch_margin', 0),
        config['cache'].get('negative_ttl', 60),
        config['cache'].get('gc_interval', 300),
        config['cache'].get('prefetch_min_hits', 3)
    )

    handler = DNSHandler(
        config, config.get('assignments', {}), "ALLOW", rule_engines,
        config.get('groups', {}), mac_mapper, upstream, cache
    )

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def get_ports(key, default):
        val = config['server'].get(key, default)
        return val if isinstance(val, list) else [val]

    udp_ports = get_ports('port_udp', [53])
    tcp_ports = get_ports('port_tcp', [53])

    # --- Listeners ---
    for ip in listen_ips:
        # UDP
        for port in udp_ports:
            try:
                await loop.create_datagram_endpoint(
                    lambda: UDPServer(handler, ip, port),
                    local_addr=(ip, port)
                )
                logger.info(f"UDP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"UDP Bind Error {ip}:{port}: {e}")

        # TCP
        for port in tcp_ports:
            try:
                await asyncio.start_server(
                    TCPServer(handler, ip, port).handle_client,
                    ip, port
                )
                logger.info(f"TCP Listening on {ip}:{port}")
            except Exception as e:
                logger.error(f"TCP Bind Error {ip}:{port}: {e}")

    # --- Signal Handling ---
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, stop_event)))

    await stop_event.wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Server stopped.")


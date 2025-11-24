#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# Updated: 2025-11-24 14:20:00
# -----------------------------------------------------------------------------

import asyncio
import yaml
import sys
import os
import ssl
import argparse
from aiohttp import web

from filtering import ListManager
from resolver import UpstreamManager, DNSHandler, DNSCache
from utils import setup_logger, MacMapper, get_server_ips, logger

# -----------------------------------------------------------------------------
# UDP & TCP Handlers
# -----------------------------------------------------------------------------
# These classes act as the network layer. They receive raw bytes, pass them
# to the DNSHandler, and send back the response.
# -----------------------------------------------------------------------------
class UDPServer:
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    def connection_made(self, transport): self.transport = transport

    def datagram_received(self, data, addr):
        # Fire and forget processing for high throughput
        asyncio.create_task(self.handle(data, addr))

    async def handle(self, data, addr):
        meta = {'proto': 'udp'}
        # Process the query
        resp = await self.handler.process_query(data, addr, meta)
        # Send response if valid
        if resp: self.transport.sendto(resp, addr)

class TCPServer:
    def __init__(self, handler, proto='tcp'):
        self.handler = handler
        self.proto = proto

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        sni = None
        ssl_obj = writer.get_extra_info('ssl_object')
        if ssl_obj: sni = ssl_obj.server_hostname
        
        # DoT (DNS over TLS) SNI Validation
        if self.proto == 'dot':
            config = self.handler.config['server']
            allowed_snis = config.get('dot_server_names', [])
            action = config.get('listener_validation', 'log_pass')

            if allowed_snis:
                if not sni or sni not in allowed_snis:
                    logger.warning(f"DoT SNI Mismatch: IP {addr[0]} requested '{sni}'. Action: {action}")
                    if action == 'drop':
                        writer.close()
                        return

        meta = {'proto': self.proto, 'sni': sni}
        
        try:
            # TCP DNS messages are prefixed with a 2-byte length field
            len_bytes = await reader.readexactly(2)
            length = int.from_bytes(len_bytes, 'big')
            data = await reader.readexactly(length)
            
            resp = await self.handler.process_query(data, addr, meta)
            
            if resp:
                writer.write(len(resp).to_bytes(2, 'big') + resp)
                await writer.drain()
        except asyncio.IncompleteReadError: pass 
        except Exception as e:
            if "SSLError" not in str(e): logger.debug(f"TCP/DoT Error {addr}: {e}")
        finally: writer.close()

# -----------------------------------------------------------------------------
# HTTP Handler (DoH)
# -----------------------------------------------------------------------------
async def doh_handler(request):
    dns_handler = request.app['dns_handler']
    config = request.app['config']['server']
    
    ssl_obj = request.transport.get_extra_info('ssl_object')
    sni = ssl_obj.server_hostname if ssl_obj else None
    
    allowed_snis = config.get('doh_server_names', [])
    action = config.get('listener_validation', 'log_pass')

    if allowed_snis:
        if not sni or sni not in allowed_snis:
            addr = request.transport.get_extra_info('peername')
            logger.warning(f"DoH SNI Mismatch: IP {addr[0]} requested '{sni}'. Action: {action}")
            if action == 'drop': return web.Response(status=403, text="Forbidden: SNI Mismatch")

    if request.method == 'POST':
        if request.content_type != 'application/dns-message': return web.Response(status=415)
        data = await request.read()
    elif request.method == 'GET':
        # Some clients use GET with base64 params. Not implemented here for simplicity.
        return web.Response(status=405)
    
    addr = request.transport.get_extra_info('peername')
    if addr is None: addr = ('0.0.0.0', 0)
    
    meta = {'proto': 'doh', 'sni': sni, 'path': request.path}
    
    resp_data = await dns_handler.process_query(data, addr, meta)
    
    return web.Response(body=resp_data, status=200, content_type='application/dns-message')

# -----------------------------------------------------------------------------
# Main Application Entry
# -----------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Filtering DNS Server (UDP/TCP/DoT/DoH)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to YAML configuration file.")
    return parser.parse_args()

async def main():
    args = parse_arguments()
    config_path = args.config

    if not os.path.exists(config_path):
        print(f"Error: Configuration file not found at '{config_path}'")
        return

    try:
        with open(config_path, 'r') as f: config = yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to load config: {e}")
        return

    setup_logger(config)
    logger.info(f"Starting DNS Filter Server using config: {config_path}")

    listen_ips = get_server_ips(config)
    if not listen_ips:
        logger.error("No IPs to bind to! Check bind_ip or bind_interfaces in config.")
        return
    logger.info(f"Configured to bind on: {listen_ips}")

    # Initialize Managers
    mac_mapper = MacMapper(config.get('mac_cache_refresh_interval', 300))
    list_manager = ListManager(cache_dir="./list_cache", refresh_interval=config.get('list_refresh_interval', 86400))
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
        config['cache'].get('gc_interval', 300)
    )

    handler = DNSHandler(
        config, config.get('assignments', {}), "ALLOW", rule_engines,
        config.get('groups', {}), mac_mapper, upstream, cache
    )

    loop = asyncio.get_running_loop()
    
    # Bind to all resolved IPs
    for ip in listen_ips:
        # UDP
        try:
            await loop.create_datagram_endpoint(lambda: UDPServer(handler, ip, config['server']['port_udp']), local_addr=(ip, config['server']['port_udp']))
            logger.info(f"Running UDP Listener on {ip}:{config['server']['port_udp']}")
        except Exception as e: logger.error(f"Failed to bind UDP on {ip}: {e}")

        # TCP
        try:
            await asyncio.start_server(TCPServer(handler, 'tcp').handle_client, ip, config['server']['port_tcp'])
            logger.info(f"Running TCP Listener on {ip}:{config['server']['port_tcp']}")
        except Exception as e: logger.error(f"Failed to bind TCP on {ip}: {e}")

        # DoT
        if config['server'].get('dot_enabled'):
            port_dot = config['server']['port_dot']
            cert = config['server']['tls_cert_file']
            key = config['server']['tls_key_file']
            if os.path.exists(cert) and os.path.exists(key):
                try:
                    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_ctx.load_cert_chain(certfile=cert, keyfile=key)
                    ssl_ctx.verify_mode = ssl.CERT_NONE 
                    ssl_ctx.set_alpn_protocols(["dot"])
                    await asyncio.start_server(TCPServer(handler, 'dot').handle_client, ip, port_dot, ssl=ssl_ctx)
                    logger.info(f"Running DoT Listener on {ip}:{port_dot}")
                except Exception as e: logger.error(f"Failed to bind DoT on {ip}: {e}")

        # DoH
        if config['server'].get('doh_enabled'):
            port_doh = config['server']['port_doh']
            doh_paths = config['server'].get('doh_paths', ["/dns-query"])
            cert = config['server']['tls_cert_file']
            key = config['server']['tls_key_file']
            if os.path.exists(cert) and os.path.exists(key):
                try:
                    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_ctx.load_cert_chain(certfile=cert, keyfile=key)
                    ssl_ctx.verify_mode = ssl.CERT_NONE 
                    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])
                    app = web.Application()
                    app['dns_handler'] = handler
                    app['config'] = config
                    for path in doh_paths: app.router.add_post(path, doh_handler)
                    runner = web.AppRunner(app)
                    await runner.setup()
                    site = web.TCPSite(runner, ip, port_doh, ssl_context=ssl_ctx)
                    await site.start()
                    logger.info(f"Running DoH Listener on {ip}:{port_doh}")
                except Exception as e: logger.error(f"Failed to bind DoH on {ip}: {e}")

    # Alert if encrypted DNS was requested but keys were missing
    if (config['server'].get('dot_enabled') or config['server'].get('doh_enabled')):
        if not (os.path.exists(config['server']['tls_cert_file']) and os.path.exists(config['server']['tls_key_file'])):
            logger.error("TLS Cert/Key missing. DoT/DoH listeners could not be started.")

    # Keep the event loop running forever
    try: await asyncio.Event().wait()
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: logger.info("Shutting down...")



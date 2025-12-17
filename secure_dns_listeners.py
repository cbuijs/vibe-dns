#!/usr/bin/env python3
"""
DNS over HTTPS (DoH) and DNS over TLS (DoT) Listeners
RFC 8484 (DoH) and RFC 7858 (DoT)
"""

import asyncio
import ssl
import logging
from typing import Optional, List, Union
from urllib.parse import urlparse, parse_qs

from utils import get_logger

logger = get_logger("SecureDNS")


class DoTServer:
    """DNS over TLS (RFC 7858) - Port 853"""
    def __init__(self, handler, host, port):
        self.handler = handler
        self.host = host
        self.port = port

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        ssl_obj = writer.get_extra_info('ssl_object')
        
        # Extract TLS info
        tls_version = None
        cipher = None
        if ssl_obj:
            tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
        
        logger.info(f"DoT Connection from {addr[0]}:{addr[1]} on {self.host}:{self.port} "
                   f"(TLS: {tls_version}, Cipher: {cipher[0] if cipher else 'Unknown'})")
        
        meta = {
            'proto': 'dot',
            'server_ip': self.host,
            'server_port': self.port
        }
        
        queries_handled = 0
        bytes_sent = 0
        bytes_received = 0
        
        try:
            len_bytes = await reader.readexactly(2)
            length = int.from_bytes(len_bytes, 'big')
            bytes_received = length + 2
            
            logger.debug(f"DoT {addr[0]}:{addr[1]} - Receiving query ({length} bytes)")
            
            data = await reader.readexactly(length)
            
            resp = await self.handler.process_query(data, addr, meta)
            
            if resp:
                resp_len = len(resp)
                bytes_sent = resp_len + 2
                writer.write(len(resp).to_bytes(2, 'big') + resp)
                await writer.drain()
                queries_handled = 1
                logger.debug(f"DoT {addr[0]}:{addr[1]} - Sent response ({resp_len} bytes)")
            else:
                logger.warning(f"DoT {addr[0]}:{addr[1]} - No response generated")
                
        except asyncio.IncompleteReadError:
            logger.debug(f"DoT {addr[0]}:{addr[1]} - Connection closed by client (incomplete read)")
        except ssl.SSLError as e:
            logger.warning(f"DoT {addr[0]}:{addr[1]} - SSL Error: {e}")
        except Exception as e:
            logger.error(f"DoT {addr[0]}:{addr[1]} - Error: {e}", exc_info=True)
        finally:
            logger.info(f"DoT {addr[0]}:{addr[1]} - Session closed "
                       f"(Queries: {queries_handled}, RX: {bytes_received}B, TX: {bytes_sent}B)")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"DoT {addr[0]}:{addr[1]} - Error closing connection: {e}")


class DoHServer:
    """DNS over HTTPS (RFC 8484) - HTTP/2 ONLY"""
    def __init__(self, handler, host, port, paths: Union[List[str], str, None] = None, strict_paths: bool = False):
        self.handler = handler
        self.host = host
        self.port = port
        
        # Normalize and validate paths
        if paths is None:
            self.paths = {'/dns-query'}
        elif isinstance(paths, str):
            self.paths = {paths.strip()}
        else:
            self.paths = {p.strip() for p in paths if p and p.strip()}
            
        self.strict_paths = strict_paths
        
        # Ensure fallback if empty
        if not self.paths:
            self.paths = {'/dns-query'}
            
        logger.debug(f"DoH Initialized: strict_paths={self.strict_paths}, allowed_paths={self.paths}")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        ssl_obj = writer.get_extra_info('ssl_object')
        
        # Extract TLS info
        tls_version = None
        cipher = None
        alpn_protocol = None
        if ssl_obj:
            tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            try:
                alpn_protocol = ssl_obj.selected_alpn_protocol()
            except:
                pass
        
        # Require HTTP/2
        if alpn_protocol != 'h2':
            logger.warning(f"DoH {addr[0]}:{addr[1]} - HTTP/2 required but client negotiated: {alpn_protocol or 'http/1.1'}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            return
        
        logger.info(f"DoH Connection from {addr[0]}:{addr[1]} on {self.host}:{self.port} "
                   f"(TLS: {tls_version}, Cipher: {cipher[0] if cipher else 'Unknown'}, ALPN: h2)")
        
        try:
            # Import h2 library
            try:
                from h2.connection import H2Connection
                from h2.events import (
                    RequestReceived, DataReceived, StreamEnded,
                    ConnectionTerminated, StreamReset
                )
                from h2.config import H2Configuration
            except ImportError:
                logger.error("h2 library not installed. Install with: pip install h2")
                writer.close()
                await writer.wait_closed()
                return
            
            import time
            import base64
            
            # Initialize HTTP/2 connection
            config = H2Configuration(client_side=False)
            h2_conn = H2Connection(config=config)
            h2_conn.initiate_connection()
            writer.write(h2_conn.data_to_send())
            await writer.drain()
            
            # Track active streams
            streams = {}
            session_start = time.time()
            queries_handled = 0
            bytes_received = 0
            bytes_sent = 0
            
            meta = {
                'proto': 'doh',
                'server_ip': self.host,
                'server_port': self.port
            }
            
            while True:
                # Read data from client
                data = await reader.read(65535)
                if not data:
                    break
                
                bytes_received += len(data)
                events = h2_conn.receive_data(data)
                
                for event in events:
                    if isinstance(event, RequestReceived):
                        # New request on stream
                        stream_id = event.stream_id
                        headers_dict = dict(event.headers)
                        
                        method = headers_dict.get(b':method', b'').decode('utf-8')
                        path = headers_dict.get(b':path', b'').decode('utf-8')
                        authority = headers_dict.get(b':authority', b'').decode('utf-8')
                        
                        logger.info(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: {method} {path}")
                        
                        streams[stream_id] = {
                            'method': method,
                            'path': path,
                            'authority': authority,
                            'headers': headers_dict,
                            'data': b'',
                            'start_time': time.time()
                        }
                    
                    elif isinstance(event, DataReceived):
                        # Request body data
                        stream_id = event.stream_id
                        if stream_id in streams:
                            streams[stream_id]['data'] += event.data
                            logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Received {len(event.data)} bytes")
                    
                    elif isinstance(event, StreamEnded):
                        # Request complete, process it
                        stream_id = event.stream_id
                        if stream_id not in streams:
                            continue
                        
                        stream_info = streams[stream_id]
                        method = stream_info['method']
                        path = stream_info['path']
                        request_data = stream_info['data']
                        
                        # Parse path
                        parsed = urlparse(path)
                        request_path = parsed.path
                        
                        # Validate path
                        if request_path not in self.paths:
                            if self.strict_paths:
                                logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Path rejected (strict mode). Requested: '{request_path}', Allowed: {self.paths}")
                                # Send 404
                                response_headers = [
                                    (':status', '404'),
                                    ('content-type', 'text/plain'),
                                ]
                                h2_conn.send_headers(stream_id, response_headers)
                                h2_conn.send_data(stream_id, b'Not Found', end_stream=True)
                                writer.write(h2_conn.data_to_send())
                                await writer.drain()
                                bytes_sent += len(h2_conn.data_to_send())
                                del streams[stream_id]
                                continue
                            else:
                                logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Path '{request_path}' not in {self.paths} but strict mode disabled")
                        
                        dns_data = None
                        
                        if method == 'GET':
                            # GET: dns= parameter in base64url
                            params = parse_qs(parsed.query)
                            if 'dns' in params:
                                try:
                                    b64_data = params['dns'][0]
                                    missing_padding = len(b64_data) % 4
                                    if missing_padding:
                                        b64_data += '=' * (4 - missing_padding)
                                    dns_data = base64.urlsafe_b64decode(b64_data)
                                    logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: GET query decoded ({len(dns_data)} bytes)")
                                except Exception as e:
                                    logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: GET decode error: {e}")
                                    response_headers = [(':status', '400')]
                                    h2_conn.send_headers(stream_id, response_headers)
                                    h2_conn.send_data(stream_id, b'Bad Request', end_stream=True)
                                    writer.write(h2_conn.data_to_send())
                                    await writer.drain()
                                    del streams[stream_id]
                                    continue
                            else:
                                logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: GET missing dns parameter")
                                response_headers = [(':status', '400')]
                                h2_conn.send_headers(stream_id, response_headers)
                                h2_conn.send_data(stream_id, b'Bad Request', end_stream=True)
                                writer.write(h2_conn.data_to_send())
                                await writer.drain()
                                del streams[stream_id]
                                continue
                        
                        elif method == 'POST':
                            # POST: DNS wire format in body
                            content_type = stream_info['headers'].get(b'content-type', b'').decode('utf-8')
                            if 'application/dns-message' not in content_type:
                                logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Invalid content-type: {content_type}")
                                response_headers = [(':status', '415')]
                                h2_conn.send_headers(stream_id, response_headers)
                                h2_conn.send_data(stream_id, b'Unsupported Media Type', end_stream=True)
                                writer.write(h2_conn.data_to_send())
                                await writer.drain()
                                del streams[stream_id]
                                continue
                            
                            dns_data = request_data
                            logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: POST body ({len(dns_data)} bytes)")
                        
                        else:
                            logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Unsupported method: {method}")
                            response_headers = [(':status', '405')]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, b'Method Not Allowed', end_stream=True)
                            writer.write(h2_conn.data_to_send())
                            await writer.drain()
                            del streams[stream_id]
                            continue
                        
                        if not dns_data:
                            logger.warning(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: No DNS data")
                            response_headers = [(':status', '400')]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, b'Bad Request', end_stream=True)
                            writer.write(h2_conn.data_to_send())
                            await writer.drain()
                            del streams[stream_id]
                            continue
                        
                        # Process DNS query
                        logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Processing DNS query ({len(dns_data)} bytes)")
                        dns_response = await self.handler.process_query(dns_data, addr, meta)
                        
                        if dns_response:
                            duration_ms = (time.time() - stream_info['start_time']) * 1000
                            
                            # Send response
                            response_headers = [
                                (':status', '200'),
                                ('content-type', 'application/dns-message'),
                                ('content-length', str(len(dns_response))),
                                ('cache-control', 'max-age=0'),
                            ]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, dns_response, end_stream=True)
                            
                            data_to_send = h2_conn.data_to_send()
                            writer.write(data_to_send)
                            await writer.drain()
                            bytes_sent += len(data_to_send)
                            
                            queries_handled += 1
                            logger.info(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: {method} {path} → 200 OK ({len(dns_response)} bytes, {duration_ms:.1f}ms)")
                        else:
                            logger.error(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id}: Handler returned no response")
                            response_headers = [(':status', '500')]
                            h2_conn.send_headers(stream_id, response_headers)
                            h2_conn.send_data(stream_id, b'Internal Server Error', end_stream=True)
                            writer.write(h2_conn.data_to_send())
                            await writer.drain()
                        
                        del streams[stream_id]
                    
                    elif isinstance(event, ConnectionTerminated):
                        logger.debug(f"DoH {addr[0]}:{addr[1]} - Connection terminated")
                        break
                    
                    elif isinstance(event, StreamReset):
                        stream_id = event.stream_id
                        logger.debug(f"DoH {addr[0]}:{addr[1]} - Stream {stream_id} reset")
                        if stream_id in streams:
                            del streams[stream_id]
                
                # Send any pending data
                data_to_send = h2_conn.data_to_send()
                if data_to_send:
                    writer.write(data_to_send)
                    await writer.drain()
                    bytes_sent += len(data_to_send)
            
            session_duration = time.time() - session_start
            logger.info(f"DoH {addr[0]}:{addr[1]} - Session closed "
                       f"(Queries: {queries_handled}, RX: {bytes_received}B, TX: {bytes_sent}B, "
                       f"Duration: {session_duration:.2f}s)")
        
        except Exception as e:
            logger.error(f"DoH {addr[0]}:{addr[1]} - Error: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"DoH {addr[0]}:{addr[1]} - Error closing connection: {e}")


def create_ssl_context(cert_file: str, key_file: str, ca_file: Optional[str] = None) -> ssl.SSLContext:
    """Create SSL context for DoT/DoH"""
    logger.info(f"Creating SSL context (Cert: {cert_file}, Key: {key_file})")
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    try:
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        logger.info("✓ Certificate chain loaded successfully")
    except Exception as e:
        logger.error(f"✗ Failed to load certificate chain: {e}")
        raise
    
    if ca_file:
        try:
            context.load_verify_locations(cafile=ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
            logger.info(f"✓ Client certificate verification enabled (CA: {ca_file})")
        except Exception as e:
            logger.error(f"✗ Failed to load CA file: {e}")
            raise
    else:
        context.verify_mode = ssl.CERT_NONE
        logger.info("Client certificate verification disabled")
    
    # Modern TLS settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    # Configure ALPN to only advertise HTTP/2 (h2)
    # This forces clients to use HTTP/2
    try:
        context.set_alpn_protocols(['h2'])
        logger.info("✓ SSL context configured (Min TLS: 1.2, ALPN: h2, Modern cipher suite)")
    except Exception as e:
        logger.warning(f"Could not set ALPN protocols: {e}")
        logger.info("✓ SSL context configured (Min TLS: 1.2, Modern cipher suite)")
    
    return context


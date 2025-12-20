#!/usr/bin/env python3
"""Root hints and trust anchors - simplified"""
import asyncio
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict
from dataclasses import dataclass

from utils import get_logger

logger = get_logger("Hints")

BUILTIN_ROOT_SERVERS = [
    ("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net", "202.12.27.33", "2001:dc3::35"),
]

BUILTIN_TRUST_ANCHOR = {
    20326: {
        'algorithm': 8,
        'digest_type': 2,
        'digest': 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
    }
}


@dataclass
class RootServer:
    name: str
    ipv4: str
    ipv6: str
    
    def get_ips(self, prefer_ipv6=False):
        if prefer_ipv6:
            return [self.ipv6, self.ipv4] if self.ipv6 else [self.ipv4]
        return [self.ipv4, self.ipv6] if self.ipv6 else [self.ipv4]


class RootHints:
    """Manages root server hints"""
    def __init__(self, config: dict):
        self.config = config
        self.servers = []
        self.source = config.get('source', 'builtin')
    
    async def initialize(self):
        """Load root hints"""
        if self.source == 'builtin':
            self._load_builtin()
        elif self.source == 'url':
            await self._fetch_url()
        elif self.source == 'file':
            self._load_file()
        
        logger.info(f"Root hints loaded: {len(self.servers)} servers from {self.source}")
        return len(self.servers) > 0
    
    def _load_builtin(self):
        for name, ipv4, ipv6 in BUILTIN_ROOT_SERVERS:
            self.servers.append(RootServer(name, ipv4, ipv6))
    
    async def _fetch_url(self):
        """Fetch from InterNIC"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(self.config['url'])
                self._parse_named_root(resp.text)
        except:
            logger.warning("Failed to fetch root hints, using builtin")
            self._load_builtin()
    
    def _load_file(self):
        """Load from file"""
        try:
            with open(self.config['file']) as f:
                self._parse_named_root(f.read())
        except:
            logger.warning("Failed to load root hints file, using builtin")
            self._load_builtin()
    
    def _parse_named_root(self, content: str):
        """Parse named.root format"""
        servers = {}
        for line in content.splitlines():
            if line.startswith(';') or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            
            name = parts[0].lower()
            rtype = parts[2]
            rdata = parts[3]
            
            if name not in servers:
                servers[name] = {'name': name, 'ipv4': None, 'ipv6': None}
            
            if rtype == 'A':
                servers[name]['ipv4'] = rdata
            elif rtype == 'AAAA':
                servers[name]['ipv6'] = rdata
        
        for data in servers.values():
            if data['ipv4'] or data['ipv6']:
                self.servers.append(RootServer(data['name'], data['ipv4'], data['ipv6']))
    
    def get_servers(self, prefer_ipv6=False):
        """Get list of (name, [ips])"""
        result = []
        for srv in self.servers:
            ips = srv.get_ips(prefer_ipv6)
            result.append((srv.name, ips))
        return result


class TrustAnchors:
    """Manages DNSSEC trust anchors"""
    def __init__(self, config: dict):
        self.config = config
        self.anchors = {}
        self.source = config.get('source', 'builtin')
    
    async def initialize(self):
        """Load trust anchors"""
        if self.source == 'builtin':
            self.anchors = BUILTIN_TRUST_ANCHOR.copy()
        elif self.source == 'url':
            await self._fetch_url()
        elif self.source == 'file':
            self._load_file()
        
        logger.info(f"Trust anchors loaded: {len(self.anchors)} keys from {self.source}")
        return len(self.anchors) > 0
    
    async def _fetch_url(self):
        """Fetch root-anchors.xml"""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(self.config['url'])
                self._parse_xml(resp.text)
        except:
            logger.warning("Failed to fetch trust anchors, using builtin")
            self.anchors = BUILTIN_TRUST_ANCHOR.copy()
    
    def _load_file(self):
        """Load from file"""
        try:
            with open(self.config['file']) as f:
                self._parse_xml(f.read())
        except:
            logger.warning("Failed to load trust anchors file, using builtin")
            self.anchors = BUILTIN_TRUST_ANCHOR.copy()
    
    def _parse_xml(self, content: str):
        """Parse IANA root-anchors.xml"""
        try:
            root = ET.fromstring(content)
            for kd in root.iter('KeyDigest'):
                tag = int(kd.find('KeyTag').text)
                algo = int(kd.find('Algorithm').text)
                dtype = int(kd.find('DigestType').text)
                digest = kd.find('Digest').text.strip().upper()
                
                self.anchors[tag] = {
                    'algorithm': algo,
                    'digest_type': dtype,
                    'digest': digest,
                }
        except:
            logger.warning("Failed to parse trust anchors XML")
    
    def get(self):
        return self.anchors


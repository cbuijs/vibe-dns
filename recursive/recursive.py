#!/usr/bin/env python3
"""Recursive resolver facade - ties iterator, validator, and hints together"""
import asyncio
from typing import Optional

import dns.message
import dns.name
import dns.rdatatype

from utils import get_logger
from .iterator import Iterator
from .hints import RootHints, TrustAnchors
from .validator import Validator

logger = get_logger("Recursive")


class RecursiveResolver:
    """Main recursive resolver interface"""
    
    def __init__(self, config: dict, upstream_manager=None):
        """
        Initialize recursive resolver.
        
        Args:
            config: Configuration from upstream.recursive section
            upstream_manager: Optional upstream manager for fallback
        """
        self.config = config
        self.upstream_manager = upstream_manager
        self.enabled = config.get('enabled', False)
        
        # Fallback configuration
        self.fallback_enabled = config.get('fallback_enabled', False)
        self.fallback_group = config.get('fallback_group', 'Default')
        
        # Components (initialized in initialize())
        self.root_hints = None
        self.trust_anchors = None
        self.validator = None
        self.iterator = None
    
    async def initialize(self) -> bool:
        """
        Initialize all components.
        
        Returns:
            True on success, False on failure
        """
        if not self.enabled:
            return True
        
        try:
            # Load root hints
            self.root_hints = RootHints(self.config.get('root_hints', {}))
            if not await self.root_hints.initialize():
                logger.error("Failed to initialize root hints")
                return False
            
            # Load trust anchors
            self.trust_anchors = TrustAnchors(self.config.get('trust_anchors', {}))
            await self.trust_anchors.initialize()
            
            # Create validator if DNSSEC enabled
            dnssec_config = self.config.get('dnssec', {})
            if dnssec_config.get('mode', 'none') != 'none':
                self.validator = Validator(
                    dnssec_config,
                    self.trust_anchors.get(),
                    self._raw_query_for_validator
                )
                logger.info(f"DNSSEC validator initialized (mode: {dnssec_config.get('mode')})")
            
            # Create iterator
            self.iterator = Iterator(self.config, self.root_hints, self.validator)
            
            logger.info("Recursive resolver initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize recursive resolver: {e}")
            return False
    
    async def resolve(self, qname: str, qtype: int, req_logger=None) -> Optional[dns.message.Message]:
        """
        Main resolve entry point.
        
        Args:
            qname: Domain name as string (e.g. "google.com")
            qtype: Query type as int (e.g. dns.rdatatype.A)
            req_logger: Optional logger for this request
            
        Returns:
            dns.message.Message on success, None on failure
        """
        log = req_logger or logger
        
        if not self.enabled:
            return None
        
        try:
            qname_obj = dns.name.from_text(qname)
            log.info(f"Recursive: {qname} [{dns.rdatatype.to_text(qtype)}]")
            
            # Try iterative resolution
            response = await self.iterator.resolve(qname_obj, qtype, log)
            
            # Check if we got a good response
            if response and response.rcode() == dns.rcode.NOERROR:
                return response
            
            # Fallback to forwarding if enabled
            if self.fallback_enabled and self.upstream_manager:
                log.info(f"Recursive failed, falling back to {self.fallback_group}")
                msg = await self.upstream_manager.resolve(
                    qname,
                    qtype,
                    group=self.fallback_group,
                    logger=log
                )
                if msg:
                    return dns.message.from_wire(msg)
            
            return response
            
        except Exception as e:
            log.error(f"Recursive resolution error: {e}")
            
            # Fallback on exception
            if self.fallback_enabled and self.upstream_manager:
                log.info(f"Exception occurred, falling back to {self.fallback_group}")
                try:
                    msg = await self.upstream_manager.resolve(
                        qname,
                        qtype,
                        group=self.fallback_group,
                        logger=log
                    )
                    if msg:
                        return dns.message.from_wire(msg)
                except:
                    pass
            
            return None
    
    async def _raw_query_for_validator(self, wire: bytes) -> Optional[bytes]:
        """
        Raw query interface for validator (internal DNSSEC queries).
        
        The validator needs to fetch DNSKEY and DS records without triggering
        validation (to avoid infinite loops). This provides that interface.
        
        Args:
            wire: DNS query as wire format bytes
            
        Returns:
            DNS response as wire format bytes, or None on failure
        """
        try:
            query = dns.message.from_wire(wire)
            qname = query.question[0].name
            qtype = query.question[0].rdtype
            
            # Use iterator directly without validator
            # Create temporary iterator without validator to avoid recursion
            temp_iterator = Iterator(self.config, self.root_hints, validator=None)
            response = await temp_iterator.resolve(qname, qtype, logger)
            
            if response:
                return response.to_wire()
            return None
            
        except Exception as e:
            logger.debug(f"Validator query failed: {e}")
            return None


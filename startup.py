#!/usr/bin/env python3
# filename: startup.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server (Refactored)
# Version: 3.2.0 (dnspython)
# -----------------------------------------------------------------------------
"""
Startup Connectivity Verifier.
"""

import asyncio
import random
import dns.message
import dns.rdatatype
from utils import get_logger

logger = get_logger("Startup")

async def perform_startup_checks(upstream_manager, test_domain="www.google.com"):
    logger.info("Verifying upstream connectivity...")
    q = dns.message.make_query(test_domain, dns.rdatatype.A)
    
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            qid = random.randint(1, 65535)
            q.id = qid
            pkt = q.to_wire()
            start_time = asyncio.get_running_loop().time()
            
            response_data = await upstream_manager.forward_query(pkt, qid=qid, client_ip="STARTUP_CHECK")
            
            if response_data:
                duration = asyncio.get_running_loop().time() - start_time
                try:
                    dns.message.from_wire(response_data)
                    logger.info(f"Upstream check PASSED in {duration:.3f}s.")
                    return True
                except Exception: pass
        except Exception as e:
            logger.warning(f"Attempt {attempt} failed: {e}")
        await asyncio.sleep(1)

    logger.error("CRITICAL FAILURE - Cannot resolve DNS upstreams.")
    return False


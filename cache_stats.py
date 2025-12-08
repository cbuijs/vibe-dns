#!/usr/bin/env python3
# filename: cache_stats.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 2.0.0 (LRU Cache Base)
# -----------------------------------------------------------------------------
"""
Reusable cache infrastructure with LRU eviction and statistics.
"""

import time
from collections import OrderedDict
from typing import Any, Tuple, Optional


class CacheStats:
    """Base class for cache statistics tracking"""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0
        self.writes = 0
    
    def record_hit(self):
        """Record a cache hit"""
        self.hits += 1
    
    def record_miss(self):
        """Record a cache miss"""
        self.misses += 1
    
    def record_eviction(self):
        """Record a cache eviction (LRU)"""
        self.evictions += 1
    
    def record_expiration(self):
        """Record a cache expiration (TTL)"""
        self.expirations += 1
    
    def record_write(self):
        """Record a cache write"""
        self.writes += 1
    
    def get_stats(self, current_size: int, max_size: int) -> dict:
        """
        Get formatted statistics.
        
        Args:
            current_size: Current number of entries in cache
            max_size: Maximum cache capacity
            
        Returns:
            Dictionary with formatted statistics
        """
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'size': current_size,
            'max_size': max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.1f}%",
            'evictions': self.evictions,
            'expirations': self.expirations,
            'writes': self.writes
        }
    
    def reset(self):
        """Reset all statistics"""
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0
        self.writes = 0


class LRUCache:
    """
    Generic LRU cache with TTL support.
    
    Features:
    - LRU eviction when full
    - Per-entry TTL expiration
    - Automatic statistics tracking
    - Type-agnostic (subclasses define value structure)
    """
    
    def __init__(self, max_size: int, default_ttl: int = 300):
        """
        Initialize LRU cache.
        
        Args:
            max_size: Maximum number of entries (0 = disabled)
            default_ttl: Default TTL in seconds
        """
        self.cache: OrderedDict[Any, Tuple[Any, float]] = OrderedDict()
        self.max_size = max_size or 0
        self.default_ttl = default_ttl
        self.stats = CacheStats()
    
    def get(self, key: Any) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if expired/missing
        """
        if self.max_size == 0:
            self.stats.record_miss()
            return None
        
        if key not in self.cache:
            self.stats.record_miss()
            return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        
        value, expires = self.cache[key]
        now = time.time()
        
        if now >= expires:
            # Expired
            del self.cache[key]
            self.stats.record_expiration()
            self.stats.record_miss()
            return None
        
        self.stats.record_hit()
        return value
    
    def put(self, key: Any, value: Any, ttl: Optional[int] = None):
        """
        Store value in cache.
        
        Args:
            key: Cache key
            value: Value to store
            ttl: Time-to-live in seconds (None = use default)
        """
        if self.max_size == 0:
            return
        
        # LRU eviction if full
        if len(self.cache) >= self.max_size and key not in self.cache:
            evicted_key = next(iter(self.cache))
            del self.cache[evicted_key]
            self.stats.record_eviction()
        
        expires = time.time() + (ttl if ttl is not None else self.default_ttl)
        self.cache[key] = (value, expires)
        
        # Move to end if updating existing key
        if key in self.cache:
            self.cache.move_to_end(key)
        
        self.stats.record_write()
    
    def delete(self, key: Any):
        """Remove entry from cache"""
        if key in self.cache:
            del self.cache[key]
    
    def clear(self):
        """Clear all entries"""
        self.cache.clear()
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        return self.stats.get_stats(len(self.cache), self.max_size)
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries.
        
        Returns:
            Number of entries removed
        """
        now = time.time()
        expired = [k for k, (_, exp) in self.cache.items() if exp < now]
        
        for k in expired:
            del self.cache[k]
            self.stats.record_expiration()
        
        return len(expired)


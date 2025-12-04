#!/usr/bin/env python3
# filename: cache_stats.py
# -----------------------------------------------------------------------------
# Project: Filtering DNS Server
# Version: 1.0.0
# -----------------------------------------------------------------------------
"""
Reusable statistics tracking for cache implementations.
"""


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


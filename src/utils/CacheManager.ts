/**
 * Cache Manager
 * Provides caching utilities for responses and computed data
 */

export interface CacheOptions {
    maxItems?: number;
    ttlMs?: number;
}

interface CacheEntry<T> {
    value: T;
    expiresAt: number;
}

export class CacheManager<T = unknown> {
    private cache: Map<string, CacheEntry<T>> = new Map();
    private maxItems: number;
    private defaultTtl: number;
    private hits: number = 0;
    private misses: number = 0;

    constructor(options: CacheOptions = {}) {
        this.maxItems = options.maxItems || 500;
        this.defaultTtl = options.ttlMs || 5 * 60 * 1000; // 5 minutes default
    }

    /**
     * Get item from cache
     */
    get(key: string): T | undefined {
        const entry = this.cache.get(key);

        if (!entry) {
            this.misses++;
            return undefined;
        }

        if (Date.now() > entry.expiresAt) {
            this.cache.delete(key);
            this.misses++;
            return undefined;
        }

        this.hits++;
        return entry.value;
    }

    /**
     * Set item in cache
     */
    set(key: string, value: T, ttlMs?: number): void {
        // Evict oldest if at capacity
        if (this.cache.size >= this.maxItems) {
            const firstKey = this.cache.keys().next().value;
            if (firstKey) this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            value,
            expiresAt: Date.now() + (ttlMs || this.defaultTtl),
        });
    }

    /**
     * Check if key exists in cache
     */
    has(key: string): boolean {
        return this.get(key) !== undefined;
    }

    /**
     * Delete item from cache
     */
    delete(key: string): boolean {
        return this.cache.delete(key);
    }

    /**
     * Clear all items from cache
     */
    clear(): void {
        this.cache.clear();
        this.hits = 0;
        this.misses = 0;
    }

    /**
     * Get or set pattern - retrieve from cache or compute and store
     */
    async getOrSet(key: string, computeFn: () => Promise<T>, ttlMs?: number): Promise<T> {
        const cached = this.get(key);
        if (cached !== undefined) {
            return cached;
        }

        const value = await computeFn();
        this.set(key, value, ttlMs);
        return value;
    }

    /**
     * Get cache statistics
     */
    getStats(): { size: number; hits: number; misses: number; hitRate: number } {
        const total = this.hits + this.misses;
        return {
            size: this.cache.size,
            hits: this.hits,
            misses: this.misses,
            hitRate: total > 0 ? this.hits / total : 0,
        };
    }

    /**
     * Get all keys in cache
     */
    keys(): string[] {
        return Array.from(this.cache.keys());
    }

    /**
     * Get all values in cache
     */
    values(): T[] {
        return Array.from(this.cache.values()).map(e => e.value);
    }
}

// Singleton instances for different cache types
export const responseCache = new CacheManager({ maxItems: 1000, ttlMs: 5 * 60 * 1000 });
export const signatureCache = new CacheManager({ maxItems: 500, ttlMs: 60 * 60 * 1000 });
export const payloadResultCache = new CacheManager({ maxItems: 2000, ttlMs: 10 * 60 * 1000 });

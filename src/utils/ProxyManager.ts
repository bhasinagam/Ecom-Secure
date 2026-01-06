/**
 * Proxy Manager
 * Handles proxy rotation for HTTP and SOCKS proxies
 */

import { logger } from '../core/Logger';

export interface ProxyConfig {
    url: string;
    type: 'http' | 'https' | 'socks4' | 'socks5';
    username?: string;
    password?: string;
    weight?: number;
    healthy?: boolean;
    lastUsed?: number;
    failureCount?: number;
}

export class ProxyManager {
    private proxies: ProxyConfig[] = [];
    private currentIndex: number = 0;
    private rotationStrategy: 'round-robin' | 'random' | 'weighted' = 'round-robin';
    private healthCheckInterval?: NodeJS.Timeout;

    constructor(proxies: (string | ProxyConfig)[] = []) {
        this.addProxies(proxies);
    }

    /**
     * Add proxies to the pool
     */
    addProxies(proxies: (string | ProxyConfig)[]): void {
        for (const proxy of proxies) {
            if (typeof proxy === 'string') {
                this.proxies.push(this.parseProxyUrl(proxy));
            } else {
                this.proxies.push({
                    ...proxy,
                    healthy: proxy.healthy !== false,
                    failureCount: proxy.failureCount || 0,
                    weight: proxy.weight || 1,
                });
            }
        }
    }

    /**
     * Parse proxy URL string into ProxyConfig
     */
    private parseProxyUrl(url: string): ProxyConfig {
        try {
            const parsed = new URL(url);
            const protocol = parsed.protocol.replace(':', '') as ProxyConfig['type'];

            return {
                url: `${parsed.protocol}//${parsed.host}`,
                type: protocol,
                username: parsed.username || undefined,
                password: parsed.password || undefined,
                healthy: true,
                failureCount: 0,
                weight: 1,
            };
        } catch {
            throw new Error(`Invalid proxy URL: ${url}`);
        }
    }

    /**
     * Get next proxy based on rotation strategy
     */
    getNext(): ProxyConfig | null {
        const healthyProxies = this.proxies.filter(p => p.healthy);

        if (healthyProxies.length === 0) {
            return null;
        }

        let proxy: ProxyConfig;

        switch (this.rotationStrategy) {
            case 'random':
                proxy = healthyProxies[Math.floor(Math.random() * healthyProxies.length)];
                break;

            case 'weighted':
                proxy = this.getWeightedProxy(healthyProxies);
                break;

            case 'round-robin':
            default:
                this.currentIndex = (this.currentIndex + 1) % healthyProxies.length;
                proxy = healthyProxies[this.currentIndex];
                break;
        }

        proxy.lastUsed = Date.now();
        return proxy;
    }

    /**
     * Get proxy based on weighted selection
     */
    private getWeightedProxy(proxies: ProxyConfig[]): ProxyConfig {
        const totalWeight = proxies.reduce((sum, p) => sum + (p.weight || 1), 0);
        let random = Math.random() * totalWeight;

        for (const proxy of proxies) {
            random -= proxy.weight || 1;
            if (random <= 0) {
                return proxy;
            }
        }

        return proxies[0];
    }

    /**
     * Get proxy URL string for axios/request config
     */
    getProxyUrl(): string | null {
        const proxy = this.getNext();
        if (!proxy) return null;

        let url = proxy.url;
        if (proxy.username && proxy.password) {
            const parsed = new URL(url);
            parsed.username = proxy.username;
            parsed.password = proxy.password;
            url = parsed.toString();
        }

        return url;
    }

    /**
     * Report proxy failure
     */
    reportFailure(proxyUrl: string): void {
        const proxy = this.proxies.find(p => p.url === proxyUrl);
        if (proxy) {
            proxy.failureCount = (proxy.failureCount || 0) + 1;

            // Mark as unhealthy after 3 consecutive failures
            if (proxy.failureCount >= 3) {
                proxy.healthy = false;
                logger.warn(`Proxy marked as unhealthy: ${proxyUrl}`);
            }
        }
    }

    /**
     * Report proxy success (reset failure count)
     */
    reportSuccess(proxyUrl: string): void {
        const proxy = this.proxies.find(p => p.url === proxyUrl);
        if (proxy) {
            proxy.failureCount = 0;
            proxy.healthy = true;
        }
    }

    /**
     * Set rotation strategy
     */
    setStrategy(strategy: 'round-robin' | 'random' | 'weighted'): void {
        this.rotationStrategy = strategy;
    }

    /**
     * Get list of healthy proxies
     */
    getHealthyProxies(): ProxyConfig[] {
        return this.proxies.filter(p => p.healthy);
    }

    /**
     * Get all proxies
     */
    getAllProxies(): ProxyConfig[] {
        return [...this.proxies];
    }

    /**
     * Remove proxy from pool
     */
    removeProxy(proxyUrl: string): boolean {
        const index = this.proxies.findIndex(p => p.url === proxyUrl);
        if (index > -1) {
            this.proxies.splice(index, 1);
            return true;
        }
        return false;
    }

    /**
     * Reset all proxies to healthy state
     */
    resetAll(): void {
        for (const proxy of this.proxies) {
            proxy.healthy = true;
            proxy.failureCount = 0;
        }
    }

    /**
     * Start periodic health checks
     */
    startHealthCheck(intervalMs: number = 60000): void {
        this.healthCheckInterval = setInterval(() => {
            this.checkHealth();
        }, intervalMs);
    }

    /**
     * Stop health checks
     */
    stopHealthCheck(): void {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
        }
    }

    /**
     * Perform health check on all proxies
     */
    private async checkHealth(): Promise<void> {
        // Re-enable proxies that have been unhealthy for a while
        const now = Date.now();
        for (const proxy of this.proxies) {
            if (!proxy.healthy && proxy.lastUsed && (now - proxy.lastUsed) > 5 * 60 * 1000) {
                // Try again after 5 minutes
                proxy.healthy = true;
                proxy.failureCount = 0;
                logger.info(`Re-enabling proxy for retry: ${proxy.url}`);
            }
        }
    }

    /**
     * Get proxy count
     */
    get count(): number {
        return this.proxies.length;
    }

    /**
     * Get healthy proxy count
     */
    get healthyCount(): number {
        return this.proxies.filter(p => p.healthy).length;
    }
}

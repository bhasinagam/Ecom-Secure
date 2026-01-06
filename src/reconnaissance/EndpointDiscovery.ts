/**
 * Endpoint Discovery
 * Enumerates API endpoints from traffic analysis
 */

import { Endpoint, EndpointType, Parameter } from '../types';
import { logger } from '../core/Logger';

interface HttpTrafficEntry {
    url: string;
    method: string;
    headers: Record<string, string>;
    postData?: string;
    resourceType: string;
    response?: {
        status: number;
        headers: Record<string, string>;
    };
}

export class EndpointDiscovery {
    private endpoints: Map<string, Endpoint> = new Map();

    /**
     * Discover endpoints from HTTP traffic
     */
    discover(traffic: HttpTrafficEntry[]): Endpoint[] {
        for (const entry of traffic) {
            // Skip static resources
            if (this.isStaticResource(entry)) {
                continue;
            }

            const endpoint = this.createEndpoint(entry);
            const key = `${endpoint.method}:${this.normalizeUrl(endpoint.url)}`;

            if (!this.endpoints.has(key)) {
                this.endpoints.set(key, endpoint);
            } else {
                // Merge parameters from duplicate endpoints
                this.mergeParameters(this.endpoints.get(key)!, endpoint);
            }
        }

        const discovered = Array.from(this.endpoints.values());
        logger.info(`Discovered ${discovered.length} unique endpoints`);
        return discovered;
    }

    /**
     * Check if request is for a static resource
     */
    private isStaticResource(entry: HttpTrafficEntry): boolean {
        const staticTypes = ['image', 'font', 'stylesheet', 'script', 'media'];
        if (staticTypes.includes(entry.resourceType)) {
            return true;
        }

        const staticExtensions = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)(\?|$)/i;
        if (staticExtensions.test(entry.url)) {
            return true;
        }

        return false;
    }

    /**
     * Create endpoint from traffic entry
     */
    private createEndpoint(entry: HttpTrafficEntry): Endpoint {
        const type = this.inferEndpointType(entry.url, entry.method);
        const parameters = this.extractParameters(entry);

        return {
            url: entry.url,
            method: entry.method,
            type,
            parameters,
            headers: this.sanitizeHeaders(entry.headers),
            requiresAuth: this.detectAuthRequirement(entry),
        };
    }

    /**
     * Normalize URL for comparison (remove query params, normalize path)
     */
    private normalizeUrl(url: string): string {
        try {
            const parsed = new URL(url);
            // Remove query string but keep path
            return `${parsed.origin}${parsed.pathname}`;
        } catch {
            return url;
        }
    }

    /**
     * Infer endpoint type from URL and method
     */
    private inferEndpointType(url: string, method: string): EndpointType {
        const urlLower = url.toLowerCase();

        if (/\/cart|\/basket/i.test(urlLower)) return 'cart';
        if (/\/checkout/i.test(urlLower)) return 'checkout';
        if (/\/payment|\/pay\//i.test(urlLower)) return 'payment';
        if (/\/order/i.test(urlLower)) return 'order';
        if (/\/product|\/item/i.test(urlLower)) return 'product';
        if (/\/api\/|\/rest\/|\/graphql/i.test(urlLower)) return 'api';

        return 'unknown';
    }

    /**
     * Extract parameters from request
     */
    private extractParameters(entry: HttpTrafficEntry): Parameter[] {
        const parameters: Parameter[] = [];

        // Extract query parameters
        try {
            const url = new URL(entry.url);
            for (const [name, value] of url.searchParams) {
                parameters.push({
                    name,
                    value,
                    type: this.inferType(value),
                    location: 'query',
                });
            }
        } catch {
            // Invalid URL, skip query params
        }

        // Extract body parameters
        if (entry.postData) {
            try {
                const data = JSON.parse(entry.postData);
                this.extractJsonParameters(data, parameters, 'body');
            } catch {
                // Try form-urlencoded
                this.extractFormParameters(entry.postData, parameters);
            }
        }

        return parameters;
    }

    /**
     * Extract parameters from JSON body recursively
     */
    private extractJsonParameters(
        data: Record<string, unknown>,
        parameters: Parameter[],
        location: 'body' | 'query',
        prefix: string = ''
    ): void {
        for (const [key, value] of Object.entries(data)) {
            const name = prefix ? `${prefix}.${key}` : key;

            if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
                this.extractJsonParameters(value as Record<string, unknown>, parameters, location, name);
            } else {
                parameters.push({
                    name,
                    value,
                    type: this.inferType(value),
                    location,
                });
            }
        }
    }

    /**
     * Extract parameters from form-urlencoded body
     */
    private extractFormParameters(body: string, parameters: Parameter[]): void {
        const params = new URLSearchParams(body);
        for (const [name, value] of params) {
            parameters.push({
                name,
                value,
                type: this.inferType(value),
                location: 'body',
            });
        }
    }

    /**
     * Infer parameter type from value
     */
    private inferType(value: unknown): 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown' {
        if (typeof value === 'number') return 'number';
        if (typeof value === 'boolean') return 'boolean';
        if (Array.isArray(value)) return 'array';
        if (typeof value === 'object' && value !== null) return 'object';
        if (typeof value === 'string') {
            // Check if string represents a number
            if (!isNaN(parseFloat(value)) && isFinite(parseFloat(value))) {
                return 'number';
            }
            return 'string';
        }
        return 'unknown';
    }

    /**
     * Sanitize headers (remove sensitive data)
     */
    private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
        const sanitized: Record<string, string> = {};
        const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'api-key'];

        for (const [name, value] of Object.entries(headers)) {
            if (sensitiveHeaders.includes(name.toLowerCase())) {
                sanitized[name] = '[REDACTED]';
            } else {
                sanitized[name] = value;
            }
        }

        return sanitized;
    }

    /**
     * Detect if endpoint requires authentication
     */
    private detectAuthRequirement(entry: HttpTrafficEntry): boolean {
        const headers = entry.headers;

        // Check for auth headers
        if (headers['authorization'] || headers['x-api-key'] || headers['api-key']) {
            return true;
        }

        // Check for session cookies
        const cookie = headers['cookie'] || '';
        if (/session|token|auth|jwt/i.test(cookie)) {
            return true;
        }

        // Check for protected URL patterns
        if (/\/admin|\/account|\/my-|\/user\//i.test(entry.url)) {
            return true;
        }

        return false;
    }

    /**
     * Merge parameters from duplicate endpoints
     */
    private mergeParameters(existing: Endpoint, newEndpoint: Endpoint): void {
        const existingNames = new Set(existing.parameters.map(p => p.name));

        for (const param of newEndpoint.parameters) {
            if (!existingNames.has(param.name)) {
                existing.parameters.push(param);
            }
        }
    }

    /**
     * Get endpoints by type
     */
    getByType(type: EndpointType): Endpoint[] {
        return Array.from(this.endpoints.values()).filter(e => e.type === type);
    }

    /**
     * Get endpoints requiring authentication
     */
    getAuthenticatedEndpoints(): Endpoint[] {
        return Array.from(this.endpoints.values()).filter(e => e.requiresAuth);
    }

    /**
     * Get API endpoints
     */
    getApiEndpoints(): Endpoint[] {
        return Array.from(this.endpoints.values()).filter(e =>
            e.type === 'api' || e.url.includes('/api/') || e.url.includes('/rest/')
        );
    }

    /**
     * Clear discovered endpoints
     */
    clear(): void {
        this.endpoints.clear();
    }
}

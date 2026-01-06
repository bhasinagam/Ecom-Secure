/**
 * Traffic Analyzer
 * Extracts attack parameters from captured HTTP traffic
 * Used as fallback when form-based parameter extraction fails
 */

import { Parameter, ParameterType, Endpoint, EndpointType, CheckoutFlow } from '../types';
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

interface ExtractedEndpoint {
    endpoint: Endpoint;
    parameters: Parameter[];
    source: 'traffic' | 'form';
}

export class TrafficAnalyzer {
    /**
     * Analyze HTTP traffic and extract parameters from API calls
     */
    analyzeTraffic(traffic: HttpTrafficEntry[]): ExtractedEndpoint[] {
        const endpoints: ExtractedEndpoint[] = [];

        logger.debug(`TrafficAnalyzer: Analyzing ${traffic.length} HTTP requests`);

        // Filter for relevant requests (POST/PUT to checkout-related endpoints)
        const relevantRequests = traffic.filter(entry =>
            this.isRelevantRequest(entry)
        );

        logger.debug(`Found ${relevantRequests.length} relevant API requests`);

        for (const entry of relevantRequests) {
            const extracted = this.extractFromRequest(entry);
            if (extracted) {
                endpoints.push(extracted);
                logger.debug(`Extracted endpoint: ${entry.url}`, {
                    method: entry.method,
                    paramCount: extracted.parameters.length,
                    params: extracted.parameters.map(p => p.name)
                });
            }
        }

        return endpoints;
    }

    /**
     * Check if request is relevant for vulnerability testing
     */
    private isRelevantRequest(entry: HttpTrafficEntry): boolean {
        // Only interested in data-modifying requests
        if (!['POST', 'PUT', 'PATCH'].includes(entry.method)) {
            return false;
        }

        // Skip non-document requests
        if (entry.resourceType !== 'xhr' && entry.resourceType !== 'fetch' && entry.resourceType !== 'document') {
            return false;
        }

        // Must have request body
        if (!entry.postData) {
            return false;
        }

        const urlLower = entry.url.toLowerCase();

        // Relevant URL patterns for e-commerce
        const relevantPatterns = [
            /\/cart/i,
            /\/basket/i,
            /\/checkout/i,
            /\/order/i,
            /\/payment/i,
            /\/api.*cart/i,
            /\/api.*checkout/i,
            /\/api.*order/i,
            /\/graphql/i,  // GraphQL endpoints
            /\/add.*item/i,
            /\/update.*item/i,
            /\/apply.*coupon/i,
            /\/discount/i,
            /\/promo/i,
            /\/shipping/i,
            /\/quantity/i,
        ];

        return relevantPatterns.some(pattern => pattern.test(urlLower));
    }

    /**
     * Extract endpoint and parameters from HTTP request
     */
    private extractFromRequest(entry: HttpTrafficEntry): ExtractedEndpoint | null {
        const parameters: Parameter[] = [];

        try {
            // Try to parse as JSON
            const data = JSON.parse(entry.postData!);

            // Extract parameters from JSON body
            this.extractJsonParameters(data, '', parameters);

        } catch {
            // Try form-urlencoded
            try {
                const params = new URLSearchParams(entry.postData!);
                for (const [name, value] of params) {
                    parameters.push({
                        name,
                        value,
                        type: this.inferType(name, value),
                        location: 'body',
                        required: true,
                    });
                }
            } catch {
                logger.debug(`Could not parse request body for ${entry.url}`);
                return null;
            }
        }

        if (parameters.length === 0) {
            return null;
        }

        // Determine endpoint type
        const type = this.inferEndpointType(entry.url);

        const endpoint: Endpoint = {
            url: entry.url,
            method: entry.method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
            type,
            parameters,
            headers: entry.headers,
            requiresAuth: this.hasAuthHeaders(entry.headers),
        };

        return {
            endpoint,
            parameters,
            source: 'traffic',
        };
    }

    /**
     * Recursively extract parameters from JSON object
     */
    private extractJsonParameters(
        obj: unknown,
        prefix: string,
        parameters: Parameter[]
    ): void {
        if (obj === null || obj === undefined) {
            return;
        }

        if (Array.isArray(obj)) {
            // Handle arrays - extract from first element if object
            if (obj.length > 0 && typeof obj[0] === 'object') {
                this.extractJsonParameters(obj[0], `${prefix}[0]`, parameters);
            }

            // Also add array itself as parameter
            parameters.push({
                name: prefix || 'items',
                value: obj,
                type: 'array',
                location: 'body',
                required: false,
            });
            return;
        }

        if (typeof obj === 'object') {
            for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
                const paramName = prefix ? `${prefix}.${key}` : key;

                if (typeof value === 'object' && value !== null) {
                    // Recurse into nested objects
                    this.extractJsonParameters(value, paramName, parameters);
                } else {
                    // Add leaf parameter
                    parameters.push({
                        name: key,  // Use simple name for matching
                        value,
                        type: this.inferType(key, value),
                        location: 'body',
                        required: false,
                    });
                }
            }
        }
    }

    /**
     * Infer parameter type from name and value
     */
    private inferType(name: string, value: unknown): ParameterType {
        if (typeof value === 'number') return 'number';
        if (typeof value === 'boolean') return 'boolean';
        if (Array.isArray(value)) return 'array';
        if (typeof value === 'object' && value !== null) return 'object';

        // Infer from name
        const nameLower = name.toLowerCase();
        if (/price|amount|total|cost|qty|quantity|count/.test(nameLower)) {
            return 'number';
        }

        return 'string';
    }

    /**
     * Infer endpoint type from URL
     */
    private inferEndpointType(url: string): EndpointType {
        const urlLower = url.toLowerCase();

        if (/payment|pay|transaction/.test(urlLower)) return 'payment';
        if (/checkout/.test(urlLower)) return 'checkout';
        if (/cart|basket/.test(urlLower)) return 'cart';
        if (/order/.test(urlLower)) return 'order';
        if (/api/.test(urlLower)) return 'api';
        if (/product/.test(urlLower)) return 'product';

        return 'unknown';
    }

    /**
     * Check if request has authentication headers
     */
    private hasAuthHeaders(headers: Record<string, string>): boolean {
        const authHeaders = ['authorization', 'cookie', 'x-auth-token', 'x-api-key'];
        return authHeaders.some(h =>
            Object.keys(headers).some(key => key.toLowerCase() === h)
        );
    }

    /**
     * Merge traffic-discovered endpoints with form-discovered endpoints
     */
    mergeWithFlows(flows: CheckoutFlow[], trafficEndpoints: ExtractedEndpoint[]): CheckoutFlow[] {
        logger.debug(`Merging ${trafficEndpoints.length} traffic endpoints with ${flows.length} flows`);

        // If we have no flows but have traffic endpoints, create a synthetic flow
        if (flows.length === 0 && trafficEndpoints.length > 0) {
            logger.info(`Creating synthetic flow from ${trafficEndpoints.length} traffic endpoints`);

            const syntheticFlow: CheckoutFlow = {
                productUrl: trafficEndpoints[0]?.endpoint.url || 'unknown',
                endpoints: trafficEndpoints.map(e => e.endpoint),
                parameters: {},
                stateTransitions: ['traffic_analysis'],
            };

            // Add parameters to flow
            for (const extracted of trafficEndpoints) {
                for (const param of extracted.parameters) {
                    syntheticFlow.parameters[param.name] = {
                        value: param.value,
                        type: String(param.type),
                        endpoint: extracted.endpoint.url,
                        method: extracted.endpoint.method,
                    };
                }
            }

            return [syntheticFlow];
        }

        // Merge traffic endpoints into existing flows
        for (const flow of flows) {
            for (const extracted of trafficEndpoints) {
                // Check if endpoint already exists
                const exists = flow.endpoints.some(e =>
                    e.url === extracted.endpoint.url && e.method === extracted.endpoint.method
                );

                if (!exists) {
                    flow.endpoints.push(extracted.endpoint);

                    // Add parameters
                    for (const param of extracted.parameters) {
                        if (!flow.parameters[param.name]) {
                            flow.parameters[param.name] = {
                                value: param.value,
                                type: String(param.type),
                                endpoint: extracted.endpoint.url,
                                method: extracted.endpoint.method,
                            };
                        }
                    }
                }
            }
        }

        return flows;
    }

    /**
     * Get high-value parameters for vulnerability testing
     */
    getHighValueParameters(endpoints: ExtractedEndpoint[]): Parameter[] {
        const highValuePatterns = [
            /price/i,
            /amount/i,
            /total/i,
            /quantity/i,
            /qty/i,
            /discount/i,
            /coupon/i,
            /promo/i,
            /shipping/i,
            /payment/i,
            /currency/i,
        ];

        const highValue: Parameter[] = [];

        for (const endpoint of endpoints) {
            for (const param of endpoint.parameters) {
                if (highValuePatterns.some(p => p.test(param.name))) {
                    highValue.push(param);
                }
            }
        }

        logger.debug(`Found ${highValue.length} high-value parameters`, {
            params: highValue.map(p => p.name)
        });

        return highValue;
    }
}

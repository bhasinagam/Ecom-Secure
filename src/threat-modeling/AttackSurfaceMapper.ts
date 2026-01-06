/**
 * Attack Surface Mapper
 * Builds attack graph from discovered endpoints and parameters
 */

import {
    CheckoutFlow,
    AttackSurface,
    AttackEndpoint,
    AttackParameter,
    TrustBoundary,
    DataFlow,
    PlatformDetectionResult,
    Parameter
} from '../types';
import { logger } from '../core/Logger';

export class AttackSurfaceMapper {
    /**
     * Analyze checkout flows and build attack surface
     */
    async analyze(flows: CheckoutFlow[], platform: PlatformDetectionResult): Promise<AttackSurface> {
        const attackEndpoints: AttackEndpoint[] = [];
        const attackParameters: AttackParameter[] = [];
        const trustBoundaries: TrustBoundary[] = [];
        const dataFlows: DataFlow[] = [];

        logger.debug(`AttackSurfaceMapper: Analyzing ${flows.length} checkout flows`);

        if (flows.length === 0) {
            logger.warn('AttackSurfaceMapper: No checkout flows to analyze!');
        }

        for (const flow of flows) {
            logger.debug(`Analyzing flow: ${flow.productUrl}`, {
                endpointCount: flow.endpoints.length,
                parameterCount: Object.keys(flow.parameters).length,
                stateTransitions: flow.stateTransitions
            });

            // Analyze endpoints
            for (const endpoint of flow.endpoints) {
                logger.debug(`Analyzing endpoint: ${endpoint.url}`, {
                    method: endpoint.method,
                    type: endpoint.type,
                    paramCount: endpoint.parameters.length,
                    paramNames: endpoint.parameters.map(p => p.name)
                });

                const attackVectors = this.identifyAttackVectors(endpoint, platform);
                const riskScore = this.calculateEndpointRisk(endpoint, attackVectors);

                attackEndpoints.push({
                    endpoint,
                    attackVectors,
                    riskScore,
                });

                // Analyze parameters
                for (const param of endpoint.parameters) {
                    logger.debug(`Found parameter: ${param.name}`, {
                        type: param.type,
                        value: param.value,
                        location: param.location
                    });

                    const paramVectors = this.identifyParameterVectors(param);
                    const exploitability = this.calculateExploitability(param, paramVectors);

                    attackParameters.push({
                        parameter: param,
                        attackVectors: paramVectors,
                        exploitability,
                    });
                }
            }

            // Identify trust boundaries
            const boundaries = this.identifyTrustBoundaries(flow);
            trustBoundaries.push(...boundaries);

            // Map data flows
            const flows_data = this.mapDataFlows(flow);
            dataFlows.push(...flows_data);
        }

        // Add platform-specific attack vectors
        this.addPlatformVectors(attackEndpoints, platform);

        logger.info(`Mapped attack surface: ${attackEndpoints.length} endpoints, ${attackParameters.length} parameters`);
        logger.debug(`Attack surface details:`, {
            endpoints: attackEndpoints.map(e => ({ url: e.endpoint.url, risk: e.riskScore })),
            params: attackParameters.map(p => ({ name: p.parameter.name, exploitability: p.exploitability })),
            boundaries: trustBoundaries.length,
            dataFlows: dataFlows.length
        });

        if (attackParameters.length === 0) {
            logger.warn('WARNING: No attack parameters found! Detectors will have nothing to test.');
            logger.debug('This usually happens when:');
            logger.debug('  1. Crawler could not find forms on the site');
            logger.debug('  2. Site uses JavaScript-heavy forms that were not detected');
            logger.debug('  3. Site requires authentication to access checkout');
        }

        return {
            endpoints: attackEndpoints,
            parameters: attackParameters,
            trustBoundaries,
            dataFlows,
        };
    }

    /**
     * Identify attack vectors for an endpoint
     */
    private identifyAttackVectors(
        endpoint: { url: string; method: string; type: string; requiresAuth: boolean },
        platform: PlatformDetectionResult
    ): string[] {
        const vectors: string[] = [];
        const urlLower = endpoint.url.toLowerCase();

        // Method-based vectors
        if (endpoint.method === 'POST' || endpoint.method === 'PUT') {
            vectors.push('parameter_tampering');
        }
        if (endpoint.method === 'DELETE') {
            vectors.push('unauthorized_deletion');
        }

        // Endpoint type vectors
        if (endpoint.type === 'cart') {
            vectors.push('cart_manipulation', 'quantity_tampering', 'price_override');
        }
        if (endpoint.type === 'checkout') {
            vectors.push('checkout_bypass', 'price_manipulation', 'discount_abuse');
        }
        if (endpoint.type === 'payment') {
            vectors.push('payment_bypass', 'amount_mismatch', 'callback_manipulation');
        }

        // URL pattern vectors
        if (/api|rest|graphql/i.test(urlLower)) {
            vectors.push('api_abuse', 'rate_limiting_bypass');
        }
        if (/admin|dashboard/i.test(urlLower)) {
            vectors.push('privilege_escalation', 'unauthorized_access');
        }
        if (/webhook|callback/i.test(urlLower)) {
            vectors.push('webhook_replay', 'callback_forgery');
        }

        // Auth-based vectors
        if (!endpoint.requiresAuth) {
            vectors.push('unauthenticated_access');
        } else {
            vectors.push('authentication_bypass', 'session_hijacking');
        }

        // Platform-specific vectors
        for (const vuln of platform.knownVulnerabilities) {
            if (!vectors.includes(vuln)) {
                vectors.push(vuln);
            }
        }

        return [...new Set(vectors)];
    }

    /**
     * Calculate risk score for an endpoint (0-10)
     */
    private calculateEndpointRisk(
        endpoint: { type: string; requiresAuth: boolean; parameters: Parameter[] },
        attackVectors: string[]
    ): number {
        let score = 0;

        // Base score by endpoint type
        const typeScores: Record<string, number> = {
            payment: 4,
            checkout: 3.5,
            cart: 2.5,
            order: 2,
            api: 1.5,
            product: 1,
            unknown: 1,
        };
        score += typeScores[endpoint.type] || 1;

        // Attack vector count
        score += Math.min(attackVectors.length * 0.3, 2);

        // High-risk parameters
        const highRiskParams = endpoint.parameters.filter(p =>
            /price|amount|total|quantity|discount|payment/i.test(p.name)
        );
        score += Math.min(highRiskParams.length * 0.5, 2);

        // Authentication factor
        if (!endpoint.requiresAuth) {
            score += 1;
        }

        // Critical vectors boost
        const criticalVectors = ['payment_bypass', 'price_manipulation', 'authentication_bypass'];
        if (attackVectors.some(v => criticalVectors.includes(v))) {
            score += 1;
        }

        return Math.min(score, 10);
    }

    /**
     * Identify attack vectors for a parameter
     */
    private identifyParameterVectors(param: Parameter): string[] {
        const vectors: string[] = [];
        const nameLower = param.name.toLowerCase();

        // Type-based vectors
        if (param.type === 'number') {
            vectors.push('integer_overflow', 'negative_value', 'zero_value', 'type_confusion');
        }
        if (param.type === 'string') {
            vectors.push('sqli', 'xss', 'ldap_injection', 'command_injection', 'formula_injection');
        }
        if (param.type === 'array' || param.type === 'object') {
            vectors.push('array_injection', 'prototype_pollution');
        }

        // Name-based vectors
        if (/price|amount|cost|total/i.test(nameLower)) {
            vectors.push('price_manipulation', 'negative_price', 'zero_price', 'currency_confusion');
        }
        if (/quantity|qty|count/i.test(nameLower)) {
            vectors.push('negative_quantity', 'quantity_overflow', 'quantity_type_confusion');
        }
        if (/discount|coupon|promo/i.test(nameLower)) {
            vectors.push('discount_stacking', 'negative_discount', 'discount_replay', 'percentage_overflow');
        }
        if (/id|user|session|cart/i.test(nameLower)) {
            vectors.push('idor', 'session_manipulation', 'horizontal_privesc');
        }
        if (/email|mail/i.test(nameLower)) {
            vectors.push('email_injection', 'header_injection');
        }
        if (/url|redirect|callback/i.test(nameLower)) {
            vectors.push('open_redirect', 'ssrf');
        }
        if (/file|path|name/i.test(nameLower)) {
            vectors.push('path_traversal', 'file_inclusion');
        }

        return [...new Set(vectors)];
    }

    /**
     * Calculate exploitability score (0-1)
     */
    private calculateExploitability(param: Parameter, vectors: string[]): number {
        let score = 0.3; // Base score

        // High-impact parameter types
        if (/price|amount|payment/i.test(param.name)) {
            score += 0.3;
        }
        if (/discount|coupon/i.test(param.name)) {
            score += 0.2;
        }
        if (/quantity/i.test(param.name)) {
            score += 0.15;
        }

        // Attack vector count
        score += Math.min(vectors.length * 0.03, 0.2);

        // Type factor
        if (param.type === 'number') {
            score += 0.1; // Easier to test numeric manipulation
        }

        // Required fields are more critical
        if (param.required) {
            score += 0.05;
        }

        return Math.min(score, 1);
    }

    /**
     * Identify trust boundaries in the flow
     */
    private identifyTrustBoundaries(flow: CheckoutFlow): TrustBoundary[] {
        const boundaries: TrustBoundary[] = [];

        // Client to server boundary
        boundaries.push({
            name: 'client_server',
            from: 'browser',
            to: 'web_server',
            dataTypes: ['form_data', 'cookies', 'headers'],
            validationPresent: true, // Assume some validation
        });

        // Cart to checkout boundary
        if (flow.stateTransitions.some(t => t.includes('cart') && t.includes('checkout'))) {
            boundaries.push({
                name: 'cart_checkout',
                from: 'cart_state',
                to: 'checkout_state',
                dataTypes: ['cart_items', 'prices', 'quantities'],
                validationPresent: false, // Needs testing
            });
        }

        // Checkout to payment boundary
        if (flow.stateTransitions.some(t => t.includes('checkout') && t.includes('payment'))) {
            boundaries.push({
                name: 'checkout_payment',
                from: 'checkout_state',
                to: 'payment_gateway',
                dataTypes: ['order_total', 'payment_details'],
                validationPresent: false, // Critical boundary
            });
        }

        return boundaries;
    }

    /**
     * Map data flows through the checkout process
     */
    private mapDataFlows(flow: CheckoutFlow): DataFlow[] {
        const dataFlows: DataFlow[] = [];

        // Price flow
        if (Object.keys(flow.parameters).some(k => /price|amount/i.test(k))) {
            dataFlows.push({
                source: 'product_catalog',
                destination: 'cart',
                dataType: 'price',
                transformations: ['aggregation', 'discount_application'],
                canBeManipulated: true,
            });

            dataFlows.push({
                source: 'cart',
                destination: 'checkout',
                dataType: 'total_price',
                transformations: ['tax_calculation', 'shipping_calculation'],
                canBeManipulated: true,
            });

            dataFlows.push({
                source: 'checkout',
                destination: 'payment_gateway',
                dataType: 'payment_amount',
                transformations: ['currency_conversion'],
                canBeManipulated: true,
            });
        }

        // Quantity flow
        if (Object.keys(flow.parameters).some(k => /quantity|qty/i.test(k))) {
            dataFlows.push({
                source: 'user_input',
                destination: 'cart',
                dataType: 'quantity',
                transformations: ['validation'],
                canBeManipulated: true,
            });

            dataFlows.push({
                source: 'cart',
                destination: 'inventory',
                dataType: 'reserved_quantity',
                transformations: ['stock_check'],
                canBeManipulated: true,
            });
        }

        // Discount flow
        if (Object.keys(flow.parameters).some(k => /discount|coupon/i.test(k))) {
            dataFlows.push({
                source: 'user_input',
                destination: 'discount_engine',
                dataType: 'coupon_code',
                transformations: ['validation', 'usage_check'],
                canBeManipulated: true,
            });

            dataFlows.push({
                source: 'discount_engine',
                destination: 'cart_total',
                dataType: 'discount_amount',
                transformations: ['percentage_calculation'],
                canBeManipulated: true,
            });
        }

        return dataFlows;
    }

    /**
     * Add platform-specific attack vectors
     */
    private addPlatformVectors(endpoints: AttackEndpoint[], platform: PlatformDetectionResult): void {
        for (const endpoint of endpoints) {
            // Add known vulnerabilities for the platform
            for (const vuln of platform.knownVulnerabilities) {
                if (!endpoint.attackVectors.includes(vuln)) {
                    endpoint.attackVectors.push(`platform:${vuln}`);
                }
            }
        }
    }

    /**
     * Get high-risk attack points
     */
    getHighRiskPoints(surface: AttackSurface): AttackEndpoint[] {
        return surface.endpoints
            .filter(e => e.riskScore >= 7)
            .sort((a, b) => b.riskScore - a.riskScore);
    }

    /**
     * Get exploitable parameters
     */
    getExploitableParameters(surface: AttackSurface): AttackParameter[] {
        return surface.parameters
            .filter(p => p.exploitability >= 0.6)
            .sort((a, b) => b.exploitability - a.exploitability);
    }
}

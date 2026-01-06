/**
 * Trust Boundary Identifier
 * Maps client-server trust boundaries and validation points
 */

import { CheckoutFlow, TrustBoundary, Endpoint } from '../types';
import { logger } from '../core/Logger';

export interface BoundaryAnalysis {
    boundary: TrustBoundary;
    crossings: BoundaryCrossing[];
    vulnerabilities: string[];
    recommendations: string[];
}

export interface BoundaryCrossing {
    parameter: string;
    direction: 'client_to_server' | 'server_to_client';
    encrypted: boolean;
    signed: boolean;
    validated: boolean;
}

export class TrustBoundaryIdentifier {
    /**
     * Identify all trust boundaries in checkout flow
     */
    identify(flow: CheckoutFlow): TrustBoundary[] {
        const boundaries: TrustBoundary[] = [];

        // Browser to Web Server
        boundaries.push({
            name: 'browser_to_server',
            from: 'user_browser',
            to: 'web_application',
            dataTypes: this.extractDataTypes(flow, 'client'),
            validationPresent: this.hasInputValidation(flow),
        });

        // Web Application to Database
        boundaries.push({
            name: 'app_to_database',
            from: 'web_application',
            to: 'database',
            dataTypes: ['order_data', 'user_data', 'payment_info'],
            validationPresent: true, // Assume ORM/prepared statements
        });

        // Web Application to Payment Gateway
        if (this.hasPaymentEndpoint(flow)) {
            boundaries.push({
                name: 'app_to_payment',
                from: 'web_application',
                to: 'payment_gateway',
                dataTypes: ['payment_amount', 'card_token', 'order_reference'],
                validationPresent: false, // Critical - needs verification
            });
        }

        // Session boundary
        boundaries.push({
            name: 'session_boundary',
            from: 'anonymous_user',
            to: 'authenticated_session',
            dataTypes: ['session_id', 'cart_id', 'user_context'],
            validationPresent: this.hasSessionValidation(flow),
        });

        // Cart to Order boundary
        if (this.hasCheckoutTransition(flow)) {
            boundaries.push({
                name: 'cart_to_order',
                from: 'cart_context',
                to: 'order_context',
                dataTypes: ['cart_items', 'calculated_total', 'applied_discounts'],
                validationPresent: false, // Often vulnerable
            });
        }

        return boundaries;
    }

    /**
     * Analyze a specific trust boundary
     */
    analyzeBoundary(boundary: TrustBoundary, flow: CheckoutFlow): BoundaryAnalysis {
        const crossings = this.identifyCrossings(boundary, flow);
        const vulnerabilities = this.findBoundaryVulnerabilities(boundary, crossings);
        const recommendations = this.generateRecommendations(boundary, vulnerabilities);

        return {
            boundary,
            crossings,
            vulnerabilities,
            recommendations,
        };
    }

    /**
     * Identify data crossings at a boundary
     */
    private identifyCrossings(boundary: TrustBoundary, flow: CheckoutFlow): BoundaryCrossing[] {
        const crossings: BoundaryCrossing[] = [];

        // Client to server crossings
        if (boundary.from.includes('browser') || boundary.from.includes('client')) {
            for (const [paramName, paramInfo] of Object.entries(flow.parameters)) {
                crossings.push({
                    parameter: paramName,
                    direction: 'client_to_server',
                    encrypted: this.isEncrypted(paramInfo.endpoint),
                    signed: this.isSigned(paramName, flow),
                    validated: this.isValidated(paramName, flow),
                });
            }
        }

        // Payment boundary crossings
        if (boundary.name === 'app_to_payment') {
            const paymentParams = ['amount', 'currency', 'order_id', 'callback_url'];
            for (const param of paymentParams) {
                crossings.push({
                    parameter: param,
                    direction: 'client_to_server',
                    encrypted: true, // Assumed for payment
                    signed: false, // Needs verification
                    validated: false, // Critical
                });
            }
        }

        return crossings;
    }

    /**
     * Find vulnerabilities at boundary
     */
    private findBoundaryVulnerabilities(
        boundary: TrustBoundary,
        crossings: BoundaryCrossing[]
    ): string[] {
        const vulnerabilities: string[] = [];

        // Check for unvalidated crossings
        const unvalidated = crossings.filter(c => !c.validated);
        if (unvalidated.length > 0) {
            vulnerabilities.push(
                `Unvalidated parameters crossing ${boundary.name}: ${unvalidated.map(c => c.parameter).join(', ')}`
            );
        }

        // Check for unsigned critical data
        const unsignedCritical = crossings.filter(
            c => !c.signed && this.isCriticalParameter(c.parameter)
        );
        if (unsignedCritical.length > 0) {
            vulnerabilities.push(
                `Unsigned critical parameters: ${unsignedCritical.map(c => c.parameter).join(', ')}`
            );
        }

        // Boundary-specific vulnerabilities
        if (boundary.name === 'browser_to_server' && !boundary.validationPresent) {
            vulnerabilities.push('No server-side input validation detected');
        }

        if (boundary.name === 'app_to_payment') {
            vulnerabilities.push('Payment amount may be client-controlled');
            vulnerabilities.push('Payment callback URL may be manipulable');
        }

        if (boundary.name === 'cart_to_order' && !boundary.validationPresent) {
            vulnerabilities.push('Cart items may not be re-validated at order creation');
            vulnerabilities.push('Prices may be cached from cart without verification');
        }

        if (boundary.name === 'session_boundary') {
            vulnerabilities.push('Session fixation may be possible');
            vulnerabilities.push('Cart may not be properly bound to session');
        }

        return vulnerabilities;
    }

    /**
     * Generate security recommendations
     */
    private generateRecommendations(boundary: TrustBoundary, vulnerabilities: string[]): string[] {
        const recommendations: string[] = [];

        if (boundary.name === 'browser_to_server') {
            recommendations.push('Implement server-side validation for ALL parameters');
            recommendations.push('Never trust client-provided price or total values');
            recommendations.push('Use CSRF tokens for state-changing operations');
        }

        if (boundary.name === 'app_to_payment') {
            recommendations.push('Sign payment requests with server-side secret');
            recommendations.push('Verify payment amounts on callback');
            recommendations.push('Validate callback URL is internal');
            recommendations.push('Implement idempotency for payment webhooks');
        }

        if (boundary.name === 'cart_to_order') {
            recommendations.push('Re-calculate prices from product catalog at checkout');
            recommendations.push('Verify inventory availability atomically');
            recommendations.push('Use database transactions for order creation');
        }

        if (boundary.name === 'session_boundary') {
            recommendations.push('Regenerate session ID after authentication');
            recommendations.push('Bind cart to authenticated user, not just session');
            recommendations.push('Implement session timeout');
        }

        return recommendations;
    }

    /**
     * Check if parameter is critical (price, payment, etc.)
     */
    private isCriticalParameter(paramName: string): boolean {
        const criticalPatterns = /price|amount|total|payment|card|discount|quantity/i;
        return criticalPatterns.test(paramName);
    }

    /**
     * Extract data types from flow
     */
    private extractDataTypes(flow: CheckoutFlow, context: string): string[] {
        const types: string[] = [];

        for (const [key] of Object.entries(flow.parameters)) {
            if (/price|amount/i.test(key)) types.push('price_data');
            if (/quantity/i.test(key)) types.push('quantity_data');
            if (/discount|coupon/i.test(key)) types.push('discount_data');
            if (/card|payment/i.test(key)) types.push('payment_data');
            if (/address|email/i.test(key)) types.push('user_data');
        }

        return [...new Set(types)];
    }

    /**
     * Check if flow has input validation
     */
    private hasInputValidation(flow: CheckoutFlow): boolean {
        // This would be determined by probing - default to false (unsafe assumption)
        return false;
    }

    /**
     * Check if flow has payment endpoint
     */
    private hasPaymentEndpoint(flow: CheckoutFlow): boolean {
        return flow.endpoints.some(e => e.type === 'payment') ||
            flow.stateTransitions.some(t => t.includes('payment'));
    }

    /**
     * Check for checkout transition
     */
    private hasCheckoutTransition(flow: CheckoutFlow): boolean {
        return flow.stateTransitions.some(t =>
            t.includes('cart') && (t.includes('checkout') || t.includes('order'))
        );
    }

    /**
     * Check if endpoint is encrypted (HTTPS)
     */
    private isEncrypted(endpoint: string): boolean {
        return endpoint.startsWith('https://');
    }

    /**
     * Check if parameter is signed
     */
    private isSigned(paramName: string, flow: CheckoutFlow): boolean {
        // Look for signature/hmac parameters
        const hasSignature = Object.keys(flow.parameters).some(
            k => /signature|hmac|hash|sign/i.test(k)
        );
        return hasSignature;
    }

    /**
     * Check if parameter is validated
     */
    private isValidated(paramName: string, flow: CheckoutFlow): boolean {
        // Default to false - will be determined by testing
        return false;
    }

    /**
     * Check for session validation
     */
    private hasSessionValidation(flow: CheckoutFlow): boolean {
        // Look for CSRF tokens or session validation
        return Object.keys(flow.parameters).some(
            k => /csrf|token|nonce/i.test(k)
        );
    }
}

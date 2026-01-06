/**
 * Checkout Flow Detector
 * Identifies checkout patterns and state transitions
 */

import { CheckoutFlow, Endpoint, EndpointType } from '../types';
import { logger } from '../core/Logger';

export interface CheckoutState {
    name: string;
    url: string;
    nextStates: string[];
    requiredFields: string[];
    validations: string[];
}

export class CheckoutFlowDetector {
    private states: Map<string, CheckoutState> = new Map();

    /**
     * Analyze checkout flow and identify states
     */
    analyzeFlow(flow: CheckoutFlow): CheckoutState[] {
        const states: CheckoutState[] = [];

        // Build state machine from transitions
        for (const transition of flow.stateTransitions) {
            const [from, to] = transition.split(' → ').map(s => s.trim());

            if (!this.states.has(from)) {
                this.states.set(from, {
                    name: from,
                    url: '',
                    nextStates: [],
                    requiredFields: [],
                    validations: [],
                });
            }

            const state = this.states.get(from)!;
            if (!state.nextStates.includes(to)) {
                state.nextStates.push(to);
            }
        }

        // Map endpoints to states
        for (const endpoint of flow.endpoints) {
            const stateName = this.inferStateName(endpoint);
            if (this.states.has(stateName)) {
                const state = this.states.get(stateName)!;
                state.url = endpoint.url;
                state.requiredFields = endpoint.parameters
                    .filter(p => p.required)
                    .map(p => p.name);
            }
        }

        return Array.from(this.states.values());
    }

    /**
     * Infer state name from endpoint
     */
    private inferStateName(endpoint: Endpoint): string {
        const endpointTypeToState: Record<EndpointType, string> = {
            cart: 'cart',
            checkout: 'checkout',
            payment: 'payment',
            order: 'order_confirmation',
            product: 'product_page',
            api: 'api',
            unknown: 'unknown',
        };

        return endpointTypeToState[endpoint.type] || 'unknown';
    }

    /**
     * Detect checkout bypass opportunities
     */
    detectBypassOpportunities(flows: CheckoutFlow[]): string[] {
        const opportunities: string[] = [];

        for (const flow of flows) {
            // Check if any state can be skipped
            const stateSequence = this.getStateSequence(flow);

            for (let i = 0; i < stateSequence.length - 1; i++) {
                const currentState = stateSequence[i];
                const skipToState = stateSequence[i + 2]; // Skip next state

                if (skipToState) {
                    opportunities.push(
                        `Potential bypass: ${currentState} → ${skipToState} (skipping ${stateSequence[i + 1]})`
                    );
                }
            }

            // Check for direct payment endpoint access
            const paymentEndpoints = flow.endpoints.filter(e => e.type === 'payment');
            if (paymentEndpoints.length > 0) {
                opportunities.push('Direct payment endpoint access possible');
            }

            // Check for missing authentication on checkout states
            const unauthenticatedCheckout = flow.endpoints.filter(
                e => e.type === 'checkout' && !e.requiresAuth
            );
            if (unauthenticatedCheckout.length > 0) {
                opportunities.push('Checkout available without authentication');
            }
        }

        return opportunities;
    }

    /**
     * Get ordered sequence of states
     */
    private getStateSequence(flow: CheckoutFlow): string[] {
        const sequence: string[] = [];
        const visited = new Set<string>();

        for (const transition of flow.stateTransitions) {
            const [from, to] = transition.split(' → ').map(s => s.trim());

            if (!visited.has(from)) {
                sequence.push(from);
                visited.add(from);
            }
            if (!visited.has(to)) {
                sequence.push(to);
                visited.add(to);
            }
        }

        return sequence;
    }

    /**
     * Identify critical state transitions
     */
    getCriticalTransitions(flow: CheckoutFlow): Array<{ from: string; to: string; risk: string }> {
        const critical: Array<{ from: string; to: string; risk: string }> = [];

        for (const transition of flow.stateTransitions) {
            const [from, to] = transition.split(' → ').map(s => s.trim());

            // Cart to checkout (price finalization)
            if (from === 'cart' && to === 'checkout') {
                critical.push({
                    from,
                    to,
                    risk: 'Price manipulation window between cart and checkout',
                });
            }

            // Checkout to payment (amount transfer)
            if (from === 'checkout' && to.includes('payment')) {
                critical.push({
                    from,
                    to,
                    risk: 'Amount mismatch potential between checkout and payment',
                });
            }

            // Any transition to order confirmation
            if (to.includes('confirm') || to.includes('success')) {
                critical.push({
                    from,
                    to,
                    risk: 'Order finalization - ensure all validations complete',
                });
            }
        }

        return critical;
    }

    /**
     * Detect race condition opportunities
     */
    detectRaceOpportunities(flow: CheckoutFlow): string[] {
        const opportunities: string[] = [];

        // Check for inventory-sensitive endpoints
        const cartEndpoints = flow.endpoints.filter(e => e.type === 'cart');
        if (cartEndpoints.length > 0) {
            opportunities.push('Cart operations may be vulnerable to race conditions');
        }

        // Check for concurrent checkout potential
        const checkoutEndpoints = flow.endpoints.filter(e => e.type === 'checkout');
        if (checkoutEndpoints.length > 0) {
            opportunities.push('Checkout endpoint may allow concurrent requests');
        }

        // Check for coupon application
        const hasDiscountParams = Object.keys(flow.parameters).some(
            key => /discount|coupon|promo/.test(key.toLowerCase())
        );
        if (hasDiscountParams) {
            opportunities.push('Discount application may be vulnerable to race conditions');
        }

        return opportunities;
    }

    /**
     * Get flow summary
     */
    getFlowSummary(flow: CheckoutFlow): {
        stateCount: number;
        endpointCount: number;
        parameterCount: number;
        transitions: string[];
        hasAuth: boolean;
    } {
        return {
            stateCount: new Set(flow.stateTransitions.flatMap(t => t.split(' → '))).size,
            endpointCount: flow.endpoints.length,
            parameterCount: Object.keys(flow.parameters).length,
            transitions: flow.stateTransitions,
            hasAuth: flow.endpoints.some(e => e.requiresAuth),
        };
    }
}

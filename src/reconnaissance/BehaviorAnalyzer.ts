/**
 * Behavior Analyzer - State Machine Learning
 * Detects checkout flow bypass vulnerabilities by analyzing state transitions
 * 
 * BLACKHAT INSIGHT: Real vulnerabilities emerge when state transitions are violated.
 * E.g., going from /cart → /order-confirmation without /checkout
 */

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

interface StateTransition {
    from: string;
    to: string;
    method: string;
    timestamp: number;
    url: string;
}

interface StateNode {
    id: string;
    type: 'cart' | 'checkout' | 'payment' | 'confirmation' | 'product' | 'unknown';
    url: string;
    inEdges: string[];
    outEdges: string[];
}

interface StateBypass {
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    path: string[];
    exploitability: string;
    cvss: number;
    description: string;
}

interface StateGraph {
    nodes: Map<string, StateNode>;
    edges: StateTransition[];
    bypasses: StateBypass[];
}

export class BehaviorAnalyzer {
    private statePatterns: Map<string, string> = new Map([
        ['cart', '/cart|/basket|/bag|/shopping-cart'],
        ['checkout', '/checkout|/order|/place-order'],
        ['payment', '/payment|/pay|/billing|/stripe|/razorpay'],
        ['confirmation', '/confirmation|/thank-you|/success|/order-complete|/receipt'],
        ['product', '/product|/item|/p/|/dp/'],
    ]);

    /**
     * Build state model from HTTP traffic
     */
    async buildStateModel(httpTraffic: HttpTrafficEntry[]): Promise<StateGraph> {
        logger.debug(`BehaviorAnalyzer: Analyzing ${httpTraffic.length} requests`);

        // Extract state transitions from traffic
        const transitions = this.extractTransitions(httpTraffic);
        logger.debug(`Extracted ${transitions.length} state transitions`);

        // Build graph
        const graph = this.buildGraph(transitions);

        // Find state bypass vulnerabilities
        const bypasses = this.findStateBypassVulnerabilities(graph);

        if (bypasses.length > 0) {
            logger.warn(`Found ${bypasses.length} potential state bypass vulnerabilities`);
        }

        return { ...graph, bypasses };
    }

    /**
     * Extract state transitions from HTTP traffic
     */
    private extractTransitions(traffic: HttpTrafficEntry[]): StateTransition[] {
        const transitions: StateTransition[] = [];
        const navigationRequests = traffic.filter(t =>
            t.resourceType === 'document' ||
            t.method === 'POST' ||
            t.resourceType === 'xhr'
        );

        for (let i = 1; i < navigationRequests.length; i++) {
            const prev = navigationRequests[i - 1];
            const curr = navigationRequests[i];

            transitions.push({
                from: this.classifyState(prev.url),
                to: this.classifyState(curr.url),
                method: curr.method,
                timestamp: i,
                url: curr.url,
            });
        }

        return transitions;
    }

    /**
     * Classify URL into state type
     */
    private classifyState(url: string): string {
        const urlLower = url.toLowerCase();

        for (const [stateType, pattern] of this.statePatterns) {
            if (new RegExp(pattern, 'i').test(urlLower)) {
                return stateType;
            }
        }

        return 'unknown';
    }

    /**
     * Build state graph from transitions
     */
    private buildGraph(transitions: StateTransition[]): StateGraph {
        const nodes = new Map<string, StateNode>();
        const edges: StateTransition[] = [];

        for (const transition of transitions) {
            // Ensure nodes exist
            if (!nodes.has(transition.from)) {
                nodes.set(transition.from, {
                    id: transition.from,
                    type: transition.from as StateNode['type'],
                    url: '',
                    inEdges: [],
                    outEdges: [],
                });
            }

            if (!nodes.has(transition.to)) {
                nodes.set(transition.to, {
                    id: transition.to,
                    type: transition.to as StateNode['type'],
                    url: transition.url,
                    inEdges: [],
                    outEdges: [],
                });
            }

            // Add edge
            nodes.get(transition.from)!.outEdges.push(transition.to);
            nodes.get(transition.to)!.inEdges.push(transition.from);
            edges.push(transition);
        }

        return { nodes, edges, bypasses: [] };
    }

    /**
     * Find state bypass vulnerabilities
     * Tests if critical states can be skipped
     */
    private findStateBypassVulnerabilities(graph: StateGraph): StateBypass[] {
        const bypasses: StateBypass[] = [];

        // Expected checkout flow: cart → checkout → payment → confirmation
        const expectedFlow = ['cart', 'checkout', 'payment', 'confirmation'];

        // Check for payment bypass (cart → confirmation without payment)
        const confirmationNode = graph.nodes.get('confirmation');
        if (confirmationNode) {
            const pathsToConfirmation = this.findAllPaths(graph, 'cart', 'confirmation');

            for (const path of pathsToConfirmation) {
                // Check if payment is in path
                const hasPayment = path.includes('payment');
                const hasCheckout = path.includes('checkout');

                if (!hasPayment && path.length > 1) {
                    bypasses.push({
                        type: 'payment_bypass_via_state_jump',
                        severity: 'CRITICAL',
                        path,
                        exploitability: 'Direct URL manipulation to skip payment',
                        cvss: 9.8,
                        description: `Path to confirmation exists without payment: ${path.join(' → ')}`
                    });
                }

                if (!hasCheckout && path.length > 1) {
                    bypasses.push({
                        type: 'checkout_bypass_via_state_jump',
                        severity: 'HIGH',
                        path,
                        exploitability: 'Direct URL manipulation to skip checkout validation',
                        cvss: 8.5,
                        description: `Path to confirmation exists without checkout: ${path.join(' → ')}`
                    });
                }
            }
        }

        // Check for direct access to payment without cart
        const paymentNode = graph.nodes.get('payment');
        if (paymentNode) {
            const hasDirectAccess = !paymentNode.inEdges.includes('checkout') &&
                paymentNode.inEdges.length > 0;

            if (hasDirectAccess) {
                bypasses.push({
                    type: 'payment_direct_access',
                    severity: 'HIGH',
                    path: ['direct', 'payment'],
                    exploitability: 'Direct URL access to payment endpoint',
                    cvss: 7.5,
                    description: 'Payment endpoint accessible without proper checkout flow'
                });
            }
        }

        // Check for confirmation page without proper flow
        if (confirmationNode && confirmationNode.inEdges.includes('unknown')) {
            bypasses.push({
                type: 'confirmation_direct_access',
                severity: 'HIGH',
                path: ['unknown', 'confirmation'],
                exploitability: 'Direct URL access to order confirmation',
                cvss: 8.0,
                description: 'Order confirmation accessible from unexpected states'
            });
        }

        return bypasses;
    }

    /**
     * Find all paths between two nodes using DFS
     */
    private findAllPaths(
        graph: StateGraph,
        start: string,
        end: string,
        maxDepth: number = 10
    ): string[][] {
        const allPaths: string[][] = [];
        const visited = new Set<string>();

        const dfs = (current: string, path: string[], depth: number) => {
            if (depth > maxDepth) return;
            if (current === end) {
                allPaths.push([...path]);
                return;
            }

            visited.add(current);
            const node = graph.nodes.get(current);

            if (node) {
                for (const next of node.outEdges) {
                    if (!visited.has(next)) {
                        dfs(next, [...path, next], depth + 1);
                    }
                }
            }

            visited.delete(current);
        };

        dfs(start, [start], 0);
        return allPaths;
    }

    /**
     * Analyze for timing-based state manipulation
     */
    async analyzeTimingVulnerabilities(
        traffic: HttpTrafficEntry[]
    ): Promise<StateBypass[]> {
        const bypasses: StateBypass[] = [];

        // Find rapid state changes (potential race conditions)
        const stateChangeTimes = new Map<string, number[]>();
        let lastTime = 0;

        for (const entry of traffic) {
            const state = this.classifyState(entry.url);
            if (state !== 'unknown') {
                if (!stateChangeTimes.has(state)) {
                    stateChangeTimes.set(state, []);
                }
                stateChangeTimes.get(state)!.push(lastTime);
            }
            lastTime++;
        }

        // Check for repeated rapid accesses to payment/checkout
        const paymentAccesses = stateChangeTimes.get('payment') || [];
        if (paymentAccesses.length > 3) {
            bypasses.push({
                type: 'rapid_payment_access',
                severity: 'MEDIUM',
                path: ['multiple', 'payment', 'requests'],
                exploitability: 'Potential race condition in payment processing',
                cvss: 6.5,
                description: `Payment endpoint accessed ${paymentAccesses.length} times rapidly`
            });
        }

        return bypasses;
    }

    /**
     * Generate test cases for detected bypasses
     */
    generateBypassTests(bypasses: StateBypass[]): BypassTest[] {
        return bypasses.map(bypass => ({
            name: bypass.type,
            description: bypass.description,
            steps: this.generateTestSteps(bypass),
            expectedResult: 'Request should be rejected',
            exploitResult: 'Request succeeds, order created without proper flow',
        }));
    }

    private generateTestSteps(bypass: StateBypass): string[] {
        switch (bypass.type) {
            case 'payment_bypass_via_state_jump':
                return [
                    '1. Add item to cart',
                    '2. Note the cart ID / session',
                    '3. Skip checkout, directly POST to confirmation endpoint',
                    '4. Check if order was created'
                ];
            case 'checkout_bypass_via_state_jump':
                return [
                    '1. Add item to cart',
                    '2. Skip cart validation, directly access payment',
                    '3. Complete payment',
                    '4. Check if validation was enforced'
                ];
            default:
                return ['1. Access endpoint directly without prior state'];
        }
    }
}

interface BypassTest {
    name: string;
    description: string;
    steps: string[];
    expectedResult: string;
    exploitResult: string;
}

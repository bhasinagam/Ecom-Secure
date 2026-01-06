/**
 * Concurrent Checkout Detector
 * Detects race conditions in checkout process
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint, HttpRequest } from '../../types';

export class ConcurrentCheckoutDetector extends BaseDetector {
    private concurrentRequests = 50;
    private timeWindowMs = 100;

    constructor() {
        super('concurrent-checkout', 'race-conditions');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const checkoutEndpoints = attackSurface.endpoints.filter(
            ae => ae.endpoint.type === 'checkout' || ae.endpoint.type === 'order'
        );

        for (const attackEndpoint of checkoutEndpoints) {
            const result = await this.testConcurrentCheckout(attackEndpoint.endpoint);
            if (result.vulnerable) {
                results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private async testConcurrentCheckout(endpoint: Endpoint): Promise<DetectorResult> {
        const request: HttpRequest = {
            method: endpoint.method,
            url: endpoint.url,
            headers: { 'Content-Type': 'application/json' },
            data: Object.fromEntries(endpoint.parameters.map(p => [p.name, p.value])),
        };

        // Fire concurrent requests
        const startTime = Date.now();
        const promises = Array(this.concurrentRequests).fill(null).map(() =>
            this.sendRequest(request).catch(err => ({ status: 0, body: '', error: err }))
        );

        const responses = await Promise.allSettled(promises);
        const endTime = Date.now();

        // Analyze responses
        const successfulResponses = responses.filter(
            r => r.status === 'fulfilled' &&
                r.value.status >= 200 &&
                r.value.status < 300
        );

        // Look for multiple order IDs
        const orderIds = new Set<string>();
        for (const r of successfulResponses) {
            if (r.status === 'fulfilled') {
                const match = r.value.body.match(/"order_id":\s*"?([^",}]+)"?/);
                if (match) {
                    orderIds.add(match[1]);
                }
            }
        }

        const vulnerable = orderIds.size > 1;
        const evidence: string[] = [];

        if (vulnerable) {
            evidence.push(`${orderIds.size} unique orders created from ${this.concurrentRequests} concurrent requests`);
            evidence.push(`Order IDs: ${Array.from(orderIds).slice(0, 5).join(', ')}...`);
        }

        evidence.push(`${successfulResponses.length}/${this.concurrentRequests} requests succeeded`);
        evidence.push(`Time window: ${endTime - startTime}ms`);

        return this.createResult('concurrent_checkout', vulnerable, vulnerable ? 'HIGH' : 'LOW', {
            endpoint: endpoint.url,
            evidence,
            confidence: vulnerable ? 0.9 : 0.3,
            impact: vulnerable
                ? `Attacker can place ${orderIds.size} orders while paying for one`
                : 'No race condition detected in checkout',
        });
    }
}

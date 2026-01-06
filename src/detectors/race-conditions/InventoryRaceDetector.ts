/**
 * Inventory Race Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint, HttpRequest } from '../../types';

export class InventoryRaceDetector extends BaseDetector {
    private concurrentRequests = 20;

    constructor() {
        super('inventory-race', 'race-conditions');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const cartEndpoints = attackSurface.endpoints.filter(ae => ae.endpoint.type === 'cart');

        for (const attackEndpoint of cartEndpoints) {
            const result = await this.testInventoryRace(attackEndpoint.endpoint);
            if (result.vulnerable) {
                results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private async testInventoryRace(endpoint: Endpoint): Promise<DetectorResult> {
        // Simulate adding same item to cart concurrently
        const request: HttpRequest = {
            method: 'POST',
            url: endpoint.url,
            headers: { 'Content-Type': 'application/json' },
            data: { product_id: 'test_product', quantity: 1 },
        };

        const promises = Array(this.concurrentRequests).fill(null).map(() =>
            this.sendRequest(request).catch(() => null)
        );

        const responses = await Promise.allSettled(promises);
        const successfulAdds = responses.filter(
            r => r.status === 'fulfilled' && r.value && r.value.status >= 200 && r.value.status < 300
        );

        const evidence: string[] = [];
        evidence.push(`${successfulAdds.length} concurrent add-to-cart requests succeeded`);

        // If more requests succeeded than expected stock, there's a race condition
        const vulnerable = successfulAdds.length > 10; // Assume low stock

        return this.createResult('inventory_race', vulnerable, 'MEDIUM', {
            endpoint: endpoint.url,
            evidence,
            confidence: vulnerable ? 0.7 : 0.3,
            impact: vulnerable
                ? 'Inventory can be oversold through concurrent requests'
                : 'Inventory locking appears to be present',
        });
    }
}

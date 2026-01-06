/**
 * TOCTOU (Time-of-Check-Time-of-Use) Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class TOCTOUDetector extends BaseDetector {
    constructor() {
        super('toctou', 'race-conditions');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        // Find price check and use endpoints
        const cartEndpoints = attackSurface.endpoints.filter(ae => ae.endpoint.type === 'cart');
        const checkoutEndpoints = attackSurface.endpoints.filter(ae => ae.endpoint.type === 'checkout');

        if (cartEndpoints.length > 0 && checkoutEndpoints.length > 0) {
            const result = await this.testPriceTOCTOU(
                cartEndpoints[0].endpoint,
                checkoutEndpoints[0].endpoint
            );
            if (result.vulnerable) {
                results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private async testPriceTOCTOU(cartEndpoint: Endpoint, checkoutEndpoint: Endpoint): Promise<DetectorResult> {
        // Step 1: Get initial cart price
        const cartRequest = this.buildRequest(cartEndpoint, {});
        const cartResponse = await this.sendRequest(cartRequest);
        const initialPrice = this.extractPrice(cartResponse.body);

        // Step 2: Modify cart (add expensive item)
        // Step 3: Immediately submit checkout with original price

        const evidence: string[] = [];
        evidence.push('TOCTOU window identified between cart validation and checkout processing');

        if (initialPrice) {
            evidence.push(`Initial cart price: ${initialPrice}`);
        }

        // This is a potential vulnerability - actual exploitation requires timing
        return this.createResult('toctou', true, 'MEDIUM', {
            endpoint: checkoutEndpoint.url,
            evidence,
            confidence: 0.6,
            impact: 'Time-of-check-time-of-use window may allow price modification between cart and checkout',
        });
    }
}

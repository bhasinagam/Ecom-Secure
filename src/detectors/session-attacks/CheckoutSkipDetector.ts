/**
 * Checkout Skip Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class CheckoutSkipDetector extends BaseDetector {
    constructor() {
        super('checkout-skip', 'session-attacks');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        // Find payment/order endpoints that might be directly accessible
        const paymentEndpoints = attackSurface.endpoints.filter(
            ae => ae.endpoint.type === 'payment' || ae.endpoint.type === 'order'
        );

        for (const attackEndpoint of paymentEndpoints) {
            const result = await this.testDirectAccess(attackEndpoint.endpoint);
            if (result.vulnerable) results.push(result);
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private async testDirectAccess(endpoint: Endpoint): Promise<DetectorResult> {
        // Try to access payment endpoint directly without checkout flow
        const testResult = await this.testPayload(endpoint, '', '', '');

        const directAccessible = testResult.exploitResponse.status >= 200 &&
            testResult.exploitResponse.status < 300;

        return this.createResult('checkout_skip', directAccessible, 'HIGH', {
            endpoint: endpoint.url,
            evidence: directAccessible ? ['Payment endpoint accessible without checkout flow'] : [],
            confidence: directAccessible ? 0.8 : 0.3,
            impact: 'Checkout flow can be skipped - direct payment/order creation possible',
        });
    }
}

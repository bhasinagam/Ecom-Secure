/**
 * Shipping Abuse Detector
 */
import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class ShippingAbuseDetector extends BaseDetector {
    constructor() { super('shipping-abuse', 'business-logic'); }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        for (const ap of attackSurface.parameters) {
            if (!/shipping|delivery|freight/i.test(ap.parameter.name)) continue;
            const endpoints = attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === ap.parameter.name));
            for (const endpoint of endpoints) {
                const result = await this.testPayload(endpoint, ap.parameter.name, ap.parameter.value, 0);
                if (result.exploitable) {
                    results.push(this.createResult('shipping_abuse', true, 'MEDIUM', {
                        parameter: ap.parameter.name, endpoint: endpoint.url, exploitValue: 0,
                        evidence: result.evidence, confidence: result.confidence,
                        impact: 'Shipping cost can be set to zero'
                    }));
                }
            }
        }
        return results;
    }
    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => /shipping/i.test(p.name));
    }
}

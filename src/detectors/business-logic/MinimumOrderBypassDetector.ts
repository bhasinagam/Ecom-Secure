/**
 * Minimum Order Bypass Detector
 */
import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter } from '../../types';

export class MinimumOrderBypassDetector extends BaseDetector {
    constructor() { super('minimum-order-bypass', 'business-logic'); }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        for (const ap of attackSurface.parameters) {
            if (!/min_order|minimum|subtotal/i.test(ap.parameter.name)) continue;
            const endpoints = attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === ap.parameter.name));
            for (const endpoint of endpoints) {
                const result = await this.testPayload(endpoint, ap.parameter.name, ap.parameter.value, 0.01);
                if (result.exploitable) {
                    results.push(this.createResult('minimum_order_bypass', true, 'LOW', {
                        parameter: ap.parameter.name, endpoint: endpoint.url, exploitValue: 0.01,
                        evidence: result.evidence, confidence: result.confidence,
                        impact: 'Minimum order requirement can be bypassed'
                    }));
                }
            }
        }
        return results;
    }
    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => /minimum/i.test(p.name));
    }
}

/**
 * Return Fraud Detector
 */
import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter } from '../../types';

export class ReturnFraudDetector extends BaseDetector {
    constructor() { super('return-fraud', 'business-logic'); }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const returnEndpoints = attackSurface.endpoints.filter(ae => /return|refund/i.test(ae.endpoint.url));
        for (const ae of returnEndpoints) {
            const result = await this.testPayload(ae.endpoint, '', '', '');
            if (result.exploitable) {
                results.push(this.createResult('return_fraud', true, 'MEDIUM', {
                    endpoint: ae.endpoint.url, evidence: result.evidence,
                    confidence: result.confidence, impact: 'Return/refund endpoint accessible for manipulation'
                }));
            }
        }
        return results;
    }
    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] { return []; }
}

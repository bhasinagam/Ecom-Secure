/**
 * Referral Game Detector
 */
import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter } from '../../types';

export class ReferralGameDetector extends BaseDetector {
    constructor() { super('referral-game', 'business-logic'); }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        for (const ap of attackSurface.parameters) {
            if (!/referral|ref_code|referred_by/i.test(ap.parameter.name)) continue;
            const endpoints = attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === ap.parameter.name));
            for (const endpoint of endpoints) {
                const result = await this.testPayload(endpoint, ap.parameter.name, ap.parameter.value, 'SELF_REFERRAL');
                if (result.exploitable) {
                    results.push(this.createResult('referral_abuse', true, 'MEDIUM', {
                        parameter: ap.parameter.name, endpoint: endpoint.url,
                        evidence: result.evidence, confidence: result.confidence,
                        impact: 'Self-referral or referral manipulation possible'
                    }));
                }
            }
        }
        return results;
    }
    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => /referral/i.test(p.name));
    }
}

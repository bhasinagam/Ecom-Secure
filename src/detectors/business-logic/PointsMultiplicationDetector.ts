/**
 * Points Multiplication Detector
 */
import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter } from '../../types';

export class PointsMultiplicationDetector extends BaseDetector {
    constructor() { super('points-multiplication', 'business-logic'); }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        for (const ap of attackSurface.parameters) {
            if (!/points|rewards|credits|loyalty/i.test(ap.parameter.name)) continue;
            const endpoints = attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === ap.parameter.name));
            for (const endpoint of endpoints) {
                const result = await this.testPayload(endpoint, ap.parameter.name, ap.parameter.value, 999999);
                if (result.exploitable) {
                    results.push(this.createResult('points_multiplication', true, 'HIGH', {
                        parameter: ap.parameter.name, endpoint: endpoint.url, exploitValue: 999999,
                        evidence: result.evidence, confidence: result.confidence,
                        impact: 'Loyalty points can be manipulated'
                    }));
                }
            }
        }
        return results;
    }
    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => /points|rewards/i.test(p.name));
    }
}

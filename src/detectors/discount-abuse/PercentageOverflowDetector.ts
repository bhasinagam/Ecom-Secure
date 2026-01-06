/**
 * Percentage Overflow Detector
 * Detects discount percentages > 100%
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class PercentageOverflowDetector extends BaseDetector {
    constructor() {
        super('percentage-overflow', 'discount-abuse');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isPercentageParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const percentage of [101, 150, 200, 500]) {
                    const result = await this.testPercentage(endpoint, attackParam.parameter, percentage);
                    if (result.vulnerable) {
                        results.push(result);
                        break;
                    }
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isPercentageParam(p));
    }

    private isPercentageParam(param: Parameter): boolean {
        return /percent|percentage|discount_rate/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testPercentage(endpoint: Endpoint, param: Parameter, percentage: number): Promise<DetectorResult> {
        const testResult = await this.testPayload(endpoint, param.name, param.value, percentage);

        let negativeTotal = false;
        const exploitPrice = this.extractPrice(testResult.exploitResponse.body);
        if (exploitPrice !== null && exploitPrice < 0) {
            negativeTotal = true;
            testResult.evidence.push(`Discount > 100% resulted in negative total: ${exploitPrice}`);
        }

        return this.createResult('percentage_overflow', testResult.exploitable, negativeTotal ? 'CRITICAL' : 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: percentage,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: `Discount percentage of ${percentage}% accepted - may result in negative total or credit`,
        });
    }
}

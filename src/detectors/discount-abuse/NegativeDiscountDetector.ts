/**
 * Negative Discount Detector
 * Detects negative discount value vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class NegativeDiscountDetector extends BaseDetector {
    constructor() {
        super('negative-discount', 'discount-abuse');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isDiscountAmountParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testNegativeDiscount(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isDiscountAmountParam(p));
    }

    private isDiscountAmountParam(param: Parameter): boolean {
        return /discount_amount|discount_value|discount_percent/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testNegativeDiscount(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const testResult = await this.testPayload(endpoint, param.name, param.value, -50);

        let increased = false;
        const basePrice = this.extractPrice(testResult.baselineResponse.body);
        const exploitPrice = this.extractPrice(testResult.exploitResponse.body);

        if (basePrice && exploitPrice && exploitPrice > basePrice) {
            increased = true;
            testResult.evidence.push(`Price increased from ${basePrice} to ${exploitPrice} with negative discount`);
        }

        return this.createResult('negative_discount', testResult.exploitable && !increased, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: -50,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Negative discount value accepted - may increase cart total',
        });
    }
}

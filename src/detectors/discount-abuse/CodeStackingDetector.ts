/**
 * Code Stacking Detector
 * Detects unauthorized discount code stacking vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class CodeStackingDetector extends BaseDetector {
    constructor() {
        super('code-stacking', 'discount-abuse');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const discountParams = this.getRelevantParameters(attackSurface);

        for (const attackParam of attackSurface.parameters) {
            if (!this.isDiscountParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testCodeStacking(endpoint, attackParam.parameter);
                if (result.vulnerable) {
                    results.push(result);
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isDiscountParam(p));
    }

    private isDiscountParam(param: Parameter): boolean {
        return /discount|coupon|promo|code|voucher/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testCodeStacking(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        // Test array of codes
        const stackedCodes = ['CODE1', 'CODE2', 'CODE3'];
        const testResult = await this.testPayload(endpoint, param.name, param.value, stackedCodes);

        // Check if multiple codes were accepted
        let stackingAllowed = false;
        const responseBody = testResult.exploitResponse.body.toLowerCase();

        if (testResult.exploitResponse.status >= 200 && testResult.exploitResponse.status < 300) {
            if (responseBody.includes('applied') || responseBody.includes('success')) {
                stackingAllowed = true;
                testResult.evidence.push('Multiple discount codes appear to be accepted');
            }
        }

        return this.createResult('discount_stacking', stackingAllowed, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: stackedCodes,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Multiple discount codes can be stacked for excessive discounts',
        });
    }
}

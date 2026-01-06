/**
 * Negative Price Detector
 * Detects negative price manipulation vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';

export class NegativePriceDetector extends BaseDetector {
    constructor() {
        super('negative-price', 'price-manipulation');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isPriceParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                // Test small negative
                const smallNegResult = await this.testNegativePrice(endpoint, attackParam.parameter, -1);
                if (smallNegResult.vulnerable) {
                    results.push(smallNegResult);
                }

                // Test large negative
                const largeNegResult = await this.testNegativePrice(endpoint, attackParam.parameter, -9999);
                if (largeNegResult.vulnerable) {
                    results.push(largeNegResult);
                }

                // Test negative matching original (credit scenario)
                const originalValue = parseFloat(String(attackParam.parameter.value)) || 100;
                const creditResult = await this.testNegativePrice(
                    endpoint,
                    attackParam.parameter,
                    -originalValue
                );
                if (creditResult.vulnerable) {
                    results.push(creditResult);
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => this.isPriceParam(p));
    }

    private isPriceParam(param: Parameter): boolean {
        return /price|amount|total|cost|subtotal|fee/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testNegativePrice(
        endpoint: Endpoint,
        param: Parameter,
        negativeValue: number
    ): Promise<DetectorResult> {
        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            negativeValue
        );

        // Check if response suggests credit/refund
        let isCreditScenario = false;
        const responseBody = testResult.exploitResponse.body.toLowerCase();
        if (responseBody.includes('credit') ||
            responseBody.includes('refund') ||
            responseBody.includes('balance')) {
            isCreditScenario = true;
            testResult.evidence.push('Response suggests credit/refund scenario');
        }

        return this.createResult('negative_price', testResult.exploitable, 'CRITICAL', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: negativeValue,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: isCreditScenario
                ? `Attacker gains money ($${Math.abs(negativeValue)}) with each "purchase"`
                : 'Negative price accepted - potential for financial manipulation',
        });
    }
}

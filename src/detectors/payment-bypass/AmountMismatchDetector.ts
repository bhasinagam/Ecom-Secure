/**
 * Amount Mismatch Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class AmountMismatchDetector extends BaseDetector {
    constructor() {
        super('amount-mismatch', 'payment-bypass');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const paymentEndpoints = attackSurface.endpoints.filter(ae => ae.endpoint.type === 'payment');

        for (const attackEndpoint of paymentEndpoints) {
            const amountParams = attackEndpoint.endpoint.parameters.filter(p => /amount|total|price/i.test(p.name));

            for (const param of amountParams) {
                const result = await this.testAmountMismatch(attackEndpoint.endpoint, param);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => /amount|total/i.test(p.name));
    }

    private async testAmountMismatch(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const originalAmount = parseFloat(String(param.value)) || 100;
        const reducedAmount = 0.01;

        const testResult = await this.testPayload(endpoint, param.name, originalAmount, reducedAmount);

        return this.createResult('amount_mismatch', testResult.exploitable, 'CRITICAL', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: originalAmount,
            exploitValue: reducedAmount,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Payment amount can be reduced - pay less than cart total',
        });
    }
}

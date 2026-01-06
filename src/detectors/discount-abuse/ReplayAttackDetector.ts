/**
 * Replay Attack Detector
 * Detects single-use coupon replay vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class ReplayAttackDetector extends BaseDetector {
    constructor() {
        super('replay-attack', 'discount-abuse');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isCouponParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testReplay(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isCouponParam(p));
    }

    private isCouponParam(param: Parameter): boolean {
        return /coupon|promo|code|voucher/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testReplay(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const couponCode = param.value || 'TESTCODE';

        // First application
        const firstResult = await this.testPayload(endpoint, param.name, '', couponCode);

        // Second application (replay)
        const secondResult = await this.testPayload(endpoint, param.name, '', couponCode);

        let replaySuccessful = false;
        if (firstResult.exploitResponse.status >= 200 && firstResult.exploitResponse.status < 300 &&
            secondResult.exploitResponse.status >= 200 && secondResult.exploitResponse.status < 300) {
            replaySuccessful = true;
            firstResult.evidence.push('Coupon code accepted on multiple requests');
        }

        return this.createResult('coupon_replay', replaySuccessful, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: '',
            exploitValue: couponCode,
            evidence: firstResult.evidence,
            confidence: replaySuccessful ? 0.8 : firstResult.confidence,
            impact: 'Single-use coupon codes can be reused multiple times',
        });
    }
}

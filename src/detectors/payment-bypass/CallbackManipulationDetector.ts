/**
 * Callback Manipulation Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class CallbackManipulationDetector extends BaseDetector {
    constructor() {
        super('callback-manipulation', 'payment-bypass');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isCallbackParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testCallbackManipulation(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isCallbackParam(p));
    }

    private isCallbackParam(param: Parameter): boolean {
        return /callback|redirect|return_url|success_url|cancel_url/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testCallbackManipulation(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const maliciousUrl = 'https://attacker.com/capture-payment';
        const testResult = await this.testPayload(endpoint, param.name, param.value, maliciousUrl);

        return this.createResult('callback_manipulation', testResult.exploitable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: maliciousUrl,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Payment callback URL can be changed - redirect to attacker-controlled server',
        });
    }
}

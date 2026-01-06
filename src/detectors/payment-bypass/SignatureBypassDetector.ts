/**
 * Signature Bypass Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class SignatureBypassDetector extends BaseDetector {
    constructor() {
        super('signature-bypass', 'payment-bypass');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isSignatureParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testSignatureBypass(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isSignatureParam(p));
    }

    private isSignatureParam(param: Parameter): boolean {
        return /signature|sig|hmac|hash|checksum/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testSignatureBypass(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        // Test with empty signature
        const emptyResult = await this.testPayload(endpoint, param.name, param.value, '');
        // Test with invalid signature
        const invalidResult = await this.testPayload(endpoint, param.name, param.value, 'invalid_signature');

        const bypassable = emptyResult.exploitable || invalidResult.exploitable;

        return this.createResult('signature_bypass', bypassable, 'CRITICAL', {
            parameter: param.name,
            endpoint: endpoint.url,
            evidence: bypassable ? ['Payment signature validation can be bypassed'] : [],
            confidence: bypassable ? 0.9 : 0.3,
            impact: 'Payment signature not validated - allows tampering with payment data',
        });
    }
}

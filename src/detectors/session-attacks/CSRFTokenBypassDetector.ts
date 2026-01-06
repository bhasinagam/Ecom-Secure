/**
 * CSRF Token Bypass Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class CSRFTokenBypassDetector extends BaseDetector {
    constructor() {
        super('csrf-bypass', 'session-attacks');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isCSRFParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testCSRFBypass(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isCSRFParam(p));
    }

    private isCSRFParam(param: Parameter): boolean {
        return /csrf|token|nonce|_token/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testCSRFBypass(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        // Test with empty token
        const emptyResult = await this.testPayload(endpoint, param.name, param.value, '');
        // Test with invalid token
        const invalidResult = await this.testPayload(endpoint, param.name, param.value, 'invalid_token_12345');
        // Test without token at all
        const missingResult = await this.testPayload(endpoint, param.name, param.value, undefined);

        const bypassable = emptyResult.exploitable || invalidResult.exploitable || missingResult.exploitable;

        return this.createResult('csrf_bypass', bypassable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            evidence: bypassable ? ['CSRF token validation can be bypassed'] : [],
            confidence: bypassable ? 0.9 : 0.3,
            impact: 'CSRF protection can be bypassed - vulnerable to cross-site request forgery',
        });
    }
}

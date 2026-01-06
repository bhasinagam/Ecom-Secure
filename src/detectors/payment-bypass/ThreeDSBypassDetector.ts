/**
 * 3D Secure Bypass Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class ThreeDSBypassDetector extends BaseDetector {
    constructor() {
        super('3ds-bypass', 'payment-bypass');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.is3DSParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.test3DSBypass(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.is3DSParam(p));
    }

    private is3DSParam(param: Parameter): boolean {
        return /3ds|threeds|secure|enrolled|authenticated/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async test3DSBypass(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        // Try to skip 3DS by setting enrolled to false
        const testResult = await this.testPayload(endpoint, param.name, param.value, false);

        return this.createResult('3ds_bypass', testResult.exploitable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: false,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: '3D Secure verification can be bypassed',
        });
    }
}

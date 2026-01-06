/**
 * Boundary Test Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class BoundaryTestDetector extends BaseDetector {
    private boundaryValues = [0, 2147483647, 2147483648, -2147483648, 999999999, Number.MAX_SAFE_INTEGER];

    constructor() {
        super('boundary-test', 'quantity-manipulation');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isQuantityParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const boundary of this.boundaryValues) {
                    const result = await this.testBoundary(endpoint, attackParam.parameter, boundary);
                    if (result.vulnerable) results.push(result);
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isQuantityParam(p));
    }

    private isQuantityParam(param: Parameter): boolean {
        return /quantity|qty|count/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testBoundary(endpoint: Endpoint, param: Parameter, boundary: number): Promise<DetectorResult> {
        const testResult = await this.testPayload(endpoint, param.name, param.value, boundary);

        return this.createResult('boundary_test', testResult.exploitable, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: boundary,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: `Boundary value ${boundary} accepted - potential overflow/underflow`,
        });
    }
}

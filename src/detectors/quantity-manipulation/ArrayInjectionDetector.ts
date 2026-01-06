/**
 * Array Injection Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class ArrayInjectionDetector extends BaseDetector {
    constructor() {
        super('array-injection', 'quantity-manipulation');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testArrayInjection(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testArrayInjection(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const arrayPayload = [param.value, 0, -1];
        const testResult = await this.testPayload(endpoint, param.name, param.value, arrayPayload);

        return this.createResult('array_injection', testResult.exploitable, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: arrayPayload,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Array injection accepted - may use first/last/sum of values',
        });
    }
}

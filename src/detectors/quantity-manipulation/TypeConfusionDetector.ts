/**
 * Type Confusion Detector for Quantity
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class QuantityTypeConfusionDetector extends BaseDetector {
    private typePayloads = [
        { value: '1', type: 'string_number' },
        { value: '1.5', type: 'float_string' },
        { value: [1, 2, 3], type: 'array' },
        { value: { quantity: 1 }, type: 'object' },
        { value: null, type: 'null' },
        { value: true, type: 'boolean' },
        { value: '', type: 'empty_string' },
    ];

    constructor() {
        super('type-confusion', 'quantity-manipulation');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isQuantityParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const payload of this.typePayloads) {
                    const result = await this.testTypeConfusion(endpoint, attackParam.parameter, payload);
                    if (result.vulnerable) {
                        results.push(result);
                    }
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

    private async testTypeConfusion(endpoint: Endpoint, param: Parameter, payload: { value: unknown; type: string }): Promise<DetectorResult> {
        const testResult = await this.testPayload(endpoint, param.name, param.value, payload.value);

        return this.createResult('type_confusion', testResult.exploitable, 'MEDIUM', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: payload.value,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: `Type confusion with ${payload.type} - may bypass validation`,
        });
    }
}

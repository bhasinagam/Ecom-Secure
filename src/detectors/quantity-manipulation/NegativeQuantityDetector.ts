/**
 * Negative Quantity Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class NegativeQuantityDetector extends BaseDetector {
    constructor() {
        super('negative-quantity', 'quantity-manipulation');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isQuantityParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const negValue of [-1, -100, -999]) {
                    const result = await this.testNegativeQuantity(endpoint, attackParam.parameter, negValue);
                    if (result.vulnerable) {
                        results.push(result);
                        break;
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
        return /quantity|qty|count|num|units/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testNegativeQuantity(endpoint: Endpoint, param: Parameter, negValue: number): Promise<DetectorResult> {
        const testResult = await this.testPayload(endpoint, param.name, param.value, negValue);

        return this.createResult('negative_quantity', testResult.exploitable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: negValue,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Negative quantity accepted - may result in credit or inventory manipulation',
        });
    }
}

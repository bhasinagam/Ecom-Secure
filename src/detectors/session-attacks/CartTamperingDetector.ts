/**
 * Cart Tampering Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class CartTamperingDetector extends BaseDetector {
    constructor() {
        super('cart-tampering', 'session-attacks');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isCartParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testCartTampering(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isCartParam(p));
    }

    private isCartParam(param: Parameter): boolean {
        return /cart_id|cart|basket_id/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testCartTampering(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const tamperedCartId = 'TAMPERED_CART_ID_12345';
        const testResult = await this.testPayload(endpoint, param.name, param.value, tamperedCartId);

        return this.createResult('cart_tampering', testResult.exploitable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: tamperedCartId,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Cart ID can be tampered - may access other users\' carts',
        });
    }
}

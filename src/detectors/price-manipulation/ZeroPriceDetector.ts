/**
 * Zero Price Detector
 * Detects zero and minimal price bypass vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';

export class ZeroPriceDetector extends BaseDetector {
    constructor() {
        super('zero-price', 'price-manipulation');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const priceParams = this.getRelevantParameters(attackSurface);

        this.log('Starting zero price detection', {
            paramCount: priceParams.length,
            totalParams: attackSurface.parameters.length,
            totalEndpoints: attackSurface.endpoints.length
        });

        if (attackSurface.parameters.length === 0) {
            this.log('WARNING: No parameters in attack surface - cannot test');
            return results;
        }

        if (priceParams.length === 0) {
            this.log('WARNING: No price-related parameters found', {
                allParamNames: attackSurface.parameters.map(p => p.parameter.name)
            });
            return results;
        }

        for (const attackParam of attackSurface.parameters) {
            const isPriceRelated = this.isPriceParam(attackParam.parameter);
            this.log(`Checking parameter: ${attackParam.parameter.name}`, {
                isPriceRelated,
                value: attackParam.parameter.value
            });

            if (!isPriceRelated) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);
            this.log(`Found ${endpoints.length} endpoints with param ${attackParam.parameter.name}`, {
                endpoints: endpoints.map(e => e.url)
            });

            for (const endpoint of endpoints) {
                // Test zero price
                this.log(`Testing zero price on ${endpoint.url}`);
                const zeroResult = await this.testZeroPrice(endpoint, attackParam.parameter);
                if (zeroResult.vulnerable) {
                    this.log('VULNERABLE: Zero price accepted!');
                    results.push(zeroResult);
                }

                // Test minimal price (0.01)
                this.log(`Testing minimal price on ${endpoint.url}`);
                const minimalResult = await this.testMinimalPrice(endpoint, attackParam.parameter);
                if (minimalResult.vulnerable) {
                    this.log('VULNERABLE: Minimal price accepted!');
                    results.push(minimalResult);
                }
            }
        }

        this.log(`Detection complete`, { vulnerabilitiesFound: results.length });
        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => this.isPriceParam(p));
    }

    private isPriceParam(param: Parameter): boolean {
        return /price|amount|total|cost|subtotal/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testZeroPrice(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            0
        );

        return this.createResult('zero_price', testResult.exploitable, 'CRITICAL', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: 0,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: testResult.orderCreated
                ? 'Attacker can purchase items for free'
                : 'Zero price accepted but order creation uncertain',
        });
    }

    private async testMinimalPrice(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            0.01
        );

        return this.createResult('minimal_price', testResult.exploitable, 'CRITICAL', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: 0.01,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: testResult.orderCreated
                ? 'Attacker can purchase items for $0.01'
                : 'Minimal price accepted but order creation uncertain',
        });
    }
}

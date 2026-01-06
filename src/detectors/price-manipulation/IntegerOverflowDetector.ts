/**
 * Integer Overflow Detector
 * Detects integer overflow vulnerabilities in price calculations
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';

export class IntegerOverflowDetector extends BaseDetector {
    private overflowPayloads = [
        { value: 2147483647, name: 'MAX_INT32', description: 'Maximum 32-bit signed integer' },
        { value: 2147483648, name: 'MAX_INT32+1', description: 'Overflow 32-bit signed integer' },
        { value: 4294967295, name: 'MAX_UINT32', description: 'Maximum 32-bit unsigned integer' },
        { value: 4294967296, name: 'MAX_UINT32+1', description: 'Overflow 32-bit unsigned integer' },
        { value: -2147483648, name: 'MIN_INT32', description: 'Minimum 32-bit signed integer' },
        { value: -2147483649, name: 'MIN_INT32-1', description: 'Underflow 32-bit signed integer' },
        { value: 9007199254740992, name: 'JS_MAX_SAFE+1', description: 'Beyond JavaScript safe integer' },
        { value: Number.MAX_VALUE, name: 'MAX_FLOAT', description: 'Maximum float value' },
        { value: 99999999999999, name: 'LARGE_VALUE', description: 'Very large number' },
    ];

    constructor() {
        super('integer-overflow', 'price-manipulation');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isNumericParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const payload of this.overflowPayloads) {
                    const result = await this.testOverflow(endpoint, attackParam.parameter, payload);
                    if (result.vulnerable) {
                        results.push(result);
                    }
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => this.isNumericParam(p));
    }

    private isNumericParam(param: Parameter): boolean {
        return param.type === 'number' ||
            /price|amount|total|quantity|qty|count/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testOverflow(
        endpoint: Endpoint,
        param: Parameter,
        payload: { value: number; name: string; description: string }
    ): Promise<DetectorResult> {
        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            payload.value
        );

        // Check for overflow indicators
        let overflowDetected = false;
        const responseBody = testResult.exploitResponse.body;

        // Check if result wrapped to negative
        if (responseBody.includes('-') && !String(payload.value).includes('-')) {
            // Look for negative prices in response
            const negativePrice = /-\d+\.?\d*/g.exec(responseBody);
            if (negativePrice) {
                overflowDetected = true;
                testResult.evidence.push(`Overflow detected: value wrapped to negative (${negativePrice[0]})`);
            }
        }

        // Check if result became zero
        const responsePrice = this.extractPrice(responseBody);
        if (responsePrice === 0 && payload.value > 0) {
            overflowDetected = true;
            testResult.evidence.push('Overflow detected: value became zero');
        }

        // Check if result became very small
        if (responsePrice && responsePrice < 1 && payload.value > 1000000) {
            overflowDetected = true;
            testResult.evidence.push(`Overflow detected: large value resulted in tiny price (${responsePrice})`);
        }

        // Check for error messages indicating overflow
        const overflowErrors = ['overflow', 'too large', 'out of range', 'maximum exceeded'];
        if (overflowErrors.some(err => responseBody.toLowerCase().includes(err))) {
            testResult.evidence.push('Server reported overflow error');
        }

        return this.createResult(
            'integer_overflow',
            overflowDetected && testResult.exploitable,
            overflowDetected ? 'CRITICAL' : 'LOW',
            {
                parameter: param.name,
                endpoint: endpoint.url,
                originalValue: param.value,
                exploitValue: payload.value,
                evidence: testResult.evidence,
                confidence: overflowDetected ? 0.9 : testResult.confidence,
                impact: overflowDetected
                    ? `Integer overflow with ${payload.name} (${payload.description}) - price calculation corrupted`
                    : 'Large value accepted - potential for overflow',
            }
        );
    }
}

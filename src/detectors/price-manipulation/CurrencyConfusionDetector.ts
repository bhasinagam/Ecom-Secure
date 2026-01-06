/**
 * Currency Confusion Detector
 * Detects currency switching and confusion vulnerabilities
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';

export class CurrencyConfusionDetector extends BaseDetector {
    private currencyPayloads = [
        { code: 'USD', symbol: '$', rate: 1 },
        { code: 'EUR', symbol: '€', rate: 0.92 },
        { code: 'GBP', symbol: '£', rate: 0.79 },
        { code: 'JPY', symbol: '¥', rate: 149 },
        { code: 'INR', symbol: '₹', rate: 83 },
        { code: 'VND', symbol: '₫', rate: 24000 },
        { code: 'IDR', symbol: 'Rp', rate: 15500 },
        { code: 'KRW', symbol: '₩', rate: 1300 },
        { code: 'IRR', symbol: '﷼', rate: 42000 },
    ];

    constructor() {
        super('currency-confusion', 'price-manipulation');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isCurrencyParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                for (const currency of this.currencyPayloads) {
                    const result = await this.testCurrencySwitch(endpoint, attackParam.parameter, currency);
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
            .filter(p => this.isCurrencyParam(p));
    }

    private isCurrencyParam(param: Parameter): boolean {
        return /currency|curr|currency_code|curr_code/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testCurrencySwitch(
        endpoint: Endpoint,
        param: Parameter,
        targetCurrency: { code: string; symbol: string; rate: number }
    ): Promise<DetectorResult> {
        const originalCurrency = String(param.value);

        // Skip if same currency
        if (originalCurrency.toUpperCase() === targetCurrency.code) {
            return this.createResult('currency_confusion', false, 'NONE', {});
        }

        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            targetCurrency.code
        );

        // Check if currency was accepted
        const currencyAccepted = testResult.exploitResponse.status >= 200 &&
            testResult.exploitResponse.status < 300;

        // Check for potential exploitation
        let exploitable = false;
        const responseBody = testResult.exploitResponse.body;

        // Check if the response shows the new currency
        if (responseBody.includes(targetCurrency.code) ||
            responseBody.includes(targetCurrency.symbol)) {
            exploitable = true;
            testResult.evidence.push(`Response shows currency changed to ${targetCurrency.code}`);
        }

        // Check for unchanged price (currency confusion)
        const originalPrice = this.extractPrice(testResult.baselineResponse.body);
        const newPrice = this.extractPrice(responseBody);

        if (originalPrice && newPrice && Math.abs(originalPrice - newPrice) < 0.01) {
            exploitable = true;
            testResult.evidence.push('Price unchanged despite currency switch - confusion vulnerability');
        }

        return this.createResult('currency_confusion', exploitable && currencyAccepted, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: originalCurrency,
            exploitValue: targetCurrency.code,
            evidence: testResult.evidence,
            confidence: exploitable ? 0.85 : testResult.confidence,
            impact: targetCurrency.rate > 100
                ? `Switch to ${targetCurrency.code} (1 USD = ${targetCurrency.rate} ${targetCurrency.code}) could result in massive undercharge`
                : `Currency switched to ${targetCurrency.code} - potential for pricing confusion`,
        });
    }
}

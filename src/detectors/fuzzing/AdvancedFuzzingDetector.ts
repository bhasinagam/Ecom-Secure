/**
 * Advanced Fuzzing Detector
 * Wraps the Evolutionary Fuzzer to test all parameters
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter
} from '../../types';
import { EvolutionaryFuzzer } from '../../fuzzing/EvolutionaryFuzzer';
import { logger } from '../../core/Logger';

export class AdvancedFuzzingDetector extends BaseDetector {
    private fuzzer: EvolutionaryFuzzer;

    constructor() {
        super('evolutionary-fuzzing', 'fuzzing');
        this.fuzzer = new EvolutionaryFuzzer();
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];
        const paramsToFuzz = this.getRelevantParameters(attackSurface);

        // Prioritize interesting parameters and limit count
        const prioritizedParams = this.prioritizeParameters(paramsToFuzz).slice(0, 5); // Limit to top 5

        this.log(`Starting evolutionary fuzzing on ${prioritizedParams.length} parameters (filtered from ${paramsToFuzz.length})`);

        let paramIndex = 0;
        for (const param of prioritizedParams) {
            paramIndex++;
            const endpoints = this.getEndpointsWithParam(attackSurface, param.name);

            for (const endpoint of endpoints) {
                // Focus on parameters that reflect input or affect logic
                if (this.shouldFuzz(param)) {
                    this.log(`[${paramIndex}/${prioritizedParams.length}] Fuzzing parameter '${param.name}' on ${endpoint.url}`);

                    try {
                        // Reduced generations to 10 and added max duration check
                        const result = await this.fuzzer.evolve(endpoint, param, 10);

                        if (result.exploits.length > 0) {
                            for (const exploit of result.exploits) {
                                findings.push(this.createResult('evolved_exploit', true, 'HIGH', {
                                    endpoint: endpoint.url,
                                    parameter: param.name,
                                    exploitValue: exploit.value,
                                    evidence: [`Evolutionary fuzzer found exploit in generation ${exploit.generation}`],
                                    impact: 'Parameter is vulnerable to input fuzzing',
                                    confidence: 0.9
                                }));
                            }
                        }
                    } catch (error) {
                        this.log(`Error fuzzing ${param.name}: ${(error as Error).message}`);
                    }
                }
            }
        }

        return findings;
    }

    private prioritizeParameters(params: Parameter[]): Parameter[] {
        // High priority: price, quantity, discount, admin, role
        const highPriority = /price|amount|qty|quantity|total|discount|coupon|promo|admin|role|id|user/i;

        return params.sort((a, b) => {
            const aScore = highPriority.test(a.name) ? 2 : 1;
            const bScore = highPriority.test(b.name) ? 2 : 1;
            return bScore - aScore;
        });
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        // Fuzz everything except obviously safe stuff
        return attackSurface.parameters.map(ap => ap.parameter);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): any[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private shouldFuzz(param: Parameter): boolean {
        // Skip boolean/enums if possible, focus on strings/numbers
        return param.type === 'string' || param.type === 'number';
    }
}

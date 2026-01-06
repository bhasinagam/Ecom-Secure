/**
 * Session Fixation Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class SessionFixationDetector extends BaseDetector {
    constructor() {
        super('session-fixation', 'session-attacks');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];

        for (const attackParam of attackSurface.parameters) {
            if (!this.isSessionParam(attackParam.parameter)) continue;

            const endpoints = this.getEndpointsWithParam(attackSurface, attackParam.parameter.name);

            for (const endpoint of endpoints) {
                const result = await this.testSessionFixation(endpoint, attackParam.parameter);
                if (result.vulnerable) results.push(result);
            }
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters.map(ap => ap.parameter).filter(p => this.isSessionParam(p));
    }

    private isSessionParam(param: Parameter): boolean {
        return /session|sid|session_id/i.test(param.name);
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints.map(ae => ae.endpoint).filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testSessionFixation(endpoint: Endpoint, param: Parameter): Promise<DetectorResult> {
        const fixatedSession = 'ATTACKER_CONTROLLED_SESSION_ID';
        const testResult = await this.testPayload(endpoint, param.name, param.value, fixatedSession);

        return this.createResult('session_fixation', testResult.exploitable, 'HIGH', {
            parameter: param.name,
            endpoint: endpoint.url,
            originalValue: param.value,
            exploitValue: fixatedSession,
            evidence: testResult.evidence,
            confidence: testResult.confidence,
            impact: 'Session ID can be set by attacker - session fixation possible',
        });
    }
}

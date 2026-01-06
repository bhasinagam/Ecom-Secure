/**
 * Webhook Replay Detector
 */

import { BaseDetector } from '../base/BaseDetector';
import { DetectorResult, AttackSurface, PlatformDetectionResult, Parameter, Endpoint } from '../../types';

export class WebhookReplayDetector extends BaseDetector {
    constructor() {
        super('webhook-replay', 'payment-bypass');
    }

    async test(attackSurface: AttackSurface, platform: PlatformDetectionResult): Promise<DetectorResult[]> {
        const results: DetectorResult[] = [];
        const webhookEndpoints = attackSurface.endpoints.filter(
            ae => ae.endpoint.url.includes('webhook') || ae.endpoint.url.includes('callback')
        );

        for (const attackEndpoint of webhookEndpoints) {
            const result = await this.testWebhookReplay(attackEndpoint.endpoint);
            if (result.vulnerable) results.push(result);
        }

        return results;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private async testWebhookReplay(endpoint: Endpoint): Promise<DetectorResult> {
        // Send same webhook twice
        const firstResult = await this.testPayload(endpoint, '', '', '');
        const secondResult = await this.testPayload(endpoint, '', '', '');

        const replayable = firstResult.exploitResponse.status >= 200 &&
            secondResult.exploitResponse.status >= 200;

        return this.createResult('webhook_replay', replayable, 'HIGH', {
            endpoint: endpoint.url,
            evidence: replayable ? ['Webhook can be replayed multiple times'] : [],
            confidence: replayable ? 0.7 : 0.3,
            impact: 'Payment webhook can be replayed - may credit account multiple times',
        });
    }
}

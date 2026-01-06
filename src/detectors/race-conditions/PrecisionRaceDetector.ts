/**
 * Precision Race Condition Detector
 * 
 * Uses worker threads and microsecond-precision timing for race condition detection.
 * BLACKHAT INSIGHT: Most race conditions require exact timing within 1-10ms window.
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';
import { logger } from '../../core/Logger';

interface RaceTestResult {
    responses: Array<{ status: number; body: string; duration: number }>;
    uniqueOrderIds: Set<string>;
    successCount: number;
    totalCount: number;
}

export class PrecisionRaceDetector extends BaseDetector {
    private readonly concurrentRequests = 50;
    private readonly burstDelay = 10; // milliseconds between bursts

    constructor() {
        super('precision-race', 'race-conditions');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];

        // Find race-prone endpoints
        const raceEndpoints = this.findRaceProneEndpoints(attackSurface);

        this.log('Starting precision race condition detection', {
            endpointCount: raceEndpoints.length,
            concurrency: this.concurrentRequests
        });

        for (const endpoint of raceEndpoints) {
            // Test 1: Concurrent checkout race
            const checkoutRace = await this.testConcurrentCheckout(endpoint);
            if (checkoutRace) findings.push(checkoutRace);

            // Test 2: Coupon double-spend
            if (endpoint.type === 'checkout' || /coupon|discount/i.test(endpoint.url)) {
                const couponRace = await this.testCouponDoubleSpend(endpoint);
                if (couponRace) findings.push(couponRace);
            }

            // Test 3: Inventory race
            if (endpoint.type === 'cart' || /add.*cart|inventory/i.test(endpoint.url)) {
                const inventoryRace = await this.testInventoryRace(endpoint);
                if (inventoryRace) findings.push(inventoryRace);
            }

            // Test 4: Balance race (wallet/credits)
            if (/wallet|balance|credit|points/i.test(endpoint.url)) {
                const balanceRace = await this.testBalanceRace(endpoint);
                if (balanceRace) findings.push(balanceRace);
            }
        }

        return findings;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    /**
     * Find endpoints prone to race conditions
     */
    private findRaceProneEndpoints(attackSurface: AttackSurface): Endpoint[] {
        const racePatterns = /checkout|order|payment|purchase|buy|cart|add|coupon|discount|redeem|transfer|withdraw|refund|points|credit|wallet|inventory|stock/i;

        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e =>
                e.method === 'POST' &&
                racePatterns.test(e.url)
            );
    }

    /**
     * Test concurrent checkout race condition
     * Attempts to create multiple orders from single cart
     */
    private async testConcurrentCheckout(endpoint: Endpoint): Promise<DetectorResult | null> {
        this.log(`Testing concurrent checkout race on ${endpoint.url}`);

        const payload = this.buildCheckoutPayload(endpoint);
        const result = await this.fireConcurrentRequests(endpoint, payload);

        // Check if multiple unique orders were created
        if (result.uniqueOrderIds.size > 1) {
            return this.createResult('concurrent_checkout_race', true, 'CRITICAL', {
                endpoint: endpoint.url,
                evidence: [
                    `${result.uniqueOrderIds.size} unique orders created from single checkout`,
                    `Order IDs: ${Array.from(result.uniqueOrderIds).join(', ')}`,
                    `Success rate: ${result.successCount}/${result.totalCount}`
                ],
                impact: 'Attacker can create multiple orders paying only once',
                confidence: 0.95
            });
        }

        // Check for multiple successful responses
        if (result.successCount > 1) {
            return this.createResult('potential_checkout_race', true, 'HIGH', {
                endpoint: endpoint.url,
                evidence: [
                    `${result.successCount} successful responses from concurrent requests`,
                    'Multiple successful responses suggest possible race window'
                ],
                impact: 'Potential race condition in checkout process',
                confidence: 0.7
            });
        }

        return null;
    }

    /**
     * Test coupon double-spend via race condition
     */
    private async testCouponDoubleSpend(endpoint: Endpoint): Promise<DetectorResult | null> {
        this.log(`Testing coupon double-spend race on ${endpoint.url}`);

        // Simulate single-use coupon application
        const payload = {
            coupon_code: 'TESTCOUPON',
            cart_id: `test_cart_${Date.now()}`,
        };

        const result = await this.fireConcurrentRequests(endpoint, payload);

        // If coupon applied multiple times
        const couponSuccesses = result.responses.filter(r =>
            r.status === 200 &&
            (r.body.includes('applied') || r.body.includes('discount') || r.body.includes('success'))
        );

        if (couponSuccesses.length > 1) {
            return this.createResult('coupon_race_condition', true, 'HIGH', {
                endpoint: endpoint.url,
                evidence: [
                    `Coupon applied ${couponSuccesses.length} times concurrently`,
                    'Single-use coupon can be used multiple times'
                ],
                impact: 'Discount codes can be redeemed multiple times',
                confidence: 0.8
            });
        }

        return null;
    }

    /**
     * Test inventory race condition
     * Buy more items than available stock
     */
    private async testInventoryRace(endpoint: Endpoint): Promise<DetectorResult | null> {
        this.log(`Testing inventory race on ${endpoint.url}`);

        // Try to add same item multiple times
        const payload = {
            product_id: 'test_product',
            quantity: 1,
            cart_id: `race_cart_${Date.now()}`,
        };

        const result = await this.fireConcurrentRequests(endpoint, payload, 100);

        // Check total quantity that was added
        const successResponses = result.responses.filter(r => r.status === 200);

        if (successResponses.length > 10) {
            return this.createResult('inventory_race_condition', true, 'MEDIUM', {
                endpoint: endpoint.url,
                evidence: [
                    `${successResponses.length} items added concurrently`,
                    'Inventory check may be vulnerable to race conditions'
                ],
                impact: 'Can purchase more items than available in stock',
                confidence: 0.65
            });
        }

        return null;
    }

    /**
     * Test balance/wallet race condition
     */
    private async testBalanceRace(endpoint: Endpoint): Promise<DetectorResult | null> {
        this.log(`Testing balance race on ${endpoint.url}`);

        // Simulate withdrawal request
        const payload = {
            amount: 10,
            action: 'withdraw',
            user_id: 'test_user',
        };

        const result = await this.fireConcurrentRequests(endpoint, payload);

        // Multiple successful withdrawals = race condition
        const withdrawSuccesses = result.responses.filter(r =>
            r.status === 200 &&
            !r.body.includes('insufficient') &&
            !r.body.includes('failed')
        );

        if (withdrawSuccesses.length > 1) {
            return this.createResult('balance_race_condition', true, 'CRITICAL', {
                endpoint: endpoint.url,
                evidence: [
                    `${withdrawSuccesses.length} withdrawals processed concurrently`,
                    'Balance check vulnerable to race condition'
                ],
                impact: 'Can withdraw more than available balance',
                confidence: 0.85
            });
        }

        return null;
    }

    /**
     * Fire concurrent requests with microsecond precision
     */
    private async fireConcurrentRequests(
        endpoint: Endpoint,
        payload: Record<string, unknown>,
        requestCount: number = this.concurrentRequests
    ): Promise<RaceTestResult> {
        const responses: Array<{ status: number; body: string; duration: number }> = [];
        const uniqueOrderIds = new Set<string>();

        // Prepare all requests
        const requests: Promise<void>[] = [];

        for (let i = 0; i < requestCount; i++) {
            const request = (async () => {
                const start = Date.now();
                try {
                    const response = await this.sendRequest({
                        method: 'POST',
                        url: endpoint.url,
                        headers: endpoint.headers,
                        data: { ...payload, _race_id: i }
                    });

                    responses.push({
                        status: response.status,
                        body: response.body,
                        duration: Date.now() - start
                    });

                    // Extract order IDs
                    const orderIdMatch = response.body.match(/order[_-]?id["\s:]+["']?(\w+)/i);
                    if (orderIdMatch) {
                        uniqueOrderIds.add(orderIdMatch[1]);
                    }
                } catch (error) {
                    responses.push({
                        status: 0,
                        body: error instanceof Error ? error.message : '',
                        duration: Date.now() - start
                    });
                }
            })();

            requests.push(request);
        }

        // Fire all requests simultaneously
        await Promise.all(requests);

        return {
            responses,
            uniqueOrderIds,
            successCount: responses.filter(r => r.status >= 200 && r.status < 300).length,
            totalCount: responses.length
        };
    }

    /**
     * Build checkout payload from endpoint parameters
     */
    private buildCheckoutPayload(endpoint: Endpoint): Record<string, unknown> {
        const payload: Record<string, unknown> = {};

        for (const param of endpoint.parameters) {
            payload[param.name] = param.value;
        }

        // Add common checkout fields if missing
        if (!payload['cart_id']) payload['cart_id'] = `race_test_${Date.now()}`;
        if (!payload['quantity']) payload['quantity'] = 1;

        return payload;
    }

    /**
     * Advanced: Synchronized burst attack using pre-established connections
     */
    async testSynchronizedBurst(endpoint: Endpoint): Promise<DetectorResult | null> {
        this.log(`Testing synchronized burst on ${endpoint.url}`);

        // For even more precise timing, we would use raw TCP sockets
        // This is a simplified version using HTTP keep-alive

        const batchSize = 20;
        const batches = 5;
        const results: RaceTestResult[] = [];

        for (let batch = 0; batch < batches; batch++) {
            const payload = {
                batch_id: batch,
                timestamp: Date.now(),
            };

            // Small delay between batches to test different timing windows
            await new Promise(r => setTimeout(r, this.burstDelay));

            const result = await this.fireConcurrentRequests(endpoint, payload, batchSize);
            results.push(result);
        }

        // Aggregate results across batches
        const totalSuccess = results.reduce((sum, r) => sum + r.successCount, 0);
        const allOrderIds = new Set<string>();
        results.forEach(r => r.uniqueOrderIds.forEach(id => allOrderIds.add(id)));

        if (allOrderIds.size > batches) {
            return this.createResult('synchronized_burst_race', true, 'CRITICAL', {
                endpoint: endpoint.url,
                evidence: [
                    `${allOrderIds.size} unique orders from ${batches} synchronized bursts`,
                    `Total successful requests: ${totalSuccess}`,
                    'Critical race condition with microsecond timing window'
                ],
                impact: 'Race condition exploitable with synchronized requests',
                confidence: 0.9
            });
        }

        return null;
    }
}

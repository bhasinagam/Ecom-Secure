/**
 * Workflow Contradiction Detector
 * LLM-Powered Business Logic Vulnerability Detection
 * 
 * BLACKHAT INSIGHT: Business logic bugs are the hardest to find.
 * Uses AI to understand workflow, then tests contradictions.
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint,
    HttpResponse // NEW
} from '../../types';
import { LLMClient } from '../../agent/LLMClient';
import { logger } from '../../core/Logger';

interface BusinessRule {
    type: string;
    description: string;
    threshold?: number;
    code?: string;
    condition: string;
    endpoint?: string;
}

interface ContradictionTest {
    name: string;
    description: string;
    setup: Record<string, unknown>;
    steps?: Array<{ action: string; params: Record<string, unknown> }>;
    expectedBehavior: string;
    exploitBehavior: string;
    endpoint?: Endpoint;
}

export class WorkflowContradictionDetector extends BaseDetector {
    private llmClient: LLMClient;

    constructor() {
        super('workflow-contradiction', 'business-logic');
        this.llmClient = new LLMClient({
            apiKey: process.env.OPENROUTER_API_KEY || '',
            model: process.env.LLM_MODEL || 'google/gemini-2.0-flash-exp:free'
        });
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];

        this.log('Starting workflow contradiction detection');

        // Step 1: Extract business rules using LLM
        const businessRules = await this.extractBusinessRules(attackSurface);
        this.log(`Extracted ${businessRules.length} business rules`);

        // Step 2: Generate contradiction test cases
        const contradictions = this.generateContradictions(businessRules, attackSurface);
        this.log(`Generated ${contradictions.length} contradiction tests`);

        // Step 3: Test each contradiction
        for (const test of contradictions) {
            const result = await this.testContradiction(test);
            if (result) findings.push(result);
        }

        // Step 4: Test refund amount manipulation
        const refundResult = await this.testRefundManipulation(attackSurface);
        if (refundResult) findings.push(refundResult);

        // Step 5: Test discount persistence
        const discountResult = await this.testDiscountPersistence(attackSurface);
        if (discountResult) findings.push(discountResult);

        return findings;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    /**
     * Extract business rules from attack surface using LLM
     */
    private async extractBusinessRules(attackSurface: AttackSurface): Promise<BusinessRule[]> {
        if (!this.llmClient.isConfigured()) {
            this.log('LLM not configured, using heuristic rule extraction');
            return this.extractRulesHeuristically(attackSurface);
        }

        try {
            const endpointSummary = attackSurface.endpoints.slice(0, 10).map(ae => ({
                url: ae.endpoint.url,
                method: ae.endpoint.method,
                type: ae.endpoint.type,
                params: ae.endpoint.parameters.map(p => p.name)
            }));

            const paramSummary = attackSurface.parameters.slice(0, 20).map(ap => ({
                name: ap.parameter.name,
                type: ap.parameter.type,
                value: String(ap.parameter.value).substring(0, 50)
            }));

            const prompt = `Analyze this e-commerce checkout flow and extract business rules:

Endpoints:
${JSON.stringify(endpointSummary, null, 2)}

Parameters:
${JSON.stringify(paramSummary, null, 2)}

Extract business rules in this JSON format:
[
  {
    "type": "free_shipping_threshold",
    "description": "Free shipping above $50",
    "threshold": 50,
    "condition": "cart_total > 50 => shipping = 0"
  },
  {
    "type": "discount_limit",
    "description": "Maximum 50% discount",
    "threshold": 50,
    "condition": "discount_percent <= 50"
  }
]

Return ONLY the JSON array, no explanation.`;

            const response = await this.llmClient.analyze(prompt);

            // Parse JSON from response
            const jsonMatch = response.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
        } catch (error) {
            this.log('LLM rule extraction failed, using heuristics');
        }

        return this.extractRulesHeuristically(attackSurface);
    }

    /**
     * Extract rules using heuristics (fallback without LLM)
     */
    private extractRulesHeuristically(attackSurface: AttackSurface): BusinessRule[] {
        const rules: BusinessRule[] = [];

        // Check for shipping-related parameters
        const hasShipping = attackSurface.parameters.some(p =>
            /shipping|delivery/i.test(p.parameter.name)
        );
        if (hasShipping) {
            rules.push({
                type: 'shipping_cost',
                description: 'Shipping cost calculation',
                condition: 'shipping_cost >= 0'
            });
        }

        // Check for discount-related parameters
        const hasDiscount = attackSurface.parameters.some(p =>
            /discount|coupon|promo/i.test(p.parameter.name)
        );
        if (hasDiscount) {
            rules.push({
                type: 'discount_limit',
                description: 'Discount must be positive and limited',
                threshold: 100,
                condition: '0 <= discount_percent <= 100'
            });
        }

        // Check for quantity parameters
        const hasQuantity = attackSurface.parameters.some(p =>
            /quantity|qty/i.test(p.parameter.name)
        );
        if (hasQuantity) {
            rules.push({
                type: 'quantity_limit',
                description: 'Quantity must be positive',
                condition: 'quantity > 0'
            });
        }

        // Check for minimum order
        const hasMinOrder = attackSurface.endpoints.some(ae =>
            /minimum|min.*order/i.test(ae.endpoint.url)
        );
        if (hasMinOrder) {
            rules.push({
                type: 'minimum_order',
                description: 'Minimum order requirement',
                threshold: 10,
                condition: 'cart_total >= minimum_order'
            });
        }

        return rules;
    }

    /**
     * Generate contradiction test cases from business rules
     */
    private generateContradictions(
        rules: BusinessRule[],
        attackSurface: AttackSurface
    ): ContradictionTest[] {
        const tests: ContradictionTest[] = [];

        for (const rule of rules) {
            switch (rule.type) {
                case 'free_shipping_threshold':
                    tests.push({
                        name: 'free_shipping_bypass',
                        description: `Bypass: ${rule.description}`,
                        setup: {
                            cart_total: (rule.threshold || 50) - 0.01,
                            shipping_cost: 0
                        },
                        expectedBehavior: 'Server should recalculate shipping based on cart total',
                        exploitBehavior: 'Server accepts $0 shipping below threshold',
                        endpoint: this.findEndpointByType(attackSurface, 'checkout')
                    });
                    break;

                case 'discount_limit':
                    tests.push({
                        name: 'discount_exceeds_limit',
                        description: `Bypass: ${rule.description}`,
                        setup: {
                            discount_percent: (rule.threshold || 50) + 50,
                            discount_amount: 999999
                        },
                        expectedBehavior: 'Server should cap discount at maximum',
                        exploitBehavior: 'Server accepts discount exceeding limit',
                        endpoint: this.findEndpointByType(attackSurface, 'checkout')
                    });
                    break;

                case 'minimum_order':
                    tests.push({
                        name: 'minimum_order_bypass',
                        description: `Bypass: ${rule.description}`,
                        setup: {
                            cart_total: (rule.threshold || 10) - 5,
                            bypass_minimum: true
                        },
                        expectedBehavior: 'Server should reject orders below minimum',
                        exploitBehavior: 'Order proceeds despite being below minimum',
                        endpoint: this.findEndpointByType(attackSurface, 'checkout')
                    });
                    break;

                case 'quantity_limit':
                    tests.push({
                        name: 'negative_quantity_exploit',
                        description: 'Negative quantity to reduce total',
                        setup: {
                            quantity: -1
                        },
                        expectedBehavior: 'Server should reject negative quantity',
                        exploitBehavior: 'Negative quantity reduces order total',
                        endpoint: this.findEndpointByType(attackSurface, 'cart')
                    });
                    break;
            }
        }

        // Always test discount persistence
        tests.push({
            name: 'discount_persistence',
            description: 'Apply discount, modify cart, check if discount persists incorrectly',
            setup: {}, // Required by interface
            steps: [
                { action: 'add_items', params: { value: 100 } },
                { action: 'apply_discount', params: { code: 'TEST10' } },
                { action: 'remove_items', params: { value: 50 } },
                { action: 'checkout', params: {} }
            ],
            expectedBehavior: 'Discount recalculated after cart modification',
            exploitBehavior: 'Original discount amount persists',
            endpoint: this.findEndpointByType(attackSurface, 'checkout')
        });

        return tests;
    }

    /**
     * Find endpoint by type
     */
    private findEndpointByType(
        attackSurface: AttackSurface,
        type: string
    ): Endpoint | undefined {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .find(e => e.type === type || e.url.toLowerCase().includes(type));
    }

    /**
     * Test a contradiction scenario
     */
    private async testContradiction(test: ContradictionTest): Promise<DetectorResult | null> {
        if (!test.endpoint) {
            this.log(`No endpoint found for test: ${test.name}`);
            return null;
        }

        this.log(`Testing contradiction: ${test.name}`);

        try {
            // Send request with contradictory values
            const response = await this.sendRequest({
                method: test.endpoint.method,
                url: test.endpoint.url,
                headers: test.endpoint.headers,
                data: test.setup
            });

            // Check if exploit behavior occurred
            const isVulnerable = this.detectExploitBehavior(response, test);

            if (isVulnerable) {
                return this.createResult('workflow_contradiction', true, 'HIGH', {
                    endpoint: test.endpoint.url,
                    evidence: [
                        test.description,
                        `Expected: ${test.expectedBehavior}`,
                        `Got: ${test.exploitBehavior}`
                    ],
                    impact: `Business logic bypass: ${test.name}`,
                    confidence: 0.75
                });
            }
        } catch (error) {
            this.log(`Contradiction test failed: ${test.name}`);
        }

        return null;
    }

    /**
     * Detect if exploit behavior occurred
     */
    private detectExploitBehavior(
        response: HttpResponse,
        test: ContradictionTest
    ): boolean {
        // Successful response with contradictory values = potential issue
        if (response.status !== 200) return false;

        const body = response.body.toLowerCase();

        // Check for success indicators
        if (body.includes('success') || body.includes('confirmed') || body.includes('order')) {
            // Additional checks based on test type
            switch (test.name) {
                case 'free_shipping_bypass':
                    return body.includes('shipping') && body.includes('0');
                case 'discount_exceeds_limit':
                    return body.includes('discount');
                case 'minimum_order_bypass':
                    return !body.includes('minimum') && !body.includes('error');
                default:
                    return true;
            }
        }

        return false;
    }

    /**
     * Test refund amount manipulation
     * Buy with discount, return for full amount
     */
    private async testRefundManipulation(
        attackSurface: AttackSurface
    ): Promise<DetectorResult | null> {
        const refundEndpoint = attackSurface.endpoints
            .map(ae => ae.endpoint)
            .find(e => /refund|return/i.test(e.url));

        if (!refundEndpoint) return null;

        this.log('Testing refund amount manipulation');

        // Simulate refund request with inflated amount
        try {
            const response = await this.sendRequest({
                method: 'POST',
                url: refundEndpoint.url,
                headers: refundEndpoint.headers,
                data: {
                    order_id: 'test_order',
                    refund_amount: 100,  // Original price
                    paid_amount: 90      // What was actually paid (after discount)
                }
            });

            if (response.status === 200 &&
                response.body.includes('refund') &&
                !response.body.includes('error')) {
                return this.createResult('refund_manipulation', true, 'HIGH', {
                    endpoint: refundEndpoint.url,
                    evidence: [
                        'Refund amount may not consider original discount',
                        'Potential to receive more than paid'
                    ],
                    impact: 'Attacker can profit from refund/return cycle',
                    confidence: 0.65
                });
            }
        } catch {
            // Test failed
        }

        return null;
    }

    /**
     * Test discount persistence after cart modification
     */
    private async testDiscountPersistence(
        attackSurface: AttackSurface
    ): Promise<DetectorResult | null> {
        const cartEndpoint = this.findEndpointByType(attackSurface, 'cart');
        const checkoutEndpoint = this.findEndpointByType(attackSurface, 'checkout');

        if (!cartEndpoint || !checkoutEndpoint) return null;

        this.log('Testing discount persistence');

        try {
            // Step 1: Apply discount
            await this.sendRequest({
                method: 'POST',
                url: cartEndpoint.url,
                headers: cartEndpoint.headers,
                data: {
                    action: 'apply_coupon',
                    coupon_code: 'TEST',
                    cart_total: 100
                }
            });

            // Step 2: Modify cart (reduce items)
            await this.sendRequest({
                method: 'POST',
                url: cartEndpoint.url,
                headers: cartEndpoint.headers,
                data: {
                    action: 'update_cart',
                    cart_total: 30  // Reduced below discount threshold
                }
            });

            // Step 3: Check if discount still applies incorrectly
            const checkoutResponse = await this.sendRequest({
                method: 'POST',
                url: checkoutEndpoint.url,
                headers: checkoutEndpoint.headers,
                data: {
                    cart_id: 'test',
                    expected_discount: 0  // Should be 0 after cart reduction
                }
            });

            if (checkoutResponse.status === 200 &&
                checkoutResponse.body.includes('discount')) {
                return this.createResult('discount_persistence', true, 'MEDIUM', {
                    endpoint: checkoutEndpoint.url,
                    evidence: [
                        'Discount persists after reducing cart below threshold',
                        'Cart recalculation may not update discounts'
                    ],
                    impact: 'Get discounts on orders that dont qualify',
                    confidence: 0.6
                });
            }
        } catch {
            // Test failed
        }

        return null;
    }
}

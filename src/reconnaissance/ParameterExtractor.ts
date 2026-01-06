/**
 * Parameter Extractor
 * Extracts and analyzes form fields and API parameters
 */

import { CheckoutFlow, Parameter, ParameterType, ParameterLocation } from '../types';
import { logger } from '../core/Logger';

export interface ExtractedParameter extends Parameter {
    endpoint: string;
    confidence: number;
    possibleAttacks: string[];
}

export class ParameterExtractor {
    /**
     * Extract all parameters from checkout flows
     */
    async extractAll(flows: CheckoutFlow[]): Promise<ExtractedParameter[]> {
        const parameters: ExtractedParameter[] = [];
        const seen = new Set<string>();

        for (const flow of flows) {
            // Extract from endpoints
            for (const endpoint of flow.endpoints) {
                for (const param of endpoint.parameters) {
                    const key = `${endpoint.url}:${param.name}`;
                    if (!seen.has(key)) {
                        seen.add(key);
                        parameters.push(this.enrichParameter(param, endpoint.url));
                    }
                }
            }

            // Extract from flow parameters
            for (const [name, info] of Object.entries(flow.parameters)) {
                const key = `${info.endpoint}:${name}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    parameters.push(this.enrichParameter({
                        name,
                        value: info.value,
                        type: info.type as ParameterType,
                        location: 'body',
                    }, info.endpoint));
                }
            }
        }

        logger.info(`Extracted ${parameters.length} unique parameters`);
        return parameters;
    }

    /**
     * Enrich parameter with attack analysis
     */
    private enrichParameter(param: Parameter, endpoint: string): ExtractedParameter {
        const possibleAttacks = this.analyzePossibleAttacks(param);
        const confidence = this.calculateConfidence(param, possibleAttacks);

        return {
            ...param,
            endpoint,
            confidence,
            possibleAttacks,
        };
    }

    /**
     * Analyze possible attacks for a parameter
     */
    private analyzePossibleAttacks(param: Parameter): string[] {
        const attacks: string[] = [];
        const nameLower = param.name.toLowerCase();

        // Price-related parameters
        if (/price|amount|total|cost|subtotal|fee/.test(nameLower)) {
            attacks.push('zero_price', 'negative_price', 'integer_overflow', 'type_confusion');
        }

        // Quantity parameters
        if (/quantity|qty|count|units|num/.test(nameLower)) {
            attacks.push('negative_quantity', 'integer_overflow', 'type_confusion', 'boundary_testing');
        }

        // Discount parameters
        if (/discount|coupon|promo|code|voucher/.test(nameLower)) {
            attacks.push('discount_stacking', 'negative_discount', 'percentage_overflow', 'replay_attack');
        }

        // Currency parameters
        if (/currency|curr/.test(nameLower)) {
            attacks.push('currency_confusion', 'type_confusion');
        }

        // ID parameters
        if (/id|cart|session|user|order/.test(nameLower)) {
            attacks.push('idor', 'session_manipulation', 'cart_tampering');
        }

        // Payment parameters
        if (/payment|card|token|method|gateway/.test(nameLower)) {
            attacks.push('payment_bypass', 'callback_manipulation', 'signature_bypass');
        }

        // Email/contact parameters
        if (/email|mail/.test(nameLower)) {
            attacks.push('email_injection', 'sqli');
        }

        // Address parameters (potential for injection)
        if (/address|street|city|zip|postal/.test(nameLower)) {
            attacks.push('sqli', 'xss', 'formula_injection');
        }

        // Any text field
        if (param.type === 'string') {
            attacks.push('xss', 'formula_injection');
        }

        return [...new Set(attacks)];
    }

    /**
     * Calculate confidence score for parameter exploitation potential
     */
    private calculateConfidence(param: Parameter, attacks: string[]): number {
        let score = 0;
        const nameLower = param.name.toLowerCase();

        // High-value parameter names
        if (/price|amount|total/.test(nameLower)) score += 0.3;
        if (/quantity|qty/.test(nameLower)) score += 0.25;
        if (/discount|coupon/.test(nameLower)) score += 0.25;

        // Type-based scoring
        if (param.type === 'number') score += 0.1;
        if (param.type === 'string' && attacks.includes('sqli')) score += 0.1;

        // Attack vector count
        score += attacks.length * 0.05;

        // Required parameters are more critical
        if (param.required) score += 0.1;

        return Math.min(score, 1.0);
    }

    /**
     * Categorize parameters by attack type
     */
    categorizeByAttackType(parameters: ExtractedParameter[]): Record<string, ExtractedParameter[]> {
        const categories: Record<string, ExtractedParameter[]> = {
            price_manipulation: [],
            quantity_manipulation: [],
            discount_abuse: [],
            session_attacks: [],
            payment_bypass: [],
            injection: [],
            other: [],
        };

        for (const param of parameters) {
            let categorized = false;

            if (param.possibleAttacks.some(a => a.includes('price'))) {
                categories.price_manipulation.push(param);
                categorized = true;
            }
            if (param.possibleAttacks.some(a => a.includes('quantity'))) {
                categories.quantity_manipulation.push(param);
                categorized = true;
            }
            if (param.possibleAttacks.some(a => a.includes('discount'))) {
                categories.discount_abuse.push(param);
                categorized = true;
            }
            if (param.possibleAttacks.some(a => a.includes('session') || a.includes('cart'))) {
                categories.session_attacks.push(param);
                categorized = true;
            }
            if (param.possibleAttacks.some(a => a.includes('payment'))) {
                categories.payment_bypass.push(param);
                categorized = true;
            }
            if (param.possibleAttacks.some(a => ['sqli', 'xss', 'formula_injection'].includes(a))) {
                categories.injection.push(param);
                categorized = true;
            }
            if (!categorized) {
                categories.other.push(param);
            }
        }

        return categories;
    }

    /**
     * Get high-priority parameters for scanning
     */
    getHighPriorityParameters(parameters: ExtractedParameter[]): ExtractedParameter[] {
        return parameters
            .filter(p => p.confidence >= 0.5)
            .sort((a, b) => b.confidence - a.confidence);
    }

    /**
     * Detect validation from server responses
     */
    inferValidation(param: Parameter, responses: Array<{ payload: unknown; status: number; body: string }>): string | undefined {
        const patterns: Array<{ pattern: RegExp; validation: string }> = [
            { pattern: /must be (a )?number/i, validation: 'numeric_only' },
            { pattern: /must be positive/i, validation: 'positive_only' },
            { pattern: /must be (greater|more) than/i, validation: 'minimum_value' },
            { pattern: /must be (less|fewer) than/i, validation: 'maximum_value' },
            { pattern: /invalid (type|format)/i, validation: 'type_validation' },
            { pattern: /required/i, validation: 'required_field' },
            { pattern: /(not|in)valid email/i, validation: 'email_format' },
            { pattern: /csrf|token/i, validation: 'csrf_protection' },
        ];

        for (const response of responses) {
            if (response.status >= 400) {
                for (const { pattern, validation } of patterns) {
                    if (pattern.test(response.body)) {
                        return validation;
                    }
                }
            }
        }

        return undefined;
    }
}

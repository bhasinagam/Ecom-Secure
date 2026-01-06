/**
 * Fuzzing Engine - Intelligent payload generation
 */

import { LLMClient } from '../agent/LLMClient';
import { Parameter, PlatformDetectionResult } from '../types';
import { logger } from '../core/Logger';

export interface FuzzPayload {
    value: unknown;
    type: string;
    rationale: string;
    likelihood: number;
}

export class FuzzingEngine {
    private llmClient: LLMClient;
    private staticPayloads: Map<string, FuzzPayload[]> = new Map();

    constructor() {
        this.llmClient = new LLMClient();
        this.initializeStaticPayloads();
    }

    /**
     * Initialize static payload library
     */
    private initializeStaticPayloads(): void {
        // Price payloads
        this.staticPayloads.set('price', [
            { value: 0, type: 'zero', rationale: 'Zero price bypass', likelihood: 0.8 },
            { value: -1, type: 'negative', rationale: 'Negative price', likelihood: 0.7 },
            { value: -9999, type: 'large_negative', rationale: 'Large credit', likelihood: 0.6 },
            { value: 0.001, type: 'minimal', rationale: 'Minimal price', likelihood: 0.7 },
            { value: 0.01, type: 'penny', rationale: 'One cent', likelihood: 0.8 },
            { value: '0', type: 'string_zero', rationale: 'Type confusion', likelihood: 0.5 },
            { value: null, type: 'null', rationale: 'Null handling', likelihood: 0.4 },
            { value: 2147483647, type: 'max_int', rationale: 'Integer overflow', likelihood: 0.5 },
            { value: Number.MAX_SAFE_INTEGER + 1, type: 'js_overflow', rationale: 'JS safe integer overflow', likelihood: 0.4 },
        ]);

        // Quantity payloads
        this.staticPayloads.set('quantity', [
            { value: -1, type: 'negative', rationale: 'Negative quantity', likelihood: 0.8 },
            { value: 0, type: 'zero', rationale: 'Zero quantity', likelihood: 0.6 },
            { value: 999999999, type: 'huge', rationale: 'Huge quantity', likelihood: 0.5 },
            { value: 1.5, type: 'float', rationale: 'Fractional quantity', likelihood: 0.6 },
            { value: '1', type: 'string', rationale: 'Type confusion', likelihood: 0.4 },
            { value: [1, 2, -10], type: 'array', rationale: 'Array injection', likelihood: 0.5 },
            { value: '-1', type: 'string_negative', rationale: 'String negative', likelihood: 0.5 },
        ]);

        // Discount payloads
        this.staticPayloads.set('discount', [
            { value: 101, type: 'over_100', rationale: '> 100% discount', likelihood: 0.7 },
            { value: -50, type: 'negative', rationale: 'Negative discount (adds to price)', likelihood: 0.6 },
            { value: 999999, type: 'huge', rationale: 'Huge discount amount', likelihood: 0.5 },
            { value: ['CODE1', 'CODE2'], type: 'stacking', rationale: 'Multiple codes', likelihood: 0.7 },
            { value: 'ADMIN100OFF', type: 'guess', rationale: 'Guess admin code', likelihood: 0.3 },
        ]);

        // ID payloads (IDOR)
        this.staticPayloads.set('id', [
            { value: 1, type: 'low_id', rationale: 'First user/order', likelihood: 0.6 },
            { value: 0, type: 'zero_id', rationale: 'ID zero', likelihood: 0.5 },
            { value: -1, type: 'negative_id', rationale: 'Negative ID', likelihood: 0.4 },
            { value: 'admin', type: 'admin_string', rationale: 'Admin string', likelihood: 0.3 },
            { value: '../../../etc/passwd', type: 'traversal', rationale: 'Path traversal', likelihood: 0.4 },
        ]);

        // Session payloads
        this.staticPayloads.set('session', [
            { value: '', type: 'empty', rationale: 'Empty session', likelihood: 0.6 },
            { value: 'null', type: 'null_string', rationale: 'Null string', likelihood: 0.5 },
            { value: 'admin', type: 'admin', rationale: 'Admin session', likelihood: 0.3 },
            { value: '0', type: 'zero', rationale: 'Zero session', likelihood: 0.4 },
        ]);
    }

    /**
     * Generate payloads for a parameter
     */
    async generatePayloads(
        param: Parameter,
        platform: PlatformDetectionResult
    ): Promise<FuzzPayload[]> {
        const payloads: FuzzPayload[] = [];
        const paramLower = param.name.toLowerCase();

        // Get static payloads based on parameter name
        if (/price|amount|total|cost/.test(paramLower)) {
            payloads.push(...(this.staticPayloads.get('price') || []));
        }
        if (/quantity|qty|count|num/.test(paramLower)) {
            payloads.push(...(this.staticPayloads.get('quantity') || []));
        }
        if (/discount|coupon|promo|code/.test(paramLower)) {
            payloads.push(...(this.staticPayloads.get('discount') || []));
        }
        if (/id|user|cart|order|session/.test(paramLower)) {
            payloads.push(...(this.staticPayloads.get('id') || []));
            payloads.push(...(this.staticPayloads.get('session') || []));
        }

        // Add LLM-generated payloads if available
        if (this.llmClient.isConfigured()) {
            try {
                const llmPayloads = await this.llmClient.generatePayloads({
                    parameterName: param.name,
                    parameterType: param.type,
                    originalValue: param.value,
                    platform: platform.platform,
                });

                for (const p of llmPayloads) {
                    payloads.push({
                        value: p.payload,
                        type: 'llm_generated',
                        rationale: p.rationale,
                        likelihood: p.likelihood,
                    });
                }
            } catch (error) {
                logger.debug('LLM payload generation failed', { error });
            }
        }

        // Deduplicate and sort by likelihood
        const unique = this.deduplicatePayloads(payloads);
        return unique.sort((a, b) => b.likelihood - a.likelihood);
    }

    /**
     * Get static payloads for a type
     */
    getStaticPayloads(type: string): FuzzPayload[] {
        return this.staticPayloads.get(type) || [];
    }

    /**
     * Deduplicate payloads
     */
    private deduplicatePayloads(payloads: FuzzPayload[]): FuzzPayload[] {
        const seen = new Set<string>();
        return payloads.filter(p => {
            const key = JSON.stringify(p.value);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    /**
     * Generate mutation of original value
     */
    mutate(value: unknown): FuzzPayload[] {
        const mutations: FuzzPayload[] = [];

        if (typeof value === 'number') {
            mutations.push(
                { value: 0, type: 'zero', rationale: 'Zero value', likelihood: 0.7 },
                { value: -value, type: 'negated', rationale: 'Negated value', likelihood: 0.6 },
                { value: value * -1, type: 'inverted', rationale: 'Sign inversion', likelihood: 0.6 },
                { value: value + 0.001, type: 'epsilon', rationale: 'Epsilon addition', likelihood: 0.3 },
                { value: Math.floor(value), type: 'floor', rationale: 'Floor value', likelihood: 0.3 },
            );
        }

        if (typeof value === 'string') {
            mutations.push(
                { value: '', type: 'empty', rationale: 'Empty string', likelihood: 0.6 },
                { value: value + '<script>', type: 'xss', rationale: 'XSS attempt', likelihood: 0.4 },
                { value: value + "' OR '1'='1", type: 'sqli', rationale: 'SQL injection', likelihood: 0.4 },
            );
        }

        return mutations;
    }
}

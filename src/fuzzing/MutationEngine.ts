/**
 * Mutation Engine - Generate payload variations
 */

export class MutationEngine {
    /**
     * Generate numeric mutations
     */
    mutateNumber(value: number): Array<{ value: number; technique: string }> {
        return [
            { value: 0, technique: 'zero' },
            { value: -1, technique: 'negative_one' },
            { value: -value, technique: 'negation' },
            { value: value * -1, technique: 'sign_flip' },
            { value: value + 0.01, technique: 'epsilon_plus' },
            { value: value - 0.01, technique: 'epsilon_minus' },
            { value: Math.floor(value), technique: 'floor' },
            { value: Math.ceil(value), technique: 'ceil' },
            { value: value * 1000, technique: 'scale_up' },
            { value: value / 1000, technique: 'scale_down' },
            { value: Number.MAX_SAFE_INTEGER, technique: 'max_safe' },
            { value: Number.MIN_SAFE_INTEGER, technique: 'min_safe' },
            { value: 2147483647, technique: 'max_int32' },
            { value: -2147483648, technique: 'min_int32' },
            { value: 4294967295, technique: 'max_uint32' },
        ];
    }

    /**
     * Generate string mutations
     */
    mutateString(value: string): Array<{ value: string; technique: string }> {
        return [
            { value: '', technique: 'empty' },
            { value: ' ', technique: 'whitespace' },
            { value: value.toUpperCase(), technique: 'uppercase' },
            { value: value.toLowerCase(), technique: 'lowercase' },
            { value: value + '\0', technique: 'null_byte' },
            { value: value + '\n', technique: 'newline' },
            { value: value.repeat(100), technique: 'repeat' },
            { value: encodeURIComponent(value), technique: 'url_encode' },
            { value: Buffer.from(value).toString('base64'), technique: 'base64' },
            { value: `<script>alert(1)</script>`, technique: 'xss' },
            { value: `' OR '1'='1`, technique: 'sqli' },
            { value: `{{7*7}}`, technique: 'ssti' },
            { value: `=1+1`, technique: 'formula' },
        ];
    }

    /**
     * Generate type confusion mutations
     */
    mutateType(value: unknown): Array<{ value: unknown; technique: string }> {
        return [
            { value: null, technique: 'null' },
            { value: undefined, technique: 'undefined' },
            { value: true, technique: 'boolean_true' },
            { value: false, technique: 'boolean_false' },
            { value: [], technique: 'empty_array' },
            { value: {}, technique: 'empty_object' },
            { value: [value], technique: 'wrapped_array' },
            { value: { value }, technique: 'wrapped_object' },
            { value: String(value), technique: 'to_string' },
            { value: Number(value), technique: 'to_number' },
        ];
    }

    /**
     * Deep mutation for objects
     */
    mutateObject(obj: Record<string, unknown>): Array<{ value: Record<string, unknown>; technique: string }> {
        const mutations: Array<{ value: Record<string, unknown>; technique: string }> = [];

        // Empty object
        mutations.push({ value: {}, technique: 'empty_object' });

        // Extra fields
        mutations.push({ value: { ...obj, __proto__: { admin: true } }, technique: 'prototype_pollution' });
        mutations.push({ value: { ...obj, admin: true }, technique: 'privilege_escalation' });

        // Remove required fields one by one
        for (const key of Object.keys(obj)) {
            const partial = { ...obj };
            delete partial[key];
            mutations.push({ value: partial, technique: `remove_${key}` });
        }

        return mutations;
    }
}

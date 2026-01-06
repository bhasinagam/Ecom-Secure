/**
 * Pattern Matcher - Embedding-based similarity
 */
import { logger } from '../core/Logger';

export class PatternMatcher {
    private patterns: Map<string, number[]> = new Map();

    async match(finding: { type: string; evidence: string[] }): Promise<number> {
        // Simple pattern matching based on known vulnerability signatures
        const vulnPatterns: Record<string, string[]> = {
            price_manipulation: ['price', 'amount', 'total', '0', 'negative', 'zero'],
            discount_abuse: ['discount', 'coupon', 'stacking', 'replay', 'percentage'],
            race_condition: ['concurrent', 'race', 'multiple', 'orders', 'inventory'],
            session_attack: ['session', 'cart', 'csrf', 'token', 'bypass'],
        };

        const evidenceText = finding.evidence.join(' ').toLowerCase();
        let maxScore = 0;

        for (const [pattern, keywords] of Object.entries(vulnPatterns)) {
            const matchCount = keywords.filter(kw => evidenceText.includes(kw)).length;
            const score = matchCount / keywords.length;
            if (score > maxScore) maxScore = score;
        }

        return maxScore;
    }
}

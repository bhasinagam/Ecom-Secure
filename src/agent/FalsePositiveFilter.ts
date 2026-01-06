/**
 * False Positive Filter
 */

export class FalsePositiveFilter {
    private fpPatterns = [
        { pattern: /validation (error|failed)/i, reason: 'Server-side validation detected' },
        { pattern: /invalid (input|parameter|value)/i, reason: 'Input validation present' },
        { pattern: /not (allowed|permitted|authorized)/i, reason: 'Authorization check present' },
        { pattern: /error|failed|rejected/i, reason: 'Request rejected' },
    ];

    filter(finding: { evidence: string[]; response: string }): {
        isFalsePositive: boolean;
        reason?: string;
    } {
        const combinedText = [...finding.evidence, finding.response].join(' ');

        for (const { pattern, reason } of this.fpPatterns) {
            if (pattern.test(combinedText)) {
                return { isFalsePositive: true, reason };
            }
        }

        return { isFalsePositive: false };
    }
}

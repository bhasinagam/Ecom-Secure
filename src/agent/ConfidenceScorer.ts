/**
 * Confidence Scorer - Bayesian confidence calculation
 */

export class ConfidenceScorer {
    private priorProbabilities: Record<string, number> = {
        price_manipulation: 0.15,
        discount_abuse: 0.20,
        quantity_manipulation: 0.10,
        session_attack: 0.12,
        payment_bypass: 0.08,
        race_condition: 0.05,
        business_logic: 0.10,
    };

    calculate(finding: {
        type: string;
        evidence: string[];
        detectorConfidence: number;
        aiConfidence?: number;
    }): number {
        const prior = this.priorProbabilities[finding.type] || 0.1;
        const evidenceStrength = Math.min(finding.evidence.length / 5, 1);
        const detectorScore = finding.detectorConfidence;
        const aiScore = finding.aiConfidence || detectorScore;

        // Weighted combination
        const posterior = (prior * 0.2) + (evidenceStrength * 0.2) + (detectorScore * 0.3) + (aiScore * 0.3);
        return Math.min(posterior, 1);
    }
}

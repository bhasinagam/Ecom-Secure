/**
 * Adversarial Verifier
 * Multi-Agent Debate System for False Positive Reduction
 * 
 * BLACKHAT INSIGHT: False positives kill scanner credibility.
 * Instead of one agent deciding, we have a debate:
 * 1. Attacker: Argues why it's a valid exploit
 * 2. Defender: Argues why it's a false positive
 * 3. Judge: Decides based on the debate
 */

import { LLMClient } from './LLMClient';
import { DetectorResult } from '../types';
import { logger } from '../core/Logger';

interface Argument {
    role: 'attacker' | 'defender';
    point: string;
    evidence: string;
    confidence: number;
}

interface VerificationResult {
    isConfirmed: boolean;
    confidence: number;
    reasoning: string;
    debateHistory: Argument[];
    modifiedSeverity?: string;
}

export class AdversarialVerifier {
    private llmClient: LLMClient;

    constructor() {
        this.llmClient = new LLMClient({
            apiKey: process.env.OPENROUTER_API_KEY || '',
            model: process.env.LLM_MODEL || 'google/gemini-2.0-flash-exp:free'
        });
    }

    /**
     * Verify a finding using adversarial debate
     */
    async verify(finding: DetectorResult): Promise<VerificationResult> {
        if (!this.llmClient.isConfigured()) {
            return {
                isConfirmed: true, // Fail open if no LLM
                confidence: finding.confidence,
                reasoning: 'LLM not configured for verification',
                debateHistory: []
            };
        }

        logger.info(`Starting adversarial verification for: ${finding.type} @ ${finding.endpoint}`);

        try {
            // Round 1: Attacker makes the case
            const attackArg = await this.generateAttackerArgument(finding);

            // Round 2: Defender attempts to refute
            const defenseArg = await this.generateDefenderArgument(finding, attackArg);

            // Round 3: Judge makes final decision
            const judgment = await this.generateJudgment(finding, attackArg, defenseArg);

            logger.info(`Verification complete. Confirmed: ${judgment.isConfirmed} (${judgment.confidence})`);

            return {
                isConfirmed: judgment.isConfirmed,
                confidence: judgment.confidence,
                reasoning: judgment.reasoning,
                debateHistory: [attackArg, defenseArg],
                modifiedSeverity: judgment.modifiedSeverity
            };

        } catch (error) {
            logger.error('Adversarial verification failed:', error);
            return {
                isConfirmed: true,
                confidence: finding.confidence,
                reasoning: 'Verification failed unexpectedly',
                debateHistory: []
            };
        }
    }

    /**
     * Agent 1: The Attacker
     * Tries to prove the vulnerability is real and impactful
     */
    private async generateAttackerArgument(finding: DetectorResult): Promise<Argument> {
        const prompt = `You are an Expert Pentester (The Attacker).
Your goal is to prove that the following finding is a VALID vulnerability and NOT a false positive.

Finding:
Type: ${finding.type}
Endpoint: ${finding.endpoint}
Severity: ${finding.severity}
Evidence: ${JSON.stringify(finding.evidence)}
Parameter: ${finding.parameter}

Analyze the evidence. Why is this a real threat? fast-talk the judge.
Focus on:
1. Validating the payload execution
2. Explaining the impact
3. Refuting common WAF/error page false positives

Output JSON only:
{
  "point": "Main argument summary",
  "evidence": "Detailed technical reasoning",
  "confidence": 0.0-1.0
}`;

        const response = await this.llmClient.analyze(prompt);
        const parsed = this.parseJSON<Omit<Argument, 'role'>>(response);

        return {
            role: 'attacker',
            point: parsed?.point || 'Vulnerability appears valid based on response',
            evidence: parsed?.evidence || 'Response indicates successful execution',
            confidence: parsed?.confidence || 0.8
        };
    }

    /**
     * Agent 2: The Defender
     * Tries to prove it's a false positive or harmless
     */
    private async generateDefenderArgument(
        finding: DetectorResult,
        attackArg: Argument
    ): Promise<Argument> {
        const prompt = `You are a Senior Security Engineer (The Defender).
Your goal is to prove that the finding is a FALSE POSITIVE or LOW RISK.

Finding: ${JSON.stringify(finding)}

Attacker's Argument:
"${attackArg.point}"
"${attackArg.evidence}"

Analyze critically. Is the attacker hallucinating?
Common False Positives to check for:
1. Reflected input without execution (for XSS/SSTI)
2. Generic error pages appearing like success (for SQLi)
3. Soft 404s (for path traversal)
4. WAF blocking pages (often look like 403/500)
5. Intended features (e.g., public API endpoints)

Output JSON only:
{
  "point": "Main counter-argument",
  "evidence": "Why this might be safe",
  "confidence": 0.0-1.0
}`;

        const response = await this.llmClient.analyze(prompt);
        const parsed = this.parseJSON<Omit<Argument, 'role'>>(response);

        return {
            role: 'defender',
            point: parsed?.point || 'Could be a false positive',
            evidence: parsed?.evidence || 'Response requires manual verification',
            confidence: parsed?.confidence || 0.5
        };
    }

    /**
     * Agent 3: The Judge
     * Weighs both sides and makes the final calling
     */
    private async generateJudgment(
        finding: DetectorResult,
        attackArg: Argument,
        defenseArg: Argument
    ): Promise<{ isConfirmed: boolean; confidence: number; reasoning: string; modifiedSeverity?: string }> {
        const prompt = `You are the Lead Security Architect (The Judge).
Decide if the vulnerability is REAL based on the debate.

Finding: ${finding.type} @ ${finding.endpoint}

Attacker: ${attackArg.point} (${attackArg.confidence})
"${attackArg.evidence}"

Defender: ${defenseArg.point} (${defenseArg.confidence})
"${defenseArg.evidence}"

Make a final ruling. Be conservative - if in doubt, mark as "Needs Manual Review" (Confirmed=True but lower confidence).

Output JSON only:
{
  "isConfirmed": boolean,
  "confidence": 0.0-1.0,
  "reasoning": "Final verdict explanation",
  "modifiedSeverity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null (optional adjustment)
}`;

        const response = await this.llmClient.analyze(prompt);
        const parsed = this.parseJSON<any>(response);

        return {
            isConfirmed: parsed?.isConfirmed ?? true,
            confidence: parsed?.confidence ?? finding.confidence,
            reasoning: parsed?.reasoning || 'Automated judgment',
            modifiedSeverity: parsed?.modifiedSeverity
        };
    }

    private parseJSON<T>(text: string): T | null {
        try {
            const match = text.match(/\{[\s\S]*\}/);
            if (match) return JSON.parse(match[0]);
            return JSON.parse(text);
        } catch {
            return null;
        }
    }
}

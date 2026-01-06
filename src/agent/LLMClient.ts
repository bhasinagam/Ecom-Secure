/**
 * LLM Client
 * OpenRouter API wrapper supporting multiple models
 */

import OpenAI from 'openai';
import { LLMConfig, LLMMessage, LLMResponse } from '../types';
import { logger } from '../core/Logger';

// Free models available on OpenRouter
const FREE_MODELS = [
    'google/gemini-2.0-flash-exp:free',
    'meta-llama/llama-3.2-3b-instruct:free',
    'mistralai/mistral-7b-instruct:free',
    'huggingfaceh4/zephyr-7b-beta:free',
];

export class LLMClient {
    private client: OpenAI;
    private config: LLMConfig;
    private requestCount: number = 0;
    private tokenCount: number = 0;

    constructor(config?: Partial<LLMConfig>) {
        this.config = {
            apiKey: config?.apiKey || process.env.OPENROUTER_API_KEY || '',
            baseUrl: config?.baseUrl || 'https://openrouter.ai/api/v1',
            model: config?.model || process.env.LLM_MODEL || FREE_MODELS[0],
            temperature: config?.temperature ?? 0.1,
            maxTokens: config?.maxTokens || 4096,
        };

        this.client = new OpenAI({
            apiKey: this.config.apiKey,
            baseURL: this.config.baseUrl,
            defaultHeaders: {
                'HTTP-Referer': 'https://ecomsecure-scanner.local',
                'X-Title': 'EcomSecure Scanner',
            },
        });
    }

    /**
     * Generic analysis method for AI agents
     */
    async analyze(prompt: string): Promise<string> {
        const response = await this.complete({
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.2,
        });

        return response.content;
    }

    /**
     * Complete a chat conversation
     */
    async complete(options: {
        messages: LLMMessage[];
        model?: string;
        temperature?: number;
        maxTokens?: number;
        responseFormat?: { type: 'json_object' | 'text' };
    }): Promise<LLMResponse> {
        const model = options.model || this.config.model;

        try {
            logger.debug(`LLM request to ${model}`, {
                messageCount: options.messages.length
            });

            const response = await this.client.chat.completions.create({
                model,
                messages: options.messages.map(m => ({
                    role: m.role,
                    content: m.content,
                })),
                temperature: options.temperature ?? this.config.temperature,
                max_tokens: options.maxTokens || this.config.maxTokens,
                response_format: options.responseFormat,
            });

            this.requestCount++;
            this.tokenCount += response.usage?.total_tokens || 0;

            const content = response.choices[0]?.message?.content || '';

            return {
                content,
                model: response.model,
                usage: {
                    promptTokens: response.usage?.prompt_tokens || 0,
                    completionTokens: response.usage?.completion_tokens || 0,
                    totalTokens: response.usage?.total_tokens || 0,
                },
            };
        } catch (error) {
            logger.error('LLM request failed', error);
            throw error;
        }
    }

    /**
     * Analyze a potential vulnerability
     */
    async analyzeVulnerability(context: {
        originalRequest: string;
        modifiedRequest: string;
        response: string;
        detectorName: string;
    }): Promise<{
        isVulnerable: boolean;
        confidence: number;
        severity: string;
        reasoning: string;
        cvssScore: number;
    }> {
        const prompt = `You are a security researcher analyzing potential e-commerce vulnerabilities.

## Original Request
${context.originalRequest}

## Modified Request (Exploit Attempt)
${context.modifiedRequest}

## Server Response
${context.response.substring(0, 2000)}

## Detector
${context.detectorName}

## Analysis Task
Determine if this is a GENUINE security vulnerability or a FALSE POSITIVE.

Consider:
1. Did the server accept the malicious payload without proper validation?
2. Does the response indicate successful exploitation?
3. Could this be legitimate application behavior?
4. What is the exploitability in a real-world scenario?

Respond in JSON format:
{
  "is_vulnerable": boolean,
  "confidence": 0.0-1.0,
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "reasoning": "2-3 sentence explanation",
  "cvss_score": 0.0-10.0
}`;

        const response = await this.complete({
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.1,
            responseFormat: { type: 'json_object' },
        });

        try {
            const result = JSON.parse(response.content);
            return {
                isVulnerable: result.is_vulnerable,
                confidence: result.confidence,
                severity: result.severity,
                reasoning: result.reasoning,
                cvssScore: result.cvss_score,
            };
        } catch {
            return {
                isVulnerable: false,
                confidence: 0,
                severity: 'INFO',
                reasoning: 'Failed to parse LLM response',
                cvssScore: 0,
            };
        }
    }

    /**
     * Generate attack payloads
     */
    async generatePayloads(context: {
        parameterName: string;
        parameterType: string;
        originalValue: unknown;
        platform: string;
    }): Promise<Array<{ payload: unknown; rationale: string; likelihood: number }>> {
        const prompt = `You are a penetration testing expert specializing in e-commerce vulnerabilities.

Context:
- Parameter name: ${context.parameterName}
- Original value: ${context.originalValue}
- Data type: ${context.parameterType}
- Platform: ${context.platform}

Task: Generate 10 creative payloads that could exploit this parameter in a checkout flow.
Consider: type confusion, business logic flaws, edge cases, encoding tricks.

Respond with JSON array:
[
  {
    "payload": <value>,
    "rationale": "string",
    "likelihood": 0.0-1.0
  }
]`;

        const response = await this.complete({
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.8,
            responseFormat: { type: 'json_object' },
        });

        try {
            const result = JSON.parse(response.content);
            return Array.isArray(result) ? result : result.payloads || [];
        } catch {
            return [];
        }
    }

    /**
     * Get usage statistics
     */
    getStats(): { requests: number; tokens: number } {
        return {
            requests: this.requestCount,
            tokens: this.tokenCount,
        };
    }

    /**
     * Check if API key is configured
     */
    isConfigured(): boolean {
        return !!this.config.apiKey;
    }

    /**
     * Get current model
     */
    getModel(): string {
        return this.config.model;
    }

    /**
     * Set model
     */
    setModel(model: string): void {
        this.config.model = model;
    }
}

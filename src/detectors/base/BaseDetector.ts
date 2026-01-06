/**
 * Base Detector Class
 * Abstract class for all vulnerability detectors
 */

import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint,
    Severity,
    SanitizedRequest,
    SanitizedResponse,
    HttpRequest,
    HttpResponse,
    ReproductionSteps
} from '../../types';
import { HttpClient } from '../../utils/HttpClient';
import { logger } from '../../core/Logger';

export abstract class BaseDetector {
    public readonly name: string;
    public readonly category: string;
    protected httpClient: HttpClient;
    protected requestCount: number = 0;

    constructor(name: string, category: string) {
        this.name = name;
        this.category = category;
        this.httpClient = new HttpClient();
    }

    /**
     * Main test method - must be implemented by subclasses
     */
    abstract test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]>;

    /**
     * Get parameters relevant to this detector
     */
    protected abstract getRelevantParameters(attackSurface: AttackSurface): Parameter[];

    /**
     * Build HTTP request for testing
     */
    protected buildRequest(
        endpoint: Endpoint,
        paramOverrides: Record<string, unknown>
    ): HttpRequest {
        const params: Record<string, unknown> = {};

        // Add original parameters
        for (const param of endpoint.parameters) {
            params[param.name] = param.value;
        }

        // Apply overrides
        for (const [key, value] of Object.entries(paramOverrides)) {
            params[key] = value;
        }

        return {
            method: endpoint.method,
            url: endpoint.url,
            headers: {
                'Content-Type': 'application/json',
                ...endpoint.headers,
            },
            data: params,
        };
    }

    /**
     * Send HTTP request and track count
     */
    protected async sendRequest(request: HttpRequest): Promise<HttpResponse> {
        this.requestCount++;
        logger.debug(`[${this.name}] Sending ${request.method} request to ${request.url}`, {
            requestNum: this.requestCount,
            data: request.data
        });
        try {
            const response = await this.httpClient.request(request);
            logger.debug(`[${this.name}] Response: ${response.status} (${response.duration}ms)`);
            return response;
        } catch (error) {
            logger.debug(`[${this.name}] Request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            throw error;
        }
    }

    /**
     * Test a single payload against an endpoint
     */
    protected async testPayload(
        endpoint: Endpoint,
        paramName: string,
        originalValue: unknown,
        exploitValue: unknown
    ): Promise<{
        exploitable: boolean;
        orderCreated: boolean;
        confidence: number;
        evidence: string[];
        baselineResponse: HttpResponse;
        exploitResponse: HttpResponse;
    }> {
        logger.debug(`[${this.name}] Testing payload on ${endpoint.url}`, {
            paramName,
            originalValue,
            exploitValue
        });

        // Baseline request
        const baselineReq = this.buildRequest(endpoint, { [paramName]: originalValue });
        const baselineResp = await this.sendRequest(baselineReq);

        // Exploit request
        const exploitReq = this.buildRequest(endpoint, { [paramName]: exploitValue });
        const exploitResp = await this.sendRequest(exploitReq);

        // Analyze responses
        const analysis = this.analyzeResponses(baselineResp, exploitResp, exploitValue);

        logger.debug(`[${this.name}] Payload test result`, {
            exploitable: analysis.exploitable,
            confidence: analysis.confidence,
            evidence: analysis.evidence
        });

        return {
            ...analysis,
            baselineResponse: baselineResp,
            exploitResponse: exploitResp,
        };
    }

    /**
     * Analyze baseline vs exploit responses
     */
    protected analyzeResponses(
        baseline: HttpResponse,
        exploit: HttpResponse,
        exploitValue: unknown
    ): {
        exploitable: boolean;
        orderCreated: boolean;
        confidence: number;
        evidence: string[];
    } {
        const evidence: string[] = [];
        let confidence = 0;

        // Check if exploit request was accepted
        if (exploit.status >= 200 && exploit.status < 300) {
            evidence.push('Server accepted exploit payload');
            confidence += 0.3;

            // Check for order confirmation
            if (this.detectOrderConfirmation(exploit)) {
                evidence.push('Order confirmation detected');
                confidence += 0.4;
            }

            // Check if exploit value appears in response
            if (this.valueInResponse(exploit.body, exploitValue)) {
                evidence.push(`Exploit value (${exploitValue}) reflected in response`);
                confidence += 0.2;
            }
        } else if (exploit.status === 400 || exploit.status === 422) {
            evidence.push('Server rejected payload with validation error');
            confidence = 0;
        }

        // Compare with baseline
        const behaviorDifference = this.compareBehavior(baseline, exploit);
        if (behaviorDifference) {
            evidence.push(behaviorDifference);
            confidence += 0.1;
        }

        logger.debug(`[BaseDetector] Response analysis`, {
            exploitStatus: exploit.status,
            baselineStatus: baseline.status,
            exploitBodyLength: exploit.body.length,
            exploitValue
        });

        return {
            exploitable: confidence >= 0.6,
            orderCreated: this.detectOrderConfirmation(exploit),
            confidence: Math.min(confidence, 1),
            evidence,
        };
    }

    /**
     * Detect order confirmation in response
     */
    protected detectOrderConfirmation(response: HttpResponse): boolean {
        const body = typeof response.body === 'string'
            ? response.body.toLowerCase()
            : JSON.stringify(response.data).toLowerCase();

        const confirmationPatterns = [
            'order_id',
            'order_number',
            'confirmation',
            'thank you',
            'order confirmed',
            'payment successful',
            'order placed',
            'purchase complete',
        ];

        return confirmationPatterns.some(pattern => body.includes(pattern));
    }

    /**
     * Check if value appears in response
     */
    protected valueInResponse(responseBody: string, value: unknown): boolean {
        const stringValue = String(value);
        return responseBody.includes(stringValue);
    }

    /**
     * Compare behavior between baseline and exploit responses
     */
    protected compareBehavior(baseline: HttpResponse, exploit: HttpResponse): string | null {
        // Status code difference
        if (baseline.status !== exploit.status) {
            return `Status changed from ${baseline.status} to ${exploit.status}`;
        }

        // Response time difference (possible processing difference)
        if (Math.abs(baseline.duration - exploit.duration) > 2000) {
            return `Response time changed significantly (${baseline.duration}ms vs ${exploit.duration}ms)`;
        }

        // Content length difference
        const baselineLen = baseline.body.length;
        const exploitLen = exploit.body.length;
        if (Math.abs(baselineLen - exploitLen) > baselineLen * 0.5) {
            return 'Response content significantly different';
        }

        return null;
    }

    /**
     * Sanitize request for reporting
     */
    protected sanitizeRequest(request: HttpRequest): SanitizedRequest {
        const headers = { ...request.headers };

        // Remove sensitive headers
        delete headers['cookie'];
        delete headers['authorization'];
        delete headers['x-api-key'];

        return {
            method: request.method,
            url: request.url,
            headers,
            body: request.data,
        };
    }

    /**
     * Sanitize response for reporting
     */
    protected sanitizeResponse(response: HttpResponse): SanitizedResponse {
        return {
            status: response.status,
            headers: response.headers,
            body: response.body.substring(0, 5000), // Limit body size
            duration: response.duration,
        };
    }

    /**
     * Create detector result
     */
    protected createResult(
        type: string,
        vulnerable: boolean,
        severity: Severity,
        options: {
            parameter?: string;
            endpoint?: string;
            originalValue?: unknown;
            exploitValue?: unknown;
            evidence?: string[];
            impact?: string;
            confidence?: number;
            reproduction?: ReproductionSteps;
        }
    ): DetectorResult {
        return {
            detectorName: this.name,
            vulnerable,
            type,
            severity,
            confidence: options.confidence || 0,
            parameter: options.parameter,
            endpoint: options.endpoint,
            originalValue: options.originalValue,
            exploitValue: options.exploitValue,
            evidence: options.evidence || [],
            impact: options.impact || '',
            reproduction: options.reproduction,
        };
    }

    /**
     * Get request count
     */
    getRequestCount(): number {
        return this.requestCount;
    }

    /**
     * Reset request count
     */
    resetRequestCount(): void {
        this.requestCount = 0;
    }

    /**
     * Extract price from response body
     */
    protected extractPrice(body: string): number | null {
        // Try JSON parsing
        try {
            const data = JSON.parse(body);
            const priceKeys = ['price', 'amount', 'total', 'subtotal', 'grand_total'];
            for (const key of priceKeys) {
                if (data[key] !== undefined) {
                    return parseFloat(data[key]);
                }
            }
        } catch {
            // Not JSON
        }

        // Try regex for price patterns
        const pricePatterns = [
            /\"(?:price|amount|total)\":\s*([\d.]+)/i,
            /\$\s*([\d,]+\.?\d*)/,
            /([\d,]+\.?\d*)\s*(?:USD|EUR|GBP)/i,
        ];

        for (const pattern of pricePatterns) {
            const match = body.match(pattern);
            if (match) {
                return parseFloat(match[1].replace(',', ''));
            }
        }

        return null;
    }

    /**
     * Generate cURL command for reproduction
     */
    protected generateCurlCommand(request: HttpRequest): string {
        let curl = `curl -X ${request.method} '${request.url}'`;

        for (const [name, value] of Object.entries(request.headers || {})) {
            if (!['cookie', 'authorization'].includes(name.toLowerCase())) {
                curl += ` \\\n  -H '${name}: ${value}'`;
            }
        }

        if (request.data) {
            curl += ` \\\n  -d '${JSON.stringify(request.data)}'`;
        }

        return curl;
    }

    /**
     * Generate Python script for reproduction
     */
    protected generatePythonScript(request: HttpRequest): string {
        return `import requests

response = requests.${request.method.toLowerCase()}(
    '${request.url}',
    headers=${JSON.stringify(request.headers || {}, null, 4)},
    json=${JSON.stringify(request.data, null, 4)}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")`;
    }

    /**
     * Log detector activity
     */
    protected log(action: string, details?: Record<string, unknown>): void {
        logger.detector(this.name, action, details);
    }
}

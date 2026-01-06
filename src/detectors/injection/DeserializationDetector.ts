/**
 * Deserialization Detector
 * Detects Insecure Deserialization Vulnerabilities
 * 
 * BLACKHAT INSIGHT: Serialized objects are often trusted blindly.
 * Attackers can execute code by modifying serialized data structures.
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

export class DeserializationDetector extends BaseDetector {
    // Magic bytes/signatures
    private readonly signatures = {
        java: /rO0AB/i, // Java Serialization (base64)
        python_pickle: /gASV/i, // Python Pickle (base64)
        php: /[Oa]:\d+:"/i, // PHP Serialization
        dotnet: /AAEAAAD/i, // .NET ViewState etc.
    };

    // Safe payloads that trigger sleep/delay for detection
    private readonly payloads = {
        java: [
            // CommonsCollections5 sleep(5000)
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRyeS5vZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmK63i2A5XGDAIAAkwADW1hcHRhY3BMamF2YS91dGlsL01hcDtMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDt4cHB0AAZmb29iYXJ4',
        ],
        php: [
            'O:14:"SensitiveClass":0:{}', // Generic
            'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}', // Prop manipulation
        ],
        python: [
            'gASVHAAAAACMCXRpbWUu... (sleep payload)', // Placeholder
        ]
    };

    constructor() {
        super('deserialization', 'injection');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];
        const serializedParams = this.findSerializedParameters(attackSurface);

        this.log('Starting deserialization detection', { paramCount: serializedParams.length });

        for (const param of serializedParams) {
            const endpoints = this.getEndpointsWithParam(attackSurface, param.name);

            for (const endpoint of endpoints) {
                // Test type-specific payloads
                const type = this.detectSerializationType(String(param.value));
                if (type) {
                    this.log(`Detected ${type} serialization in ${param.name}`);

                    const result = await this.testDeserialization(endpoint, param, type);
                    if (result) findings.push(result);
                }
            }
        }

        return findings;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    private findSerializedParameters(attackSurface: AttackSurface): Parameter[] {
        return attackSurface.parameters
            .map(ap => ap.parameter)
            .filter(p => this.detectSerializationType(String(p.value)) !== null);
    }

    private detectSerializationType(value: string): keyof typeof this.signatures | null {
        for (const [type, regex] of Object.entries(this.signatures)) {
            if (regex.test(value)) return type as keyof typeof this.signatures;
        }
        return null;
    }

    private getEndpointsWithParam(attackSurface: AttackSurface, paramName: string): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e => e.parameters.some(p => p.name === paramName));
    }

    private async testDeserialization(
        endpoint: Endpoint,
        param: Parameter,
        type: string
    ): Promise<DetectorResult | null> {
        // Naive test: send garbage to see if error reveals deserializer usage
        try {
            const response = await this.sendRequest({
                method: endpoint.method,
                url: endpoint.url,
                headers: endpoint.headers,
                data: { [param.name]: '!!INVALID!!' }
            });

            if (this.detectDeserializationError(response.body)) {
                return this.createResult('deserialization_error_leak', true, 'MEDIUM', {
                    endpoint: endpoint.url,
                    parameter: param.name,
                    evidence: [`Found deserialization error: ${response.body.substring(0, 100)}`],
                    impact: 'Information disclosure about serialization library',
                    confidence: 0.9
                });
            }

            // Advanced: Send actual payload if available (simplified for this plan)
            // Real implementation would use ysoserial generated payloads

        } catch {
            // Error is good info too
        }

        return null;
    }

    private detectDeserializationError(body: string): boolean {
        const errors = [
            'ObjectInputStream',
            'unserialize()',
            'pickle.load',
            'EndOfStreamException',
            'InvalidClassException'
        ];
        return errors.some(e => body.includes(e));
    }
}

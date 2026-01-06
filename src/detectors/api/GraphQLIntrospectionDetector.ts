/**
 * GraphQL Introspection Detector
 * 
 * BLACKHAT INSIGHT: GraphQL often exposes entire schema via introspection.
 * This reveals hidden mutations, deprecated fields with less validation.
 */

import { BaseDetector } from '../base/BaseDetector';
import {
    DetectorResult,
    AttackSurface,
    PlatformDetectionResult,
    Parameter,
    Endpoint,
    HttpRequest
} from '../../types';
import { logger } from '../../core/Logger';

interface GraphQLField {
    name: string;
    type: { name: string; kind: string };
    args: Array<{ name: string; type: { name: string; kind: string } }>;
    isDeprecated: boolean;
    deprecationReason?: string;
    parentType?: string;
}

interface GraphQLType {
    name: string;
    kind: string;
    fields: GraphQLField[];
}

interface GraphQLSchema {
    types: GraphQLType[];
    mutations: GraphQLField[];
    queries: GraphQLField[];
}

export class GraphQLIntrospectionDetector extends BaseDetector {
    constructor() {
        super('graphql-introspection', 'api');
    }

    async test(
        attackSurface: AttackSurface,
        platform: PlatformDetectionResult
    ): Promise<DetectorResult[]> {
        const findings: DetectorResult[] = [];
        const graphqlEndpoints = this.findGraphQLEndpoints(attackSurface);

        this.log('Starting GraphQL introspection analysis', {
            endpointCount: graphqlEndpoints.length
        });

        for (const endpoint of graphqlEndpoints) {
            // Test 1: Schema introspection
            const schema = await this.introspectSchema(endpoint);

            if (schema) {
                this.log('Schema introspection successful!', {
                    types: schema.types.length,
                    mutations: schema.mutations.length
                });

                findings.push(this.createResult('graphql_introspection_enabled', true, 'MEDIUM', {
                    endpoint: endpoint.url,
                    evidence: ['GraphQL introspection is enabled'],
                    impact: 'Attackers can discover entire API schema including hidden endpoints',
                    confidence: 0.95
                }));

                // Test 2: Find hidden/deprecated mutations
                const hiddenMutations = schema.mutations.filter(m =>
                    m.isDeprecated ||
                    m.name.startsWith('_') ||
                    /internal|admin|debug|test/i.test(m.name)
                );

                if (hiddenMutations.length > 0) {
                    this.log(`Found ${hiddenMutations.length} hidden/deprecated mutations`);

                    for (const mutation of hiddenMutations) {
                        const exploit = await this.testMutation(endpoint, mutation);
                        if (exploit) findings.push(exploit);
                    }
                }

                // Test 3: Field-level authorization bypass
                const authBypass = await this.testFieldLevelAuthBypass(endpoint, schema);
                if (authBypass) findings.push(authBypass);

                // Test 4: Batch query complexity attack
                const dosVuln = await this.testBatchQueryExhaustion(endpoint, schema);
                if (dosVuln) findings.push(dosVuln);

                // Test 5: Alias-based rate limit bypass
                const aliasVuln = await this.testAliasBatching(endpoint, schema);
                if (aliasVuln) findings.push(aliasVuln);
            }
        }

        return findings;
    }

    protected getRelevantParameters(attackSurface: AttackSurface): Parameter[] {
        return [];
    }

    /**
     * Find GraphQL endpoints in attack surface
     */
    private findGraphQLEndpoints(attackSurface: AttackSurface): Endpoint[] {
        return attackSurface.endpoints
            .map(ae => ae.endpoint)
            .filter(e =>
                /graphql/i.test(e.url) ||
                e.headers?.['content-type']?.includes('application/graphql') ||
                e.type === 'api'
            );
    }

    /**
     * Attempt schema introspection
     */
    private async introspectSchema(endpoint: Endpoint): Promise<GraphQLSchema | null> {
        const introspectionQuery = `
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                            args { name type { name kind } }
                            isDeprecated
                            deprecationReason
                        }
                    }
                    mutationType { 
                        name 
                        fields { 
                            name 
                            args { name type { name } }
                            isDeprecated
                            deprecationReason
                        } 
                    }
                    queryType { 
                        name 
                        fields { name } 
                    }
                }
            }
        `;

        try {
            const response = await this.sendRequest({
                method: 'POST',
                url: endpoint.url,
                headers: {
                    'Content-Type': 'application/json',
                    ...endpoint.headers
                },
                data: { query: introspectionQuery }
            });

            if (response.status === 200) {
                try {
                    const data = JSON.parse(response.body);
                    if (data.data?.__schema) {
                        return this.parseSchema(data.data.__schema);
                    }
                } catch {
                    // Not valid JSON
                }
            }
        } catch (e) {
            this.log('Introspection failed - may be disabled (good security)');
        }

        return null;
    }

    /**
     * Parse introspection response into schema object
     */
    private parseSchema(rawSchema: any): GraphQLSchema {
        const types: GraphQLType[] = (rawSchema.types || []).map((t: any) => ({
            name: t.name,
            kind: t.kind,
            fields: (t.fields || []).map((f: any) => ({
                name: f.name,
                type: f.type || {},
                args: f.args || [],
                isDeprecated: f.isDeprecated || false,
                deprecationReason: f.deprecationReason
            }))
        }));

        const mutations: GraphQLField[] = rawSchema.mutationType?.fields || [];
        const queries: GraphQLField[] = rawSchema.queryType?.fields || [];

        return { types, mutations, queries };
    }

    /**
     * Test a specific mutation for authorization bypass
     */
    private async testMutation(
        endpoint: Endpoint,
        mutation: GraphQLField
    ): Promise<DetectorResult | null> {
        // Build minimal mutation query
        const args = mutation.args.map(a => `${a.name}: null`).join(', ');
        const query = `mutation { ${mutation.name}${args ? `(${args})` : ''} }`;

        try {
            const response = await this.sendRequest({
                method: 'POST',
                url: endpoint.url,
                headers: { 'Content-Type': 'application/json' },
                data: { query }
            });

            // If mutation accessible without auth
            if (response.status === 200 && !response.body.includes('unauthorized')) {
                return this.createResult('graphql_hidden_mutation', true, 'HIGH', {
                    endpoint: endpoint.url,
                    parameter: mutation.name,
                    evidence: [
                        `Hidden/deprecated mutation accessible: ${mutation.name}`,
                        mutation.isDeprecated ? `Deprecated: ${mutation.deprecationReason}` : '',
                    ].filter(Boolean),
                    impact: 'Hidden API functionality may lack proper validation',
                    confidence: 0.7
                });
            }
        } catch {
            // Mutation failed
        }

        return null;
    }

    /**
     * Test for field-level authorization bypass
     * Query sensitive fields without proper authentication
     */
    private async testFieldLevelAuthBypass(
        endpoint: Endpoint,
        schema: GraphQLSchema
    ): Promise<DetectorResult | null> {
        // Find sensitive field types
        const sensitivePatterns = /email|password|credit|card|ssn|payment|secret|token|key/i;

        const sensitiveFields: GraphQLField[] = [];
        for (const type of schema.types) {
            for (const field of type.fields) {
                if (sensitivePatterns.test(field.name)) {
                    sensitiveFields.push({ ...field, parentType: type.name });
                }
            }
        }

        this.log(`Found ${sensitiveFields.length} potentially sensitive fields`);

        for (const field of sensitiveFields.slice(0, 5)) { // Test first 5
            const query = `{ ${field.parentType?.toLowerCase()} { ${field.name} } }`;

            try {
                const response = await this.sendRequest({
                    method: 'POST',
                    url: endpoint.url,
                    headers: { 'Content-Type': 'application/json' },
                    data: { query }
                });

                // Check if data returned without auth
                const data = JSON.parse(response.body);
                if (response.status === 200 && data.data && !data.errors) {
                    return this.createResult('graphql_field_auth_bypass', true, 'HIGH', {
                        endpoint: endpoint.url,
                        parameter: `${field.parentType}.${field.name}`,
                        evidence: ['Sensitive field accessible without authentication'],
                        impact: 'Sensitive data exposed without proper authorization',
                        confidence: 0.85
                    });
                }
            } catch {
                // Query failed
            }
        }

        return null;
    }

    /**
     * Test for batch query complexity/DoS attack
     * Deeply nested queries can cause exponential database load
     */
    private async testBatchQueryExhaustion(
        endpoint: Endpoint,
        schema: GraphQLSchema
    ): Promise<DetectorResult | null> {
        // Find potential circular references
        const circularRef = this.findCircularReference(schema);
        if (!circularRef) {
            this.log('No circular references found for complexity attack');
            return null;
        }

        // Build deeply nested query (5 levels to start)
        const nestedQuery = this.buildNestedQuery(circularRef, 5);

        const startTime = Date.now();
        try {
            const response = await this.sendRequest({
                method: 'POST',
                url: endpoint.url,
                headers: { 'Content-Type': 'application/json' },
                data: { query: nestedQuery }
            });
            const duration = Date.now() - startTime;

            // If query took >3s, likely vulnerable to complexity attacks
            if (duration > 3000) {
                return this.createResult('graphql_query_complexity', true, 'MEDIUM', {
                    endpoint: endpoint.url,
                    evidence: [
                        `Nested query took ${duration}ms`,
                        'No query complexity limits detected'
                    ],
                    impact: 'Server resources can be exhausted via complex nested queries',
                    confidence: 0.75
                });
            }
        } catch {
            // Query might have timed out - also indicates vulnerability
            const duration = Date.now() - startTime;
            if (duration > 5000) {
                return this.createResult('graphql_query_complexity', true, 'MEDIUM', {
                    endpoint: endpoint.url,
                    evidence: ['Complex query caused timeout'],
                    impact: 'DoS via query complexity',
                    confidence: 0.7
                });
            }
        }

        return null;
    }

    /**
     * Test alias-based rate limit bypass
     * Use aliases to make multiple queries appear as one
     */
    private async testAliasBatching(
        endpoint: Endpoint,
        schema: GraphQLSchema
    ): Promise<DetectorResult | null> {
        if (schema.queries.length === 0) return null;

        const queryField = schema.queries[0].name;

        // Create query with 100 aliased calls
        const aliases = Array.from({ length: 100 }, (_, i) =>
            `alias${i}: ${queryField}`
        ).join('\n');

        const query = `{ ${aliases} }`;

        try {
            const response = await this.sendRequest({
                method: 'POST',
                url: endpoint.url,
                headers: { 'Content-Type': 'application/json' },
                data: { query }
            });

            if (response.status === 200) {
                return this.createResult('graphql_alias_batching', true, 'MEDIUM', {
                    endpoint: endpoint.url,
                    evidence: ['100 aliased queries executed in single request'],
                    impact: 'Rate limits can be bypassed using query aliases',
                    confidence: 0.7
                });
            }
        } catch {
            // Query failed
        }

        return null;
    }

    /**
     * Find circular references in schema for complexity attacks
     */
    private findCircularReference(schema: GraphQLSchema): string[] | null {
        const typeMap = new Map<string, string[]>();

        for (const type of schema.types) {
            const references = type.fields
                .filter(f => f.type?.kind === 'OBJECT')
                .map(f => f.type.name);
            typeMap.set(type.name, references);
        }

        // Look for cycles (A → B → A)
        for (const [typeName, refs] of typeMap) {
            for (const ref of refs) {
                const refRefs = typeMap.get(ref) || [];
                if (refRefs.includes(typeName)) {
                    return [typeName, ref];
                }
            }
        }

        return null;
    }

    /**
     * Build nested query for complexity attack
     */
    private buildNestedQuery(circularRef: string[], depth: number): string {
        const [type1, type2] = circularRef;
        let query = type1.toLowerCase();

        for (let i = 0; i < depth; i++) {
            const inner = i % 2 === 0 ? type2.toLowerCase() : type1.toLowerCase();
            query = `${query} { ${inner}`;
        }

        query += ' { id } ' + '}'.repeat(depth);
        return `{ ${query} }`;
    }
}

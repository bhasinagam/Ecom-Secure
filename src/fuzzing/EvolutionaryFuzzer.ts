/**
 * Evolutionary Fuzzer - Genetic Algorithm-Based Payload Evolution
 * 
 * Uses genetic algorithms to evolve payloads that bypass multiple defenses.
 * Successful exploits often combine multiple tricks - this finds optimal combinations.
 */

import { Endpoint, Parameter, HttpRequest, HttpResponse } from '../types';
import { HttpClient } from '../utils/HttpClient';
import { logger } from '../core/Logger';
import { v4 as uuidv4 } from 'uuid';

interface Payload {
    id: string;
    value: unknown;
    encoding: 'raw' | 'url' | 'base64' | 'unicode' | 'double_url';
    wrapper: 'none' | 'array' | 'object' | 'string' | 'nested_array';
    injectionLayer: 'none' | 'sql' | 'nosql' | 'template' | 'command';
    mutations: string[];
    generation: number;
}

interface FitnessResult {
    score: number;
    factors: {
        statusProgression: number;
        errorUniqueness: number;
        timingAnomaly: number;
        sizeDeviation: number;
        payloadReflection: number;
        headerWeakening: number;
        transactionSuccess: number;
    };
    response: HttpResponse;
}

interface FuzzingResult {
    bestPayloads: Payload[];
    exploits: Payload[];
    generations: number;
    totalTests: number;
    highestFitness: number;
}

export class EvolutionaryFuzzer {
    private population: Payload[] = [];
    private fitnessScores: Map<string, FitnessResult> = new Map();
    private errorFingerprints: Set<string> = new Set();
    private baselineResponses: Map<string, HttpResponse> = new Map();
    private httpClient: HttpClient;

    // Evolutionary parameters
    private readonly populationSize = 30; // Reduced from 50 for performance
    private readonly survivalRate = 0.3;
    private readonly mutationRate = 0.15;
    private readonly crossoverRate = 0.7;

    constructor() {
        this.httpClient = new HttpClient();
    }

    /**
     * Evolve payloads to find exploits
     */
    async evolve(
        endpoint: Endpoint,
        param: Parameter,
        generations: number = 30
    ): Promise<FuzzingResult> {
        logger.info(`[EvolutionaryFuzzer] Starting evolution for ${param.name} @ ${endpoint.url}`);
        logger.debug(`Settings: ${this.populationSize} population, ${generations} generations`);

        // Get baseline response for comparison
        await this.establishBaseline(endpoint, param);

        // Initialize population with seed payloads
        this.initializePopulation(param);

        const exploits: Payload[] = [];
        let highestFitness = 0;
        let stagnationCounter = 0;
        const STAGNATION_LIMIT = 5; // Stop if no improvement for 5 generations
        const startTime = Date.now();
        const MAX_DURATION_MS = 120000; // 2 minutes max per parameter

        for (let gen = 0; gen < generations; gen++) {
            // Check global timeout
            if (Date.now() - startTime > MAX_DURATION_MS) {
                logger.warn(`[EvolutionaryFuzzer] Timeout reached (${MAX_DURATION_MS}ms) for ${param.name}. Moving on.`);
                break;
            }

            logger.debug(`Generation ${gen + 1}/${generations} - Population: ${this.population.length}`);

            let generationImproved = false;

            // Evaluate fitness for each payload
            for (const payload of this.population) {
                if (!this.fitnessScores.has(payload.id)) {
                    const fitness = await this.evaluateFitness(endpoint, param, payload);
                    this.fitnessScores.set(payload.id, fitness);

                    if (fitness.score > highestFitness) {
                        highestFitness = fitness.score;
                        generationImproved = true;
                        logger.debug(`New highest fitness: ${fitness.score.toFixed(3)}`);
                    }

                    // Found exploit!
                    if (fitness.score >= 0.9) {
                        logger.warn(`[EvolutionaryFuzzer] Found potential exploit! Score: ${fitness.score}`);
                        exploits.push(payload);
                    }
                }
            }

            // Stagnation check
            if (generationImproved) {
                stagnationCounter = 0;
            } else {
                stagnationCounter++;
                if (stagnationCounter >= STAGNATION_LIMIT) {
                    logger.info(`[EvolutionaryFuzzer] Evolution stagnated for ${STAGNATION_LIMIT} generations. Stopping early.`);
                    break;
                }
            }

            // Early termination if exploits found
            if (exploits.length >= 3) {
                logger.info(`Found ${exploits.length} exploits, terminating early`);
                break;
            }

            // Selection: Keep top performers
            const survivors = this.selectTopPerformers();

            // Crossover: Combine successful techniques
            const offspring = this.crossover(survivors);

            // Mutation: Introduce variations
            const mutated = this.mutate(offspring);

            // New generation
            this.population = [...survivors, ...mutated];

            // Add some fresh random payloads to maintain diversity
            while (this.population.length < this.populationSize) {
                this.population.push(this.generateRandomPayload(param, gen));
            }
        }

        // Sort by fitness and return results
        const sortedPayloads = this.population.sort((a, b) => {
            const fitnessA = this.fitnessScores.get(a.id)?.score || 0;
            const fitnessB = this.fitnessScores.get(b.id)?.score || 0;
            return fitnessB - fitnessA;
        });

        return {
            bestPayloads: sortedPayloads.slice(0, 10),
            exploits,
            generations,
            totalTests: this.fitnessScores.size,
            highestFitness,
        };
    }

    /**
     * Establish baseline response for comparison
     */
    private async establishBaseline(endpoint: Endpoint, param: Parameter): Promise<void> {
        const request: HttpRequest = {
            method: endpoint.method,
            url: endpoint.url,
            headers: endpoint.headers || {},
            data: { [param.name]: param.value },
        };

        try {
            const response = await this.httpClient.request(request);
            this.baselineResponses.set(endpoint.url, response);
            logger.debug(`Baseline established: ${response.status}, ${response.body.length} bytes, ${response.duration}ms`);
        } catch (error) {
            logger.debug('Failed to establish baseline');
        }
    }

    /**
     * Initialize population with diverse seed payloads
     */
    private initializePopulation(param: Parameter): void {
        this.population = [];
        this.fitnessScores.clear();

        // Seed payloads based on parameter type
        const seeds = this.generateSeedPayloads(param);

        for (const seed of seeds) {
            this.population.push({
                id: uuidv4(),
                value: seed,
                encoding: 'raw',
                wrapper: 'none',
                injectionLayer: 'none',
                mutations: ['seed'],
                generation: 0,
            });
        }

        // Add encoded variants
        for (const seed of seeds.slice(0, 10)) {
            const encodings: Payload['encoding'][] = ['url', 'base64', 'unicode'];
            for (const encoding of encodings) {
                this.population.push({
                    id: uuidv4(),
                    value: seed,
                    encoding,
                    wrapper: 'none',
                    injectionLayer: 'none',
                    mutations: ['seed', encoding],
                    generation: 0,
                });
            }
        }

        logger.debug(`Initialized population with ${this.population.length} payloads`);
    }

    /**
     * Generate seed payloads based on parameter type
     */
    private generateSeedPayloads(param: Parameter): unknown[] {
        const seeds: unknown[] = [];

        // Numeric attacks
        if (param.type === 'number' || /price|amount|qty|quantity|total/i.test(param.name)) {
            seeds.push(
                0, -1, -0.01, 0.001, 0.00001,
                -999999, 999999999,
                2147483647, -2147483648, // Int32 boundaries
                9007199254740991, // JS MAX_SAFE_INTEGER
                Number.MAX_VALUE,
                1e308, 1e-308,
                NaN, Infinity, -Infinity,
                '0', '-1', '0.00',
                '0x0', '0b0', '0o0', // Different numeric bases
                '1e999', '-1e999',
                '   0   ', '0\n', '\t0',
            );
        }

        // String attacks
        if (param.type === 'string') {
            seeds.push(
                '', ' ', '\n', '\r\n', '\t',
                'null', 'undefined', 'NaN',
                'true', 'false',
                '<script>alert(1)</script>',
                '${7*7}', '{{7*7}}', // Template injection
                "' OR '1'='1", '"; DROP TABLE--', // SQL injection
                '{"$gt":""}', // NoSQL injection
            );
        }

        // Discount/coupon attacks
        if (/discount|coupon|promo|code/i.test(param.name)) {
            seeds.push(
                '', 'INVALID', 'TEST',
                '100%OFF', '-100', '-50',
                'ADMIN', 'DEBUG', 'INTERNAL',
                Array(100).fill('CODE').join(','), // Stacking
                param.value, // Replay same code
            );
        }

        // Array/object attacks
        seeds.push(
            [], [null], [0], [-1],
            {}, { value: 0 }, { price: 0 },
            [param.value, param.value], // Duplicate
            null, undefined,
        );

        return seeds;
    }

    /**
     * Evaluate fitness of a payload
     */
    private async evaluateFitness(
        endpoint: Endpoint,
        param: Parameter,
        payload: Payload
    ): Promise<FitnessResult> {
        const encodedValue = this.encodePayload(payload);

        const request: HttpRequest = {
            method: endpoint.method,
            url: endpoint.url,
            headers: endpoint.headers || {},
            data: { [param.name]: encodedValue },
        };

        let response: HttpResponse;
        try {
            response = await this.httpClient.request(request);
        } catch (error) {
            return {
                score: 0,
                factors: {
                    statusProgression: 0,
                    errorUniqueness: 0,
                    timingAnomaly: 0,
                    sizeDeviation: 0,
                    payloadReflection: 0,
                    headerWeakening: 0,
                    transactionSuccess: 0,
                },
                response: { status: 0, statusText: '', body: '', headers: {}, duration: 0, data: null },
            };
        }

        const baseline = this.baselineResponses.get(endpoint.url);
        const factors = {
            statusProgression: this.scoreStatusProgression(response),
            errorUniqueness: this.scoreErrorUniqueness(response),
            timingAnomaly: this.scoreTimingAnomaly(response, baseline),
            sizeDeviation: this.scoreSizeDeviation(response, baseline),
            payloadReflection: this.scorePayloadReflection(response, payload),
            headerWeakening: this.scoreHeaderWeakening(response, baseline),
            transactionSuccess: this.scoreTransactionSuccess(response),
        };

        const score = Object.values(factors).reduce((a, b) => a + b, 0);

        return { score: Math.min(score, 1), factors, response };
    }

    /**
     * Score based on response status (200 is good, 400 better than 403)
     */
    private scoreStatusProgression(response: HttpResponse): number {
        if (response.status === 200 || response.status === 201) return 0.2;
        if (response.status === 400 || response.status === 422) return 0.05; // Validation error = interesting
        if (response.status === 500) return 0.1; // Server error = potential exploit
        return 0;
    }

    /**
     * Score based on unique error messages (new code paths)
     */
    private scoreErrorUniqueness(response: HttpResponse): number {
        const fingerprint = this.extractErrorFingerprint(response);
        if (fingerprint && !this.errorFingerprints.has(fingerprint)) {
            this.errorFingerprints.add(fingerprint);
            return 0.15; // Discovered new error type
        }
        return 0;
    }

    /**
     * Extract error fingerprint for uniqueness check
     */
    private extractErrorFingerprint(response: HttpResponse): string | null {
        const body = response.body.toLowerCase();

        // Extract error message patterns
        const patterns = [
            /error[:\s]+([^"<\n]+)/i,
            /message[:\s]+([^"<\n]+)/i,
            /exception[:\s]+([^"<\n]+)/i,
        ];

        for (const pattern of patterns) {
            const match = body.match(pattern);
            if (match) {
                return match[1].substring(0, 100);
            }
        }

        return null;
    }

    /**
     * Score based on response timing anomalies
     */
    private scoreTimingAnomaly(response: HttpResponse, baseline?: HttpResponse): number {
        if (!baseline) return 0;
        const ratio = response.duration / baseline.duration;
        if (ratio > 2) return 0.1; // Much slower = deeper processing
        if (ratio > 1.5) return 0.05;
        return 0;
    }

    /**
     * Score based on response size deviation
     */
    private scoreSizeDeviation(response: HttpResponse, baseline?: HttpResponse): number {
        if (!baseline) return 0;
        const diff = Math.abs(response.body.length - baseline.body.length);
        if (diff > baseline.body.length * 0.5) return 0.1;
        if (diff > 1000) return 0.05;
        return 0;
    }

    /**
     * Score if payload appears in response (reflection)
     */
    private scorePayloadReflection(response: HttpResponse, payload: Payload): number {
        const payloadStr = String(payload.value);
        if (response.body.includes(payloadStr)) return 0.1;
        return 0;
    }

    /**
     * Score if security headers weakened
     */
    private scoreHeaderWeakening(response: HttpResponse, baseline?: HttpResponse): number {
        if (!baseline) return 0;

        const securityHeaders = ['content-security-policy', 'x-frame-options', 'x-xss-protection'];
        let score = 0;

        for (const header of securityHeaders) {
            const hadHeader = header in baseline.headers;
            const hasHeader = header in response.headers;
            if (hadHeader && !hasHeader) score += 0.05;
        }

        return score;
    }

    /**
     * Score for transaction/order success indicators
     */
    private scoreTransactionSuccess(response: HttpResponse): number {
        const body = response.body.toLowerCase();
        const successPatterns = [
            'order_id', 'order_number', 'confirmation',
            'thank you', 'success', 'payment_id',
            'transaction_id', 'receipt',
        ];

        for (const pattern of successPatterns) {
            if (body.includes(pattern)) return 0.3;
        }
        return 0;
    }

    /**
     * Encode payload based on encoding type
     */
    private encodePayload(payload: Payload): unknown {
        let value = payload.value;

        // Apply encoding
        if (typeof value === 'string') {
            switch (payload.encoding) {
                case 'url':
                    value = encodeURIComponent(value);
                    break;
                case 'base64':
                    value = Buffer.from(value).toString('base64');
                    break;
                case 'unicode':
                    value = this.toUnicodeEscape(value);
                    break;
                case 'double_url':
                    value = encodeURIComponent(encodeURIComponent(value));
                    break;
            }
        }

        // Apply wrapper
        switch (payload.wrapper) {
            case 'array':
                value = [value];
                break;
            case 'object':
                value = { value };
                break;
            case 'nested_array':
                value = [[value]];
                break;
            case 'string':
                value = String(value);
                break;
        }

        return value;
    }

    /**
     * Convert string to unicode escape sequences
     */
    private toUnicodeEscape(str: string): string {
        return str.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
    }

    /**
     * Select top performing payloads
     */
    private selectTopPerformers(): Payload[] {
        const sorted = this.population.sort((a, b) => {
            const fitnessA = this.fitnessScores.get(a.id)?.score || 0;
            const fitnessB = this.fitnessScores.get(b.id)?.score || 0;
            return fitnessB - fitnessA;
        });

        return sorted.slice(0, Math.floor(this.population.length * this.survivalRate));
    }

    /**
     * Crossover: Combine techniques from two parents
     */
    private crossover(parents: Payload[]): Payload[] {
        const offspring: Payload[] = [];

        for (let i = 0; i < parents.length - 1; i += 2) {
            if (Math.random() > this.crossoverRate) continue;

            const parent1 = parents[i];
            const parent2 = parents[i + 1];

            // Child 1: Value from parent1, encoding from parent2
            offspring.push({
                id: uuidv4(),
                value: parent1.value,
                encoding: parent2.encoding,
                wrapper: parent1.wrapper,
                injectionLayer: parent2.injectionLayer,
                mutations: [...parent1.mutations, 'crossover'],
                generation: Math.max(parent1.generation, parent2.generation) + 1,
            });

            // Child 2: Value from parent2, wrapper from parent1
            offspring.push({
                id: uuidv4(),
                value: parent2.value,
                encoding: parent1.encoding,
                wrapper: parent2.wrapper,
                injectionLayer: parent1.injectionLayer,
                mutations: [...parent2.mutations, 'crossover'],
                generation: Math.max(parent1.generation, parent2.generation) + 1,
            });
        }

        return offspring;
    }

    /**
     * Mutate payloads
     */
    private mutate(payloads: Payload[]): Payload[] {
        return payloads.map(payload => {
            if (Math.random() > this.mutationRate) return payload;

            const mutated = { ...payload, id: uuidv4(), mutations: [...payload.mutations] };
            const strategy = this.selectMutationStrategy();

            switch (strategy) {
                case 'encoding':
                    mutated.encoding = this.randomEncoding();
                    mutated.mutations.push('mut_encoding');
                    break;
                case 'wrapper':
                    mutated.wrapper = this.randomWrapper();
                    mutated.mutations.push('mut_wrapper');
                    break;
                case 'boundary':
                    mutated.value = this.mutateBoundary(payload.value);
                    mutated.mutations.push('mut_boundary');
                    break;
                case 'injection':
                    mutated.injectionLayer = this.randomInjection();
                    mutated.value = this.addInjectionLayer(payload.value, mutated.injectionLayer);
                    mutated.mutations.push('mut_injection');
                    break;
            }

            return mutated;
        });
    }

    private selectMutationStrategy(): string {
        const strategies = ['encoding', 'wrapper', 'boundary', 'injection'];
        return strategies[Math.floor(Math.random() * strategies.length)];
    }

    private randomEncoding(): Payload['encoding'] {
        const encodings: Payload['encoding'][] = ['raw', 'url', 'base64', 'unicode', 'double_url'];
        return encodings[Math.floor(Math.random() * encodings.length)];
    }

    private randomWrapper(): Payload['wrapper'] {
        const wrappers: Payload['wrapper'][] = ['none', 'array', 'object', 'string', 'nested_array'];
        return wrappers[Math.floor(Math.random() * wrappers.length)];
    }

    private randomInjection(): Payload['injectionLayer'] {
        const layers: Payload['injectionLayer'][] = ['none', 'sql', 'nosql', 'template', 'command'];
        return layers[Math.floor(Math.random() * layers.length)];
    }

    private mutateBoundary(value: unknown): unknown {
        if (typeof value === 'number') {
            const mutations = [
                value + 0.00001,
                value - 0.00001,
                value * 2,
                value / 2,
                -value,
                Math.floor(value),
                Math.ceil(value),
            ];
            return mutations[Math.floor(Math.random() * mutations.length)];
        }
        return value;
    }

    private addInjectionLayer(value: unknown, layer: Payload['injectionLayer']): unknown {
        const strValue = String(value);
        switch (layer) {
            case 'sql':
                return `${strValue}' OR '1'='1`;
            case 'nosql':
                return { '$gt': strValue };
            case 'template':
                return `\${${strValue}}`;
            case 'command':
                return `${strValue}; ls -la`;
            default:
                return value;
        }
    }

    private generateRandomPayload(param: Parameter, generation: number): Payload {
        const seeds = this.generateSeedPayloads(param);
        const value = seeds[Math.floor(Math.random() * seeds.length)];

        return {
            id: uuidv4(),
            value,
            encoding: this.randomEncoding(),
            wrapper: this.randomWrapper(),
            injectionLayer: Math.random() > 0.7 ? this.randomInjection() : 'none',
            mutations: ['random'],
            generation,
        };
    }
}

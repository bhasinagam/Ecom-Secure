/**
 * Configuration Management
 * Handles loading and validation of scanner configuration
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
import { ScanConfig, DetectorModule, OutputFormat } from '../types';

export interface ConfigOptions {
    configPath?: string;
    envPrefix?: string;
}

const DEFAULT_CONFIG: ScanConfig = {
    targetUrl: '',
    modules: ['all'],
    depth: 2,
    timeout: 30000,
    concurrency: 5,
    rateLimit: 10,
    format: 'console',
    verbose: false,
    stealth: false,
    noVerify: false,
    model: 'google/gemini-2.0-flash-exp:free',
    exportHar: false,
};

const AVAILABLE_MODULES: DetectorModule[] = [
    'price', 'discount', 'quantity', 'session', 'payment', 'business', 'race', 'all'
];

const AVAILABLE_FORMATS: OutputFormat[] = ['console', 'json', 'html', 'markdown'];

export class Config {
    private config: ScanConfig;
    private configPath: string;

    constructor(options: ConfigOptions = {}) {
        this.configPath = options.configPath || path.join(process.cwd(), 'config', 'default.yml');
        this.config = { ...DEFAULT_CONFIG };
    }

    /**
     * Load configuration from file, environment, and CLI options
     */
    async load(cliOptions: Partial<ScanConfig> = {}): Promise<ScanConfig> {
        // Layer 1: Default config
        this.config = { ...DEFAULT_CONFIG };

        // Layer 2: Config file
        if (fs.existsSync(this.configPath)) {
            const fileConfig = await this.loadFromFile(this.configPath);
            this.config = { ...this.config, ...fileConfig };
        }

        // Layer 3: Environment variables
        const envConfig = this.loadFromEnv();
        this.config = { ...this.config, ...envConfig };

        // Layer 4: CLI options (highest priority)
        this.config = { ...this.config, ...cliOptions };

        // Validate
        this.validate();

        return this.config;
    }

    /**
     * Load configuration from YAML file
     */
    private async loadFromFile(filePath: string): Promise<Partial<ScanConfig>> {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const parsed = yaml.parse(content);
            return this.mapYamlToConfig(parsed);
        } catch (error) {
            console.warn(`Warning: Could not load config file ${filePath}`);
            return {};
        }
    }

    /**
     * Load configuration from environment variables
     */
    private loadFromEnv(): Partial<ScanConfig> {
        const env: Partial<ScanConfig> = {};

        if (process.env.OPENROUTER_API_KEY) {
            // API key is handled separately in LLMClient
        }

        if (process.env.LLM_MODEL) {
            env.model = process.env.LLM_MODEL;
        }

        if (process.env.SCAN_TIMEOUT) {
            env.timeout = parseInt(process.env.SCAN_TIMEOUT, 10);
        }

        if (process.env.RATE_LIMIT_RPS) {
            env.rateLimit = parseInt(process.env.RATE_LIMIT_RPS, 10);
        }

        if (process.env.MAX_CONCURRENCY) {
            env.concurrency = parseInt(process.env.MAX_CONCURRENCY, 10);
        }

        if (process.env.HTTP_PROXY || process.env.SOCKS_PROXY) {
            env.proxy = process.env.HTTP_PROXY || process.env.SOCKS_PROXY;
        }

        return env;
    }

    /**
     * Map YAML structure to ScanConfig
     */
    private mapYamlToConfig(parsed: Record<string, unknown>): Partial<ScanConfig> {
        const config: Partial<ScanConfig> = {};

        if (parsed.scanner) {
            const scanner = parsed.scanner as Record<string, unknown>;
            if (scanner.depth) config.depth = scanner.depth as number;
            if (scanner.timeout) config.timeout = scanner.timeout as number;
            if (scanner.concurrency) config.concurrency = scanner.concurrency as number;
            if (scanner.rateLimit) config.rateLimit = scanner.rateLimit as number;
        }

        if (parsed.llm) {
            const llm = parsed.llm as Record<string, unknown>;
            if (llm.model) config.model = llm.model as string;
        }

        if (parsed.output) {
            const output = parsed.output as Record<string, unknown>;
            if (output.format) config.format = output.format as OutputFormat;
        }

        if (parsed.modules) {
            config.modules = parsed.modules as DetectorModule[];
        }

        return config;
    }

    /**
     * Validate configuration
     */
    private validate(): void {
        // Validate modules
        for (const mod of this.config.modules) {
            if (!AVAILABLE_MODULES.includes(mod as DetectorModule)) {
                throw new Error(`Invalid module: ${mod}. Available: ${AVAILABLE_MODULES.join(', ')}`);
            }
        }

        // Validate format
        if (!AVAILABLE_FORMATS.includes(this.config.format)) {
            throw new Error(`Invalid format: ${this.config.format}. Available: ${AVAILABLE_FORMATS.join(', ')}`);
        }

        // Validate timeout
        if (this.config.timeout < 1000 || this.config.timeout > 120000) {
            throw new Error('Timeout must be between 1000ms and 120000ms');
        }

        // Validate concurrency
        if (this.config.concurrency < 1 || this.config.concurrency > 100) {
            throw new Error('Concurrency must be between 1 and 100');
        }

        // Validate rate limit
        if (this.config.rateLimit < 1 || this.config.rateLimit > 100) {
            throw new Error('Rate limit must be between 1 and 100 RPS');
        }
    }

    /**
     * Get current configuration
     */
    get(): ScanConfig {
        return { ...this.config };
    }

    /**
     * Update configuration
     */
    update(updates: Partial<ScanConfig>): void {
        this.config = { ...this.config, ...updates };
        this.validate();
    }

    /**
     * Expand 'all' module to individual modules
     */
    getExpandedModules(): DetectorModule[] {
        if (this.config.modules.includes('all')) {
            return AVAILABLE_MODULES.filter(m => m !== 'all');
        }
        return this.config.modules as DetectorModule[];
    }

    /**
     * Check if a specific module is enabled
     */
    isModuleEnabled(module: DetectorModule): boolean {
        return this.config.modules.includes('all') || this.config.modules.includes(module);
    }
}

export const config = new Config();

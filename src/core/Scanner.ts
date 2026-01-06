import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
    ScanConfig,
    CheckoutFlow,
    AttackSurface,
    DetectorResult,
    PlatformDetectionResult,
    Endpoint,
    Vulnerability,
    ScanResult,
    Severity
} from '../types';
import { logger } from './Logger';
import { CheckoutFlowCrawler } from '../reconnaissance/Crawler';
import { TechStackFingerprint } from '../reconnaissance/TechStackFingerprint';
import { ParameterExtractor } from '../reconnaissance/ParameterExtractor';
import { TrafficAnalyzer } from '../reconnaissance/TrafficAnalyzer';
import { BehaviorAnalyzer } from '../reconnaissance/BehaviorAnalyzer';
import { AttackSurfaceMapper } from '../threat-modeling/AttackSurfaceMapper';
import { DetectorRegistry } from '../detectors/base/DetectorRegistry';
import { VulnerabilityVerifier } from '../agent/VulnerabilityVerifier';
import { MLAnomalyDetector } from '../agent/MLAnomalyDetector'; // NEW
import { AdaptiveRateLimiter } from './AdaptiveRateLimiter'; // NEW

export class Scanner extends EventEmitter {
    private config: ScanConfig;
    private scanId: string;
    private startTime: Date;
    private checkoutFlows: CheckoutFlow[] = [];
    private attackSurface: AttackSurface | null = null;
    private platform: PlatformDetectionResult | null = null;
    private findings: DetectorResult[] = [];
    private endpoints: Endpoint[] = [];
    private requestCount: number = 0;

    // Components
    private crawler: CheckoutFlowCrawler;
    private fingerprinter: TechStackFingerprint;
    private parameterExtractor: ParameterExtractor;
    private trafficAnalyzer: TrafficAnalyzer;
    private behaviorAnalyzer: BehaviorAnalyzer; // NEW
    private attackMapper: AttackSurfaceMapper;
    private detectorRegistry: DetectorRegistry;
    private verifier: VulnerabilityVerifier;
    private mlDetector: MLAnomalyDetector; // NEW
    private rateLimiter: AdaptiveRateLimiter; // NEW

    constructor(config: ScanConfig) {
        super();
        this.config = config;
        this.scanId = uuidv4();
        this.startTime = new Date();

        // Initialize components
        this.crawler = new CheckoutFlowCrawler(config);
        this.fingerprinter = new TechStackFingerprint();
        this.parameterExtractor = new ParameterExtractor();
        this.trafficAnalyzer = new TrafficAnalyzer();
        this.behaviorAnalyzer = new BehaviorAnalyzer();
        this.attackMapper = new AttackSurfaceMapper();
        this.detectorRegistry = new DetectorRegistry(config);
        this.verifier = new VulnerabilityVerifier(config);
        this.mlDetector = new MLAnomalyDetector();
        this.rateLimiter = new AdaptiveRateLimiter(config.rateLimit || 10);
    }

    /**
     * Execute the full scanning pipeline
     */
    async scan(target: string): Promise<ScanResult> {
        logger.info(`Starting scan ${this.scanId} for ${target}`);
        this.emit('phase', 'initialization');

        try {
            // Phase 1: Reconnaissance & Mapping
            this.emit('phase', 'reconnaissance');
            this.emit('progress', 'Crawling site structure...');
            await this.runReconnaissance(target);

            // Phase 2: Threat Modeling
            this.emit('phase', 'threat-modeling');
            this.emit('progress', 'Building attack surface map...');
            await this.runThreatModeling();

            // Phase 3: Active Vulnerability Probing
            this.emit('phase', 'probing');
            this.emit('progress', 'Running vulnerability detectors...');
            await this.runActiveProbing();

            // Phase 4: AI-Powered Verification
            if (this.config.aiVerification !== false) {
                this.emit('phase', 'verification');
                this.emit('progress', 'Running AI verification...');
                await this.runAIVerification();
            }

            // Phase 5: Report Generation
            this.emit('phase', 'reporting');
            const result = this.generateResult(target);

            return result;

        } catch (error) {
            logger.error('Scan failed', error);
            throw error;
        } finally {
            // Cleanup
            this.mlDetector.dispose();
        }
    }

    /**
     * Phase 1: Reconnaissance & Mapping
     */
    private async runReconnaissance(target: string): Promise<void> {
        // Step 1: Crawl and discover checkout flows
        this.checkoutFlows = await this.crawler.discover(target);
        logger.info(`Discovered ${this.checkoutFlows.length} checkout flows`);

        // Collect all endpoints
        for (const flow of this.checkoutFlows) {
            this.endpoints.push(...flow.endpoints);
        }

        // Step 2: Analyze HTTP traffic for additional parameters
        const httpTraffic = this.crawler.getHttpTraffic();
        logger.debug(`Captured ${httpTraffic.length} HTTP requests during crawl`);

        const trafficEndpoints = this.trafficAnalyzer.analyzeTraffic(httpTraffic);
        logger.info(`Extracted ${trafficEndpoints.length} endpoints from HTTP traffic`);

        // Merge traffic-discovered endpoints with form-discovered flows
        if (trafficEndpoints.length > 0) {
            this.checkoutFlows = this.trafficAnalyzer.mergeWithFlows(
                this.checkoutFlows,
                trafficEndpoints
            );
            logger.info(`After merge: ${this.checkoutFlows.length} flows with enhanced parameters`);

            // Update endpoints list
            for (const extracted of trafficEndpoints) {
                if (!this.endpoints.find(e => e.url === extracted.endpoint.url)) {
                    this.endpoints.push(extracted.endpoint);
                }
            }
        }

        // Step 2a: Behavior Analysis (State Machine)
        logger.info('Running behavioral state analysis...');
        const stateGraph = await this.behaviorAnalyzer.buildStateModel(httpTraffic);

        // Add behavioral findings
        if (stateGraph.bypasses.length > 0) {
            for (const bypass of stateGraph.bypasses) {
                this.findings.push({
                    detectorName: 'behavior-analyzer',
                    vulnerable: true,
                    type: bypass.type,
                    severity: bypass.severity as Severity,
                    confidence: 0.9,
                    endpoint: 'flow',
                    evidence: [
                        `Detected state bypass: ${bypass.description}`,
                        `Path: ${bypass.path.join(' -> ')}`
                    ],
                    impact: bypass.exploitability,
                    cvssScore: bypass.cvss
                });
            }
        }

        // Step 2b: Improve Rate Limiter
        // (Could use traffic stats to calibrate rate limiter here)

        // Step 2c: Train ML Anomaly Detector on crawl traffic (assumed normal)
        // Convert crawl traffic to simple response format for training
        const trainingData = httpTraffic.map(t => ({
            status: t.response?.status || 200,
            body: '', // We might not have body in simple traffic log, assume empty or update crawler
            headers: t.response?.headers || {},
            duration: 100, // Placeholder if not captured
            endpoint: t.url
        }));
        // NOTE: Real implementation would need full response bodies from crawler
        // For now, we skip training if data is insufficient

        // Step 3: Detect technology stack
        this.platform = await this.fingerprinter.detect(target, httpTraffic);
        logger.info(`Platform: ${this.platform.platform} (confidence: ${(this.platform.confidence * 100).toFixed(0)}%)`);

        // Step 4: Extract parameters from forms
        const formParams = await this.parameterExtractor.extractAll(this.checkoutFlows);
        logger.info(`Found ${formParams.length} form parameters`);

        // Log summary of all parameters found
        const allParamNames = new Set<string>();
        for (const flow of this.checkoutFlows) {
            for (const paramName of Object.keys(flow.parameters)) {
                allParamNames.add(paramName);
            }
        }
        logger.debug(`Total unique parameters discovered: ${allParamNames.size}`, {
            params: Array.from(allParamNames)
        });
    }

    /**
     * Phase 2: Threat Modeling
     */
    private async runThreatModeling(): Promise<void> {
        this.attackSurface = await this.attackMapper.analyze(
            this.checkoutFlows,
            this.platform!
        );

        logger.info(
            `Mapped ${this.attackSurface.endpoints.length} attack endpoints, ` +
            `${this.attackSurface.parameters.length} vulnerable parameters`
        );
    }

    /**
     * Phase 3: Active Vulnerability Probing
     */
    private async runActiveProbing(): Promise<void> {
        // Get enabled detectors
        const detectors = this.detectorRegistry.getEnabledDetectors(this.config.modules);

        logger.debug(`Starting active probing with ${detectors.length} detectors`);
        logger.debug(`Attack surface: ${this.attackSurface?.endpoints.length || 0} endpoints, ${this.attackSurface?.parameters.length || 0} parameters`);

        if (!this.attackSurface || this.attackSurface.endpoints.length === 0) {
            logger.warn('No attack surface endpoints found - detectors may not find vulnerabilities');
        }

        // Run each detector
        for (const detector of detectors) {
            this.emit('progress', `Running ${detector.name} detector...`);
            logger.debug(`Running detector: ${detector.name} (category: ${detector.category})`);

            try {
                const startTime = Date.now();
                const results = await detector.test(
                    this.attackSurface!,
                    this.platform!
                );
                const duration = Date.now() - startTime;

                logger.debug(`Detector ${detector.name} completed in ${duration}ms`, {
                    totalResults: results.length,
                    vulnerableResults: results.filter(r => r.vulnerable).length,
                    requests: detector.getRequestCount()
                });

                // Filter for potential vulnerabilities
                const vulnerabilities = results.filter(r => r.vulnerable);

                if (vulnerabilities.length > 0) {
                    logger.info(`[${detector.name}] Found ${vulnerabilities.length} vulnerabilities!`);
                    vulnerabilities.forEach(v => {
                        logger.debug(`  - ${v.type}: ${v.parameter} @ ${v.endpoint} (confidence: ${v.confidence})`);
                    });
                } else {
                    logger.debug(`[${detector.name}] No vulnerabilities found`);
                }

                this.findings.push(...vulnerabilities);
                this.requestCount += detector.getRequestCount();

            } catch (error) {
                logger.error(`Detector ${detector.name} failed`, error);
                logger.debug(`Detector ${detector.name} error details:`, {
                    errorMessage: error instanceof Error ? error.message : 'Unknown',
                    errorStack: error instanceof Error ? error.stack : 'N/A'
                });
            }
        }

        logger.info(`Probing complete. Found ${this.findings.length} potential vulnerabilities`);
        logger.debug(`Total requests made: ${this.requestCount}`);
    }

    /**
     * Phase 4: AI-Powered Verification
     */
    private async runAIVerification(): Promise<void> {
        if (this.findings.length === 0) {
            logger.info('No findings to verify');
            return;
        }

        for (const finding of this.findings) {
            // Only verify high/critical or low-confidence findings
            if (['CRITICAL', 'HIGH'].includes(finding.severity) || finding.confidence < 0.8) {
                const verification = await this.verifier.verify(finding);
                finding.aiVerification = verification;
            }
        }

        const verified = this.findings.filter(
            f => f.aiVerification?.isVulnerable
        );

        logger.info(`AI verified ${verified.length} vulnerabilities`);
    }

    /**
     * Generate the final scan result
     */
    private generateResult(target: string): ScanResult {
        const endTime = new Date();
        const duration = Math.round((endTime.getTime() - this.startTime.getTime()) / 1000);

        const vulnerabilities: Vulnerability[] = this.findings
            .filter(f => f.vulnerable)
            .map(f => ({
                type: f.type,
                severity: f.severity,
                confidence: f.confidence,
                parameter: f.parameter,
                endpoint: f.endpoint,
                evidence: f.evidence,
                impact: f.impact,
                cvssScore: f.cvssScore,
                aiVerification: f.aiVerification,
            }));

        return {
            scanId: this.scanId,
            target,
            startTime: this.startTime.toISOString(),
            endTime: endTime.toISOString(),
            duration,
            platform: this.platform,
            vulnerabilities,
            requestCount: this.requestCount,
        };
    }

    /**
     * Get scan ID
     */
    getScanId(): string {
        return this.scanId;
    }
}

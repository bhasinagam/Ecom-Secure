/**
 * EcomSecure Scanner - Type Definitions
 */

// ============================================================================
// Core Types
// ============================================================================

export interface ScanConfig {
    target?: string;
    targetUrl: string;
    modules: DetectorModule[];
    depth: number;
    timeout: number;
    concurrency: number;
    rateLimit: number;
    authToken?: string;
    authCookies?: string;
    proxy?: string;
    userAgent?: string;
    format: OutputFormat;
    outputPath?: string;
    outputFile?: string;
    verbose: boolean;
    stealth: boolean;
    noVerify: boolean;
    aiVerification?: boolean;
    model: string;
    exportHar: boolean;
}

export type OutputFormat = 'console' | 'json' | 'html' | 'markdown';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'NONE';

export type DetectorModule =
    | 'price'
    | 'discount'
    | 'quantity'
    | 'session'
    | 'payment'
    | 'business'
    | 'race'
    | 'api'
    | 'injection'
    | 'protocol'
    | 'ai'
    | 'fuzzing'
    | 'all';

// ============================================================================
// Reconnaissance Types
// ============================================================================

export interface CheckoutFlow {
    productUrl: string;
    endpoints: Endpoint[];
    parameters: Record<string, ParameterInfo>;
    stateTransitions: string[];
}

export interface Endpoint {
    url: string;
    method: string;
    type: EndpointType;
    parameters: Parameter[];
    headers: Record<string, string>;
    requiresAuth: boolean;
}

export type EndpointType = 'cart' | 'checkout' | 'payment' | 'order' | 'product' | 'api' | 'unknown';

export interface Parameter {
    name: string;
    value: unknown;
    type: ParameterType;
    location: ParameterLocation;
    validationObserved?: string;
    required?: boolean;
}

export type ParameterType = 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';
export type ParameterLocation = 'body' | 'query' | 'header' | 'cookie' | 'path';

export interface ParameterInfo {
    value: unknown;
    type: string;
    endpoint: string;
    method: string;
}

export interface PlatformDetectionResult {
    platform: EcommercePlatform;
    confidence: number;
    knownVulnerabilities: string[];
    signatures: PlatformSignature;
}

export type EcommercePlatform = 'shopify' | 'woocommerce' | 'magento' | 'prestashop' | 'custom';

export interface PlatformSignature {
    headers: string[];
    cookies: string[];
    urls: string[];
    html: string[];
    knownVulns: string[];
}

// ============================================================================
// Threat Modeling Types
// ============================================================================

export interface AttackSurface {
    endpoints: AttackEndpoint[];
    parameters: AttackParameter[];
    trustBoundaries: TrustBoundary[];
    dataFlows: DataFlow[];
}

export interface AttackEndpoint {
    endpoint: Endpoint;
    attackVectors: string[];
    riskScore: number;
}

export interface AttackParameter {
    parameter: Parameter;
    attackVectors: string[];
    exploitability: number;
}

export interface TrustBoundary {
    name: string;
    from: string;
    to: string;
    dataTypes: string[];
    validationPresent: boolean;
}

export interface DataFlow {
    source: string;
    destination: string;
    dataType: string;
    transformations: string[];
    canBeManipulated: boolean;
}

// ============================================================================
// Detector Types
// ============================================================================

export interface DetectorResult {
    detectorName: string;
    vulnerable: boolean;
    type: string;
    severity: Severity;
    confidence: number;
    parameter?: string;
    endpoint?: string;
    originalValue?: unknown;
    exploitValue?: unknown;
    evidence: string[];
    impact: string;
    cvssScore?: number;
    reproduction?: ReproductionSteps;
    aiVerification?: AIVerificationResult;
}

export interface ReproductionSteps {
    description: string;
    curlCommand?: string;
    pythonScript?: string;
    steps?: string[];
}

export interface TestResult {
    exploitable: boolean;
    orderCreated: boolean;
    confidence: number;
    evidence: string[];
    baselineRequest: SanitizedRequest;
    exploitRequest: SanitizedRequest;
    baselineResponse: SanitizedResponse;
    exploitResponse: SanitizedResponse;
}

export interface SanitizedRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
}

export interface SanitizedResponse {
    status: number;
    headers: Record<string, string>;
    body: string;
    duration: number;
}

// ============================================================================
// Fuzzing Types
// ============================================================================

export interface Payload {
    value: unknown;
    type: string;
    rationale: string;
    severity: Severity;
    likelihood?: number;
    attackType?: string;
    index?: number;
}

export interface FuzzingContext {
    platform: EcommercePlatform;
    parameterType: ParameterType;
    observedValidation?: string;
    previousSuccesses: Payload[];
}

export interface MutationResult {
    original: Payload;
    mutated: Payload;
    mutationType: string;
}

// ============================================================================
// AI/LLM Types
// ============================================================================

export interface LLMConfig {
    apiKey: string;
    baseUrl: string;
    model: string;
    temperature: number;
    maxTokens: number;
}

export interface LLMMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
}

export interface LLMResponse {
    content: string;
    model: string;
    usage: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    };
}

export interface AIVerificationResult {
    isVulnerable: boolean;
    confidence: number;
    severity: Severity;
    modelVerdicts: ModelVerdict[];
    reasoning: string;
    falsePositiveLikelihood: number;
    cvssScore?: number;
    exploitationSteps?: string[];
    businessImpact?: string;
}

export interface ModelVerdict {
    model: string;
    isVulnerable: boolean;
    confidence: number;
    severity: Severity;
    reasoning: string;
    cvssScore?: number;
    weight: number;
}

// ============================================================================
// Exploitation Types
// ============================================================================

export interface ExploitChain {
    name: string;
    steps: ExploitStep[];
    totalSeverity: Severity;
    successProbability: number;
}

export interface ExploitStep {
    order: number;
    action: string;
    request: SanitizedRequest;
    expectedResponse: string;
    actualResponse?: SanitizedResponse;
    success?: boolean;
}

export interface ProofOfConcept {
    title: string;
    description: string;
    curl: string;
    python: string;
    javascript?: string;
    impact: string;
}

export interface ImpactAssessment {
    cvssVector: string;
    cvssScore: number;
    severity: Severity;
    businessImpact: string;
    financialRisk: string;
    exploitability: string;
    remediationPriority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
}

// ============================================================================
// Reporting Types
// ============================================================================

export interface ScanReport {
    scanId: string;
    targetUrl: string;
    platform: PlatformDetectionResult;
    startTime: Date;
    endTime: Date;
    duration: number;
    config: Partial<ScanConfig>;
    summary: ScanSummary;
    vulnerabilities: VulnerabilityReport[];
    endpoints: Endpoint[];
    harData?: HARArchive;
}

export interface ScanSummary {
    totalRequests: number;
    endpointsTested: number;
    parametersFuzzed: number;
    vulnerabilitiesFound: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
}

export interface VulnerabilityReport {
    id: string;
    type: string;
    severity: Severity;
    confidence: number;
    cvssScore: number;
    title: string;
    description: string;
    endpoint: string;
    parameter: string;
    proofOfConcept: ProofOfConcept;
    impact: ImpactAssessment;
    reproduction: ReproductionSteps;
    aiVerification?: AIVerificationResult;
    harEntryId?: string;
}

export interface HARArchive {
    log: {
        version: string;
        creator: {
            name: string;
            version: string;
        };
        entries: HAREntry[];
    };
}

export interface HAREntry {
    id: string;
    startedDateTime: string;
    time: number;
    request: {
        method: string;
        url: string;
        httpVersion: string;
        headers: Array<{ name: string; value: string }>;
        queryString: Array<{ name: string; value: string }>;
        postData?: {
            mimeType: string;
            text: string;
        };
    };
    response: {
        status: number;
        statusText: string;
        httpVersion: string;
        headers: Array<{ name: string; value: string }>;
        content: {
            size: number;
            mimeType: string;
            text: string;
        };
    };
}

// ============================================================================
// Race Condition Types
// ============================================================================

export interface RaceConditionResult {
    vulnerable: boolean;
    type: RaceConditionType;
    severity: Severity;
    details: RaceConditionDetails;
    impact: string;
    reproduction: ReproductionSteps;
}

export type RaceConditionType = 'concurrent_checkout' | 'inventory_race' | 'coupon_race' | 'toctou';

export interface RaceConditionDetails {
    requestsSent: number;
    successfulOrders?: number;
    uniqueOrders?: number;
    timeWindow: number;
    orderIds?: string[];
    itemId?: string;
    availableStock?: number;
    itemsAddedToCarts?: number;
    oversold?: number;
}

// ============================================================================
// HTTP Types
// ============================================================================

export interface HttpRequest {
    method: string;
    url: string;
    headers?: Record<string, string>;
    data?: unknown;
    timeout?: number;
    proxy?: string;
}

export interface HttpResponse {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    data: unknown;
    body: string;
    duration: number;
}

// ============================================================================
// Session Types
// ============================================================================

export interface Session {
    id: string;
    cookies: string;
    cartId?: string;
    userId?: string;
    csrfToken?: string;
}

// ============================================================================
// Event Types
// ============================================================================

export type ScanPhase =
    | 'reconnaissance'
    | 'threat-modeling'
    | 'probing'
    | 'verification'
    | 'exploitation';

export interface ScanProgress {
    phase: ScanPhase;
    currentModule?: string;
    currentEndpoint?: string;
    progress: number;
    message: string;
}

export type ScanEventType =
    | 'scan:start'
    | 'scan:phase'
    | 'scan:progress'
    | 'scan:finding'
    | 'scan:error'
    | 'scan:complete';

export interface ScanEvent {
    type: ScanEventType;
    timestamp: Date;
    data: unknown;
}

// ============================================================================
// Additional Result Types
// ============================================================================

export interface ScanResult {
    scanId: string;
    target: string;
    startTime: string;
    endTime: string;
    duration: number;
    platform: PlatformDetectionResult | null;
    vulnerabilities: Vulnerability[];
    requestCount: number;
}

export interface Vulnerability {
    type: string;
    severity: Severity;
    confidence: number;
    parameter?: string;
    endpoint?: string;
    evidence: string[];
    impact: string;
    cvssScore?: number;
    aiVerification?: AIVerificationResult;
}

export type ReportFormat = 'json' | 'html' | 'markdown' | 'sarif';

export interface ReportOptions {
    format: ReportFormat;
    outputPath: string;
    includeEvidence: boolean;
    includeRemediation: boolean;
    includeReproduction: boolean;
}

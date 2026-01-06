/**
 * ML Anomaly Detector
 * Uses TensorFlow.js autoencoder to detect zero-day vulnerabilities
 * 
 * SECURITY INSIGHT: Train on "normal" responses, flag deviations.
 * Catches 0-days that don't match known vulnerability patterns.
 */

// Static import removed to support dynamic loading
// import * as tf from '@tensorflow/tfjs-node';
import { logger } from '../core/Logger';

// Dynamic type definition for TF
let tf: any;

// Try backends in order of performance: GPU -> Node (CPU) -> Pure JS
try {
    tf = require('@tensorflow/tfjs-node-gpu');
    logger.info('MLAnomalyDetector: Using TensorFlow GPU backend (CUDA/cuDNN accelerated)');
} catch (gpuError: any) {
    logger.warn('MLAnomalyDetector: Failed to load tensorflow/tfjs-node-gpu. ' + gpuError.message);
    try {
        tf = require('@tensorflow/tfjs-node');
        logger.info('MLAnomalyDetector: Using TensorFlow Node backend (Native CPU accelerated)');
    } catch (nodeError: any) {
        try {
            logger.warn('MLAnomalyDetector: Failing back to tensorflow/tfjs (pure JS/CPU). ' + nodeError.message);
            tf = require('@tensorflow/tfjs');
            logger.info('MLAnomalyDetector: Using TensorFlow Pure JS backend (CPU only - slower)');
        } catch (e) {
            logger.error('MLAnomalyDetector: Failed to load ANY TensorFlow backend.');
            tf = null;
        }
    }
}

interface Response {
    status: number;
    body: string;
    headers: Record<string, string>;
    duration: number;
    endpoint: string;
    redirects?: string[];
    size?: number;
}

interface AnomalyScore {
    score: number;
    confidence: number;
    suspiciousFeatures?: string[];
    reasoning?: string;
}

interface TrainingData {
    features: number[][];
    responses: Response[];
}

export class MLAnomalyDetector {
    private model: any = null; // Use current TF model type
    private threshold: number = 0;
    private featureSize: number = 15;
    private baselineStats: {
        meanDuration: number;
        stdDuration: number;
        meanSize: number;
        stdSize: number;
    } = { meanDuration: 0, stdDuration: 1, meanSize: 0, stdSize: 1 };

    constructor() {
        if (!tf) {
            logger.error('MLAnomalyDetector disabled: TensorFlow module missing');
        }
    }

    /**
     * Train on normal behavior responses
     */
    async trainOnNormalBehavior(responses: Response[]): Promise<void> {
        if (!tf) return;

        if (responses.length < 10) {
            logger.warn('MLAnomalyDetector: Need at least 10 responses for training');
            return;
        }

        logger.info(`MLAnomalyDetector: Training on ${responses.length} normal responses`);

        // Calculate baseline statistics
        this.calculateBaselineStats(responses);

        // Extract features
        const features = responses.map(r => this.extractFeatures(r));
        this.featureSize = features[0].length;

        // Build and train autoencoder
        this.model = this.buildAutoencoder();

        const xs = tf.tensor2d(features);

        await this.model.fit(xs, xs, {
            epochs: 50,
            batchSize: Math.min(32, Math.floor(responses.length / 2)),
            validationSplit: 0.2,
            shuffle: true,
            callbacks: {
                onEpochEnd: (epoch: number, logs: any) => {
                    if (epoch % 10 === 0) {
                        logger.debug(`Training epoch ${epoch}: loss=${logs?.loss?.toFixed(4)}`);
                    }
                }
            }
        });

        // Calculate reconstruction error threshold (95th percentile)
        const reconstructionErrors = await this.calculateReconstructionErrors(features);
        this.threshold = this.calculateThreshold(reconstructionErrors, 0.95);

        logger.info(`MLAnomalyDetector: Training complete. Threshold: ${this.threshold.toFixed(4)}`);

        xs.dispose();
    }

    /**
     * Calculate baseline statistics for normalization
     */
    private calculateBaselineStats(responses: Response[]): void {
        const durations = responses.map(r => r.duration);
        const sizes = responses.map(r => r.body.length);

        this.baselineStats = {
            meanDuration: this.mean(durations),
            stdDuration: this.std(durations) || 1,
            meanSize: this.mean(sizes),
            stdSize: this.std(sizes) || 1,
        };
    }

    /**
     * Build autoencoder neural network
     */
    private buildAutoencoder(): any {
        const inputDim = this.featureSize;
        const encodingDim = Math.max(4, Math.floor(inputDim / 3));

        // Encoder
        const input = tf.input({ shape: [inputDim] });

        let encoded = tf.layers.dense({
            units: Math.floor((inputDim + encodingDim) / 2),
            activation: 'relu'
        }).apply(input);

        encoded = tf.layers.dense({
            units: encodingDim,
            activation: 'relu'
        }).apply(encoded);

        // Decoder
        let decoded = tf.layers.dense({
            units: Math.floor((inputDim + encodingDim) / 2),
            activation: 'relu'
        }).apply(encoded);

        decoded = tf.layers.dense({
            units: inputDim,
            activation: 'sigmoid'
        }).apply(decoded);

        const autoencoder = tf.model({ inputs: input, outputs: decoded });

        autoencoder.compile({
            optimizer: tf.train.adam(0.001),
            loss: 'meanSquaredError'
        });

        return autoencoder;
    }

    /**
     * Detect anomaly in a response
     */
    async detectAnomaly(response: Response): Promise<AnomalyScore> {
        if (!tf || !this.model) {
            return { score: 0, confidence: 0, reasoning: 'Model not trained' };
        }

        const features = this.extractFeatures(response);
        const input = tf.tensor2d([features]);

        // Reconstruct using autoencoder
        const reconstruction = this.model.predict(input);
        const reconstructedArray = await reconstruction.array() as number[][];

        // Calculate reconstruction error
        const error = this.meanSquaredError(features, reconstructedArray[0]);

        // Cleanup tensors
        input.dispose();
        reconstruction.dispose();

        // Calculate anomaly score
        const normalizedError = error / this.threshold;
        const isAnomalous = error > this.threshold;

        if (isAnomalous) {
            const suspiciousFeatures = this.identifySuspiciousFeatures(features, reconstructedArray[0]);

            return {
                score: Math.min(normalizedError, 5), // Cap at 5x threshold
                confidence: this.calculateConfidence(error),
                suspiciousFeatures,
                reasoning: `Response deviates from normal patterns by ${(normalizedError * 100).toFixed(1)}%`
            };
        }

        return { score: normalizedError, confidence: 0 };
    }

    /**
     * Extract features from HTTP response (15+ features)
     */
    private extractFeatures(response: Response): number[] {
        const body = response.body || '';
        const bodyLower = body.toLowerCase();

        return [
            // Response characteristics (normalized 0-1)
            Math.min(response.status / 600, 1),          // 1. Status code
            Math.min(body.length / 100000, 1),            // 2. Body size
            this.normalize(response.duration, this.baselineStats.meanDuration, this.baselineStats.stdDuration), // 3. Duration

            // Content analysis
            this.countJSONKeys(body) / 100,               // 4. JSON complexity
            this.calculateEntropy(body) / 8,              // 5. Data entropy (max ~8 for random)
            Object.keys(response.headers).length / 20,    // 6. Header count

            // Security indicators
            this.hasSecurityHeaders(response.headers) ? 1 : 0, // 7. Security headers
            this.hasErrorKeywords(bodyLower) ? 1 : 0,     // 8. Error presence
            this.hasSuccessKeywords(bodyLower) ? 1 : 0,   // 9. Success indicators
            this.hasOrderId(bodyLower) ? 1 : 0,           // 10. Transaction indicator

            // Anomaly indicators
            this.hasStackTrace(body) ? 1 : 0,             // 11. Stack trace leak
            this.hasSensitiveData(body) ? 1 : 0,          // 12. Sensitive data
            this.hasReflection(body) ? 1 : 0,             // 13. Input reflection

            // Structure indicators
            body.includes('<html') ? 1 : 0,               // 14. HTML response
            body.startsWith('{') || body.startsWith('[') ? 1 : 0, // 15. JSON response
        ];
    }

    /**
     * Normalize value using z-score
     */
    private normalize(value: number, mean: number, std: number): number {
        const zScore = (value - mean) / std;
        // Sigmoid to get 0-1 range
        return 1 / (1 + Math.exp(-zScore));
    }

    /**
     * Calculate Shannon entropy (randomness) of data
     */
    private calculateEntropy(data: string): number {
        if (!data || data.length === 0) return 0;

        const freq = new Map<string, number>();
        for (const char of data.slice(0, 10000)) { // Sample first 10k chars
            freq.set(char, (freq.get(char) || 0) + 1);
        }

        let entropy = 0;
        const len = Math.min(data.length, 10000);
        for (const count of freq.values()) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }

    /**
     * Count keys in JSON response
     */
    private countJSONKeys(body: string): number {
        try {
            const data = JSON.parse(body);
            return this.countKeys(data);
        } catch {
            return 0;
        }
    }

    private countKeys(obj: unknown, depth: number = 0): number {
        if (depth > 5 || obj === null || typeof obj !== 'object') return 0;

        let count = Object.keys(obj as object).length;
        for (const value of Object.values(obj as object)) {
            count += this.countKeys(value, depth + 1);
        }
        return count;
    }

    /**
     * Check for security headers
     */
    private hasSecurityHeaders(headers: Record<string, string>): boolean {
        const securityHeaders = [
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'strict-transport-security'
        ];
        const headerKeys = Object.keys(headers).map(k => k.toLowerCase());
        return securityHeaders.some(h => headerKeys.includes(h));
    }

    /**
     * Check for error keywords
     */
    private hasErrorKeywords(body: string): boolean {
        const errorPatterns = /error|exception|failed|invalid|denied|forbidden|unauthorized/i;
        return errorPatterns.test(body);
    }

    /**
     * Check for success keywords
     */
    private hasSuccessKeywords(body: string): boolean {
        const successPatterns = /success|completed|confirmed|approved|created/i;
        return successPatterns.test(body);
    }

    /**
     * Check for order/transaction ID
     */
    private hasOrderId(body: string): boolean {
        return /order[_-]?id|transaction[_-]?id|confirmation|receipt/i.test(body);
    }

    /**
     * Check for stack trace leak
     */
    private hasStackTrace(body: string): boolean {
        return /at\s+\w+\.\w+\s*\(|Traceback|Exception in thread/i.test(body);
    }

    /**
     * Check for sensitive data patterns
     */
    private hasSensitiveData(body: string): boolean {
        const sensitivePatterns = /password|secret|api[_-]?key|token|credit[_-]?card|\b\d{16}\b|root:/i;
        return sensitivePatterns.test(body);
    }

    /**
     * Check for input reflection (potential XSS/injection)
     */
    private hasReflection(body: string): boolean {
        return /<script|javascript:|on\w+=/i.test(body);
    }

    /**
     * Calculate reconstruction errors for all training samples
     */
    async calculateReconstructionErrors(features: number[][]): Promise<number[]> {
        if (!tf || !this.model) return [];

        const errors: number[] = [];
        const xs = tf.tensor2d(features);
        const predictions = this.model.predict(xs);
        const predArray = await predictions.array() as number[][];

        for (let i = 0; i < features.length; i++) {
            errors.push(this.meanSquaredError(features[i], predArray[i]));
        }

        xs.dispose();
        predictions.dispose();

        return errors;
    }

    /**
     * Calculate threshold at given percentile
     */
    private calculateThreshold(errors: number[], percentile: number): number {
        const sorted = [...errors].sort((a, b) => a - b);
        const index = Math.floor(sorted.length * percentile);
        return sorted[index] || sorted[sorted.length - 1];
    }

    /**
     * Calculate confidence based on error magnitude
     */
    private calculateConfidence(error: number): number {
        // Higher error = higher confidence in anomaly
        const ratio = error / this.threshold;
        return Math.min(ratio / 3, 1); // Caps at 3x threshold = 100% confidence
    }

    /**
     * Identify which features contributed most to anomaly
     */
    private identifySuspiciousFeatures(original: number[], reconstructed: number[]): string[] {
        const featureNames = [
            'status_code', 'body_size', 'duration',
            'json_complexity', 'entropy', 'header_count',
            'security_headers', 'error_keywords', 'success_keywords',
            'order_id', 'stack_trace', 'sensitive_data',
            'input_reflection', 'html_response', 'json_response'
        ];

        const suspicious: string[] = [];
        for (let i = 0; i < original.length; i++) {
            const diff = Math.abs(original[i] - reconstructed[i]);
            if (diff > 0.3) { // Significant deviation
                suspicious.push(featureNames[i] || `feature_${i}`);
            }
        }

        return suspicious;
    }

    /**
     * Mean squared error calculation
     */
    private meanSquaredError(a: number[], b: number[]): number {
        let sum = 0;
        for (let i = 0; i < a.length; i++) {
            sum += Math.pow(a[i] - b[i], 2);
        }
        return sum / a.length;
    }

    private mean(arr: number[]): number {
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    private std(arr: number[]): number {
        const m = this.mean(arr);
        return Math.sqrt(arr.reduce((sum, x) => sum + Math.pow(x - m, 2), 0) / arr.length);
    }

    /**
     * Dispose of TensorFlow resources
     */
    dispose(): void {
        if (this.model) {
            this.model.dispose();
            this.model = null;
        }
    }
}

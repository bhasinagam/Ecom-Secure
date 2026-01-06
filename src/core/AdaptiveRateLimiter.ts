/**
 * Adaptive Rate Limiter & Stealth Engine
 * 
 * BLACKHAT INSIGHT: Static rate limits get blocked.
 * Dynamic adaptation (finding the edge) is how you stay undetectable.
 */

import { logger } from './Logger';

interface RateLimitConfig {
    initialRps: number;
    minRps: number;
    maxRps: number;
    adaptiveness: number; // 0-1, how quickly to adapt
}

export class AdaptiveRateLimiter {
    private currentRps: number;
    private config: RateLimitConfig;
    private requestTimestamps: number[] = [];
    private consecutiveErrors: number = 0;
    private blocked: boolean = false;
    private backoffUntil: number = 0;

    constructor(initialRps: number = 10) {
        this.config = {
            initialRps,
            minRps: 1,
            maxRps: 50,
            adaptiveness: 0.5
        };
        this.currentRps = initialRps;
    }

    /**
     * Wait before sending request to maintain rate limit
     */
    async waitForSlot(): Promise<void> {
        if (this.blocked) {
            const wait = Math.max(0, this.backoffUntil - Date.now());
            if (wait > 0) {
                logger.warn(`Rate limiter blocked. Waiting ${wait}ms`);
                await new Promise(r => setTimeout(r, wait));
            }
            this.blocked = false;
        }

        const now = Date.now();
        // Remove timestamps older than 1 second
        this.requestTimestamps = this.requestTimestamps.filter(t => t > now - 1000);

        if (this.requestTimestamps.length >= this.currentRps) {
            const oldest = this.requestTimestamps[0];
            const wait = 1000 - (now - oldest);
            if (wait > 0) {
                await new Promise(r => setTimeout(r, wait));
            }
        }

        this.requestTimestamps.push(Date.now());
    }

    /**
     * Process response feedback to adapt rate
     */
    ProcessResponse(status: number, duration: number): void {
        // Detect blocking signals
        if (status === 429 || status === 503) {
            this.handleBlockage();
            return;
        }

        // Detect timeouts/slowdowns (soft limiting)
        if (duration > 2000) {
            this.consecutiveErrors++;
            if (this.consecutiveErrors > 3) {
                this.decreaseRate();
                this.consecutiveErrors = 0;
            }
        } else {
            // Success - slowly recover or increase rate
            this.consecutiveErrors = 0;
            this.increaseRate();
        }
    }

    private handleBlockage(): void {
        logger.warn(`Rate limit hit! Backing off. Current RPS: ${this.currentRps.toFixed(1)}`);

        this.blocked = true;
        // Exponential backoff: 30s, 60s, etc.
        const backoffMs = 30000 + (Math.random() * 10000);
        this.backoffUntil = Date.now() + backoffMs;

        // Slash rate by half
        this.currentRps = Math.max(this.config.minRps, this.currentRps * 0.5);
    }

    private decreaseRate(): void {
        this.currentRps = Math.max(
            this.config.minRps,
            this.currentRps * 0.8
        );
        logger.debug(`Decreasing rate to ${this.currentRps.toFixed(1)} RPS`);
    }

    private increaseRate(): void {
        if (this.currentRps < this.config.maxRps) {
            // Additive increase (slowly probe limits)
            this.currentRps += 0.2 * this.config.adaptiveness;
        }
    }

    getCurrentRps(): number {
        return this.currentRps;
    }
}

/**
 * Rate Limiter Utility
 * Provides adaptive rate limiting for HTTP requests
 */

import Bottleneck from 'bottleneck';
import { logger } from '../core/Logger';

export interface RateLimiterOptions {
    requestsPerSecond?: number;
    maxConcurrent?: number;
    retryCount?: number;
    retryDelay?: number;
}

export class RateLimiter {
    private limiter: Bottleneck;
    private options: RateLimiterOptions;
    private failureCount: number = 0;
    private successCount: number = 0;
    private lastAdjustment: number = Date.now();
    private currentMinTime: number;

    constructor(options: RateLimiterOptions = {}) {
        this.options = {
            requestsPerSecond: options.requestsPerSecond || 10,
            maxConcurrent: options.maxConcurrent || 5,
            retryCount: options.retryCount || 3,
            retryDelay: options.retryDelay || 1000,
        };

        this.currentMinTime = 1000 / this.options.requestsPerSecond!;

        this.limiter = new Bottleneck({
            minTime: this.currentMinTime,
            maxConcurrent: this.options.maxConcurrent,
            reservoir: this.options.requestsPerSecond! * 10, // Allow burst
            reservoirRefreshAmount: this.options.requestsPerSecond!,
            reservoirRefreshInterval: 1000,
        });

        this.setupEvents();
    }

    /**
     * Setup limiter events for monitoring
     */
    private setupEvents(): void {
        this.limiter.on('failed', async (error, jobInfo) => {
            this.failureCount++;

            if (jobInfo.retryCount < this.options.retryCount!) {
                // Exponential backoff
                const delay = this.options.retryDelay! * Math.pow(2, jobInfo.retryCount);
                logger.warn(`Request failed, retrying in ${delay}ms`, {
                    retryCount: jobInfo.retryCount,
                    error: error.message
                });
                return delay;
            }

            return undefined;
        });

        this.limiter.on('done', () => {
            this.successCount++;
            this.adaptiveAdjust();
        });
    }

    /**
     * Adaptively adjust rate limit based on success/failure ratio
     */
    private adaptiveAdjust(): void {
        const now = Date.now();

        // Only adjust every 30 seconds
        if (now - this.lastAdjustment < 30000) {
            return;
        }

        const total = this.successCount + this.failureCount;
        if (total < 10) return; // Not enough data

        const failureRate = this.failureCount / total;

        if (failureRate > 0.1) {
            // More than 10% failures, slow down
            this.slowDown();
        } else if (failureRate < 0.02 && this.successCount > 50) {
            // Less than 2% failures with significant success, speed up
            this.speedUp();
        }

        // Reset counters
        this.failureCount = 0;
        this.successCount = 0;
        this.lastAdjustment = now;
    }

    /**
     * Slow down the rate limit
     */
    private slowDown(): void {
        const newMinTime = Math.min(this.currentMinTime * 1.5, 2000); // Max 0.5 RPS
        this.currentMinTime = newMinTime;

        this.limiter.updateSettings({ minTime: newMinTime });
        logger.warn(`Rate limit decreased to ${(1000 / newMinTime).toFixed(1)} RPS due to failures`);
    }

    /**
     * Speed up the rate limit
     */
    private speedUp(): void {
        const targetMinTime = 1000 / this.options.requestsPerSecond!;
        const newMinTime = Math.max(this.currentMinTime * 0.8, targetMinTime);
        this.currentMinTime = newMinTime;

        this.limiter.updateSettings({ minTime: newMinTime });
        logger.info(`Rate limit increased to ${(1000 / newMinTime).toFixed(1)} RPS`);
    }

    /**
     * Schedule a function with rate limiting
     */
    async schedule<T>(fn: () => Promise<T>): Promise<T> {
        return this.limiter.schedule(fn);
    }

    /**
     * Schedule with priority (higher = sooner)
     */
    async scheduleWithPriority<T>(priority: number, fn: () => Promise<T>): Promise<T> {
        return this.limiter.schedule({ priority }, fn);
    }

    /**
     * Get current rate limit status
     */
    getStatus(): { running: number; queued: number; rps: number } {
        const counts = this.limiter.counts();

        return {
            running: counts.RUNNING,
            queued: counts.QUEUED,
            rps: 1000 / this.currentMinTime,
        };
    }

    /**
     * Pause the limiter
     */
    pause(): void {
        this.limiter.stop({ dropWaitingJobs: false });
    }

    /**
     * Resume the limiter (re-create it)
     */
    resume(): void {
        // Bottleneck doesn't have a direct resume, but we can update settings
        this.limiter.updateSettings({
            reservoir: this.options.requestsPerSecond! * 10,
        });
    }

    /**
     * Stop and clear all pending jobs
     */
    async stop(): Promise<void> {
        await this.limiter.stop({ dropWaitingJobs: true });
    }
}

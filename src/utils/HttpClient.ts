/**
 * HTTP Client with Connection Pooling, Caching, and Rate Limiting
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import * as http from 'http';
import * as https from 'https';
import { LRUCache } from 'lru-cache';
import Bottleneck from 'bottleneck';
import { HttpRequest, HttpResponse, HAREntry } from '../types';
import { logger } from '../core/Logger';

export interface HttpClientOptions {
    timeout?: number;
    rateLimit?: number;
    concurrency?: number;
    proxy?: string;
    userAgent?: string;
    cookies?: string;
    authToken?: string;
}

export class HttpClient {
    private client: AxiosInstance;
    private cache: LRUCache<string, HttpResponse>;
    private rateLimiter: Bottleneck;
    private harEntries: HAREntry[] = [];
    private requestCount: number = 0;
    private options: HttpClientOptions;

    constructor(options: HttpClientOptions = {}) {
        this.options = options;

        // Connection pooling agents
        const httpAgent = new http.Agent({
            keepAlive: true,
            maxSockets: 50,
            maxFreeSockets: 10,
        });

        const httpsAgent = new https.Agent({
            keepAlive: true,
            maxSockets: 50,
            maxFreeSockets: 10,
        });

        // Create axios instance
        this.client = axios.create({
            timeout: options.timeout || 30000,
            httpAgent,
            httpsAgent,
            validateStatus: () => true, // Don't throw on any status code
            headers: {
                'User-Agent': options.userAgent || this.getDefaultUserAgent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                ...(options.cookies ? { 'Cookie': options.cookies } : {}),
                ...(options.authToken ? { 'Authorization': `Bearer ${options.authToken}` } : {}),
            },
        });

        // Response caching (5 minute TTL)
        this.cache = new LRUCache<string, HttpResponse>({
            max: 1000,
            ttl: 5 * 60 * 1000,
        });

        // Rate limiting
        const minTime = options.rateLimit ? 1000 / options.rateLimit : 100;
        this.rateLimiter = new Bottleneck({
            minTime,
            maxConcurrent: options.concurrency || 5,
        });

        // Add request/response interceptors for HAR recording
        this.setupInterceptors();
    }

    /**
     * Default User-Agent that mimics a real browser
     */
    private getDefaultUserAgent(): string {
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }

    /**
     * Setup interceptors for logging and HAR recording
     */
    private setupInterceptors(): void {
        this.client.interceptors.request.use(
            (config) => {
                (config as any).metadata = { startTime: Date.now() };
                return config;
            },
            (error) => Promise.reject(error)
        );

        this.client.interceptors.response.use(
            (response) => {
                const duration = Date.now() - (response.config as any).metadata?.startTime;
                logger.http(
                    response.config.method?.toUpperCase() || 'GET',
                    response.config.url || '',
                    response.status,
                    duration
                );
                return response;
            },
            (error) => {
                logger.error('HTTP request failed', error);
                return Promise.reject(error);
            }
        );
    }

    /**
     * Generate cache key for request
     */
    private generateCacheKey(req: HttpRequest): string {
        return `${req.method}:${req.url}:${JSON.stringify(req.data || '')}`;
    }

    /**
     * Execute HTTP request with rate limiting and caching
     */
    async request(req: HttpRequest): Promise<HttpResponse> {
        const cacheKey = this.generateCacheKey(req);

        // Check cache for GET requests
        if (req.method.toUpperCase() === 'GET' && this.cache.has(cacheKey)) {
            logger.debug(`Cache hit: ${req.url}`);
            return this.cache.get(cacheKey)!;
        }

        // Rate-limited execution
        const response = await this.rateLimiter.schedule(async () => {
            const startTime = Date.now();

            const axiosConfig: AxiosRequestConfig = {
                method: req.method as any,
                url: req.url,
                headers: req.headers,
                data: req.data,
                timeout: req.timeout || this.options.timeout,
            };

            // Add proxy if configured
            if (req.proxy || this.options.proxy) {
                axiosConfig.proxy = this.parseProxy(req.proxy || this.options.proxy!);
            }

            const axiosResponse = await this.client.request(axiosConfig);
            const duration = Date.now() - startTime;

            const httpResponse = this.convertResponse(axiosResponse, duration);

            // Record HAR entry
            this.recordHAREntry(req, httpResponse, startTime);

            this.requestCount++;

            return httpResponse;
        });

        // Cache successful GET responses
        if (req.method.toUpperCase() === 'GET' && response.status === 200) {
            this.cache.set(cacheKey, response);
        }

        return response;
    }

    /**
     * Convenience method for GET requests
     */
    async get(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
        return this.request({ method: 'GET', url, headers });
    }

    /**
     * Convenience method for POST requests
     */
    async post(url: string, data?: unknown, headers?: Record<string, string>): Promise<HttpResponse> {
        return this.request({
            method: 'POST',
            url,
            data,
            headers: { 'Content-Type': 'application/json', ...headers },
        });
    }

    /**
     * Convenience method for PUT requests
     */
    async put(url: string, data?: unknown, headers?: Record<string, string>): Promise<HttpResponse> {
        return this.request({
            method: 'PUT',
            url,
            data,
            headers: { 'Content-Type': 'application/json', ...headers },
        });
    }

    /**
     * Convenience method for DELETE requests
     */
    async delete(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
        return this.request({ method: 'DELETE', url, headers });
    }

    /**
     * Convert Axios response to HttpResponse
     */
    private convertResponse(axiosResponse: AxiosResponse, duration: number): HttpResponse {
        let body = '';
        if (typeof axiosResponse.data === 'string') {
            body = axiosResponse.data;
        } else if (axiosResponse.data) {
            body = JSON.stringify(axiosResponse.data);
        }

        return {
            status: axiosResponse.status,
            statusText: axiosResponse.statusText,
            headers: axiosResponse.headers as Record<string, string>,
            data: axiosResponse.data,
            body,
            duration,
        };
    }

    /**
     * Parse proxy URL into axios proxy config
     */
    private parseProxy(proxyUrl: string): { host: string; port: number; protocol: string } | false {
        try {
            const url = new URL(proxyUrl);
            return {
                host: url.hostname,
                port: parseInt(url.port, 10),
                protocol: url.protocol.replace(':', ''),
            };
        } catch {
            return false;
        }
    }

    /**
     * Record request/response for HAR export
     */
    private recordHAREntry(req: HttpRequest, res: HttpResponse, startTime: number): void {
        const entry: HAREntry = {
            id: `entry-${this.requestCount}`,
            startedDateTime: new Date(startTime).toISOString(),
            time: res.duration,
            request: {
                method: req.method,
                url: req.url,
                httpVersion: 'HTTP/1.1',
                headers: Object.entries(req.headers || {}).map(([name, value]) => ({ name, value })),
                queryString: this.parseQueryString(req.url),
                ...(req.data ? {
                    postData: {
                        mimeType: 'application/json',
                        text: typeof req.data === 'string' ? req.data : JSON.stringify(req.data),
                    }
                } : {}),
            },
            response: {
                status: res.status,
                statusText: res.statusText,
                httpVersion: 'HTTP/1.1',
                headers: Object.entries(res.headers || {}).map(([name, value]) => ({
                    name,
                    value: Array.isArray(value) ? value.join(', ') : String(value)
                })),
                content: {
                    size: res.body.length,
                    mimeType: res.headers['content-type'] || 'text/plain',
                    text: res.body,
                },
            },
        };

        this.harEntries.push(entry);
    }

    /**
     * Parse query string from URL
     */
    private parseQueryString(url: string): Array<{ name: string; value: string }> {
        try {
            const urlObj = new URL(url);
            return Array.from(urlObj.searchParams.entries()).map(([name, value]) => ({ name, value }));
        } catch {
            return [];
        }
    }

    /**
     * Get all HAR entries
     */
    getHAREntries(): HAREntry[] {
        return this.harEntries;
    }

    /**
     * Get request count
     */
    getRequestCount(): number {
        return this.requestCount;
    }

    /**
     * Clear cache
     */
    clearCache(): void {
        this.cache.clear();
    }

    /**
     * Update cookies
     */
    setCookies(cookies: string): void {
        this.client.defaults.headers.common['Cookie'] = cookies;
    }

    /**
     * Update auth token
     */
    setAuthToken(token: string): void {
        this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
}

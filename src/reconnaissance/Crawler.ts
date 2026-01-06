/**
 * Checkout Flow Crawler
 * Maps e-commerce site structure and checkout flows using Playwright
 */

import { chromium, Browser, BrowserContext, Page, Route, Request } from 'playwright';
import {
    ScanConfig,
    CheckoutFlow,
    Endpoint,
    EndpointType,
    Parameter,
    ParameterType,
    HAREntry,
    HARArchive
} from '../types';
import { logger } from '../core/Logger';
import { Validators } from '../utils/Validators';

interface HttpTrafficEntry {
    url: string;
    method: string;
    headers: Record<string, string>;
    postData?: string;
    resourceType: string;
    response?: {
        status: number;
        headers: Record<string, string>;
    };
}

export class CheckoutFlowCrawler {
    private browser: Browser | null = null;
    private config: ScanConfig;
    private visitedUrls: Set<string> = new Set();
    private httpTraffic: HttpTrafficEntry[] = [];
    private harEntries: HAREntry[] = [];
    private maxDepth: number;

    constructor(config: ScanConfig) {
        this.config = config;
        this.maxDepth = config.depth || 2;
    }

    /**
     * Discover checkout flows starting from target URL
     */
    async discover(targetUrl: string): Promise<CheckoutFlow[]> {
        // Normalize URL - add https:// if protocol is missing
        let normalizedUrl = targetUrl;
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = `https://${normalizedUrl}`;
        }

        const checkoutFlows: CheckoutFlow[] = [];

        try {
            this.browser = await chromium.launch({
                headless: true,
                args: [
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                ],
            });

            const context = await this.createContext();
            const page = await context.newPage();

            // Enable request interception
            await this.setupRequestInterception(context);

            // Navigate to homepage
            logger.info(`Navigating to ${normalizedUrl}`);
            await page.goto(normalizedUrl, {
                waitUntil: 'domcontentloaded',  // Faster than networkidle for heavy sites
                timeout: Math.max(this.config.timeout, 60000)  // At least 60 seconds
            });

            // Wait a bit more for dynamic content
            await page.waitForTimeout(3000);

            // Find product links
            const productLinks = await this.findProductLinks(page, normalizedUrl);
            logger.info(`Found ${productLinks.length} product pages`);

            // Trace checkout flow for first 5 products
            const productsToTest = productLinks.slice(0, 5);

            for (const productUrl of productsToTest) {
                try {
                    const flow = await this.traceCheckoutFlow(context, productUrl);
                    if (flow) {
                        checkoutFlows.push(flow);
                    }
                } catch (error) {
                    logger.warn(`Failed to trace checkout flow for ${productUrl}`, { error });
                }
            }

            await context.close();

        } finally {
            if (this.browser) {
                await this.browser.close();
            }
        }

        return checkoutFlows;
    }

    /**
     * Create browser context with anti-detection measures
     */
    private async createContext(): Promise<BrowserContext> {
        const extraHeaders: Record<string, string> = {};

        // Add authentication headers
        if (this.config.authCookies) {
            extraHeaders['Cookie'] = this.config.authCookies;
            logger.debug('Using provided authentication cookies');
        }

        if (this.config.authToken) {
            extraHeaders['Authorization'] = `Bearer ${this.config.authToken}`;
            logger.debug('Using provided auth token');
        }

        if (Object.keys(extraHeaders).length > 0) {
            logger.info('Authenticated session configured');
        } else {
            logger.debug('Running unauthenticated scan - checkout may require login');
        }

        return this.browser!.newContext({
            userAgent: this.config.userAgent || this.getRandomUserAgent(),
            viewport: { width: 1920, height: 1080 },
            locale: 'en-US',
            timezoneId: 'America/New_York',
            permissions: ['geolocation'],
            extraHTTPHeaders: extraHeaders,
        });
    }

    /**
     * Get random realistic user agent
     */
    private getRandomUserAgent(): string {
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ];
        return userAgents[Math.floor(Math.random() * userAgents.length)];
    }

    /**
     * Setup request interception for traffic analysis
     */
    private async setupRequestInterception(context: BrowserContext): Promise<void> {
        await context.route('**/*', async (route: Route) => {
            const request = route.request();

            // Record HTTP traffic
            this.recordRequest(request);

            // Continue the request
            await route.continue();
        });

        // Also capture responses
        context.on('response', async (response) => {
            const request = response.request();
            const entry = this.httpTraffic.find(t => t.url === request.url());
            if (entry) {
                entry.response = {
                    status: response.status(),
                    headers: response.headers(),
                };
            }
        });
    }

    /**
     * Record request for analysis
     */
    private recordRequest(request: Request): void {
        const entry: HttpTrafficEntry = {
            url: request.url(),
            method: request.method(),
            headers: request.headers(),
            postData: request.postData() || undefined,
            resourceType: request.resourceType(),
        };

        this.httpTraffic.push(entry);

        // Record HAR entry
        this.recordHAREntry(request);
    }

    /**
     * Record HAR entry
     */
    private recordHAREntry(request: Request): void {
        const entry: HAREntry = {
            id: `entry-${this.harEntries.length}`,
            startedDateTime: new Date().toISOString(),
            time: 0,
            request: {
                method: request.method(),
                url: request.url(),
                httpVersion: 'HTTP/1.1',
                headers: Object.entries(request.headers()).map(([name, value]) => ({ name, value })),
                queryString: this.parseQueryString(request.url()),
                ...(request.postData() ? {
                    postData: {
                        mimeType: 'application/json',
                        text: request.postData()!,
                    }
                } : {}),
            },
            response: {
                status: 0,
                statusText: '',
                httpVersion: 'HTTP/1.1',
                headers: [],
                content: { size: 0, mimeType: 'text/plain', text: '' },
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
     * Find product links on the page
     */
    private async findProductLinks(page: Page, baseUrl: string): Promise<string[]> {
        const links: string[] = [];
        const origin = new URL(baseUrl).origin;

        // Common product link patterns
        const productSelectors = [
            'a[href*="/product"]',
            'a[href*="/item"]',
            'a[href*="/p/"]',
            'a[href*="/products/"]',
            'a[href*="/shop/"]',
            '.product-card a',
            '.product-link',
            '[data-product-id] a',
            '.product-item a',
            '.product a',
        ];

        for (const selector of productSelectors) {
            try {
                const elements = await page.$$(selector);
                for (const el of elements) {
                    const href = await el.getAttribute('href');
                    if (href) {
                        const fullUrl = href.startsWith('http') ? href : `${origin}${href.startsWith('/') ? '' : '/'}${href}`;
                        if (Validators.isSameOrigin(fullUrl, baseUrl) && !links.includes(fullUrl)) {
                            links.push(fullUrl);
                        }
                    }
                }
            } catch {
                // Selector doesn't exist on this page
            }
        }

        // Deduplicate and limit
        return [...new Set(links)].slice(0, 20);
    }

    /**
     * Trace the complete checkout flow for a product
     */
    private async traceCheckoutFlow(context: BrowserContext, productUrl: string): Promise<CheckoutFlow | null> {
        const page = await context.newPage();

        const flow: CheckoutFlow = {
            productUrl,
            endpoints: [],
            parameters: {},
            stateTransitions: [],
        };

        try {
            // Navigate to product page
            await page.goto(productUrl, { waitUntil: 'networkidle' });
            flow.stateTransitions.push('start → product_page');

            // Try to add to cart
            const cartAdded = await this.tryAddToCart(page);
            if (cartAdded) {
                flow.stateTransitions.push('product_page → cart');
            }

            // Navigate to cart
            const cartUrl = await this.navigateToCart(page);
            if (cartUrl) {
                flow.endpoints.push(await this.analyzeEndpoint(page, 'cart'));
            }

            // Try to proceed to checkout
            const checkoutReached = await this.proceedToCheckout(page);
            if (checkoutReached) {
                flow.stateTransitions.push('cart → checkout');
                flow.endpoints.push(await this.analyzeEndpoint(page, 'checkout'));

                // Extract checkout form parameters
                const formParams = await this.extractFormParameters(page);
                for (const param of formParams) {
                    flow.parameters[param.name] = {
                        value: param.value,
                        type: param.type,
                        endpoint: page.url(),
                        method: 'POST',
                    };
                }
            }

            // Extract payment-related parameters from network traffic
            const paymentParams = this.extractPaymentParameters();
            for (const [key, value] of Object.entries(paymentParams)) {
                flow.parameters[key] = value;
            }

        } catch (error) {
            logger.warn(`Error tracing checkout flow: ${productUrl}`, { error });
        } finally {
            await page.close();
        }

        return flow.endpoints.length > 0 ? flow : null;
    }

    /**
     * Try to add product to cart
     */
    private async tryAddToCart(page: Page): Promise<boolean> {
        const addToCartSelectors = [
            'button:has-text("Add to Cart")',
            'button:has-text("Add to Bag")',
            'button:has-text("Buy Now")',
            'button[name="add-to-cart"]',
            'button[data-action="add-to-cart"]',
            'input[type="submit"][value*="cart" i]',
            '.add-to-cart-button',
            '.add-to-cart',
            '#add-to-cart',
            '[data-add-to-cart]',
        ];

        for (const selector of addToCartSelectors) {
            try {
                const button = await page.$(selector);
                if (button) {
                    await button.click();
                    await page.waitForTimeout(2000); // Wait for cart update
                    return true;
                }
            } catch {
                // Try next selector
            }
        }

        return false;
    }

    /**
     * Navigate to cart page
     */
    private async navigateToCart(page: Page): Promise<string | null> {
        const origin = new URL(page.url()).origin;
        const cartUrls = [
            `${origin}/cart`,
            `${origin}/basket`,
            `${origin}/shopping-cart`,
            `${origin}/checkout/cart`,
        ];

        // Try clicking cart link first
        const cartLinkSelectors = [
            'a[href*="/cart"]',
            'a[href*="/basket"]',
            '.cart-link',
            '.mini-cart a',
            '[data-cart-trigger]',
        ];

        for (const selector of cartLinkSelectors) {
            try {
                const link = await page.$(selector);
                if (link) {
                    await link.click();
                    await page.waitForLoadState('networkidle');
                    return page.url();
                }
            } catch {
                // Try next selector
            }
        }

        // Try direct navigation
        for (const url of cartUrls) {
            try {
                const response = await page.goto(url, { waitUntil: 'networkidle' });
                if (response && response.ok()) {
                    return url;
                }
            } catch {
                // Try next URL
            }
        }

        return null;
    }

    /**
     * Proceed to checkout from cart
     */
    private async proceedToCheckout(page: Page): Promise<boolean> {
        const checkoutSelectors = [
            'a[href*="checkout"]',
            'button:has-text("Checkout")',
            'button:has-text("Proceed to Checkout")',
            'button:has-text("Continue to Checkout")',
            '.checkout-button',
            '#checkout-button',
            '[data-checkout]',
        ];

        for (const selector of checkoutSelectors) {
            try {
                const element = await page.$(selector);
                if (element) {
                    await element.click();
                    await page.waitForLoadState('networkidle');

                    // Verify we're on checkout
                    const url = page.url();
                    if (url.includes('checkout') || url.includes('payment')) {
                        return true;
                    }
                }
            } catch {
                // Try next selector
            }
        }

        return false;
    }

    /**
     * Analyze endpoint from current page
     */
    private async analyzeEndpoint(page: Page, type: EndpointType): Promise<Endpoint> {
        const url = page.url();
        const parameters = await this.extractFormParameters(page);

        return {
            url,
            method: 'GET',
            type,
            parameters,
            headers: {},
            requiresAuth: await this.detectAuthRequirement(page),
        };
    }

    /**
     * Extract form parameters from page
     */
    private async extractFormParameters(page: Page): Promise<Parameter[]> {
        const parameters: Parameter[] = [];

        // Find all form inputs
        const inputs = await page.$$('input, select, textarea');

        for (const input of inputs) {
            try {
                const name = await input.getAttribute('name');
                const type = await input.getAttribute('type');
                const value = await input.inputValue().catch(() => '');

                if (name) {
                    parameters.push({
                        name,
                        value,
                        type: this.inferParameterType(type, name, value),
                        location: 'body',
                        required: await input.getAttribute('required') !== null,
                    });
                }
            } catch {
                // Skip this input
            }
        }

        return parameters;
    }

    /**
     * Infer parameter type from input attributes and name
     */
    private inferParameterType(inputType: string | null, name: string, value: unknown): ParameterType {
        if (inputType === 'number') return 'number';
        if (inputType === 'checkbox') return 'boolean';

        const nameLower = name.toLowerCase();
        if (/price|amount|total|cost|qty|quantity|count/.test(nameLower)) {
            return 'number';
        }

        if (typeof value === 'number') return 'number';
        if (typeof value === 'boolean') return 'boolean';

        return 'string';
    }

    /**
     * Detect if page requires authentication
     */
    private async detectAuthRequirement(page: Page): Promise<boolean> {
        const url = page.url();
        const content = await page.content();

        // Check URL patterns
        if (/login|signin|auth/.test(url)) {
            return true;
        }

        // Check for login forms or messages
        const loginIndicators = [
            'input[type="password"]',
            'form[action*="login"]',
            'form[action*="signin"]',
        ];

        for (const selector of loginIndicators) {
            const element = await page.$(selector);
            if (element) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract payment parameters from HTTP traffic
     */
    private extractPaymentParameters(): Record<string, { value: unknown; type: string; endpoint: string; method: string }> {
        const params: Record<string, { value: unknown; type: string; endpoint: string; method: string }> = {};
        const paymentKeywords = ['amount', 'price', 'total', 'subtotal', 'quantity', 'discount', 'coupon', 'currency'];

        for (const entry of this.httpTraffic) {
            if (entry.postData && (
                entry.url.includes('/payment') ||
                entry.url.includes('/checkout') ||
                entry.url.includes('/order') ||
                entry.url.includes('/cart')
            )) {
                try {
                    const data = JSON.parse(entry.postData);

                    for (const key of paymentKeywords) {
                        if (data[key] !== undefined) {
                            params[key] = {
                                value: data[key],
                                type: typeof data[key],
                                endpoint: entry.url,
                                method: entry.method,
                            };
                        }
                    }
                } catch {
                    // Not JSON, skip
                }
            }
        }

        return params;
    }

    /**
     * Get all recorded HTTP traffic
     */
    getHttpTraffic(): HttpTrafficEntry[] {
        return this.httpTraffic;
    }

    /**
     * Get HAR data
     */
    getHARData(): HARArchive {
        return {
            log: {
                version: '1.2',
                creator: {
                    name: 'EcomSecure Scanner',
                    version: '1.0.0',
                },
                entries: this.harEntries,
            },
        };
    }
}

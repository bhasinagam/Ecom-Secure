/**
 * Technology Stack Fingerprinting
 * Detects e-commerce platform (Shopify, WooCommerce, Magento, etc.)
 */

import { PlatformDetectionResult, EcommercePlatform, PlatformSignature } from '../types';
import { logger } from '../core/Logger';

interface HttpTrafficEntry {
    url: string;
    method: string;
    headers: Record<string, string>;
    postData?: string;
    response?: {
        status: number;
        headers: Record<string, string>;
    };
}

const PLATFORM_SIGNATURES: Record<EcommercePlatform, PlatformSignature> = {
    shopify: {
        headers: ['X-Shopify-Stage', 'X-ShopId', 'X-Sorting-Hat-ShopId'],
        cookies: ['_shopify_s', '_shopify_y', 'cart', 'secure_customer_sig'],
        urls: ['/cart.js', '/cart/add.js', '/checkout', '*.myshopify.com', '/collections/', '/products/'],
        html: ['Shopify.theme', 'shopify-section', 'cdn.shopify.com', 'Shopify.checkout'],
        knownVulns: ['cart-attribute-injection', 'discount-stacking', 'checkout-manipulation'],
    },
    woocommerce: {
        headers: ['X-WC-Webhook-Resource', 'X-WP-Nonce'],
        cookies: ['woocommerce_cart_hash', 'woocommerce_items_in_cart', 'wp_woocommerce_session'],
        urls: ['/?wc-ajax=', '/wp-json/wc/', '/wc-api/', '/product-category/', '/checkout/'],
        html: ['class="woocommerce"', 'wp-content/plugins/woocommerce', 'wc-block-', 'woocommerce-message'],
        knownVulns: ['checkout-field-injection', 'coupon-replay', 'order-manipulation', 'rest-api-exposure'],
    },
    magento: {
        headers: ['X-Magento-Cache-Control', 'X-Magento-Cache-Debug', 'X-Magento-Vary'],
        cookies: ['PHPSESSID', 'mage-cache-storage', 'mage-cache-sessid', 'form_key'],
        urls: ['/checkout/cart/', '/rest/V1/', '/customer/section/', '/catalogsearch/'],
        html: ['Mage.Cookies', 'var BLANK_URL', 'mage/requirejs', 'Magento_'],
        knownVulns: ['quote-manipulation', 'payment-method-bypass', 'form-key-bypass', 'graphql-exposure'],
    },
    prestashop: {
        headers: ['Prestashop', 'X-Powered-By: PrestaShop'],
        cookies: ['PrestaShop-', 'PHPSESSID'],
        urls: ['/module/', '/index.php?controller=', '/order', '/cart'],
        html: ['prestashop', 'id_product', 'prestashop.modules', 'var prestashop'],
        knownVulns: ['cart-rule-abuse', 'order-state-manipulation', 'module-vulnerabilities'],
    },
    custom: {
        headers: [],
        cookies: [],
        urls: [],
        html: [],
        knownVulns: ['all'],
    },
};

export class TechStackFingerprint {
    private htmlContent: string = '';

    /**
     * Detect e-commerce platform from traffic and page content
     */
    async detect(targetUrl: string, httpTraffic: HttpTrafficEntry[]): Promise<PlatformDetectionResult> {
        const scores: Record<EcommercePlatform, number> = {
            shopify: 0,
            woocommerce: 0,
            magento: 0,
            prestashop: 0,
            custom: 0,
        };

        // Fetch HTML content
        await this.fetchHtml(targetUrl);

        // Score each platform
        for (const [platform, signature] of Object.entries(PLATFORM_SIGNATURES) as [EcommercePlatform, PlatformSignature][]) {
            if (platform === 'custom') continue;

            // Check HTTP headers
            scores[platform] += this.scoreHeaders(httpTraffic, signature.headers);

            // Check cookies
            scores[platform] += this.scoreCookies(httpTraffic, signature.cookies);

            // Check URL patterns
            scores[platform] += this.scoreUrls(httpTraffic, signature.urls);

            // Check HTML content
            scores[platform] += this.scoreHtml(signature.html);
        }

        // Find best match
        const sortedPlatforms = (Object.entries(scores) as [EcommercePlatform, number][])
            .filter(([platform]) => platform !== 'custom')
            .sort((a, b) => b[1] - a[1]);

        const [bestPlatform, bestScore] = sortedPlatforms[0];

        // If no clear winner, mark as custom
        if (bestScore < 20) {
            return {
                platform: 'custom',
                confidence: 0.5,
                knownVulnerabilities: PLATFORM_SIGNATURES.custom.knownVulns,
                signatures: PLATFORM_SIGNATURES.custom,
            };
        }

        const confidence = Math.min(bestScore / 100, 1.0);

        logger.info(`Detected platform: ${bestPlatform} (score: ${bestScore}, confidence: ${(confidence * 100).toFixed(0)}%)`);

        return {
            platform: bestPlatform,
            confidence,
            knownVulnerabilities: PLATFORM_SIGNATURES[bestPlatform].knownVulns,
            signatures: PLATFORM_SIGNATURES[bestPlatform],
        };
    }

    /**
     * Fetch HTML content from target
     */
    private async fetchHtml(url: string): Promise<void> {
        try {
            const response = await fetch(url);
            this.htmlContent = await response.text();
        } catch (error) {
            logger.warn('Failed to fetch HTML for fingerprinting', { error });
            this.htmlContent = '';
        }
    }

    /**
     * Score based on HTTP headers
     */
    private scoreHeaders(traffic: HttpTrafficEntry[], headerPatterns: string[]): number {
        let score = 0;

        for (const entry of traffic) {
            if (!entry.response?.headers) continue;

            const headers = entry.response.headers;
            for (const pattern of headerPatterns) {
                for (const [headerName, headerValue] of Object.entries(headers)) {
                    if (headerName.toLowerCase().includes(pattern.toLowerCase()) ||
                        (typeof headerValue === 'string' && headerValue.toLowerCase().includes(pattern.toLowerCase()))) {
                        score += 20;
                    }
                }
            }
        }

        return Math.min(score, 40); // Cap at 40
    }

    /**
     * Score based on cookies
     */
    private scoreCookies(traffic: HttpTrafficEntry[], cookiePatterns: string[]): number {
        let score = 0;

        for (const entry of traffic) {
            const cookieHeader = entry.headers['cookie'] || '';
            const setCookieHeader = entry.response?.headers['set-cookie'] || '';
            const allCookies = `${cookieHeader} ${setCookieHeader}`.toLowerCase();

            for (const pattern of cookiePatterns) {
                if (allCookies.includes(pattern.toLowerCase())) {
                    score += 15;
                }
            }
        }

        return Math.min(score, 30); // Cap at 30
    }

    /**
     * Score based on URL patterns
     */
    private scoreUrls(traffic: HttpTrafficEntry[], urlPatterns: string[]): number {
        let score = 0;

        for (const entry of traffic) {
            const url = entry.url.toLowerCase();

            for (const pattern of urlPatterns) {
                // Handle wildcard patterns
                const regex = new RegExp(pattern.replace(/\*/g, '.*'), 'i');
                if (regex.test(url)) {
                    score += 10;
                }
            }
        }

        return Math.min(score, 30); // Cap at 30
    }

    /**
     * Score based on HTML content
     */
    private scoreHtml(htmlPatterns: string[]): number {
        let score = 0;
        const htmlLower = this.htmlContent.toLowerCase();

        for (const pattern of htmlPatterns) {
            if (htmlLower.includes(pattern.toLowerCase())) {
                score += 15;
            }
        }

        return Math.min(score, 45); // Cap at 45
    }

    /**
     * Get platform-specific attack recommendations
     */
    static getAttackRecommendations(platform: EcommercePlatform): string[] {
        const recommendations: Record<EcommercePlatform, string[]> = {
            shopify: [
                'Test cart.js and cart/add.js for parameter injection',
                'Check for checkout price manipulation',
                'Test discount code stacking',
                'Look for Liquid template injection',
            ],
            woocommerce: [
                'Test WooCommerce REST API endpoints',
                'Check for coupon code replay',
                'Test checkout field injection',
                'Look for wp-json/wc exposure',
            ],
            magento: [
                'Test GraphQL endpoint for information disclosure',
                'Check for form_key bypass',
                'Test quote ID manipulation',
                'Look for REST API misconfiguration',
            ],
            prestashop: [
                'Test cart rule manipulation',
                'Check for module vulnerabilities',
                'Test order state injection',
                'Look for admin endpoint exposure',
            ],
            custom: [
                'Test all common e-commerce vulnerabilities',
                'Check for price parameter manipulation',
                'Test authentication bypass',
                'Look for business logic flaws',
            ],
        };

        return recommendations[platform];
    }

    /**
     * Get known CVEs for platform
     */
    static getKnownCVEs(platform: EcommercePlatform): string[] {
        const cves: Record<EcommercePlatform, string[]> = {
            shopify: [], // Shopify is SaaS, CVEs are patched centrally
            woocommerce: [
                'CVE-2021-32789 - SQL Injection in WooCommerce',
                'CVE-2020-29156 - Insecure Deserialization',
                'CVE-2019-20892 - XSS in Product Reviews',
            ],
            magento: [
                'CVE-2022-24086 - Template Injection RCE',
                'CVE-2021-21024 - SQL Injection',
                'CVE-2020-9689 - Stored XSS',
            ],
            prestashop: [
                'CVE-2022-31101 - SQL Injection',
                'CVE-2022-22967 - Remote Code Execution',
                'CVE-2021-37538 - Arbitrary File Upload',
            ],
            custom: [],
        };

        return cves[platform];
    }
}

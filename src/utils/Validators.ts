/**
 * Validators Utility
 * Input validation for URLs, parameters, and configurations
 */

export class Validators {
    /**
     * Validate URL format
     */
    static isValidUrl(url: string): boolean {
        try {
            const parsed = new URL(url);
            return ['http:', 'https:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    }

    /**
     * Validate URL and return parsed URL object
     */
    static parseUrl(url: string): URL | null {
        try {
            const parsed = new URL(url);
            if (['http:', 'https:'].includes(parsed.protocol)) {
                return parsed;
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Extract domain from URL
     */
    static extractDomain(url: string): string | null {
        const parsed = this.parseUrl(url);
        return parsed ? parsed.hostname : null;
    }

    /**
     * Check if URL is same origin
     */
    static isSameOrigin(url1: string, url2: string): boolean {
        const parsed1 = this.parseUrl(url1);
        const parsed2 = this.parseUrl(url2);

        if (!parsed1 || !parsed2) return false;

        return parsed1.origin === parsed2.origin;
    }

    /**
     * Validate email format
     */
    static isValidEmail(email: string): boolean {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Validate positive integer
     */
    static isPositiveInteger(value: unknown): boolean {
        if (typeof value === 'number') {
            return Number.isInteger(value) && value > 0;
        }
        if (typeof value === 'string') {
            const num = parseInt(value, 10);
            return !isNaN(num) && num > 0 && value === num.toString();
        }
        return false;
    }

    /**
     * Validate numeric value
     */
    static isNumeric(value: unknown): boolean {
        if (typeof value === 'number') {
            return !isNaN(value) && isFinite(value);
        }
        if (typeof value === 'string') {
            return !isNaN(parseFloat(value)) && isFinite(parseFloat(value));
        }
        return false;
    }

    /**
     * Validate price format (positive decimal with up to 2 decimal places)
     */
    static isValidPrice(value: unknown): boolean {
        if (!this.isNumeric(value)) return false;
        const num = typeof value === 'number' ? value : parseFloat(value as string);
        if (num < 0) return false;

        // Check decimal places
        const decimalPlaces = (num.toString().split('.')[1] || '').length;
        return decimalPlaces <= 2;
    }

    /**
     * Validate quantity (positive integer or specific allowed values)
     */
    static isValidQuantity(value: unknown): boolean {
        if (typeof value === 'number') {
            return Number.isInteger(value) && value >= 0;
        }
        if (typeof value === 'string') {
            const num = parseInt(value, 10);
            return !isNaN(num) && num >= 0;
        }
        return false;
    }

    /**
     * Validate cookie format
     */
    static isValidCookieString(cookies: string): boolean {
        if (!cookies || typeof cookies !== 'string') return false;

        // Basic cookie format validation: name=value pairs separated by semicolons
        const pairs = cookies.split(';').map(p => p.trim());
        return pairs.every(pair => {
            const [name, value] = pair.split('=');
            return name && name.length > 0 && value !== undefined;
        });
    }

    /**
     * Validate Bearer token format
     */
    static isValidBearerToken(token: string): boolean {
        if (!token || typeof token !== 'string') return false;
        return token.length >= 10 && !token.includes(' ');
    }

    /**
     * Validate proxy URL format
     */
    static isValidProxyUrl(proxyUrl: string): boolean {
        try {
            const parsed = new URL(proxyUrl);
            return ['http:', 'https:', 'socks5:', 'socks4:'].includes(parsed.protocol);
        } catch {
            return false;
        }
    }

    /**
     * Check if value is potential injection payload
     */
    static isPotentialInjection(value: unknown): boolean {
        if (typeof value !== 'string') return false;

        const injectionPatterns = [
            /[<>]/,                          // HTML/XML
            /['";]/,                         // SQL quotes
            /(\$\{|{{)/,                     // Template injection
            /(SELECT|INSERT|UPDATE|DELETE|DROP)/i, // SQL keywords
            /javascript:/i,                  // JavaScript protocol
            /(<script|<img|<svg)/i,          // Common XSS tags
            /\.\.\//,                        // Path traversal
            /(\x00|\x0a|\x0d)/,             // Null bytes, newlines
        ];

        return injectionPatterns.some(pattern => pattern.test(value));
    }

    /**
     * Sanitize string for safe output
     */
    static sanitize(value: string): string {
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    /**
     * Validate JSON string
     */
    static isValidJson(str: string): boolean {
        try {
            JSON.parse(str);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Parse and validate JSON safely
     */
    static safeJsonParse<T = unknown>(str: string, defaultValue: T): T {
        try {
            return JSON.parse(str) as T;
        } catch {
            return defaultValue;
        }
    }

    /**
     * Validate array of values against a predicate
     */
    static validateArray<T>(arr: T[], predicate: (item: T) => boolean): boolean {
        return Array.isArray(arr) && arr.every(predicate);
    }

    /**
     * Validate object has required keys
     */
    static hasRequiredKeys(obj: Record<string, unknown>, keys: string[]): boolean {
        return keys.every(key => key in obj && obj[key] !== undefined);
    }
}

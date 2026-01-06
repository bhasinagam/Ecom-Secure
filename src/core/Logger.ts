/**
 * Structured Logging with Winston
 * Provides consistent logging across the scanner
 */

import winston from 'winston';
import * as path from 'path';
import * as fs from 'fs';

const { combine, timestamp, printf, colorize, errors } = winston.format;

// Custom log format
const logFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;

    if (Object.keys(meta).length > 0) {
        log += ` ${JSON.stringify(meta)}`;
    }

    if (stack) {
        log += `\n${stack}`;
    }

    return log;
});

// Console format with colors
const consoleFormat = combine(
    colorize({ all: true }),
    timestamp({ format: 'HH:mm:ss' }),
    errors({ stack: true }),
    logFormat
);

// File format without colors
const fileFormat = combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    logFormat
);

export interface LoggerOptions {
    level?: string;
    logDir?: string;
    console?: boolean;
    file?: boolean;
}

class Logger {
    private logger: winston.Logger;
    private options: LoggerOptions;

    constructor(options: LoggerOptions = {}) {
        this.options = {
            level: options.level || process.env.LOG_LEVEL || 'info',
            logDir: options.logDir || path.join(process.cwd(), 'logs'),
            console: options.console !== false,
            file: options.file !== false,
        };

        this.logger = this.createLogger();
    }

    private createLogger(): winston.Logger {
        const transports: winston.transport[] = [];

        // Console transport
        if (this.options.console) {
            transports.push(
                new winston.transports.Console({
                    format: consoleFormat,
                })
            );
        }

        // File transport
        if (this.options.file) {
            // Ensure log directory exists
            if (!fs.existsSync(this.options.logDir!)) {
                fs.mkdirSync(this.options.logDir!, { recursive: true });
            }

            // General log file
            transports.push(
                new winston.transports.File({
                    filename: path.join(this.options.logDir!, 'scanner.log'),
                    format: fileFormat,
                    maxsize: 10 * 1024 * 1024, // 10MB
                    maxFiles: 5,
                })
            );

            // Error-only log file
            transports.push(
                new winston.transports.File({
                    filename: path.join(this.options.logDir!, 'error.log'),
                    level: 'error',
                    format: fileFormat,
                    maxsize: 10 * 1024 * 1024,
                    maxFiles: 5,
                })
            );
        }

        return winston.createLogger({
            level: this.options.level,
            transports,
        });
    }

    /**
     * Log info message
     */
    info(message: string, meta?: Record<string, unknown>): void {
        this.logger.info(message, meta);
    }

    /**
     * Log warning message
     */
    warn(message: string, meta?: Record<string, unknown>): void {
        this.logger.warn(message, meta);
    }

    /**
     * Log error message
     */
    error(message: string, error?: Error | unknown, meta?: Record<string, unknown>): void {
        if (error instanceof Error) {
            this.logger.error(message, { ...meta, stack: error.stack, errorMessage: error.message });
        } else {
            this.logger.error(message, { ...meta, error });
        }
    }

    /**
     * Log debug message
     */
    debug(message: string, meta?: Record<string, unknown>): void {
        this.logger.debug(message, meta);
    }

    /**
     * Log verbose message
     */
    verbose(message: string, meta?: Record<string, unknown>): void {
        this.logger.verbose(message, meta);
    }

    /**
     * Log HTTP request
     */
    http(method: string, url: string, status?: number, duration?: number): void {
        this.logger.http(`${method} ${url}`, { status, duration: `${duration}ms` });
    }

    /**
     * Log scan phase
     */
    phase(phaseName: string, message: string): void {
        this.logger.info(`[${phaseName.toUpperCase()}] ${message}`);
    }

    /**
     * Log vulnerability finding
     */
    finding(severity: string, type: string, endpoint: string): void {
        this.logger.warn(`[FINDING] ${severity} - ${type} at ${endpoint}`);
    }

    /**
     * Log detector activity
     */
    detector(name: string, action: string, details?: Record<string, unknown>): void {
        this.logger.debug(`[DETECTOR:${name}] ${action}`, details);
    }

    /**
     * Set log level dynamically
     */
    setLevel(level: string): void {
        this.logger.level = level;
    }

    /**
     * Create a child logger with additional context
     */
    child(context: Record<string, unknown>): winston.Logger {
        return this.logger.child(context);
    }
}

// Singleton instance
export const logger = new Logger();

// Export class for custom instances
export { Logger };

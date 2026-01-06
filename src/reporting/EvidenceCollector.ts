/**
 * Evidence Collector - Gathers proof of exploitation
 */

import { HttpRequest, HttpResponse, HAREntry } from '../types';

export interface Evidence {
    type: 'request' | 'response' | 'screenshot' | 'har' | 'diff';
    timestamp: string;
    data: unknown;
    description: string;
}

export class EvidenceCollector {
    private evidence: Evidence[] = [];

    addRequest(request: HttpRequest, description: string): void {
        this.evidence.push({
            type: 'request',
            timestamp: new Date().toISOString(),
            data: this.sanitizeRequest(request),
            description,
        });
    }

    addResponse(response: HttpResponse, description: string): void {
        this.evidence.push({
            type: 'response',
            timestamp: new Date().toISOString(),
            data: {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
                body: response.body.substring(0, 5000),
                duration: response.duration,
            },
            description,
        });
    }

    addHAREntry(entry: HAREntry, description: string): void {
        this.evidence.push({
            type: 'har',
            timestamp: new Date().toISOString(),
            data: entry,
            description,
        });
    }

    addDiff(original: unknown, modified: unknown, description: string): void {
        this.evidence.push({
            type: 'diff',
            timestamp: new Date().toISOString(),
            data: { original, modified },
            description,
        });
    }

    getAll(): Evidence[] {
        return this.evidence;
    }

    clear(): void {
        this.evidence = [];
    }

    private sanitizeRequest(request: HttpRequest): Record<string, unknown> {
        const headers = { ...request.headers };
        delete headers['authorization'];
        delete headers['cookie'];
        return { method: request.method, url: request.url, headers, data: request.data };
    }
}

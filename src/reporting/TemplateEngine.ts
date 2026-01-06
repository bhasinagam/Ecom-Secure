/**
 * Template Engine for Report Generation
 */

export class TemplateEngine {
    private helpers: Record<string, (...args: unknown[]) => string> = {};

    constructor() {
        this.registerDefaultHelpers();
    }

    private registerDefaultHelpers(): void {
        this.helpers['severity_color'] = (severity: unknown) => {
            const colors: Record<string, string> = {
                CRITICAL: '#ef4444',
                HIGH: '#f97316',
                MEDIUM: '#eab308',
                LOW: '#22c55e',
                INFO: '#3b82f6',
            };
            return colors[String(severity)] || '#64748b';
        };

        this.helpers['format_date'] = (date: unknown) => {
            return new Date(String(date)).toLocaleString();
        };

        this.helpers['percent'] = (value: unknown) => {
            return `${(Number(value) * 100).toFixed(0)}%`;
        };
    }

    render(template: string, data: Record<string, unknown>): string {
        let result = template;

        // Replace variables {{var}}
        result = result.replace(/\{\{(\w+)\}\}/g, (_, key) => {
            return String(data[key] ?? '');
        });

        // Replace helpers {{helper arg}}
        result = result.replace(/\{\{(\w+)\s+(\w+)\}\}/g, (_, helper, arg) => {
            if (this.helpers[helper]) {
                return this.helpers[helper](data[arg]);
            }
            return '';
        });

        return result;
    }

    registerHelper(name: string, fn: (...args: unknown[]) => string): void {
        this.helpers[name] = fn;
    }
}

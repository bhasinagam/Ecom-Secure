/**
 * Report Generator
 * Creates vulnerability reports in multiple formats
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import {
    ScanResult,
    Vulnerability,
    ReportFormat,
    ReportOptions,
    Severity
} from '../types';
import { logger } from '../core/Logger';

export class ReportGenerator {
    private scanResult: ScanResult;
    private options: ReportOptions;

    constructor(scanResult: ScanResult, options?: Partial<ReportOptions>) {
        this.scanResult = scanResult;
        this.options = {
            format: options?.format || 'json',
            outputPath: options?.outputPath || './reports',
            includeEvidence: options?.includeEvidence !== false,
            includeRemediation: options?.includeRemediation !== false,
            includeReproduction: options?.includeReproduction !== false,
        };
    }

    /**
     * Generate report in specified format
     */
    async generate(): Promise<string> {
        await fs.mkdir(this.options.outputPath, { recursive: true });

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `ecomsecure-report-${timestamp}`;

        let reportPath: string;

        switch (this.options.format) {
            case 'json':
                reportPath = await this.generateJSON(filename);
                break;
            case 'html':
                reportPath = await this.generateHTML(filename);
                break;
            case 'markdown':
                reportPath = await this.generateMarkdown(filename);
                break;
            case 'sarif':
                reportPath = await this.generateSARIF(filename);
                break;
            default:
                reportPath = await this.generateJSON(filename);
        }

        logger.info(`Report generated: ${reportPath}`);
        return reportPath;
    }

    /**
     * Generate JSON report
     */
    private async generateJSON(filename: string): Promise<string> {
        const reportPath = path.join(this.options.outputPath, `${filename}.json`);
        const report = this.buildReportData();
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
        return reportPath;
    }

    /**
     * Generate HTML report
     */
    private async generateHTML(filename: string): Promise<string> {
        const reportPath = path.join(this.options.outputPath, `${filename}.html`);
        const data = this.buildReportData();

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EcomSecure Scanner Report</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --accent: #3b82f6; --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
    h2 { font-size: 1.5rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
    .stat { background: var(--card); padding: 1.5rem; border-radius: 0.5rem; }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-label { color: #94a3b8; font-size: 0.875rem; }
    .vuln-card { background: var(--card); border-radius: 0.5rem; padding: 1.5rem; margin: 1rem 0; border-left: 4px solid; }
    .vuln-card.CRITICAL { border-color: var(--critical); }
    .vuln-card.HIGH { border-color: var(--high); }
    .vuln-card.MEDIUM { border-color: var(--medium); }
    .vuln-card.LOW { border-color: var(--low); }
    .severity { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .severity.CRITICAL { background: var(--critical); }
    .severity.HIGH { background: var(--high); }
    .severity.MEDIUM { background: var(--medium); color: #000; }
    .severity.LOW { background: var(--low); color: #000; }
    .evidence { background: #0f172a; padding: 1rem; border-radius: 0.25rem; margin: 1rem 0; font-family: monospace; font-size: 0.875rem; overflow-x: auto; }
    pre { white-space: pre-wrap; word-break: break-all; }
    .meta { color: #64748b; font-size: 0.875rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ EcomSecure Scanner Report</h1>
    <div class="meta">
      Target: ${data.target} | Scan Date: ${data.scanDate} | Duration: ${data.duration}s
    </div>
    
    <div class="summary">
      <div class="stat">
        <div class="stat-value">${data.summary.totalVulnerabilities}</div>
        <div class="stat-label">Total Vulnerabilities</div>
      </div>
      <div class="stat">
        <div class="stat-value" style="color: var(--critical);">${data.summary.critical}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat">
        <div class="stat-value" style="color: var(--high);">${data.summary.high}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat">
        <div class="stat-value" style="color: var(--medium);">${data.summary.medium}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat">
        <div class="stat-value">${data.summary.requestsSent}</div>
        <div class="stat-label">Requests Sent</div>
      </div>
    </div>
    
    <h2>Vulnerabilities</h2>
    ${data.vulnerabilities.map(v => `
      <div class="vuln-card ${v.severity}">
        <span class="severity ${v.severity}">${v.severity}</span>
        <h3 style="margin: 0.5rem 0;">${v.type}</h3>
        <p><strong>Endpoint:</strong> ${v.endpoint || 'N/A'}</p>
        <p><strong>Parameter:</strong> ${v.parameter || 'N/A'}</p>
        <p><strong>Confidence:</strong> ${(v.confidence * 100).toFixed(0)}%</p>
        ${v.impact ? `<p><strong>Impact:</strong> ${v.impact}</p>` : ''}
        ${v.evidence && v.evidence.length > 0 ? `
          <div class="evidence">
            <strong>Evidence:</strong>
            <pre>${v.evidence.join('\n')}</pre>
          </div>
        ` : ''}
      </div>
    `).join('')}
  </div>
</body>
</html>`;

        await fs.writeFile(reportPath, html);
        return reportPath;
    }

    /**
     * Generate Markdown report
     */
    private async generateMarkdown(filename: string): Promise<string> {
        const reportPath = path.join(this.options.outputPath, `${filename}.md`);
        const data = this.buildReportData();

        const md = `# EcomSecure Scanner Report

**Target:** ${data.target}  
**Scan Date:** ${data.scanDate}  
**Duration:** ${data.duration}s  
**Platform:** ${data.platform}

## Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | ${data.summary.totalVulnerabilities} |
| Critical | ${data.summary.critical} |
| High | ${data.summary.high} |
| Medium | ${data.summary.medium} |
| Low | ${data.summary.low} |
| Requests Sent | ${data.summary.requestsSent} |

## Vulnerabilities

${data.vulnerabilities.map(v => `
### ${v.severity} - ${v.type}

- **Endpoint:** ${v.endpoint || 'N/A'}
- **Parameter:** ${v.parameter || 'N/A'}
- **Confidence:** ${(v.confidence * 100).toFixed(0)}%
${v.impact ? `- **Impact:** ${v.impact}` : ''}

${v.evidence && v.evidence.length > 0 ? `
**Evidence:**
\`\`\`
${v.evidence.join('\n')}
\`\`\`
` : ''}
---
`).join('\n')}
`;

        await fs.writeFile(reportPath, md);
        return reportPath;
    }

    /**
     * Generate SARIF report (Static Analysis Results Interchange Format)
     */
    private async generateSARIF(filename: string): Promise<string> {
        const reportPath = path.join(this.options.outputPath, `${filename}.sarif`);

        const sarif = {
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            version: '2.1.0',
            runs: [{
                tool: {
                    driver: {
                        name: 'EcomSecure Scanner',
                        version: '1.0.0',
                        informationUri: 'https://github.com/ecomsecure/scanner',
                        rules: this.scanResult.vulnerabilities.map(v => ({
                            id: v.type,
                            name: v.type,
                            shortDescription: { text: v.type },
                            defaultConfiguration: { level: this.severityToSARIF(v.severity) },
                        })),
                    },
                },
                results: this.scanResult.vulnerabilities.map(v => ({
                    ruleId: v.type,
                    level: this.severityToSARIF(v.severity),
                    message: { text: v.impact || v.type },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: v.endpoint },
                        },
                    }],
                })),
            }],
        };

        await fs.writeFile(reportPath, JSON.stringify(sarif, null, 2));
        return reportPath;
    }

    /**
     * Build report data structure
     */
    private buildReportData(): {
        target: string;
        scanDate: string;
        duration: number;
        platform: string;
        summary: {
            totalVulnerabilities: number;
            critical: number;
            high: number;
            medium: number;
            low: number;
            requestsSent: number;
        };
        vulnerabilities: Vulnerability[];
    } {
        const vulns = this.scanResult.vulnerabilities;

        return {
            target: this.scanResult.target,
            scanDate: this.scanResult.startTime,
            duration: this.scanResult.duration,
            platform: this.scanResult.platform?.platform || 'unknown',
            summary: {
                totalVulnerabilities: vulns.length,
                critical: vulns.filter(v => v.severity === 'CRITICAL').length,
                high: vulns.filter(v => v.severity === 'HIGH').length,
                medium: vulns.filter(v => v.severity === 'MEDIUM').length,
                low: vulns.filter(v => v.severity === 'LOW').length,
                requestsSent: this.scanResult.requestCount,
            },
            vulnerabilities: vulns,
        };
    }

    /**
     * Convert severity to SARIF level
     */
    private severityToSARIF(severity: Severity): string {
        const map: Record<Severity, string> = {
            CRITICAL: 'error',
            HIGH: 'error',
            MEDIUM: 'warning',
            LOW: 'note',
            INFO: 'note',
            NONE: 'none',
        };
        return map[severity] || 'note';
    }
}

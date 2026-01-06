/**
 * EcomSecure Scanner CLI Entry Point
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora, { Ora } from 'ora';
import boxen from 'boxen';
import * as readline from 'readline';
import { Config } from '../core/Config';
import { Scanner } from '../core/Scanner';
import { logger } from '../core/Logger';
import { ReportGenerator } from '../reporting/ReportGenerator';
import { ReportFormat, ScanConfig, DetectorModule } from '../types';

const VERSION = '1.0.0';

/**
 * Display banner
 */
function displayBanner(): void {
    const banner = chalk.cyan(`
  ███████╗ ██████╗ ██████╗ ███╗   ███╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
  ██╔════╝██╔════╝██╔═══██╗████╗ ████║██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
  █████╗  ██║     ██║   ██║██╔████╔██║███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  
  ██╔══╝  ██║     ██║   ██║██║╚██╔╝██║╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  
  ███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████║███████║╚██████╗╚██████╔╝██║  ██║███████╗
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
  `);

    console.log(banner);
    console.log(chalk.gray(`  E-Commerce Vulnerability Scanner v${VERSION}\n`));
}

/**
 * Display legal consent prompt
 */
async function getLegalConsent(): Promise<boolean> {
    const consentMessage = boxen(
        chalk.yellow.bold('⚠️  LEGAL NOTICE & CONSENT REQUIRED\n\n') +
        chalk.white(
            'This tool performs active security testing against web applications.\n\n' +
            'Before proceeding, you MUST confirm that:\n\n' +
            chalk.cyan('1.') + ' You have explicit written authorization to test the target\n' +
            chalk.cyan('2.') + ' You own or have permission from the owner of the target\n' +
            chalk.cyan('3.') + ' You understand this tool will send HTTP requests that may\n' +
            '   modify data or trigger security alerts\n' +
            chalk.cyan('4.') + ' You accept full responsibility for your use of this tool\n\n'
        ) +
        chalk.red.bold('Unauthorized testing is ILLEGAL and may result in criminal charges.'),
        {
            padding: 1,
            margin: 1,
            borderStyle: 'double',
            borderColor: 'yellow',
        }
    );

    console.log(consentMessage);

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise((resolve) => {
        rl.question(
            chalk.yellow('\nDo you confirm you have authorization to test the target? (yes/no): '),
            (answer) => {
                rl.close();
                resolve(answer.toLowerCase() === 'yes' || answer.toLowerCase() === 'y');
            }
        );
    });
}

/**
 * Main CLI program
 */
async function main(): Promise<void> {
    const program = new Command();

    program
        .name('ecomsecure')
        .description('AI-powered e-commerce vulnerability scanner')
        .version(VERSION);

    program
        .command('scan <target>')
        .description('Scan an e-commerce target for vulnerabilities')
        .option('-m, --modules <modules>', 'Detection modules to run (comma-separated)', 'all')
        .option('-f, --format <format>', 'Report format (json, html, markdown, sarif)', 'json')
        .option('-o, --output <path>', 'Output directory for reports', './reports')
        .option('-c, --config <file>', 'Path to configuration file')
        .option('-d, --depth <number>', 'Crawl depth', '2')
        .option('-t, --timeout <ms>', 'Request timeout in milliseconds', '30000')
        .option('-r, --rate-limit <rps>', 'Requests per second', '10')
        .option('--concurrency <number>', 'Maximum concurrent requests', '5')
        .option('--cookies <string>', 'Authentication cookies')
        .option('--auth-token <string>', 'Bearer token for authentication')
        .option('--proxy <url>', 'HTTP proxy URL')
        .option('--no-ai', 'Disable AI verification')
        .option('--yes', 'Skip consent prompt (for CI/CD)')
        .option('-v, --verbose', 'Enable verbose logging')
        .action(async (target, options) => {
            displayBanner();

            // Legal consent check
            if (!options.yes) {
                const consent = await getLegalConsent();
                if (!consent) {
                    console.log(chalk.red('\n❌ Scan aborted. Authorization required.\n'));
                    process.exit(1);
                }
            }

            console.log(chalk.green('\n✓ Authorization confirmed. Starting scan...\n'));

            // Build configuration
            const configManager = new Config({ configPath: options.config });

            // Load and merge with CLI options
            const modules = options.modules.split(',').map((m: string) => m.trim()) as DetectorModule[];

            const scanConfig: ScanConfig = {
                targetUrl: target,
                target,
                modules,
                format: options.format === 'sarif' ? 'json' : options.format,
                outputPath: options.output,
                depth: parseInt(options.depth, 10),
                timeout: parseInt(options.timeout, 10),
                rateLimit: parseInt(options.rateLimit, 10),
                concurrency: parseInt(options.concurrency, 10),
                authCookies: options.cookies,
                authToken: options.authToken,
                proxy: options.proxy,
                aiVerification: options.ai !== false,
                verbose: options.verbose || false,
                stealth: false,
                noVerify: options.ai === false,
                model: process.env.LLM_MODEL || 'google/gemini-2.0-flash-exp:free',
                exportHar: false,
            };

            // Setup logger
            if (options.verbose) {
                logger.setLevel('debug');
            }

            let spinner: Ora | null = null;

            try {
                // Initialize scanner
                const scanner = new Scanner(scanConfig);

                // Run scan with progress updates
                spinner = ora('Initializing scanner...').start();

                scanner.on('phase', (phase: string) => {
                    spinner?.succeed();
                    spinner = ora(`Phase: ${phase}`).start();
                });

                scanner.on('progress', (msg: string) => {
                    if (spinner) {
                        spinner.text = msg;
                    }
                });

                const result = await scanner.scan(target);

                spinner?.succeed('Scan complete!');

                // Display results summary
                console.log('\n' + boxen(
                    chalk.bold('Scan Results Summary\n\n') +
                    `${chalk.cyan('Target:')} ${target}\n` +
                    `${chalk.cyan('Duration:')} ${result.duration}s\n` +
                    `${chalk.cyan('Requests:')} ${result.requestCount}\n` +
                    `${chalk.cyan('Platform:')} ${result.platform?.platform || 'Unknown'}\n\n` +
                    chalk.bold('Vulnerabilities Found:\n') +
                    `  ${chalk.red('CRITICAL:')} ${result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length}\n` +
                    `  ${chalk.yellow('HIGH:')} ${result.vulnerabilities.filter(v => v.severity === 'HIGH').length}\n` +
                    `  ${chalk.blue('MEDIUM:')} ${result.vulnerabilities.filter(v => v.severity === 'MEDIUM').length}\n` +
                    `  ${chalk.green('LOW:')} ${result.vulnerabilities.filter(v => v.severity === 'LOW').length}`,
                    {
                        padding: 1,
                        borderColor: result.vulnerabilities.some(v => v.severity === 'CRITICAL') ? 'red' : 'green',
                        borderStyle: 'round',
                    }
                ));

                // Generate report
                spinner = ora('Generating report...').start();
                const reportGenerator = new ReportGenerator(result, {
                    format: scanConfig.format as ReportFormat,
                    outputPath: scanConfig.outputPath || './reports',
                });
                const reportPath = await reportGenerator.generate();
                spinner.succeed(`Report saved to: ${reportPath}`);

                // Exit with appropriate code
                const criticalCount = result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
                process.exit(criticalCount > 0 ? 1 : 0);

            } catch (error) {
                spinner?.fail('Scan failed');
                console.error(chalk.red('\nError:'), error instanceof Error ? error.message : error);
                process.exit(2);
            }
        });

    program
        .command('modules')
        .description('List available detection modules')
        .action(() => {
            displayBanner();

            console.log(chalk.bold('Available Detection Modules:\n'));

            const modules = [
                { name: 'price', desc: 'Price manipulation (zero price, negative, overflow, etc.)' },
                { name: 'discount', desc: 'Discount abuse (stacking, replay, percentage overflow)' },
                { name: 'quantity', desc: 'Quantity manipulation (negative, type confusion, arrays)' },
                { name: 'session', desc: 'Session attacks (cart tampering, CSRF bypass, fixation)' },
                { name: 'payment', desc: 'Payment bypass (amount mismatch, callback, signature)' },
                { name: 'business', desc: 'Business logic (shipping, referrals, points, min orders)' },
                { name: 'race', desc: 'Race conditions (concurrent checkout, TOCTOU, inventory)' },
                { name: 'all', desc: 'Run all modules' },
            ];

            modules.forEach(m => {
                console.log(`  ${chalk.cyan(m.name.padEnd(12))} ${m.desc}`);
            });
            console.log();
        });

    program
        .command('init')
        .description('Initialize configuration file')
        .action(async () => {
            displayBanner();

            const configContent = `# EcomSecure Scanner Configuration
target: https://example.com
modules:
  - all
format: json
outputPath: ./reports
depth: 2
timeout: 30000
rateLimit: 10
concurrency: 5
aiVerification: true
`;

            const fs = await import('fs/promises');
            await fs.writeFile('ecomsecure.yaml', configContent);
            console.log(chalk.green('✓ Configuration file created: ecomsecure.yaml'));
        });

    await program.parseAsync(process.argv);
}

// Run CLI
main().catch((error) => {
    console.error(chalk.red('Fatal error:'), error);
    process.exit(1);
});

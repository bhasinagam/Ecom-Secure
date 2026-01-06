/**
 * Detector Registry
 * Dynamically loads and manages vulnerability detectors
 */

import { ScanConfig, DetectorModule } from '../../types';
import { BaseDetector } from './BaseDetector';
import { logger } from '../../core/Logger';

// Import all detectors
import { ZeroPriceDetector } from '../price-manipulation/ZeroPriceDetector';
import { NegativePriceDetector } from '../price-manipulation/NegativePriceDetector';
import { FormulaInjectionDetector } from '../price-manipulation/FormulaInjectionDetector';
import { CurrencyConfusionDetector } from '../price-manipulation/CurrencyConfusionDetector';
import { IntegerOverflowDetector } from '../price-manipulation/IntegerOverflowDetector';

import { CodeStackingDetector } from '../discount-abuse/CodeStackingDetector';
import { NegativeDiscountDetector } from '../discount-abuse/NegativeDiscountDetector';
import { PercentageOverflowDetector } from '../discount-abuse/PercentageOverflowDetector';
import { ReplayAttackDetector } from '../discount-abuse/ReplayAttackDetector';

import { NegativeQuantityDetector } from '../quantity-manipulation/NegativeQuantityDetector';
import { QuantityTypeConfusionDetector } from '../quantity-manipulation/TypeConfusionDetector';
import { BoundaryTestDetector } from '../quantity-manipulation/BoundaryTestDetector';
import { ArrayInjectionDetector } from '../quantity-manipulation/ArrayInjectionDetector';

import { CartTamperingDetector } from '../session-attacks/CartTamperingDetector';
import { CheckoutSkipDetector } from '../session-attacks/CheckoutSkipDetector';
import { CSRFTokenBypassDetector } from '../session-attacks/CSRFTokenBypassDetector';
import { SessionFixationDetector } from '../session-attacks/SessionFixationDetector';
import { AdvancedTokenAnalyzer } from '../session/AdvancedTokenAnalyzer';

import { AmountMismatchDetector } from '../payment-bypass/AmountMismatchDetector';
import { CallbackManipulationDetector } from '../payment-bypass/CallbackManipulationDetector';
import { SignatureBypassDetector } from '../payment-bypass/SignatureBypassDetector';
import { WebhookReplayDetector } from '../payment-bypass/WebhookReplayDetector';
import { ThreeDSBypassDetector } from '../payment-bypass/ThreeDSBypassDetector';

import { ShippingAbuseDetector } from '../business-logic/ShippingAbuseDetector';
import { ReferralGameDetector } from '../business-logic/ReferralGameDetector';
import { ReturnFraudDetector } from '../business-logic/ReturnFraudDetector';
import { PointsMultiplicationDetector } from '../business-logic/PointsMultiplicationDetector';
import { MinimumOrderBypassDetector } from '../business-logic/MinimumOrderBypassDetector';
import { WorkflowContradictionDetector } from '../business-logic/WorkflowContradictionDetector';

import { ConcurrentCheckoutDetector } from '../race-conditions/ConcurrentCheckoutDetector';
import { TOCTOUDetector } from '../race-conditions/TOCTOUDetector';
import { InventoryRaceDetector } from '../race-conditions/InventoryRaceDetector';
import { PrecisionRaceDetector } from '../race-conditions/PrecisionRaceDetector';
import { AdvancedFuzzingDetector } from '../fuzzing/AdvancedFuzzingDetector';

// New Advanced Detectors
import { GraphQLIntrospectionDetector } from '../api/GraphQLIntrospectionDetector';
import { SSRFDetector } from '../injection/SSRFDetector';
import { DeserializationDetector } from '../injection/DeserializationDetector';
import { RequestSmugglingDetector } from '../protocol/RequestSmugglingDetector';

interface DetectorDefinition {
    module: DetectorModule;
    detector: new () => BaseDetector;
    enabled: boolean;
}

export class DetectorRegistry {
    private detectors: Map<string, DetectorDefinition> = new Map();
    private config: ScanConfig;

    constructor(config: ScanConfig) {
        this.config = config;
        this.registerAll();
    }

    /**
     * Register all available detectors
     */
    private registerAll(): void {
        // Price Manipulation Detectors
        this.register('zero-price', 'price', ZeroPriceDetector);
        this.register('negative-price', 'price', NegativePriceDetector);
        this.register('formula-injection', 'price', FormulaInjectionDetector);
        this.register('currency-confusion', 'price', CurrencyConfusionDetector);
        this.register('integer-overflow', 'price', IntegerOverflowDetector);

        // Discount Abuse Detectors
        this.register('code-stacking', 'discount', CodeStackingDetector);
        this.register('negative-discount', 'discount', NegativeDiscountDetector);
        this.register('percentage-overflow', 'discount', PercentageOverflowDetector);
        this.register('replay-attack', 'discount', ReplayAttackDetector);

        // Quantity Manipulation Detectors
        this.register('negative-quantity', 'quantity', NegativeQuantityDetector);
        this.register('type-confusion', 'quantity', QuantityTypeConfusionDetector);
        this.register('boundary-test', 'quantity', BoundaryTestDetector);
        this.register('array-injection', 'quantity', ArrayInjectionDetector);

        // Session Attack Detectors
        this.register('cart-tampering', 'session', CartTamperingDetector);
        this.register('checkout-skip', 'session', CheckoutSkipDetector);
        this.register('csrf-bypass', 'session', CSRFTokenBypassDetector);
        this.register('session-fixation', 'session', SessionFixationDetector);
        this.register('advanced-token-analyzer', 'session', AdvancedTokenAnalyzer); // NEW

        // Payment Bypass Detectors
        this.register('amount-mismatch', 'payment', AmountMismatchDetector);
        this.register('callback-manipulation', 'payment', CallbackManipulationDetector);
        this.register('signature-bypass', 'payment', SignatureBypassDetector);
        this.register('webhook-replay', 'payment', WebhookReplayDetector);
        this.register('3ds-bypass', 'payment', ThreeDSBypassDetector);

        // Business Logic Detectors
        this.register('shipping-abuse', 'business', ShippingAbuseDetector);
        this.register('referral-game', 'business', ReferralGameDetector);
        this.register('return-fraud', 'business', ReturnFraudDetector);
        this.register('points-multiplication', 'business', PointsMultiplicationDetector);
        this.register('minimum-order-bypass', 'business', MinimumOrderBypassDetector);
        this.register('workflow-contradiction', 'business', WorkflowContradictionDetector); // NEW

        // Race Condition Detectors
        this.register('concurrent-checkout', 'race', ConcurrentCheckoutDetector);
        this.register('toctou', 'race', TOCTOUDetector);
        this.register('inventory-race', 'race', InventoryRaceDetector);
        this.register('precision-race', 'race', PrecisionRaceDetector); // NEW

        // API Detectors
        this.register('graphql-introspection', 'api', GraphQLIntrospectionDetector); // NEW

        // Injection Detectors
        this.register('ssrf', 'injection', SSRFDetector); // NEW
        this.register('deserialization', 'injection', DeserializationDetector); // NEW

        // Protocol Detectors
        this.register('request-smuggling', 'protocol', RequestSmugglingDetector);

        // Fuzzing Detectors
        this.register('evolutionary-fuzzing', 'fuzzing', AdvancedFuzzingDetector); // NEW

        logger.info(`Registered ${this.detectors.size} detectors`);
    }

    /**
     * Register a detector
     */
    private register(
        name: string,
        module: DetectorModule,
        detector: new () => BaseDetector
    ): void {
        this.detectors.set(name, {
            module,
            detector,
            enabled: this.isModuleEnabled(module),
        });
    }

    /**
     * Check if module is enabled in config
     */
    private isModuleEnabled(module: DetectorModule): boolean {
        if (this.config.modules.includes('all')) {
            return true;
        }
        return this.config.modules.includes(module);
    }

    /**
     * Get enabled detectors for specified modules
     */
    getEnabledDetectors(modules: DetectorModule[]): BaseDetector[] {
        const enabledDetectors: BaseDetector[] = [];

        logger.debug(`Getting enabled detectors for modules: ${modules.join(', ')}`);

        for (const [name, definition] of this.detectors) {
            const shouldEnable = modules.includes('all') || modules.includes(definition.module);

            if (shouldEnable) {
                const instance = new definition.detector();
                enabledDetectors.push(instance);
                logger.debug(`Enabled detector: ${name} (module: ${definition.module})`);
            }
        }

        logger.info(`Enabled ${enabledDetectors.length} detectors out of ${this.detectors.size} registered`);
        return enabledDetectors;
    }

    /**
     * Get all detectors
     */
    getAll(): BaseDetector[] {
        return Array.from(this.detectors.values()).map(d => new d.detector());
    }

    /**
     * Get detectors by module
     */
    getByModule(module: DetectorModule): BaseDetector[] {
        const detectors: BaseDetector[] = [];

        for (const [name, definition] of this.detectors) {
            if (definition.module === module) {
                detectors.push(new definition.detector());
            }
        }

        return detectors;
    }

    /**
     * Get detector by name
     */
    getByName(name: string): BaseDetector | null {
        const definition = this.detectors.get(name);
        return definition ? new definition.detector() : null;
    }

    /**
     * Get all registered detector names
     */
    getNames(): string[] {
        return Array.from(this.detectors.keys());
    }

    /**
     * Get detector count by module
     */
    getCountByModule(): Record<string, number> {
        const counts: Record<string, number> = {};

        for (const definition of this.detectors.values()) {
            counts[definition.module] = (counts[definition.module] || 0) + 1;
        }

        return counts;
    }
}

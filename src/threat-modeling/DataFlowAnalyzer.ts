/**
 * Data Flow Analyzer
 * Traces price, quantity, and discount flow through checkout
 */

import { CheckoutFlow, DataFlow, Parameter } from '../types';
import { logger } from '../core/Logger';

export interface FlowAnalysisResult {
    parameter: string;
    path: FlowNode[];
    vulnerabilities: FlowVulnerability[];
    manipulationPoints: string[];
}

export interface FlowNode {
    location: string;
    operation: string;
    canModify: boolean;
    validationPresent: boolean;
}

export interface FlowVulnerability {
    type: string;
    location: string;
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class DataFlowAnalyzer {
    /**
     * Analyze data flow for price manipulation opportunities
     */
    analyzePriceFlow(flow: CheckoutFlow): FlowAnalysisResult {
        const path: FlowNode[] = [];
        const vulnerabilities: FlowVulnerability[] = [];
        const manipulationPoints: string[] = [];

        // Entry point: Product page
        path.push({
            location: 'product_page',
            operation: 'display_price',
            canModify: false,
            validationPresent: false,
        });

        // Add to cart
        path.push({
            location: 'add_to_cart',
            operation: 'price_capture',
            canModify: true,
            validationPresent: false,
        });
        manipulationPoints.push('add_to_cart: price parameter may be client-controlled');

        // Cart state
        path.push({
            location: 'cart',
            operation: 'price_storage',
            canModify: true,
            validationPresent: false,
        });

        // Check if price is in flow parameters
        const priceParams = Object.entries(flow.parameters).filter(
            ([key]) => /price|amount/i.test(key)
        );

        if (priceParams.length > 0) {
            vulnerabilities.push({
                type: 'client_controlled_price',
                location: 'checkout',
                description: 'Price parameter found in client request',
                severity: 'CRITICAL',
            });
            manipulationPoints.push('checkout: price sent in POST body');
        }

        // Checkout
        path.push({
            location: 'checkout',
            operation: 'total_calculation',
            canModify: true,
            validationPresent: false,
        });

        // Payment
        path.push({
            location: 'payment_gateway',
            operation: 'charge_amount',
            canModify: true,
            validationPresent: false,
        });

        // Check for price mismatch opportunities
        if (flow.endpoints.length > 1) {
            const cartEndpoint = flow.endpoints.find(e => e.type === 'cart');
            const paymentEndpoint = flow.endpoints.find(e => e.type === 'payment');

            if (cartEndpoint && paymentEndpoint) {
                vulnerabilities.push({
                    type: 'price_mismatch',
                    location: 'cart_to_payment',
                    description: 'Price calculated at cart may differ from payment amount',
                    severity: 'HIGH',
                });
            }
        }

        return {
            parameter: 'price',
            path,
            vulnerabilities,
            manipulationPoints,
        };
    }

    /**
     * Analyze quantity data flow
     */
    analyzeQuantityFlow(flow: CheckoutFlow): FlowAnalysisResult {
        const path: FlowNode[] = [];
        const vulnerabilities: FlowVulnerability[] = [];
        const manipulationPoints: string[] = [];

        // User input
        path.push({
            location: 'product_page',
            operation: 'quantity_input',
            canModify: true,
            validationPresent: true, // Client-side only
        });

        // Add to cart
        path.push({
            location: 'add_to_cart',
            operation: 'quantity_validation',
            canModify: true,
            validationPresent: false,
        });
        manipulationPoints.push('add_to_cart: quantity parameter');

        // Check for quantity parameters
        const qtyParams = Object.entries(flow.parameters).filter(
            ([key]) => /quantity|qty|count/i.test(key)
        );

        if (qtyParams.length > 0) {
            // Check for type issues
            for (const [key, info] of qtyParams) {
                if (info.type === 'string') {
                    vulnerabilities.push({
                        type: 'type_confusion',
                        location: 'quantity_parameter',
                        description: `Quantity parameter ${key} accepts string type`,
                        severity: 'MEDIUM',
                    });
                }
            }

            vulnerabilities.push({
                type: 'negative_quantity',
                location: 'cart',
                description: 'Quantity parameter may accept negative values',
                severity: 'HIGH',
            });
        }

        // Inventory check
        path.push({
            location: 'inventory_system',
            operation: 'stock_validation',
            canModify: false,
            validationPresent: true, // Should be present
        });

        // Checkout
        path.push({
            location: 'checkout',
            operation: 'quantity_finalization',
            canModify: true,
            validationPresent: false,
        });
        manipulationPoints.push('checkout: final quantity in order');

        return {
            parameter: 'quantity',
            path,
            vulnerabilities,
            manipulationPoints,
        };
    }

    /**
     * Analyze discount/coupon flow
     */
    analyzeDiscountFlow(flow: CheckoutFlow): FlowAnalysisResult {
        const path: FlowNode[] = [];
        const vulnerabilities: FlowVulnerability[] = [];
        const manipulationPoints: string[] = [];

        // Coupon input
        path.push({
            location: 'cart_or_checkout',
            operation: 'coupon_input',
            canModify: true,
            validationPresent: true,
        });
        manipulationPoints.push('coupon_input: code value');

        // Check for discount parameters
        const discountParams = Object.entries(flow.parameters).filter(
            ([key]) => /discount|coupon|promo/i.test(key)
        );

        if (discountParams.length > 0) {
            // Discount amount in parameters
            const amountParams = discountParams.filter(
                ([key]) => /amount|value|percent/i.test(key)
            );

            if (amountParams.length > 0) {
                vulnerabilities.push({
                    type: 'client_controlled_discount',
                    location: 'discount_application',
                    description: 'Discount amount/percentage is client-controlled',
                    severity: 'CRITICAL',
                });
                manipulationPoints.push('discount: amount/percentage parameter');
            }

            vulnerabilities.push({
                type: 'discount_stacking',
                location: 'checkout',
                description: 'Multiple discount codes may be applied',
                severity: 'MEDIUM',
            });

            vulnerabilities.push({
                type: 'discount_replay',
                location: 'checkout',
                description: 'Single-use codes may be replayable',
                severity: 'MEDIUM',
            });
        }

        // Validation
        path.push({
            location: 'discount_engine',
            operation: 'coupon_validation',
            canModify: false,
            validationPresent: true,
        });

        // Application
        path.push({
            location: 'cart_total',
            operation: 'discount_application',
            canModify: true,
            validationPresent: false,
        });

        // Percentage overflow check
        vulnerabilities.push({
            type: 'percentage_overflow',
            location: 'discount_calculation',
            description: 'Discount percentage may accept values > 100%',
            severity: 'HIGH',
        });

        // Negative discount
        vulnerabilities.push({
            type: 'negative_discount',
            location: 'discount_parameter',
            description: 'Negative discount values may increase total',
            severity: 'MEDIUM',
        });

        return {
            parameter: 'discount',
            path,
            vulnerabilities,
            manipulationPoints,
        };
    }

    /**
     * Find all data manipulation points
     */
    findManipulationPoints(flow: CheckoutFlow): Map<string, string[]> {
        const points = new Map<string, string[]>();

        // Analyze each parameter
        for (const [paramName, paramInfo] of Object.entries(flow.parameters)) {
            const paramPoints: string[] = [];

            // Client-side input
            paramPoints.push(`input: User can provide value for ${paramName}`);

            // Network interception
            paramPoints.push(`network: ${paramInfo.method} to ${paramInfo.endpoint}`);

            // If numeric, additional manipulation
            if (paramInfo.type === 'number') {
                paramPoints.push('mutation: numeric value can be modified');
            }

            points.set(paramName, paramPoints);
        }

        return points;
    }

    /**
     * Identify TOCTOU (Time of Check to Time of Use) windows
     */
    findTOCTOUWindows(flow: CheckoutFlow): Array<{
        check: string;
        use: string;
        vulnerability: string;
    }> {
        const windows: Array<{
            check: string;
            use: string;
            vulnerability: string;
        }> = [];

        // Price check at cart, use at payment
        if (flow.stateTransitions.some(t => t.includes('cart')) &&
            flow.stateTransitions.some(t => t.includes('payment'))) {
            windows.push({
                check: 'cart: price calculation',
                use: 'payment: charge amount',
                vulnerability: 'Price can be modified between cart and payment',
            });
        }

        // Inventory check vs order creation
        if (flow.stateTransitions.some(t => t.includes('checkout'))) {
            windows.push({
                check: 'add_to_cart: inventory check',
                use: 'checkout: order creation',
                vulnerability: 'Inventory can be depleted by concurrent requests',
            });
        }

        // Discount validation vs application
        const hasDiscount = Object.keys(flow.parameters).some(
            k => /discount|coupon/i.test(k)
        );
        if (hasDiscount) {
            windows.push({
                check: 'coupon_apply: validation',
                use: 'checkout: discount applied',
                vulnerability: 'Discount code usage count may not be atomic',
            });
        }

        return windows;
    }

    /**
     * Generate flow diagram in Mermaid format
     */
    generateFlowDiagram(flow: CheckoutFlow): string {
        let diagram = 'graph TD\n';

        // Add state transitions
        for (const transition of flow.stateTransitions) {
            const [from, to] = transition.split(' → ').map(s => s.trim().replace(/[^a-zA-Z]/g, '_'));
            diagram += `    ${from}[${from}] --> ${to}[${to}]\n`;
        }

        // Add parameter flows
        for (const [param, info] of Object.entries(flow.parameters)) {
            const sanitizedParam = param.replace(/[^a-zA-Z]/g, '_');
            diagram += `    ${sanitizedParam}((${param})) -.-> checkout\n`;
        }

        return diagram;
    }
}
